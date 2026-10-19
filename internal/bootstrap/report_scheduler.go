// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// haLockReportScheduler names this scheduler's lease row in
// ha_scheduler_locks (ha_coordinator.go, D-048).
const haLockReportScheduler = "report-scheduler"

const (
	reportSendMaxAttempts   = 3
	reportRetryDelayDefault = 30 * time.Second

	// AlertEventReportDeliveryFailed is raised after the final failed send,
	// or on a render failure (which is not retried).
	AlertEventReportDeliveryFailed = "report.delivery_failed"

	reportContentTypeCSV  = "text/csv; charset=utf-8"
	reportContentTypeXLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	reportContentTypePDF  = "application/pdf"
)

// ReportScheduler periodically renders and emails due scheduled reports.
// Schedules are super-admin-only and render fleet-wide data.
type ReportScheduler struct {
	certProvider   CertificateProvider
	caProvider     CAProvider
	store          ReportScheduleStore
	mailer         *EvidenceMailer
	postureStore   PostureSnapshotStore
	exceptionStore FindingExceptionStore

	audit  AuditProvider
	alerts AlertEventSink

	pollInterval time.Duration
	retryDelay   time.Duration
	maxAttempts  int

	// send and sleep are test seams; nil means mailer.SendWithType and a
	// timer interrupted by ctx or Stop (returning false).
	send  func(recipients []string, subject, body string, attachment []byte, filename, contentType string) error
	sleep func(ctx context.Context, d time.Duration) bool

	// haCoordinator is nil when unavailable (soft-fail), which keeps the
	// single-replica behavior of always scanning.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewReportSchedulerFromEnv builds the scheduler (REPORT_POLL_HOURS, default 6).
// The posture and exception stores self-construct from env so the call site
// in main.go stays small.
func NewReportSchedulerFromEnv(certs CertificateProvider, cas CAProvider, store ReportScheduleStore, mailer *EvidenceMailer, audit AuditProvider) *ReportScheduler {
	pollHours := 6
	if raw := strings.TrimSpace(os.Getenv("REPORT_POLL_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollHours = n
		}
	}
	postureStore, _ := NewPostureSnapshotStoreFromEnv()
	exceptionStore, _ := newFindingExceptionStoreFromEnv()
	s := &ReportScheduler{
		certProvider:   certs,
		caProvider:     cas,
		store:          store,
		mailer:         mailer,
		postureStore:   postureStore,
		exceptionStore: exceptionStore,
		pollInterval:   time.Duration(pollHours) * time.Hour,
		retryDelay:     reportRetryDelayDefault,
		maxAttempts:    reportSendMaxAttempts,
		haCoordinator:  newHACoordinatorFromEnvLogged(),
		stop:           make(chan struct{}),
	}
	return s.WithAudit(audit)
}

// WithAudit sets the audit provider and installs the default alert sink: a
// log line plus an audit row (same shape as EvidenceScheduler.WithAudit).
func (s *ReportScheduler) WithAudit(a AuditProvider) *ReportScheduler {
	s.audit = a
	if s.alerts == nil {
		s.alerts = func(ctx context.Context, event, detail string) {
			logging.Infof("alert event %s: %s", event, detail)
			if a == nil {
				return
			}
			if err := a.AppendEntry(ctx, AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: event,
				ActorType: "system", ActorID: "report-scheduler",
				ResourceType: "report_schedule", ResourceID: evidenceScheduleIDFromDetail(detail),
				Outcome: AuditOutcomeFailure, ChangeSummary: detail,
			}); err != nil {
				logging.Infof("report scheduler: audit append failed for %s: %v", event, err)
			}
		}
	}
	return s
}

// Start launches the delivery loop. Call Stop to shut it down.
func (s *ReportScheduler) Start() {
	go func() {
		s.scan()
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.scan()
			case <-s.stop:
				return
			}
		}
	}()
}

// Stop shuts down the delivery loop.
func (s *ReportScheduler) Stop() {
	s.once.Do(func() { close(s.stop) })
}

// scan sends any due schedules.
func (s *ReportScheduler) scan() {
	if s.store == nil || s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// HA gate: only the lease holder proceeds; a lock error fails closed
	// (see PostureScheduler.capture).
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockReportScheduler, 2*s.pollInterval)
		if err != nil {
			logging.Infof("report scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	schedules, err := s.store.List(ctx)
	if err != nil {
		logging.Infof("report scheduler: list failed: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, sched := range schedules {
		if !sched.isDue(now) {
			continue
		}
		body, filename, contentType, err := s.renderScheduledReport(ctx, sched, now)
		if err != nil {
			logging.Infof("report scheduler: render %s failed: %v", sched.ID, err)
			s.alertFailure(ctx, sched, 0, err)
			continue
		}
		sent, interrupted := s.sendWithRetry(ctx, sched, now, body, filename, contentType)
		if interrupted {
			return
		}
		if !sent {
			continue
		}
		if err := s.store.MarkSent(ctx, sched.ID, now.Format(time.RFC3339)); err != nil {
			logging.Infof("report scheduler: mark-sent %s failed: %v", sched.ID, err)
		}
		logging.Infof("report scheduler: sent %s/%s to %d recipient(s)", sched.Report, sched.Format, len(sched.Recipients))
	}
}

// renderScheduledReport renders the schedule's report fleet-wide.
func (s *ReportScheduler) renderScheduledReport(ctx context.Context, sched ReportSchedule, now time.Time) (body []byte, filename, contentType string, err error) {
	all, err := listAllCertificates(ctx, s.certProvider, CertificateListQuery{})
	if err != nil {
		return nil, "", "", fmt.Errorf("list certificates: %w", err)
	}
	filename = fmt.Sprintf("%s-%s.%s", sched.Report, now.Format("2006-01-02"), sched.Format)

	if sched.Report == reportExecutiveSummary {
		if sched.Format != "pdf" {
			return nil, "", "", fmt.Errorf("unsupported format %q for %s", sched.Format, sched.Report)
		}
		var cas CAListResult
		if s.caProvider != nil {
			if cas, err = s.caProvider.ListCAs(ctx, CAListQuery{Limit: 1000}); err != nil {
				return nil, "", "", fmt.Errorf("list CAs: %w", err)
			}
		}
		summary := computeExecutiveSummary(ctx, all.Items, cas.Items, activeFindingExceptions(ctx, s.exceptionStore))
		trend, terr := loadExecutiveTrend(ctx, s.postureStore, now)
		if terr != nil {
			// The trend is a chart on the page, not the report: degrade like
			// the HTTP handler rather than fail the delivery.
			logging.Infof("report scheduler: posture trend unavailable: %v", terr)
		} else {
			summary.Trend = trend
		}
		pdf, err := renderExecutiveSummaryPDF(summary, now)
		if err != nil {
			return nil, "", "", fmt.Errorf("render executive summary: %w", err)
		}
		return pdf, filename, reportContentTypePDF, nil
	}

	var header []string
	var rows [][]string
	switch sched.Report {
	case reportInventory:
		header = inventoryExportColumns
		for _, c := range all.Items {
			rows = append(rows, inventoryExportRow(c))
		}
	case reportFindings:
		header = findingsExportColumns
		rows = findingsExportRows(all.Items)
	default:
		return nil, "", "", fmt.Errorf("unknown report %q", sched.Report)
	}
	var buf bytes.Buffer
	switch sched.Format {
	case "csv":
		err = writeCSV(&buf, header, rows)
		contentType = reportContentTypeCSV
	case "xlsx":
		err = writeXLSX(&buf, sched.Report, header, rows)
		contentType = reportContentTypeXLSX
	default:
		err = fmt.Errorf("unsupported format %q for %s", sched.Format, sched.Report)
	}
	if err != nil {
		return nil, "", "", err
	}
	return buf.Bytes(), filename, contentType, nil
}

// sendWithRetry tries up to maxAttempts sends, sleeping retryDelay between
// attempts. After the final failure it raises report.delivery_failed; the
// schedule is left unmarked so the next poll retries. interrupted is true
// when stop/ctx cut a sleep short (no alert).
func (s *ReportScheduler) sendWithRetry(ctx context.Context, sched ReportSchedule, now time.Time, body []byte, filename, contentType string) (sent, interrupted bool) {
	send := s.send
	if send == nil {
		send = s.mailer.SendWithType
	}
	attempts := s.maxAttempts
	if attempts < 1 {
		attempts = reportSendMaxAttempts
	}
	subject := fmt.Sprintf("%s — %s report (%s)", orgName(), sched.Report, now.Format("2006-01-02"))
	text := fmt.Sprintf("Attached is the scheduled %s report (%s) for %s, generated %s by Kryptkeeper.",
		sched.Report, sched.Format, orgName(), now.Format("2006-01-02 15:04 MST"))
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if lastErr = send(sched.Recipients, subject, text, body, filename, contentType); lastErr == nil {
			return true, false
		}
		logging.Infof("report scheduler: send %s failed: %s", sched.ID, redactRecipients(lastErr, sched.Recipients))
		if attempt < attempts && !s.sleepFor(ctx, s.retryDelay) {
			return false, true
		}
	}
	s.alertFailure(ctx, sched, attempts, lastErr)
	return false, false
}

func (s *ReportScheduler) alertFailure(ctx context.Context, sched ReportSchedule, attempts int, err error) {
	if s.alerts == nil {
		return
	}
	// Detail never carries recipients or SMTP credentials.
	s.alerts(ctx, AlertEventReportDeliveryFailed,
		fmt.Sprintf("schedule=%s report=%s format=%s attempts=%d error=%s",
			sched.ID, sched.Report, sched.Format, attempts, redactRecipients(err, sched.Recipients)))
}

// redactRecipients masks recipient addresses an SMTP server may echo back in
// its error text.
func redactRecipients(err error, recipients []string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, r := range recipients {
		if r != "" {
			msg = strings.ReplaceAll(msg, r, "[recipient]")
		}
	}
	return msg
}

func (s *ReportScheduler) sleepFor(ctx context.Context, d time.Duration) bool {
	if s.sleep != nil {
		return s.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-s.stop:
		return false
	}
}
