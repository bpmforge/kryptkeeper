// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// haLockEvidenceScheduler names this scheduler's lease row in
// ha_scheduler_locks (ha_coordinator.go, W6-01/PE-9/D-048).
const haLockEvidenceScheduler = "evidence-scheduler"

const (
	// evidenceSendMaxAttempts is the in-scan send attempt count per due
	// schedule. The W28-13 UAT greps the failure log line for this count.
	evidenceSendMaxAttempts   = 3
	evidenceRetryDelayDefault = 30 * time.Second

	// AlertEventEvidenceDeliveryFailed is raised after the final failed send.
	AlertEventEvidenceDeliveryFailed = "evidence.delivery_failed"
)

// evidenceRetryDelayFromEnv reads EVIDENCE_RETRY_DELAY_SECONDS (positive
// integer, default 30); invalid or non-positive values fall back to default.
func evidenceRetryDelayFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("EVIDENCE_RETRY_DELAY_SECONDS"))
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return evidenceRetryDelayDefault
}

// EvidenceScheduler periodically renders and emails due evidence packs.
type EvidenceScheduler struct {
	certProvider CertificateProvider
	caProvider   CAProvider
	store        EvidenceScheduleStore
	mailer       *EvidenceMailer

	pollInterval time.Duration

	audit      AuditProvider
	alerts     AlertEventSink
	retryDelay time.Duration

	// send and sleep are test seams; nil means mailer.Send and a timer that
	// is interrupted by ctx or Stop (returning false).
	send  func(recipients []string, subject, body string, pdf []byte, filename string) error
	sleep func(ctx context.Context, d time.Duration) bool

	// haCoordinator is nil when unavailable (soft-fail — see
	// newHACoordinatorFromEnvLogged), which preserves the pre-W6-01
	// single-replica behavior of always scanning.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewEvidenceSchedulerFromEnv builds the scheduler (EVIDENCE_POLL_HOURS, default 6).
func NewEvidenceSchedulerFromEnv(certProvider CertificateProvider, caProvider CAProvider, store EvidenceScheduleStore, mailer *EvidenceMailer) *EvidenceScheduler {
	pollHours := 6
	if raw := strings.TrimSpace(os.Getenv("EVIDENCE_POLL_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollHours = n
		}
	}
	return &EvidenceScheduler{
		certProvider:  certProvider,
		caProvider:    caProvider,
		store:         store,
		mailer:        mailer,
		pollInterval:  time.Duration(pollHours) * time.Hour,
		retryDelay:    evidenceRetryDelayFromEnv(),
		haCoordinator: newHACoordinatorFromEnvLogged(),
		stop:          make(chan struct{}),
	}
}

// WithAudit sets the audit provider and, when no sink is set, installs the
// default alert sink: a log line plus an audit row (same shape as
// PostureScheduler.WithAudit; UC-I01 channel delivery subscribes later).
func (s *EvidenceScheduler) WithAudit(a AuditProvider) *EvidenceScheduler {
	s.audit = a
	if s.alerts == nil {
		s.alerts = func(ctx context.Context, event, detail string) {
			logging.Infof("alert event %s: %s", event, detail)
			if a == nil {
				return
			}
			if err := a.AppendEntry(ctx, AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: event,
				ActorType: "system", ActorID: "evidence-scheduler",
				ResourceType: "evidence_schedule", ResourceID: evidenceScheduleIDFromDetail(detail),
				Outcome: AuditOutcomeFailure, ChangeSummary: detail,
			}); err != nil {
				logging.Infof("evidence scheduler: audit append failed for %s: %v", event, err)
			}
		}
	}
	return s
}

// evidenceScheduleIDFromDetail extracts the schedule id from a detail string
// that starts with "schedule=<id> ".
func evidenceScheduleIDFromDetail(detail string) string {
	rest, ok := strings.CutPrefix(detail, "schedule=")
	if !ok {
		return "-"
	}
	id, _, _ := strings.Cut(rest, " ")
	if id == "" {
		return "-"
	}
	return id
}

// Start launches the delivery loop. Call Stop to shut it down.
func (s *EvidenceScheduler) Start() {
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
func (s *EvidenceScheduler) Stop() {
	s.once.Do(func() { close(s.stop) })
}

// scan sends any due schedules.
func (s *EvidenceScheduler) scan() {
	if s.store == nil || s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// HA gate (W6-01/PE-9/D-048): on >=2 replicas, only the lease holder
	// proceeds — see posture_scheduler.go's capture() for why a lock error
	// fails closed (skip) rather than open (run anyway).
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockEvidenceScheduler, 2*s.pollInterval)
		if err != nil {
			logging.Warnf("evidence scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	schedules, err := s.store.List(ctx)
	if err != nil {
		logging.Warnf("evidence scheduler: list failed: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, sched := range schedules {
		if !sched.isDue(now) {
			continue
		}
		pdfBytes, filename, err := renderEvidencePackForFramework(ctx, s.certProvider, s.caProvider, sched.Framework, now)
		if err != nil {
			logging.Warnf("evidence scheduler: render %s failed: %v", sched.ID, err)
			continue
		}
		subject, body := evidenceEmailSubjectBody(sched.Framework, now)
		sent, interrupted := s.sendWithRetry(ctx, sched, subject, body, pdfBytes, filename)
		if interrupted {
			return
		}
		if !sent {
			continue
		}
		if err := s.store.MarkSent(ctx, sched.ID, now.Format(time.RFC3339)); err != nil {
			logging.Warnf("evidence scheduler: mark-sent %s failed: %v", sched.ID, err)
		}
		logging.Infof("evidence scheduler: sent %s pack to %d recipient(s)", sched.Framework, len(sched.Recipients))
	}
}

// sendWithRetry tries up to evidenceSendMaxAttempts sends, sleeping
// retryDelay between attempts. After the final failure it raises
// evidence.delivery_failed; the schedule is left unmarked so the next poll
// retries. interrupted is true when stop/ctx cut a sleep short (no alert).
func (s *EvidenceScheduler) sendWithRetry(ctx context.Context, sched EvidenceSchedule, subject, body string, pdf []byte, filename string) (sent, interrupted bool) {
	send := s.send
	if send == nil {
		send = s.mailer.Send
	}
	var lastErr error
	for attempt := 1; attempt <= evidenceSendMaxAttempts; attempt++ {
		if lastErr = send(sched.Recipients, subject, body, pdf, filename); lastErr == nil {
			return true, false
		}
		logging.Infof("evidence scheduler: send %s failed: %v", sched.ID, lastErr)
		if attempt < evidenceSendMaxAttempts && !s.sleepFor(ctx, s.retryDelay) {
			return false, true
		}
	}
	if s.alerts != nil {
		// Detail never carries recipients or SMTP credentials.
		s.alerts(ctx, AlertEventEvidenceDeliveryFailed,
			fmt.Sprintf("schedule=%s framework=%s attempts=%d error=%v", sched.ID, sched.Framework, evidenceSendMaxAttempts, lastErr))
	}
	return false, false
}

func (s *EvidenceScheduler) sleepFor(ctx context.Context, d time.Duration) bool {
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
