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

// haLockPostureScheduler names this scheduler's lease row in
// ha_scheduler_locks (ha_coordinator.go, W6-01/PE-9/D-048).
const haLockPostureScheduler = "posture-scheduler"

// postureRetentionFloorDays is the hard minimum for POSTURE_RETENTION_DAYS:
// compliance reporting needs 13 months of trend history, so the window can
// be widened but never narrowed below this.
const postureRetentionFloorDays = 400

// AlertEventPostureSnapshotMissed is raised when no snapshot has landed for
// more than two capture intervals.
const AlertEventPostureSnapshotMissed = "posture.snapshot_missed"

// AlertEventSink delivers an alert event (UC-I01 channels consume it later;
// W28-06 reuses this type).
type AlertEventSink func(ctx context.Context, event, detail string)

func postureRetentionDaysFromEnv() (int, error) {
	raw := strings.TrimSpace(os.Getenv("POSTURE_RETENTION_DAYS"))
	if raw == "" {
		return postureRetentionFloorDays, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("POSTURE_RETENTION_DAYS=%q is not an integer", raw)
	}
	if n < postureRetentionFloorDays {
		return 0, fmt.Errorf("POSTURE_RETENTION_DAYS=%d is below the %d-day minimum", n, postureRetentionFloorDays)
	}
	return n, nil
}

// ValidatePostureRetentionFromEnv lets main.go fail startup on a bad window.
func ValidatePostureRetentionFromEnv() error {
	_, err := postureRetentionDaysFromEnv()
	return err
}

// PostureScheduler periodically captures a crypto-posture snapshot so the
// dashboard can chart posture trends over time. It de-dupes within a UTC day so
// restarts don't create duplicate rows.
type PostureScheduler struct {
	certProvider CertificateProvider
	store        PostureSnapshotStore

	// exceptionStore is nil when the finding-exception DB is unavailable
	// (soft-fail — see newFindingExceptionStoreFromEnv), which degrades a
	// captured snapshot's Findings to raw==effective rather than blocking
	// capture entirely.
	exceptionStore FindingExceptionStore

	pollInterval time.Duration

	// haCoordinator is nil when unavailable (soft-fail — see
	// newHACoordinatorFromEnvLogged), which preserves the pre-W6-01
	// single-replica behavior of always capturing.
	haCoordinator *HACoordinator

	audit         AuditProvider
	alerts        AlertEventSink
	retentionDays int
	// configErr disables the loop (Start logs and returns) so a bad
	// retention value can never shorten history even if main.go skips
	// ValidatePostureRetentionFromEnv.
	configErr error
	// missedFor is the snapshot ID a missed-snapshot alert was last raised
	// for. In-memory only: a restart may re-announce one gap once.
	missedFor string
	clock     func() time.Time

	stop chan struct{}
	once sync.Once
}

func (s *PostureScheduler) now() time.Time {
	if s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

// WithAudit sets the audit sink for prune records and installs the default
// alert sink. No alert-event bus exists yet, so an alert is a log line plus
// an audit row; UC-I01 channel delivery subscribes later.
func (s *PostureScheduler) WithAudit(a AuditProvider) *PostureScheduler {
	s.audit = a
	s.alerts = func(ctx context.Context, event, detail string) {
		logging.Infof("alert event %s: %s", event, detail)
		if a == nil {
			return
		}
		if err := a.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: event,
			ActorType: "system", ActorID: "posture-scheduler",
			ResourceType: "alert_event", ResourceID: "-",
			Outcome: AuditOutcomeFailure, ChangeSummary: detail,
		}); err != nil {
			logging.Infof("posture scheduler: audit append failed for %s: %v", event, err)
		}
	}
	return s
}

// NewPostureSchedulerFromEnv creates a PostureScheduler using environment config.
//
// POSTURE_SNAPSHOT_HOURS — how often to capture a snapshot (default: 24).
//
// exceptionStore (W2-12) is self-constructed from env here rather than
// threaded through this constructor's signature — this constructor's own
// call site (cmd/kryptkeeper/main.go) is outside this ticket's write_scope,
// matching the precedent registerReportsHandlers already set for the
// crypto-posture handler's own findingExceptionStore. Keeping it a
// constructor-injected field (not fetched inside capture/computeCryptoPosture)
// is what keeps capture's DB read visible and testable — see
// posture_scheduler_test.go, which sets exceptionStore directly on a literal
// PostureScheduler and never calls this constructor.
func NewPostureSchedulerFromEnv(certProvider CertificateProvider, store PostureSnapshotStore) *PostureScheduler {
	pollHours := 24
	if raw := strings.TrimSpace(os.Getenv("POSTURE_SNAPSHOT_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollHours = n
		}
	}
	retentionDays, retentionErr := postureRetentionDaysFromEnv()
	exceptionStore, _ := newFindingExceptionStoreFromEnv()
	return &PostureScheduler{
		retentionDays:  retentionDays,
		configErr:      retentionErr,
		certProvider:   certProvider,
		store:          store,
		exceptionStore: exceptionStore,
		pollInterval:   time.Duration(pollHours) * time.Hour,
		haCoordinator:  newHACoordinatorFromEnvLogged(),
		stop:           make(chan struct{}),
	}
}

// Start launches the snapshot loop in a goroutine. Call Stop to shut it down.
func (s *PostureScheduler) Start() {
	if s.configErr != nil {
		logging.Infof("posture scheduler: disabled: %v", s.configErr)
		return
	}
	go func() {
		s.capture()

		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.capture()
			case <-s.stop:
				return
			}
		}
	}()
}

// Stop shuts down the snapshot loop.
func (s *PostureScheduler) Stop() {
	s.once.Do(func() { close(s.stop) })
}

// capture computes the current posture and stores a snapshot, skipping if one
// already exists for today.
func (s *PostureScheduler) capture() {
	if s.store == nil || s.certProvider == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// HA gate (W6-01/PE-9/D-048): on >=2 replicas, only the lease holder
	// proceeds. A lock error is treated as "not leader" — failing closed
	// here is what keeps this a no-double-run guarantee rather than a
	// best-effort one; a coordinator that is simply unavailable (nil) is
	// the separate, deliberate single-replica fallback set at construction.
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockPostureScheduler, 2*s.pollInterval)
		if err != nil {
			logging.Warnf("posture scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	now := s.now()

	latest, hasLatest, err := s.store.Latest(ctx)
	if err != nil {
		logging.Infof("posture scheduler: latest lookup failed: %v", err)
	}
	if hasLatest {
		s.checkMissed(ctx, latest, now)
		// One snapshot per UTC day.
		if dayKey(latest.CapturedAt) == dayKey(now.Format(time.RFC3339)) {
			return
		}
	}

	result, err := listAllCertificates(ctx, s.certProvider, CertificateListQuery{})
	if err != nil {
		logging.Warnf("posture scheduler: list certs failed: %v", err)
		return
	}

	report := computeCryptoPostureReport(result.Items, activeFindingExceptions(ctx, s.exceptionStore))
	id, err := newPostureSnapshotID()
	if err != nil {
		logging.Warnf("posture scheduler: id generation failed: %v", err)
		return
	}
	snap := snapshotFromReport(id, now.Format(time.RFC3339), report)
	if err := s.store.Save(ctx, snap); err != nil {
		logging.Warnf("posture scheduler: save failed: %v", err)
		return
	}
	logging.Infof("posture scheduler: captured snapshot %s (%d certs, PQC %d%%, automation %d%%)",
		id, snap.TotalCerts, snap.PQCScorePercent, snap.AutomationPercent)
	// Leader-only by construction: capture returned above for non-holders.
	s.prune(ctx, now)
}

func (s *PostureScheduler) checkMissed(ctx context.Context, latest PostureSnapshot, now time.Time) {
	if s.alerts == nil {
		return
	}
	t, err := time.Parse(time.RFC3339, latest.CapturedAt)
	if err != nil || now.Sub(t) <= 2*s.pollInterval || s.missedFor == latest.ID {
		return
	}
	s.missedFor = latest.ID
	s.alerts(ctx, AlertEventPostureSnapshotMissed, fmt.Sprintf("no posture snapshot since %s (%.0fh, interval %s)",
		latest.CapturedAt, now.Sub(t).Hours(), s.pollInterval))
}

func (s *PostureScheduler) prune(ctx context.Context, now time.Time) {
	days := max(s.retentionDays, postureRetentionFloorDays)
	cutoff := now.AddDate(0, 0, -days).UTC().Format(time.RFC3339)
	res, err := s.store.Prune(ctx, cutoff)
	if err != nil {
		logging.Infof("posture scheduler: prune failed: %v", err)
		return
	}
	if res.Deleted == 0 || s.audit == nil {
		return
	}
	if err := s.audit.AppendEntry(ctx, AuditEntry{
		Timestamp: now.Format(time.RFC3339), Action: "posture.snapshot_prune",
		ActorType: "system", ActorID: "posture-scheduler",
		ResourceType: "posture_snapshot", ResourceID: "-", Outcome: AuditOutcomeSuccess,
		ChangeSummary: fmt.Sprintf("deleted=%d oldest=%s newest=%s cutoff=%s", res.Deleted, res.Oldest, res.Newest, cutoff),
	}); err != nil {
		logging.Infof("posture scheduler: audit append failed for prune: %v", err)
	}
}
