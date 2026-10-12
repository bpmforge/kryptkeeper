// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRenewalSchedulerRunScanRecordsStatus(t *testing.T) {
	now := time.Now().UTC()
	soon := now.Add(10 * 24 * time.Hour).Format(time.RFC3339)
	far := now.Add(200 * 24 * time.Hour).Format(time.RFC3339)
	expired := now.Add(-2 * 24 * time.Hour).Format(time.RFC3339)

	// RenewalMethod no longer changes scheduler behavior (G-43): the hub has no
	// auto-renewal path regardless of tag, so an "acme"-tagged candidate is
	// notified just like a "manual" one.
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "auto", CommonName: "a", ValidUntil: soon, RenewalMethod: "acme"},
		{FingerprintSHA256: "manual", CommonName: "m", ValidUntil: soon, RenewalMethod: "manual"},
		{FingerprintSHA256: "far", CommonName: "f", ValidUntil: far, RenewalMethod: "acme"},
		{FingerprintSHA256: "exp", CommonName: "e", ValidUntil: expired, RenewalMethod: "acme"},
	}}

	s := &RenewalScheduler{
		certProvider:  certs,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  24 * time.Hour,
	}
	s.runScan()

	st := s.Status()
	if st.LastCandidates != 2 {
		t.Fatalf("expected 2 candidates (auto+manual within threshold), got %d", st.LastCandidates)
	}
	if st.LastExpiredSkipped != 1 {
		t.Fatalf("expected 1 expired-skipped, got %d", st.LastExpiredSkipped)
	}
	if st.LastAutoRenewTriggers != 0 {
		t.Fatalf("expected 0 auto-renew triggers (no hub-side auto-renewal path), got %d", st.LastAutoRenewTriggers)
	}
	if st.LastRunAt == "" {
		t.Fatal("expected LastRunAt to be set")
	}
	if st.NextRunAt == "" {
		t.Fatal("expected NextRunAt to be set")
	}
}

// recordingNotificationProvider records the target (OwnerEmail) of every
// TestDelivery call, so a test can assert exactly WHICH candidates were
// notified rather than just how many -- a plain count can pass by
// coincidence when candidates trade places (see the sabotage note on
// TestRenewalSchedulerHonoursPerTargetThreshold).
type recordingNotificationProvider struct {
	NotificationProvider
	sent []string
}

func (r *recordingNotificationProvider) Delivers() bool { return true }
func (r *recordingNotificationProvider) Name() string   { return "recording" }

func (r *recordingNotificationProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return nil, nil
}

func (r *recordingNotificationProvider) TestDelivery(_ context.Context, _ string, target string, _ string) (NotificationTestDeliveryResult, error) {
	r.sent = append(r.sent, target)
	return NotificationTestDeliveryResult{Status: "sent"}, nil
}

// TestRenewalSchedulerHonoursPerTargetThreshold is the W8-15 acceptance
// test: two managed targets with different renewal_threshold_days values
// must change which certificates are flagged as renewal candidates, and a
// certificate matching no managed target at all must still fall back to
// the scheduler's env-configured RENEWAL_THRESHOLD_DAYS default.
//
// Sabotage-checked: an earlier version of this test asserted only
// st.LastCandidates == 2, which still passed when resolveThresholdDays was
// hardcoded to ignore hostThresholds entirely -- the short- and
// long-threshold certs swapped candidacy but the total stayed 2. Asserting
// the exact set of notified owners below catches that.
func TestRenewalSchedulerHonoursPerTargetThreshold(t *testing.T) {
	targetStore := newFreshManagedTargetStore(t)
	ctx := context.Background()

	short := mkTarget("target-short", "short.example.com")
	short.RenewalThresholdDays = 5
	if _, err := targetStore.Create(ctx, short); err != nil {
		t.Fatalf("create short-threshold target: %v", err)
	}
	long := mkTarget("target-long", "long.example.com")
	long.RenewalThresholdDays = 90
	if _, err := targetStore.Create(ctx, long); err != nil {
		t.Fatalf("create long-threshold target: %v", err)
	}

	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		// Matches target-short (threshold 5d). Expiry is 20d out, past the
		// 5d window -- NOT a candidate. Would be a candidate under the 30d
		// env default, so this proves the smaller per-target override wins.
		{FingerprintSHA256: "short", CommonName: "short.example.com", ValidUntil: now.Add(20 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "short-owner@example.com"},
		// Matches target-long (threshold 90d). Expiry is 70d out, inside
		// the 90d window -- a candidate. Would NOT be a candidate under the
		// 30d env default, so this proves the larger per-target override
		// wins too, not just the smaller one above.
		{FingerprintSHA256: "long", CommonName: "long.example.com", ValidUntil: now.Add(70 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "long-owner@example.com"},
		// Matches no managed target: falls back to the 30d env default.
		// 25d out is inside that window -- a candidate.
		{FingerprintSHA256: "default-in", CommonName: "default-in.example.com", ValidUntil: now.Add(25 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "default-in-owner@example.com"},
		// Same fallback, but 40d out is outside the 30d default window --
		// NOT a candidate. Paired with default-in above, this pins the
		// fallback at exactly the env default, not some other value.
		{FingerprintSHA256: "default-out", CommonName: "default-out.example.com", ValidUntil: now.Add(40 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "default-out-owner@example.com"},
	}}

	rec := &recordingNotificationProvider{}
	s := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: rec,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  24 * time.Hour,
		targetStore:   targetStore,
	}
	s.runScan()

	st := s.Status()
	if st.LastCandidates != 2 {
		t.Fatalf("expected 2 renewal candidates (long-threshold override + in-window default fallback), got %d", st.LastCandidates)
	}

	notified := make(map[string]bool, len(rec.sent))
	for _, target := range rec.sent {
		notified[target] = true
	}
	if len(notified) != 2 {
		t.Fatalf("expected exactly 2 distinct owners notified, got %d: %v", len(notified), rec.sent)
	}
	if !notified["long-owner@example.com"] {
		t.Error("expected the long-threshold target's owner to be notified (70d expiry is within its 90d override)")
	}
	if !notified["default-in-owner@example.com"] {
		t.Error("expected the no-override target's owner to be notified via the 30d env default (25d expiry is within it)")
	}
	if notified["short-owner@example.com"] {
		t.Error("short-threshold target's owner should NOT be notified (20d expiry is outside its 5d override) -- did the scheduler fall back to the bigger env default instead of honoring the override?")
	}
	if notified["default-out-owner@example.com"] {
		t.Error("no-override target's owner should NOT be notified (40d expiry is outside the 30d env default)")
	}
}

// failingTestDeliveryNotificationProvider is a minimal NotificationProvider
// stub whose TestDelivery always fails, for exercising the W2-07
// retry/dead-letter path without a real SMTP/HTTP delivery.
type failingTestDeliveryNotificationProvider struct{ NotificationProvider }

func (failingTestDeliveryNotificationProvider) Delivers() bool { return true }
func (failingTestDeliveryNotificationProvider) Name() string   { return "failing-test" }

func (failingTestDeliveryNotificationProvider) TestDelivery(_ context.Context, _ string, _ string, _ string) (NotificationTestDeliveryResult, error) {
	return NotificationTestDeliveryResult{}, fmt.Errorf("smtp: connection refused")
}

// succeedingTestDeliveryNotificationProvider always succeeds.
type succeedingTestDeliveryNotificationProvider struct{ NotificationProvider }

func (succeedingTestDeliveryNotificationProvider) Delivers() bool { return true }
func (succeedingTestDeliveryNotificationProvider) Name() string   { return "succeeding-test" }

func (succeedingTestDeliveryNotificationProvider) TestDelivery(_ context.Context, _ string, _ string, _ string) (NotificationTestDeliveryResult, error) {
	return NotificationTestDeliveryResult{Status: "sent"}, nil
}

// TestRenewalScheduler_DeadLettersAfterMaxAttempts is the W2-07 regression: a
// renewal-notification trigger that fails every poll must enter a retry
// budget (renewalTriggerMaxAttempts) and only THEN dead-letter — not on the
// first failure — and a later successful delivery must clear it, not leave a
// stale dead-letter entry behind.
func TestRenewalScheduler_DeadLettersAfterMaxAttempts(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)

	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "stuck-cert", CommonName: "stuck", ValidUntil: soon, OwnerEmail: "owner@example.com"},
	}}

	s := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: failingTestDeliveryNotificationProvider{},
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  24 * time.Hour,
	}

	for i := 0; i < renewalTriggerMaxAttempts-1; i++ {
		s.runScan()
		if len(renewalDeadLetterSnapshot()) != 0 {
			t.Fatalf("attempt %d: expected no dead-letter entry before the retry budget is exhausted", i+1)
		}
	}

	s.runScan() // this attempt reaches renewalTriggerMaxAttempts
	deadLetters := renewalDeadLetterSnapshot()
	if len(deadLetters) != 1 {
		t.Fatalf("expected exactly 1 dead-letter entry after %d consecutive failures, got %d", renewalTriggerMaxAttempts, len(deadLetters))
	}
	if deadLetters[0].Fingerprint != "stuck-cert" {
		t.Errorf("expected dead-letter for stuck-cert, got %+v", deadLetters[0])
	}
	if deadLetters[0].Outcome != "notification_dead_letter" {
		t.Errorf("expected outcome notification_dead_letter, got %q", deadLetters[0].Outcome)
	}

	// A later successful delivery clears the dead-letter, not just resets the
	// counter — the failure record must reflect CURRENT state.
	s.notifProvider = succeedingTestDeliveryNotificationProvider{}
	s.runScan()
	if len(renewalDeadLetterSnapshot()) != 0 {
		t.Fatal("expected dead-letter entry to clear after a successful delivery")
	}
}

func TestSchedulerStatusHandler(t *testing.T) {
	auth := newReportsTestAuth(t)
	publishRenewalStatus(RenewalSchedulerStatus{
		Running:        true,
		ThresholdDays:  30,
		LastCandidates: 5,
		LastRunAt:      "2026-06-15T00:00:00Z",
	})

	mux := http.NewServeMux()
	registerSchedulerStatusHandler(mux, auth, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scheduler/renewal/status", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			HasRun bool                   `json:"has_run"`
			Status RenewalSchedulerStatus `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.HasRun {
		t.Fatal("expected has_run true after publish")
	}
	if resp.Data.Status.LastCandidates != 5 || resp.Data.Status.ThresholdDays != 30 {
		t.Fatalf("unexpected status: %+v", resp.Data.Status)
	}
}

func TestRenewalSchedulerRunScanSkipsWhenNotLeader(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", CommonName: "a", ValidUntil: soon, OwnerEmail: "owner@example.com"},
	}}
	mailer := succeedingTestDeliveryNotificationProvider{}

	db := newTestHADB(t)
	now := time.Now().UTC()
	// A peer replica holds a live lease on this scheduler's lock.
	peer := newTestHACoordinatorAt(t, db, "replica-peer", now)
	if ok, err := peer.TryAcquire(context.Background(), haLockRenewalScheduler, 5*time.Minute); err != nil || !ok {
		t.Fatalf("setup: peer acquire ok=%v err=%v", ok, err)
	}
	self := newTestHACoordinatorAt(t, db, "replica-self", now)

	s := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: mailer,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  time.Hour,
		haCoordinator: self,
	}
	s.runScan()

	st := s.Status()
	if st.LastRunAt != "" {
		t.Fatalf("expected non-leader scan to skip entirely (no status update), got LastRunAt=%q", st.LastRunAt)
	}
}

func TestRenewalSchedulerRunScanRunsWhenLeader(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", CommonName: "a", ValidUntil: soon, OwnerEmail: "owner@example.com"},
	}}
	mailer := succeedingTestDeliveryNotificationProvider{}

	db := newTestHADB(t)
	self := newTestHACoordinatorAt(t, db, "replica-self", time.Now().UTC())

	s := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: mailer,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  time.Hour,
		haCoordinator: self,
	}
	s.runScan()

	st := s.Status()
	if st.LastCandidates != 1 {
		t.Fatalf("expected leader scan to run and find 1 candidate, got %d", st.LastCandidates)
	}
}

func TestSchedulerStatusHandlerRequiresAuth(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerSchedulerStatusHandler(mux, auth, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scheduler/renewal/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestRenewalScheduler_ConfigStoreOverrideChangesNextTick is the W8-13
// acceptance #2 test for the renewal-scheduler consumer: a threshold_days
// override written through the real config store must change which
// candidates the SAME RenewalScheduler instance flags on its NEXT runScan()
// call, with no reconstruction.
//
// Sabotage-checked: temporarily hardcoded resolveConfigInt to always return
// fallbackDefault (ignoring the store) and confirmed this test goes red,
// then reverted.
func TestRenewalScheduler_ConfigStoreOverrideChangesNextTick(t *testing.T) {
	store := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "cert-1", CommonName: "example.com", ValidUntil: now.Add(20 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "owner@example.com"},
	}}
	rec := &recordingNotificationProvider{}

	s := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: rec,
		auditProvider: stubAuditProvider{},
		thresholdDays: 10, // bootstrap default: 20d-out cert is NOT a candidate at a 10d threshold
		pollInterval:  24 * time.Hour,
		configStore:   store,
	}

	s.runScan()
	if st := s.Status(); st.LastCandidates != 0 {
		t.Fatalf("expected 0 candidates before any override (10d threshold, 20d expiry), got %d", st.LastCandidates)
	}

	if err := store.Set(ctx, "renewal_policy.threshold_days", "30", "test-operator"); err != nil {
		t.Fatalf("write override: %v", err)
	}

	s.runScan() // same scheduler instance -- no reconstruction
	st := s.Status()
	if st.LastCandidates != 1 {
		t.Fatalf("expected 1 candidate after the DB override raises threshold to 30d (20d expiry now within window), got %d", st.LastCandidates)
	}
	if st.ThresholdDays != 30 {
		t.Fatalf("expected status to report the overridden threshold 30, got %d", st.ThresholdDays)
	}
	if len(rec.sent) != 1 || rec.sent[0] != "owner@example.com" {
		t.Fatalf("expected owner@example.com notified after the override took effect, got %v", rec.sent)
	}
}

// TestRenewalScheduler_PollIntervalConfigOverride proves the poll-interval
// half of acceptance #1/#2: runScan's returned interval (which Start's
// ticker uses to re-pace itself) reflects a DB override on this tick, not
// only the bootstrap default.
func TestRenewalScheduler_PollIntervalConfigOverride(t *testing.T) {
	store := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	s := &RenewalScheduler{
		certProvider:  &reportCertProvider{},
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  24 * time.Hour,
		configStore:   store,
	}

	if got := s.runScan(); got != 24*time.Hour {
		t.Fatalf("expected bootstrap default poll interval 24h with no override, got %v", got)
	}

	if err := store.Set(ctx, "renewal_policy.poll_hours", "6", "test-operator"); err != nil {
		t.Fatalf("write override: %v", err)
	}

	if got := s.runScan(); got != 6*time.Hour {
		t.Fatalf("expected overridden poll interval 6h after DB override, got %v", got)
	}
}

// TestRenewalScheduler_ConfigStoreNilFallsBackToEnvDefault guards the
// pre-W8-13 behavior: a nil configStore (store unavailable) must not panic
// and must behave exactly like before -- every tick uses the struct's
// bootstrap-default fields.
func TestRenewalScheduler_ConfigStoreNilFallsBackToEnvDefault(t *testing.T) {
	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "cert-1", CommonName: "example.com", ValidUntil: now.Add(20 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "owner@example.com"},
	}}
	rec := &recordingNotificationProvider{}

	s := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: rec,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  24 * time.Hour,
		// configStore intentionally left nil.
	}

	interval := s.runScan()
	if interval != 24*time.Hour {
		t.Fatalf("expected bootstrap default poll interval with nil configStore, got %v", interval)
	}
	if st := s.Status(); st.LastCandidates != 1 {
		t.Fatalf("expected 1 candidate at the 30d bootstrap default threshold, got %d", st.LastCandidates)
	}
}

// TestRenewalSchedulerStopReleasesHALock is W19-25: Stop() used to leave its
// ha_scheduler_locks row in place, so a restarted hub (a second scheduler
// instance, same lock name, competing for the SAME db) had to wait out the
// full lease before its own startup sweep could run. Two schedulers over one
// sqlite DB: the first becomes leader and runs a tick, Stop()s, and the
// second must both (a) acquire the lock immediately -- no lease wait -- and
// (b) actually run its Start() startup sweep once it does.
func TestRenewalSchedulerStopReleasesHALock(t *testing.T) {
	db := newTestHADB(t)
	now := time.Now().UTC()
	soon := now.Add(10 * 24 * time.Hour).Format(time.RFC3339)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", CommonName: "a", ValidUntil: soon, OwnerEmail: "owner@example.com"},
	}}
	mailer := succeedingTestDeliveryNotificationProvider{}

	haA := newTestHACoordinatorAt(t, db, "replica-a", now)
	first := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: mailer,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  time.Hour,
		haCoordinator: haA,
		stop:          make(chan struct{}),
	}
	// Becomes leader and holds a live (5x pollInterval) lease, same as a
	// real tick would via haLockRenewalScheduler.
	first.runScan()
	if st := first.Status(); st.LastRunAt == "" {
		t.Fatalf("setup: expected first scheduler's tick to have run as leader")
	}

	first.Stop()

	// A second replica, same lock name, same DB: without the fix this
	// TryAcquire fails because replica-a's lease (up to 2h out) hasn't
	// lapsed yet.
	haB := newTestHACoordinatorAt(t, db, "replica-b", now)
	ok, err := haB.TryAcquire(context.Background(), haLockRenewalScheduler, 5*time.Minute)
	if err != nil {
		t.Fatalf("second replica acquire: %v", err)
	}
	if !ok {
		t.Fatal("expected the second replica to acquire the lock immediately after the first Stop()s, not wait out the lease")
	}

	// Confirm Start()'s immediate scan then actually runs on the second
	// scheduler now that it holds the lock.
	second := &RenewalScheduler{
		certProvider:  certs,
		notifProvider: mailer,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  time.Hour,
		haCoordinator: haB,
		stop:          make(chan struct{}),
	}
	second.Start()
	defer second.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := second.Status(); st.LastRunAt != "" {
			if st.LastCandidates != 1 {
				t.Fatalf("expected second scheduler's startup sweep to find 1 candidate, got %d", st.LastCandidates)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected second scheduler's Start() to run its immediate startup sweep, but no scan completed")
}

// TestRenewalSchedulerStopWithoutHACoordinatorIsSafe guards the
// single-replica (no HA coordinator) case: Stop must remain a plain,
// panic-free channel close when haCoordinator is nil, same as before W19-25.
func TestRenewalSchedulerStopWithoutHACoordinatorIsSafe(t *testing.T) {
	s := &RenewalScheduler{stop: make(chan struct{})}
	s.Stop()
	s.Stop() // idempotent: once.Do must guard the second call too.
}

// TestRenewalSchedulerStopReleaseSurvivesClosedDB is the "safely if the DB
// is gone" half of W19-25's acceptance: Stop must not panic or block even
// when the HA lock DB is unreachable, and simply logs the release failure.
func TestRenewalSchedulerStopReleaseSurvivesClosedDB(t *testing.T) {
	db := newTestHADB(t)
	ha := newTestHACoordinatorAt(t, db, "replica-a", time.Now().UTC())
	if ok, err := ha.TryAcquire(context.Background(), haLockRenewalScheduler, 5*time.Minute); err != nil || !ok {
		t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
	}
	db.Close() // simulate the DB being gone at shutdown time

	s := &RenewalScheduler{haCoordinator: ha, stop: make(chan struct{})}
	s.Stop() // must not panic
}

func (failingTestDeliveryNotificationProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return nil, nil
}

func (succeedingTestDeliveryNotificationProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return nil, nil
}
