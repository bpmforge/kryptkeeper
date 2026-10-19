// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/notifications/delivery"
)

// haLockRenewalScheduler names this scheduler's lease row in
// ha_scheduler_locks (ha_coordinator.go, W6-01/PE-9/D-048).
const haLockRenewalScheduler = "renewal-scheduler"

// RenewalSchedulerStatus is a thread-safe snapshot of the scheduler's most
// recent scan, surfaced to operators via the status endpoint.
type RenewalSchedulerStatus struct {
	Running               bool   `json:"running"`
	ThresholdDays         int    `json:"threshold_days"`
	PollIntervalHours     int    `json:"poll_interval_hours"`
	LastRunAt             string `json:"last_run_at,omitempty"`
	NextRunAt             string `json:"next_run_at,omitempty"`
	LastCandidates        int    `json:"last_candidates"`
	LastExpiredSkipped    int    `json:"last_expired_skipped"`
	LastAutoRenewTriggers int    `json:"last_auto_renew_triggers"`
	LastNotifications     int    `json:"last_notifications"`
	// PendingInstalls counts certificates whose scheduled renewal failed to
	// install and is waiting for a retry: the host is still serving the old
	// certificate. GaveUpInstalls counts those that exhausted their attempts.
	PendingInstalls int `json:"pending_installs"`
	GaveUpInstalls  int `json:"gave_up_installs"`
	// MaxThresholdDays is the widest renewal window in force this tick: the
	// default, or the largest target or group threshold (W27-04).
	// ThresholdDays stays the global default.
	MaxThresholdDays int `json:"max_threshold_days"`
}

// ruleSendCapEnv overrides defaultRuleSendCap.
const ruleSendCapEnv = "KRYPTKEEPER_RENEWAL_RULE_SEND_CAP"

// defaultRuleSendCap keeps the first tick after an operator creates a wide
// rule (matching most of the estate) from becoming one relay-sized burst.
const defaultRuleSendCap = 500

// ruleSendBudget is one tick's remaining rule-alert allowance.
type ruleSendBudget struct {
	remaining int
	deferred  int
}

// RenewalScheduler runs daily scans for certificates approaching expiry and
// triggers auto-renewal or owner notifications as appropriate.
type RenewalScheduler struct {
	certProvider  CertificateProvider
	notifProvider NotificationProvider
	auditProvider AuditProvider
	// credStore lets the sweep read a target credential's sudo_mode when
	// deciding whether a privilege block applies (W34-10).
	credStore OutboundCredentialStore

	// thresholdDays is the number of days before expiry to trigger renewal.
	// This is the BOOTSTRAP DEFAULT (W8-13): runScan re-resolves the
	// effective value from configStore (DB override, else this env-derived
	// default) at the top of every tick, so this field is only ever read
	// when configStore is nil or has no override.
	thresholdDays int
	// pollInterval controls how often the scheduler wakes up (default 24h).
	// Bootstrap default -- see thresholdDays' comment; runScan re-resolves
	// the effective interval every tick and Start's ticker tracks it.
	pollInterval time.Duration
	// retryBase/retryCap shape the failed-install backoff (W27-19); zero means
	// the package defaults. Bootstrap defaults like pollInterval: runScan
	// re-resolves them from the config store every tick.
	retryBase, retryCap time.Duration
	// jitterSeed/jitterPercent spread retries and tick starts (W27-33);
	// zero percent disables jitter. See jitterFor.
	jitterSeed    int64
	jitterPercent int
	// cooldown is the minimum time between two renewal-reminder
	// notifications for the same certificate (W1-06/D-033). cooldownStore
	// may be nil (store unavailable) — cooldown is then simply not enforced.
	// Bootstrap default -- see thresholdDays' comment.
	cooldown      time.Duration
	cooldownStore renewalAlertCooldownStore
	// silenceStore may be nil (store unavailable) — silencing is then
	// simply not enforced.
	silenceStore NotificationSilenceStore
	// ruleOptions (W30-01) holds per-rule percent/template settings. May be nil
	// (store unavailable) — every rule is then a plain days rule.
	ruleOptions NotificationRuleOptionsStore
	// teamRoutes (W30-02) holds the owner_team routing table for "@owner_team"
	// rules. May be nil (store unavailable) — routed rules then queue to the
	// dashboard.
	teamRoutes NotificationTeamRouteStore
	// noOwner emits the ITSM expiry_no_owner event once per certificate (W32-28).
	noOwner noOwnerAnnouncer
	// targetStore resolves per-target renewal-threshold overrides (W8-15,
	// FR-P33). May be nil (store unavailable) — every candidate then simply
	// uses thresholdDays, the pre-W8-15 behavior.
	targetStore ManagedTargetStore
	// configStore resolves DB overrides for threshold/poll/cooldown (W8-13).
	// May be nil (store unavailable) — every tick then simply uses
	// thresholdDays/pollInterval/cooldown below, the pre-W8-13 behavior.
	configStore ConfigStore

	// renewalExecutor, when non-nil, lets the sweep EXECUTE renewals for
	// managed targets that opted in (S-17, on the W5-13 engine): auto_renew
	// set, install_mode ssh, complete install profile, credential_ref. Nil
	// preserves the notify-only behavior (W4-02/G-43).
	renewalExecutor renewalRunner
	// bindingStore holds the operator's cert-to-target bindings (W27-02):
	// the sweep executes only against bound targets. unboundNotes dedupes the
	// "host matches but unbound" log.
	bindingStore CertTargetBindingStore
	unboundNotes unboundNoteSeen
	// groupStore supplies group thresholds (W27-04). Nil means no groups.
	groupStore TargetGroupStore

	// stampVerifier re-checks, at sweep time, that the principal stamped on an
	// auto_renew target still exists and still holds certificate.renew
	// (RC1-A-01). Nil skips the re-check (tests).
	stampVerifier func(ctx context.Context, stamp string) error

	// ariDue (W26-27) asks the upstream CA's ACME Renewal Information when a
	// connector-pinned certificate should renew. nil disables ARI timing.
	ariDue func(ctx context.Context, cert CertificateItem, now time.Time) ARIDecision

	// ruleSendCap bounds how many rule alerts (sent, or skipped when the
	// provider does not deliver) one tick processes; the remaining matches
	// roll to the next tick because unprocessed pairs have no cooldown yet.
	// 0 means defaultRuleSendCap.
	ruleSendCap int

	// haCoordinator is nil when unavailable (soft-fail — see
	// newHACoordinatorFromEnvLogged), which preserves the pre-W6-01
	// single-replica behavior of always scanning.
	haCoordinator *HACoordinator

	mu     sync.Mutex
	status RenewalSchedulerStatus

	// skipMu guards skipSeen/skipCount: skipped alerts (non-delivering
	// provider) are audited at most once per key per skipAuditEvery.
	skipMu    sync.Mutex
	skipSeen  map[string]time.Time
	skipCount int

	stop chan struct{}
	once sync.Once
	// scansRunning counts ticks in progress so Stop can drain them (below).
	scansRunning atomic.Int32

	// scanNow (W26-29) lets RequestScan trigger an out-of-cycle scan.
	scanNow chan struct{}

	// gateMu guards gateWakeAt/gateTimer: the soonest moment a connector
	// gate (W26-28) that deferred work this tick lapses, and the timer that
	// re-scans then instead of waiting out the full poll interval.
	gateMu     sync.Mutex
	gateWakeAt time.Time
	gateTimer  *time.Timer
}

// noteGateWake records that work was deferred until a connector gate lapses.
func (s *RenewalScheduler) noteGateWake(until time.Time) {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	if s.gateWakeAt.IsZero() || until.Before(s.gateWakeAt) {
		s.gateWakeAt = until
	}
}

// armGateWake schedules an out-of-cycle scan for the soonest gate lapse noted
// this tick, when that is sooner than the next poll. Deferred renewals thus
// resume when the CA's Retry-After ends rather than up to a poll interval later.
func (s *RenewalScheduler) armGateWake(poll time.Duration) {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	at := s.gateWakeAt
	s.gateWakeAt = time.Time{}
	if at.IsZero() {
		return
	}
	d := max(time.Until(at), 0) + 250*time.Millisecond
	if d >= poll {
		return
	}
	if s.gateTimer != nil {
		s.gateTimer.Stop()
	}
	s.gateTimer = time.AfterFunc(d, s.RequestScan)
}

// WithRenewalExecutor arms the sweep's execute path (S-17). Call before
// Start; the scheduler never mutates it afterwards.
func (s *RenewalScheduler) WithRenewalExecutor(e *RenewalExecutor) *RenewalScheduler {
	if e == nil {
		s.renewalExecutor = nil // a typed-nil pointer would read as armed
		return s
	}
	s.renewalExecutor = e
	return s
}

// WithARIDue arms ARI-driven renewal timing for connector-pinned certs.
func (s *RenewalScheduler) WithARIDue(fn func(ctx context.Context, cert CertificateItem, now time.Time) ARIDecision) *RenewalScheduler {
	s.ariDue = fn
	return s
}

// WithStampVerifier arms the sweep-time re-check of who armed each target.
func (s *RenewalScheduler) WithStampVerifier(v func(ctx context.Context, stamp string) error) *RenewalScheduler {
	s.stampVerifier = v
	return s
}

// Status returns a snapshot of the scheduler's most recent scan.
func (s *RenewalScheduler) Status() RenewalSchedulerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *RenewalScheduler) setStatus(st RenewalSchedulerStatus) {
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
	publishRenewalStatus(st)
}

// renewalStatusHolder lets the status HTTP handler read the latest scan result
// without threading the scheduler instance (created in main) through the
// handler registration. A process runs a single renewal scheduler.
var renewalStatusHolder atomic.Value

func publishRenewalStatus(st RenewalSchedulerStatus) {
	renewalStatusHolder.Store(st)
}

// LatestRenewalStatus returns the most recently published scheduler status and
// whether a scan has run yet.
func LatestRenewalStatus() (RenewalSchedulerStatus, bool) {
	v := renewalStatusHolder.Load()
	if v == nil {
		return RenewalSchedulerStatus{}, false
	}
	return v.(RenewalSchedulerStatus), true
}

// NewRenewalSchedulerFromEnv creates a RenewalScheduler using environment config.
//
// RENEWAL_THRESHOLD_DAYS       — days before expiry to trigger renewal. This
//
//	is the FALLBACK default (W8-15, FR-P33): a managed_targets row whose
//	Host matches the candidate certificate (by CommonName or a SAN — see
//	hostRenewalThresholds) and carries a non-zero RenewalThresholdDays
//	overrides it for that candidate only. Only certificates matching no
//	target at all use this env value process-wide, as it did before W8-15.
//	Default: 30.
//
// RENEWAL_POLL_HOURS           — how often to run the scan (default: 24).
// RENEWAL_POLL_MINUTES         — sub-hour override of the scan cadence;
//
//	takes precedence over RENEWAL_POLL_HOURS when set. A DB override of
//	renewal_policy.poll_hours still wins over both.
//
// KRYPTKEEPER_RENEWAL_RULE_SEND_CAP — most notification-rule alerts one scan
//
//	processes (default: 500). Matches beyond it are picked up by the next
//	scan, so a wide new rule is spread over several ticks instead of one burst.
//
// RENEWAL_ALERT_COOLDOWN_HOURS — minimum time between two renewal-reminder
//
//	notifications for the same certificate (default: 24, matching
//	notification_policies.alert_cooldown_hours' own default — see
//	renewal_scheduler.go's cooldown-check comment for why that column
//	itself stays unread).
func NewRenewalSchedulerFromEnv(certProvider CertificateProvider, notifProvider NotificationProvider, auditProvider AuditProvider) *RenewalScheduler {
	thresholdDays := 30
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_THRESHOLD_DAYS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			thresholdDays = n
		}
	}
	pollHours := 24
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_POLL_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollHours = n
		}
	}
	pollInterval := time.Duration(pollHours) * time.Hour
	// RENEWAL_POLL_MINUTES, when set, wins over RENEWAL_POLL_HOURS: hour
	// granularity cannot express a sub-hour cadence, which short-lived-cert
	// deployments and unattended end-to-end tests need.
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_POLL_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollInterval = time.Duration(n) * time.Minute
		}
	}
	ruleSendCap := defaultRuleSendCap
	if raw := strings.TrimSpace(os.Getenv(ruleSendCapEnv)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			ruleSendCap = n
		}
	}
	cooldownHours := 24
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_ALERT_COOLDOWN_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			cooldownHours = n
		}
	}
	var retryBase, retryCap time.Duration
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_RETRY_BASE_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			retryBase = time.Duration(n) * time.Minute
		}
	}
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_RETRY_CAP_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			retryCap = time.Duration(n) * time.Hour
		}
	}
	initial := RenewalSchedulerStatus{
		ThresholdDays:     thresholdDays,
		MaxThresholdDays:  thresholdDays,
		PollIntervalHours: pollHours,
	}
	publishRenewalStatus(initial)
	if fq := newRenewalFailureStoreFromEnvLogged(); fq != nil {
		SetRenewalFailureStore(fq)
	}
	return &RenewalScheduler{
		certProvider:  certProvider,
		notifProvider: notifProvider,
		auditProvider: auditProvider,
		thresholdDays: thresholdDays,
		pollInterval:  pollInterval,
		retryBase:     retryBase,
		retryCap:      retryCap,
		jitterSeed:    time.Now().UnixNano(),
		jitterPercent: tickJitterPercent(),
		cooldown:      time.Duration(cooldownHours) * time.Hour,
		ruleSendCap:   ruleSendCap,
		cooldownStore: newRenewalAlertCooldownStoreFromEnvLogged(),
		silenceStore:  newNotificationSilenceStoreFromEnvLogged(),
		ruleOptions:   newNotificationRuleOptionsStoreFromEnvLogged(),
		teamRoutes:    newNotificationTeamRouteStoreFromEnvLogged(),
		targetStore:   newManagedTargetStoreFromEnv(),
		credStore:     newOutboundCredentialStoreFromEnv(),
		bindingStore:  newCertTargetBindingStoreFromEnv(),
		groupStore:    newTargetGroupStoreFromEnv(),
		configStore:   newConfigStoreFromEnv(),
		haCoordinator: newHACoordinatorFromEnvLogged(),
		status:        initial,
		stop:          make(chan struct{}),
		scanNow:       make(chan struct{}, 1),
	}
}

// Start launches the renewal scan loop in a goroutine. Call Stop to shut it down.
func (s *RenewalScheduler) Start() {
	s.mu.Lock()
	s.status.Running = true
	s.mu.Unlock()
	go func() {
		wctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		s.warnIfRulesCannotDeliver(wctx)
		cancel()

		s.installThrottleObserver()
		if j := s.jitterFor("tick-start", s.pollInterval); j > 0 {
			select {
			case <-time.After(j):
			case <-s.stop:
				return
			}
		}
		// Run once immediately at startup. runScan returns the poll interval
		// it resolved for this tick (W8-13: DB override, else the
		// env-configured bootstrap default) so the ticker below tracks a
		// config-store change without a restart.
		interval := s.runScan()
		if interval <= 0 {
			interval = s.pollInterval
		}
		ticker := time.NewTicker(interval + s.jitterFor("tick", interval))
		defer ticker.Stop()
		scan := func() {
			next := s.runScan()
			if next <= 0 {
				next = s.pollInterval
			}
			ticker.Reset(next + s.jitterFor("tick", next))
		}
		for {
			select {
			case <-ticker.C:
				scan()
			case <-renewalScanKick:
				scan()
			case <-s.scanNow:
				scan()
			case <-s.stop:
				return
			}
		}
	}()
}

// Stop shuts down the renewal scan loop.
//
// It also releases this replica's ha_scheduler_locks row for
// haLockRenewalScheduler (W19-25): TryAcquire's lease-renewal protocol has
// no unlock RPC by design (ha_coordinator.go's doc comment -- a crashed
// replica's lease is meant to simply lapse), but a clean Stop is not a
// crash, and a restarted hub waiting out a stale lease it held itself is
// pure lost time. Found live in UAT W19-07: the test fixture had to DELETE
// the lease by hand to force a second tick after a hub restart. Release is
// a no-op if this replica never held the lock (nothing to delete) and a
// logged, non-fatal error if the DB is gone -- Stop must never block or
// panic on shutdown, and a failed release just falls back to the pre-W19-25
// behavior of waiting out the lease.
func (s *RenewalScheduler) Stop() {
	s.once.Do(func() {
		close(s.stop)
		s.gateMu.Lock()
		if s.gateTimer != nil {
			s.gateTimer.Stop()
		}
		s.gateMu.Unlock()
		s.drainScans(shutdownDrainTimeout())
		if s.haCoordinator != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.haCoordinator.Release(ctx, haLockRenewalScheduler); err != nil {
				logging.Warnf("renewal scheduler: releasing ha lock failed, lease will expire naturally: %v", err)
			}
		}
	})
}

// runScan executes one scan tick and returns the poll interval that should
// govern the NEXT tick (W8-13). It always returns a positive interval, even
// on early return (HA non-leader, list-certs failure), so Start's ticker
// stays correctly paced regardless of how the tick ended.
func (s *RenewalScheduler) runScan() time.Duration {
	s.scansRunning.Add(1)
	defer s.scansRunning.Add(-1)
	// A tick may wait out a plugin's declared verify propagation window
	// (W27-37); a shorter bound would roll back a correct CDN push.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute+maxPluginVerifyWindow)
	defer cancel()
	ctx = connectors.WithDrain(ctx, s.stop) // a stop never sleeps through an upstream rate-limit hold

	// W8-13: threshold/poll/cooldown are re-resolved from the config store at
	// the top of every tick (DB override, else the env-configured bootstrap
	// default in s.thresholdDays/s.pollInterval/s.cooldown) so a
	// PUT /config/{key} override takes effect on the NEXT tick with no
	// restart. This is a bounded read -- at most 3 queries per tick per
	// replica -- not a per-request one, the same "poll, not unbounded read"
	// posture as the per-tick managed-target read below (W8-15).
	pollInterval := s.resolveConfigDuration(ctx, "renewal_policy.poll_hours", s.pollInterval)
	thresholdDaysDefault := s.resolveConfigInt(ctx, "renewal_policy.threshold_days", s.thresholdDays)
	cooldown := s.resolveConfigDuration(ctx, "renewal_policy.alert_cooldown_hours", s.cooldown)
	retryBase, retryCap := s.resolveRetryBackoff(ctx)
	pol := retryPolicy{base: retryBase, retryCap: retryCap, poll: pollInterval}

	// HA gate (W6-01/PE-9/D-048): on >=2 replicas, only the lease holder
	// proceeds — see posture_scheduler.go's capture() for why a lock error
	// fails closed (skip) rather than open (run anyway). Without this, two
	// replicas would both notify owners and both burn the same cooldown
	// window independently, i.e. exactly the duplicate-alerts acceptance
	// criterion this ticket exists to close.
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockRenewalScheduler, 2*pollInterval)
		if err != nil {
			logging.Warnf("renewal scheduler: ha lock check failed, skipping this tick: %v", err)
			return pollInterval
		}
		if !ok {
			return pollInterval
		}
	}

	result, err := listAllCertificates(ctx, s.certProvider, CertificateListQuery{})
	if err != nil {
		logging.Warnf("renewal scheduler: list certs failed: %v", err)
		return pollInterval
	}
	ctx = withSilenceMemo(ctx)

	// Per-target threshold overrides (W8-15): a single List() here, not one
	// read per candidate certificate below -- this scan runs at most once
	// per pollInterval (default 24h, a background tick, not a request hot
	// path), so one bounded read of managed_targets per tick is the "poll"
	// half of acceptance #5, not an unbounded per-request read.
	var hostThresholds map[string]int
	var sweepIdx *bindingSweepIndex
	if s.targetStore != nil {
		targets, terr := s.targetStore.List(ctx)
		if terr != nil {
			logging.Warnf("renewal scheduler: managed target list failed, using env default threshold for all candidates: %v", terr)
		} else {
			hostThresholds = hostRenewalThresholds(targets, s.tickGroupDays(ctx))
			sweepIdx = s.prepareBindingSweep(ctx, s.withoutBlockedTargets(ctx, eligibleAutoRenewTargets(targets)), result.Items, time.Now().UTC())
		}
	}

	now := time.Now().UTC()

	rules := s.enabledNotificationRules(ctx)
	ruleOpts := s.loadRuleOptions(ctx)
	routes := s.loadTeamRoutes(ctx)
	budget := &ruleSendBudget{remaining: s.effectiveRuleSendCap()}

	var renewalCandidates, expiredSkipped, notifications, autoRenewTriggers, pendingInstalls, gaveUpInstalls int
	var jobs []renewalJob
	for _, cert := range result.Items {
		if cert.RevokedAt != nil {
			continue
		}
		if cert.ValidUntil == "" {
			continue
		}
		expiry, err := time.Parse(time.RFC3339, cert.ValidUntil)
		if err != nil {
			continue
		}
		// Operator-defined alert rules (POST /notifications/rules) fire on
		// their own thresholds, which may be wider or narrower than the
		// renewal window below, so they are evaluated before that gate. They
		// also run for expired certificates: only an EXPIRED (0%) rule can
		// match one, ruleCrossed filters the rest.
		notifications += s.dispatchRuleNotifications(ctx, cert, expiry, now, rules, ruleOpts, routes, budget)
		if expiry.Before(now) {
			expiredSkipped++
			continue
		}
		threshold := now.Add(time.Duration(effectiveThresholdDays(cert, resolveThresholdDays(hostThresholds, cert, thresholdDaysDefault))) * 24 * time.Hour)
		ariForced := false
		if s.ariDue != nil && cert.RenewalConnectorID != "" {
			if d := s.ariDue(ctx, cert, now); d.Known {
				if !d.Due {
					continue
				}
				ariForced = true
				// W26-28: while the connector is rate-limited, don't re-announce every tick.
				if _, backedOff := acmeConnectorBackedOff(cert.RenewalConnectorID); !backedOff {
					s.emitRenewalAudit(ctx, cert, "acme.upstream.renew", AuditOutcomeSuccess, d.Detail)
				}
			}
		}
		if !ariForced && expiry.After(threshold) {
			continue
		}

		renewalCandidates++
		if !s.isSilenced(ctx, cert) {
			s.noOwner.announce(ctx, s.notifProvider, cert, now) // W32-28
		}
		if s.renewalExecutor != nil && sweepIdx != nil {
			jobs = append(jobs, renewalJob{cert: cert, expiry: expiry}) // executed below, most urgent first
			continue
		}
		if s.handleRenewalCandidate(ctx, cert, expiry, now, cooldown) {
			notifications++
		}
	}

	if len(jobs) > 0 {
		t := s.runRenewalJobs(ctx, jobs, sweepIdx, now, pol, cooldown)
		pendingInstalls += t.pending
		gaveUpInstalls += t.gaveUp
		autoRenewTriggers += t.renewed
		notifications += t.notifications
	}

	s.armGateWake(pollInterval)

	if n := s.takeSkipCount(); n > 0 {
		logging.Infof("renewal scheduler: %d alert(s) skipped this tick: %s", n, notDeliveringReason(s.notifProvider))
	}
	if budget.deferred > 0 {
		logging.Infof("renewal scheduler: rule alert cap %d reached; %d alert(s) deferred to the next tick (%s)",
			s.effectiveRuleSendCap(), budget.deferred, ruleSendCapEnv)
	}

	if renewalCandidates > 0 {
		logging.Infof("renewal scheduler: found %d renewal candidates (expired/skipped: %d)", renewalCandidates, expiredSkipped)
	}

	s.setStatus(RenewalSchedulerStatus{
		Running:            true,
		ThresholdDays:      thresholdDaysDefault,
		MaxThresholdDays:   maxThresholdInForce(thresholdDaysDefault, hostThresholds),
		PollIntervalHours:  int(pollInterval.Hours()),
		LastRunAt:          now.Format(time.RFC3339),
		NextRunAt:          now.Add(pollInterval).Format(time.RFC3339),
		LastCandidates:     renewalCandidates,
		LastExpiredSkipped: expiredSkipped,
		// Non-zero since S-17: the W5-13 engine generates the key/CSR
		// hub-side, so opted-in ssh-mode targets renew for real. G-43's
		// "no hub-side auto-renewal path" is history for that mode; every
		// other candidate remains notify-only.
		LastAutoRenewTriggers: autoRenewTriggers,
		PendingInstalls:       pendingInstalls,
		GaveUpInstalls:        gaveUpInstalls,
		LastNotifications:     notifications,
	})
	return pollInterval
}

// resolveConfigInt returns s.configStore's positive integer DB override for
// key, if one exists, else fallbackDefault (the env-resolved bootstrap
// value). See runScan's comment for why this read is bounded (once per
// tick), not a per-request one.
func (s *RenewalScheduler) resolveConfigInt(ctx context.Context, key string, fallbackDefault int) int {
	if s.configStore == nil {
		return fallbackDefault
	}
	entry, ok, err := s.configStore.Get(ctx, key)
	if err != nil {
		logging.Warnf("renewal scheduler: config lookup for %s failed, using bootstrap default: %v", key, err)
		return fallbackDefault
	}
	if !ok || !entry.HasValue {
		return fallbackDefault
	}
	n, err := strconv.Atoi(strings.TrimSpace(entry.Value))
	if err != nil || n <= 0 {
		logging.Infof("renewal scheduler: invalid config override %s=%q, using bootstrap default", key, entry.Value)
		return fallbackDefault
	}
	return n
}

// resolveConfigDuration is resolveConfigInt for hour-valued settings.
func (s *RenewalScheduler) resolveConfigDuration(ctx context.Context, key string, fallbackDefault time.Duration) time.Duration {
	// A zero fallback to resolveConfigInt means "no override": return the
	// exact bootstrap duration rather than round-tripping it through whole
	// hours, which would truncate a sub-hour RENEWAL_POLL_MINUTES to zero.
	if hours := s.resolveConfigInt(ctx, key, 0); hours > 0 {
		return time.Duration(hours) * time.Hour
	}
	return fallbackDefault
}

// handleRenewalCandidate acts on a cert approaching expiry and reports whether
// an owner notification was sent.
//
// This is the notify-only fallback. Since S-17, candidates matching an
// opted-in ssh-mode managed target are EXECUTED first via tryAutoRenew (the
// W5-13 engine generates the key/CSR hub-side); every other candidate can
// only be notified about — the hub holds no key material for them, and
// protocol-issued (ACME/EST/SCEP) certs live in their own store this
// scheduler never scans (see G-43, docs/work/DESIGN_REVIEW.md).
func (s *RenewalScheduler) handleRenewalCandidate(ctx context.Context, cert CertificateItem, expiry, now time.Time, cooldown time.Duration) (notified bool) {
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	if s.notifProvider == nil || cert.OwnerEmail == "" {
		return false
	}

	// W1-06/D-033: an operator's explicit silence on the cert, its issuing
	// CA, or its template unconditionally suppresses the reminder — checked
	// before the cooldown so a silenced target never even touches the
	// cooldown store.
	if s.isSilenced(ctx, cert) {
		return false
	}

	// A record-only provider (file, db) sends nothing: do not burn the
	// cooldown or audit a "sent" for a reminder nobody received.
	if !s.notifProvider.Delivers() {
		if s.noteSkip(cert.FingerprintSHA256 + "#owner") {
			s.emitRenewalAudit(ctx, cert, "renewal_notification_sent", AuditOutcomeSkipped, notDeliveringReason(s.notifProvider))
		}
		return false
	}

	// W1-06/D-033: the persisted cooldown — NOT the dead
	// notification_policies.alert_cooldown_hours column (see
	// notification_dedup.go's doc comment for why this uses its own env-
	// configured window instead of reading that column: wiring it would
	// need a store for the notification_policies table, out of this
	// ticket's write_scope; the column remains unread either way). cooldown
	// is this tick's resolved value (W8-13: DB override, else s.cooldown).
	if s.cooldownStore != nil {
		if last, ok, err := s.cooldownStore.LastAlertedAt(ctx, cert.FingerprintSHA256); err != nil {
			logging.Warnf("renewal scheduler: cooldown lookup failed for %s (proceeding without cooldown): %v", cert.FingerprintSHA256, err)
		} else if ok && isWithinCooldown(last, cooldown, now) {
			return false
		}
	}

	msg := buildRenewalNotificationMessage(cert, daysLeft)
	channel := "email"
	target := cert.OwnerEmail
	if _, err := s.notifProvider.TestDelivery(ctx, channel, target, msg); err != nil {
		attempts, deadLettered := recordRenewalTriggerFailure(cert.FingerprintSHA256, err.Error())
		if deadLettered {
			logging.Warnf("renewal scheduler: notification for %s failed %d consecutive times, dead-lettered: %v", cert.FingerprintSHA256, attempts, err)
		} else {
			logging.Warnf("renewal scheduler: notification failed for %s (attempt %d/%d): %v", cert.FingerprintSHA256, attempts, renewalTriggerMaxAttempts, err)
		}
		return false
	}
	recordRenewalTriggerSuccess(cert.FingerprintSHA256)
	if s.cooldownStore != nil {
		if err := s.cooldownStore.RecordAlerted(ctx, cert.FingerprintSHA256, now); err != nil {
			logging.Warnf("renewal scheduler: recording cooldown failed for %s: %v", cert.FingerprintSHA256, err)
		}
	}
	s.emitRenewalAudit(ctx, cert, "renewal_notification_sent", AuditOutcomeSuccess, "")
	return true
}

// enabledNotificationRules loads the operator's enabled alert rules once per
// tick. A read failure is logged and treated as "no rules": the owner reminder
// path must keep working when the rule store is down.
func (s *RenewalScheduler) enabledNotificationRules(ctx context.Context) []NotificationRule {
	if s.notifProvider == nil {
		return nil
	}
	all, err := s.notifProvider.ListRules(ctx)
	if err != nil {
		logging.Warnf("renewal scheduler: notification rules unavailable, skipping rule alerts this tick: %v", err)
		return nil
	}
	out := make([]NotificationRule, 0, len(all))
	for _, r := range all {
		if r.Enabled && r.ThresholdDays > 0 && r.Channel != "" && r.Target != "" {
			out = append(out, r)
		}
	}
	return out
}

// loadRuleOptions reads the per-rule options once per tick. A failure is
// logged and treated as "no options": every rule evaluates as a days rule.
func (s *RenewalScheduler) loadRuleOptions(ctx context.Context) map[string]NotificationRuleOption {
	if s.ruleOptions == nil {
		return nil
	}
	opts, err := s.ruleOptions.List(ctx)
	if err != nil {
		logging.Warnf("renewal scheduler: rule options unavailable, treating every rule as a days rule: %v", err)
		return nil
	}
	return opts
}

// defaultThresholdPcts are the use_defaults rules: percent of lifetime
// remaining, 0 meaning EXPIRED.
var defaultThresholdPcts = []int{50, 25, 10, 0}

// expiredAlertWindow bounds how long after expiry an EXPIRED rule still fires,
// so enabling a rule does not page for every long-dead certificate.
const expiredAlertWindow = 7 * 24 * time.Hour

// ruleCrossed reports whether a rule's threshold has been crossed for cert.
// opt is nil for a plain days rule, in which case days is the threshold; a pct
// rule ignores days (its stored value is a placeholder). Template scope is
// applied here; the override of global rules by template rules is the
// caller's concern because it needs the whole rule set.
func ruleCrossed(opt *NotificationRuleOption, days int, cert CertificateItem, now time.Time) bool {
	if opt != nil && opt.TemplateID != "" && opt.TemplateID != cert.TemplateID {
		return false
	}
	until, err := time.Parse(time.RFC3339, cert.ValidUntil)
	if err != nil {
		return false
	}
	remaining := until.Sub(now)
	from, fromErr := time.Parse(time.RFC3339, cert.ValidFrom)
	lifetime := until.Sub(from)

	if opt != nil && opt.ThresholdPct != nil {
		pct := *opt.ThresholdPct
		if fromErr != nil || lifetime <= 0 {
			return false
		}
		if pct == 0 {
			return remaining <= 0 && -remaining <= expiredAlertWindow
		}
		return remaining > 0 && float64(remaining)/float64(lifetime)*100 <= float64(pct)
	}
	if remaining <= 0 {
		return false
	}
	window := time.Duration(days) * 24 * time.Hour
	// A fixed window as long as the whole lifetime would fire on issue day;
	// short-lived certs are covered by percent rules instead.
	if fromErr == nil && lifetime > 0 && window >= lifetime {
		return false
	}
	return remaining <= window
}

// dispatchRuleNotifications sends cert's expiry alert through every enabled
// rule whose threshold has been crossed, honouring silences. Each (cert, rule)
// pair fires once per cycle: the crossing is persisted so a restart cannot
// repeat it, and a renewal (new fingerprint) starts a new cycle. It returns how
// many alerts were sent.
func (s *RenewalScheduler) dispatchRuleNotifications(ctx context.Context, cert CertificateItem, expiry, now time.Time, rules []NotificationRule, opts map[string]NotificationRuleOption, routes teamRouteIndex, budget *ruleSendBudget) int {
	if len(rules) == 0 || s.notifProvider == nil {
		return 0
	}
	// A rule scoped to this cert's template overrides every global rule.
	templateScoped := false
	if cert.TemplateID != "" {
		for _, r := range rules {
			if o, ok := opts[r.ID]; ok && o.TemplateID == cert.TemplateID {
				templateScoped = true
				break
			}
		}
	}
	var matched []NotificationRule
	for _, r := range rules {
		var opt *NotificationRuleOption
		if o, ok := opts[r.ID]; ok {
			opt = &o
		}
		if templateScoped && (opt == nil || opt.TemplateID == "") {
			continue
		}
		if ruleCrossed(opt, r.ThresholdDays, cert, now) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 || s.isSilenced(ctx, cert) {
		return 0
	}
	if !s.notifProvider.Delivers() {
		// Rule alerts through a record-only provider reach no one: skip them
		// without recording the crossing (which would suppress the alert
		// forever once a real provider is configured) and say so.
		for _, r := range matched {
			// Skips neither consume the send budget nor audit every tick.
			if s.noteSkip(cert.FingerprintSHA256 + "#rule:" + r.ID) {
				s.emitRenewalAudit(ctx, cert, "renewal_notification_sent", AuditOutcomeSkipped, "rule_id="+r.ID+" reason="+notDeliveringReason(s.notifProvider))
			}
		}
		return 0
	}
	msg := buildRenewalNotificationMessage(cert, int(expiry.Sub(now).Hours()/24))
	if expiry.Before(now) {
		msg = buildExpiredNotificationMessage(cert, expiry)
	}
	sent := 0
	for _, r := range matched {
		key := crossingKey(cert.FingerprintSHA256, r.ID)
		if hasCrossed(ctx, s.cooldownStore, key) {
			continue
		}
		if !budget.take() {
			continue
		}
		detail := "rule_id=" + r.ID
		if r.Target == routedRuleTarget {
			var ok bool
			if detail, ok = s.sendRoutedRule(ctx, cert, r, expiry, now, routes); !ok {
				continue
			}
		} else if _, err := s.notifProvider.TestDelivery(ctx, r.Channel, r.Target, msg); err != nil {
			logging.Warnf("renewal scheduler: rule %s alert for %s failed: %v", r.ID, cert.FingerprintSHA256, err)
			continue
		}
		if s.cooldownStore != nil {
			if err := s.cooldownStore.RecordAlerted(ctx, key, now); err != nil {
				logging.Warnf("renewal scheduler: recording rule crossing failed for %s: %v", key, err)
			}
		}
		s.emitRenewalAudit(ctx, cert, "renewal_notification_sent", AuditOutcomeSuccess, detail)
		sent++
	}
	return sent
}

// routedRuleTarget is the rule target that expands, per certificate, to the
// owner team's routes (W30-02).
const routedRuleTarget = "@owner_team"

// teamRouteIndex groups routes by owner_team+"|"+channel.
type teamRouteIndex map[string][]NotificationTeamRoute

func teamRouteKey(team, channel string) string { return team + "|" + channel }

// loadTeamRoutes reads the routing table once per tick. A failure is logged and
// treated as "no routes": routed rules then queue to the dashboard instead of
// sending to a stale or wrong destination.
func (s *RenewalScheduler) loadTeamRoutes(ctx context.Context) teamRouteIndex {
	if s.teamRoutes == nil {
		return nil
	}
	all, err := s.teamRoutes.List(ctx)
	if err != nil {
		logging.Warnf("renewal scheduler: team routes unavailable, routed rules will queue to the dashboard: %v", err)
		return nil
	}
	idx := teamRouteIndex{}
	for _, r := range all {
		k := teamRouteKey(r.OwnerTeam, r.Channel)
		idx[k] = append(idx[k], r)
	}
	return idx
}

// resolveTeamRoutes picks the routes for a routed rule: the cert owner team's
// routes on the rule's channel, else the global inbox's. Levels never combine,
// so a team match suppresses the global inbox. A route created by one tenant
// serves only that tenant's certificates, and an invisible team route does not
// shadow the global inbox.
func resolveTeamRoutes(ctx context.Context, idx teamRouteIndex, cert CertificateItem, channel string) []NotificationTeamRoute {
	visible := func(team string) []NotificationTeamRoute {
		var out []NotificationTeamRoute
		for _, r := range idx[teamRouteKey(team, channel)] {
			tenant := r.Tenant
			if tenant == "" {
				tenant = DefaultTenant
			}
			if caVisibleToTenant(ctx, activeTenantStore, AuthPrincipal{Tenant: tenant}, cert.CAID) {
				out = append(out, r)
			}
		}
		return out
	}
	if cert.OwnerTeam != "" {
		if routes := visible(cert.OwnerTeam); len(routes) > 0 {
			return routes
		}
	}
	return visible(globalInboxTeam)
}

// eventSender and dashboardQueuer are the optional provider capabilities a
// routed rule needs; a provider without them falls back to TestDelivery / no
// queue.
type eventSender interface {
	SendEvent(context.Context, delivery.Event) (NotificationTestDeliveryResult, error)
}

type dashboardQueuer interface {
	QueueDashboard(context.Context, string, string) NotificationDelivery
}

// buildExpiryEvent is the structured alert a routed rule sends; the dispatcher
// fills Channel and Target. It carries no key material or tokens: only
// certificate metadata.
func buildExpiryEvent(cert CertificateItem, expiry, now time.Time, expired bool, baseURL string) delivery.Event {
	subject := "Certificate expiring: " + cert.CommonName
	priority := "medium"
	switch {
	case expired:
		subject = "Certificate EXPIRED: " + cert.CommonName
		priority = "critical"
	case expiry.Sub(now) <= 7*24*time.Hour:
		priority = "high"
	}
	lines := []string{
		"CN: " + cert.CommonName,
		"Expires: " + expiry.UTC().Format(time.RFC3339),
		"Risk score: " + strconv.Itoa(cert.RiskScore),
		"Grade: " + cert.Grade,
	}
	if baseURL = strings.TrimRight(baseURL, "/"); baseURL != "" {
		lines = append(lines, "Link: "+baseURL+"/certificates/"+cert.FingerprintSHA256)
	}
	lines = append(lines, "Fingerprint: "+cert.FingerprintSHA256)
	fp := cert.FingerprintSHA256
	if len(fp) > 12 {
		fp = fp[:12]
	}
	return delivery.Event{
		ID:        "exp-" + fp + "-" + strconv.FormatInt(now.Unix(), 10),
		Subject:   subject,
		Message:   strings.Join(lines, "\n"),
		Priority:  priority,
		CreatedAt: now,
	}
}

// sendRoutedRule delivers a routed rule's alert to the cert's resolved routes,
// or queues it on the dashboard when there are none. It returns the audit
// detail and whether the crossing should be recorded: true when at least one
// route accepted the event (re-sending to the ones that did on the next tick
// would duplicate them), or the dashboard row was queued.
func (s *RenewalScheduler) sendRoutedRule(ctx context.Context, cert CertificateItem, r NotificationRule, expiry, now time.Time, idx teamRouteIndex) (string, bool) {
	ev := buildExpiryEvent(cert, expiry, now, expiry.Before(now), os.Getenv("KRYPTKEEPER_BASE_URL"))
	routes := resolveTeamRoutes(ctx, idx, cert, r.Channel)
	if len(routes) == 0 {
		q, ok := s.notifProvider.(dashboardQueuer)
		if !ok {
			logging.Infof("renewal scheduler: rule %s has no route for %s and the provider has no dashboard queue", r.ID, cert.FingerprintSHA256)
			return "", false
		}
		q.QueueDashboard(ctx, ev.Subject, ev.Message)
		return "rule_id=" + r.ID + " queued=dashboard", true
	}
	delivered := 0
	for i, route := range routes {
		e := ev
		e.ID = ev.ID + "-" + r.ID + "-" + strconv.Itoa(i)
		e.Channel, e.Target = route.Channel, route.Target
		var err error
		if sender, ok := s.notifProvider.(eventSender); ok {
			_, err = sender.SendEvent(ctx, e)
		} else {
			_, err = s.notifProvider.TestDelivery(ctx, e.Channel, e.Target, e.Message)
		}
		if err != nil {
			logging.Warnf("renewal scheduler: rule %s alert for %s to route %s failed: %v", r.ID, cert.FingerprintSHA256, route.ID, err)
			continue
		}
		delivered++
	}
	return "rule_id=" + r.ID, delivered > 0
}

func (s *RenewalScheduler) effectiveRuleSendCap() int {
	if s.ruleSendCap > 0 {
		return s.ruleSendCap
	}
	return defaultRuleSendCap
}

// take spends one unit of the tick's allowance; false means the cap is hit and
// the pair is left for the next tick.
func (b *ruleSendBudget) take() bool {
	if b.remaining <= 0 {
		b.deferred++
		return false
	}
	b.remaining--
	return true
}

const skipAuditEvery = 24 * time.Hour

// noteSkip counts a skipped alert and reports whether it should be audited,
// i.e. whether key has not been audited within skipAuditEvery. Otherwise a
// non-delivering provider would write one audit row per match per tick.
func (s *RenewalScheduler) noteSkip(key string) bool {
	now := time.Now()
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	s.skipCount++
	if s.skipSeen == nil {
		s.skipSeen = make(map[string]time.Time)
	}
	if last, ok := s.skipSeen[key]; ok && now.Sub(last) < skipAuditEvery {
		return false
	}
	if len(s.skipSeen) > 10000 {
		for k, t := range s.skipSeen {
			if now.Sub(t) >= skipAuditEvery {
				delete(s.skipSeen, k)
			}
		}
	}
	s.skipSeen[key] = now
	return true
}

func (s *RenewalScheduler) takeSkipCount() int {
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	n := s.skipCount
	s.skipCount = 0
	return n
}

// notDeliveringReason is the audit reason for an alert skipped because the
// configured provider does not send.
func notDeliveringReason(p NotificationProvider) string {
	return "notification provider " + p.Name() + " does not deliver"
}

// warnIfRulesCannotDeliver logs a WARNING when operator alert rules exist but
// the configured notification provider only records messages, so the rules
// would otherwise be evaluated forever and never reach anyone. Called once at
// scheduler start, not per tick.
func (s *RenewalScheduler) warnIfRulesCannotDeliver(ctx context.Context) {
	if s.notifProvider == nil || s.notifProvider.Delivers() {
		return
	}
	rules, err := s.notifProvider.ListRules(ctx)
	if err != nil || len(rules) == 0 {
		return
	}
	logging.Warnf("%d notification rule(s) exist but notification provider %q does not deliver; "+
		"rule alerts and owner reminders are skipped (audited as skipped). Set APP_NOTIFICATION_PROVIDER=delivery to send them.",
		len(rules), s.notifProvider.Name())
}

// isSilenced reports whether any of cert's certificate/CA/template targets
// carry an operator-filed silence. A lookup error is treated as "not
// silenced" (fail open, logged) — the same soft-fail posture as the
// cooldown store, since silencing is an annoyance-prevention feature, not a
// correctness-critical one.
func (s *RenewalScheduler) isSilenced(ctx context.Context, cert CertificateItem) bool {
	if s.silenceStore == nil {
		return false
	}
	for _, check := range []struct {
		targetType, targetID string
	}{
		{SilenceTargetCertificate, cert.FingerprintSHA256},
		{SilenceTargetCA, cert.CAID},
		{SilenceTargetTemplate, cert.TemplateID},
	} {
		if check.targetID == "" {
			continue
		}
		silenced, err := memoizedIsSilenced(ctx, s.silenceStore, check.targetType, check.targetID)
		if err != nil {
			logging.Warnf("renewal scheduler: silence lookup failed for %s %s (proceeding without silencing): %v", check.targetType, check.targetID, err)
			continue
		}
		if silenced {
			return true
		}
	}
	return false
}

func (s *RenewalScheduler) emitRenewalAudit(ctx context.Context, cert CertificateItem, action string, outcome AuditOutcome, detail string) {
	if s.auditProvider == nil {
		return
	}
	entry := AuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Action:        action,
		ActorType:     "system",
		ActorID:       "renewal-scheduler",
		ResourceType:  "certificate",
		ResourceID:    cert.FingerprintSHA256,
		Outcome:       outcome,
		ChangeSummary: detail,
	}
	if err := s.auditProvider.AppendEntry(ctx, entry); err != nil {
		logging.Warnf("renewal scheduler: audit append failed: %v", err)
	}
}

// hostRenewalThresholds indexes managed targets carrying a per-target
// override by their declared Host, for a single scan tick's worth of
// lookups. A certificate has no FK to a managed target -- neither table
// existed with the other concept in mind -- so, like
// matchManagedTargetEndpoints (managed_target_store.go), Host equality
// against the certificate's CommonName or a SAN is the only correlation
// available. Targets with no override (RenewalThresholdDays == 0) are
// omitted so a missing map entry means "use the env default", not "use 0".
// A target without its own override inherits its group's (W27-04).
func hostRenewalThresholds(targets []ManagedTarget, groupDays map[string]int) map[string]int {
	out := make(map[string]int, len(targets))
	for _, t := range targets {
		if days, src := effectiveTargetThreshold(t, groupDays[t.ID], 0); src != thresholdSourceDefault {
			out[t.Host] = days
		}
	}
	return out
}

// maxThresholdInForce is the widest renewal window any candidate may use.
func maxThresholdInForce(defaultDays int, hostThresholds map[string]int) int {
	m := defaultDays
	for _, d := range hostThresholds {
		m = max(m, d)
	}
	return m
}

// effectiveThresholdDays holds a renewal successor to half its own lifetime.
// Hub renewals are 90 days, so a threshold of 90 or more would make the
// successor due again on the very next tick, forever (RC1-A-02). An initial or
// imported certificate (no predecessor) keeps the configured window: a short
// first certificate under a long window is meant to renew at once.
func effectiveThresholdDays(cert CertificateItem, days int) int {
	if cert.PredecessorFP == nil {
		return days
	}
	from, ferr := time.Parse(time.RFC3339, cert.ValidFrom)
	until, uerr := time.Parse(time.RFC3339, cert.ValidUntil)
	if ferr != nil || uerr != nil || !until.After(from) {
		return days
	}
	half := int(until.Sub(from).Hours() / 48)
	if half < 1 {
		half = 1
	}
	return min(days, half)
}

// resolveThresholdDays returns the per-target override for cert if its
// CommonName or any SAN matches a target's Host, else defaultDays.
func resolveThresholdDays(hostThresholds map[string]int, cert CertificateItem, defaultDays int) int {
	if d, ok := hostThresholds[cert.CommonName]; ok {
		return d
	}
	for _, san := range cert.SubjectAltNames {
		if d, ok := hostThresholds[san]; ok {
			return d
		}
	}
	return defaultDays
}

// eligibleAutoRenewTargets keeps only targets the sweep may execute against:
// explicit opt-in and a credential, plus for ssh a complete install profile.
// A keychain target (W18-05) installs into the macOS keychain and has no
// server type or paths to need. A plugin target (W20-21) needs its plugin;
// the executor checks the plugin is enabled before issuing anything. The
// push targets (f5, citrix, k8s, iis) keep their device or cluster details in
// the credential, so a credential is all they need here; the executor
// resolves and type-checks it before issuing anything.
//
// An opted-in target that is left out is logged with the reason: auto_renew
// that silently does nothing is the failure this sweep exists to prevent.
func eligibleAutoRenewTargets(targets []ManagedTarget) []ManagedTarget {
	var out []ManagedTarget
	for _, t := range targets {
		if !t.AutoRenew {
			continue
		}
		if reason := autoRenewSkipReason(t); reason != "" {
			logging.Infof("renewal scheduler: target %q (%s) has auto_renew set but is skipped: %s", t.Name, t.InstallMode, reason)
			continue
		}
		out = append(out, t)
	}
	return out
}

// autoRenewTargetsByHost indexes the eligible targets by host. The sweep keys
// on target ID (two targets may share a host); this view is for diagnostics
// and the eligibility tests.
func autoRenewTargetsByHost(targets []ManagedTarget) map[string]ManagedTarget {
	out := make(map[string]ManagedTarget)
	for _, t := range eligibleAutoRenewTargets(targets) {
		out[t.Host] = t
	}
	return out
}

// autoRenewSkipReason returns why an opted-in target cannot be executed by the
// sweep, or "" when it can.
func autoRenewSkipReason(t ManagedTarget) string {
	// RC1-A-01: the hub pushes a private key to wherever this target points,
	// so the arming must have been done by a principal allowed to renew. The
	// handlers stamp that; a row without the stamp was written by something
	// else (an older release, a direct DB edit) and is not trusted.
	if t.AutoRenewSetBy == "" {
		return "auto_renew was not armed by a principal holding certificate.renew (re-save auto_renew=true as a pki-admin; pki-operator lacks discovery.manage)"
	}
	if t.CredentialRef == "" {
		return "no credential_ref"
	}
	switch t.InstallMode {
	case "ssh":
		if t.InstallServerType == "" || t.InstallCertPath == "" || t.InstallKeyPath == "" {
			return "incomplete install profile (install_server_type, install_cert_path and install_key_path are required)"
		}
	case "keychain", "f5", "citrix", "k8s", "iis":
	case "plugin":
		if t.PluginID == "" {
			return "no plugin_id"
		}
	default:
		return "install_mode " + strconv.Quote(t.InstallMode) + " is not renewed by the scheduler (agent targets renew via agent tasks)"
	}
	return ""
}

// stampStillValid re-checks the principal that armed target. A failure is
// logged and audited every tick it persists: an armed target that silently
// stops renewing is the failure this sweep exists to prevent.
func (s *RenewalScheduler) stampStillValid(ctx context.Context, cert CertificateItem, target ManagedTarget) bool {
	if s.stampVerifier == nil {
		return true
	}
	err := s.stampVerifier(ctx, target.AutoRenewSetBy)
	if err == nil {
		return true
	}
	logging.Infof("renewal scheduler: NOT pushing cert %s to target %s (%q): armed by %q, but %v; notify-only until an authorized principal saves auto_renew=true again",
		cert.FingerprintSHA256, target.ID, target.Name, target.AutoRenewSetBy, err)
	s.emitRenewalAudit(ctx, cert, "certificate.renew_execute_denied", AuditOutcomeDenied,
		fmt.Sprintf("target_id=%s armed_by=%s %v", target.ID, target.AutoRenewSetBy, err))
	return false
}

// targetMayReceiveCert reports whether the target's tenant may see cert's CA,
// the same boundary authorizeCertificateResourceAccess applies to a human.
func targetMayReceiveCert(ctx context.Context, target ManagedTarget, cert CertificateItem) bool {
	return caVisibleToTenant(ctx, activeTenantStore, AuthPrincipal{Tenant: target.Tenant}, cert.CAID)
}

// renewalInstallMaxAttempts bounds scheduled renew+install attempts per
// certificate. The Nth failure is final: the owner is notified past the
// cooldown and the scheduler stops.
const renewalInstallMaxAttempts = 5

// installAttemptState is the scheduler's per-certificate attempt history,
// derived from the append-only audit log (so it survives restarts and needs no
// extra table): consecutive failures since the last success, and when the most
// recent one happened.
type installAttemptState struct {
	failures    int
	lastFailure time.Time
}

// installState reads the attempt history for cert on one target: rows that
// name another target_id belong to that target's own backoff. An empty
// targetID reads the whole certificate's history.
func (s *RenewalScheduler) installState(ctx context.Context, cert CertificateItem, targetID string) (installAttemptState, error) {
	var st installAttemptState
	if s.auditProvider == nil {
		return st, nil
	}
	res, err := s.auditProvider.ListEntries(ctx, AuditListQuery{
		Limit: 100, Order: "desc", ActorID: "renewal-scheduler",
		ResourceType: "certificate", ResourceID: cert.FingerprintSHA256,
	})
	if err != nil {
		return st, err
	}
	marker := "target_id=" + targetID + " "
	for _, e := range res.Entries { // newest first
		// An operator's retry-now (W27-19) resets the whole certificate, so the
		// marker row carries no target_id and must bypass the per-target filter.
		if e.Action == renewalRetryRequestedAction {
			return st, nil
		}
		if targetID != "" && !strings.Contains(e.ChangeSummary, marker) {
			continue
		}
		switch e.Action {
		case "certificate.renew_execute":
			return st, nil
		case "certificate.renew_execute_partial", "certificate.renew_execute_failed":
			st.failures++
			if st.lastFailure.IsZero() {
				ts, perr := time.Parse(time.RFC3339, e.Timestamp)
				if perr != nil {
					// An unreadable timestamp must not disable backoff: treat
					// the failure as having just happened.
					logging.Infof("renewal scheduler: audit row %d for %s has unparseable timestamp %q, backing off from now: %v", e.ID, cert.FingerprintSHA256, e.Timestamp, perr)
					ts = time.Now().UTC()
				}
				st.lastFailure = ts
			}
		}
	}
	return st, nil
}

// renewalTail follows successor links to the newest certificate in cert's
// chain. A failed install leaves a successor whose private key was destroyed
// with the attempt (keys are generated hub-side and never stored), so it can
// never be installed; the retry renews from the tail instead of being refused
// as already renewed.
func (s *RenewalScheduler) renewalTail(ctx context.Context, cert CertificateItem) (string, error) {
	fp := cert.FingerprintSHA256
	for i := 0; i < renewalInstallMaxAttempts+2; i++ {
		detail, ok, err := s.certProvider.GetCertificate(ctx, fp)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errCertificateNotFound
		}
		if detail.SuccessorFP == nil {
			return fp, nil
		}
		fp = *detail.SuccessorFP
	}
	return "", errors.New("successor chain too long")
}

type autoRenewOutcome struct {
	renewed      bool // successor issued AND installed
	attempted    bool // the engine ran this tick
	pending      bool // a failed install is waiting for a retry
	gaveUp       bool // attempts exhausted
	finalFailure bool // this tick's failure was the last allowed
	// newFingerprint is the successor installed on the target (renewed only).
	newFingerprint string
}

// tryAutoRenew executes one candidate through the W5-13 engine. It honors
// silences. A failed attempt is retried with exponential backoff (see
// installBackoff) up to renewalInstallMaxAttempts, each attempt audited with
// its number; the previous certificate keeps serving throughout because the
// installer rolls back a failed install.
func (s *RenewalScheduler) tryAutoRenew(ctx context.Context, cert CertificateItem, target ManagedTarget, now time.Time, st installAttemptState, pol retryPolicy) autoRenewOutcome {
	if s.isSilenced(ctx, cert) {
		return autoRenewOutcome{}
	}
	if st.failures >= renewalInstallMaxAttempts {
		return autoRenewOutcome{gaveUp: true}
	}
	// W26-28: upstream CA rate-limited this connector; wait it out, not a failure.
	if until, backedOff := acmeConnectorBackedOff(cert.RenewalConnectorID); backedOff {
		s.noteGateWake(until)
		return autoRenewOutcome{pending: true}
	}
	if st.failures > 0 && now.Before(st.lastFailure.Add(installBackoff(pol.base, pol.retryCap, st.failures)+s.jitterFor(cert.FingerprintSHA256, pol.poll))) {
		return autoRenewOutcome{pending: true}
	}
	attempt := st.failures + 1
	logging.Infof("renewal scheduler: binding cert %s (CN %q) to target %s (%q, host %q, armed by %q), attempt %d",
		cert.FingerprintSHA256, cert.CommonName, target.ID, target.Name, target.Host, target.AutoRenewSetBy, attempt)
	// A rollback that itself failed is never retried silently (W34-18).
	stopRetrying := false
	fail := func(action, detail string) autoRenewOutcome {
		final := attempt >= renewalInstallMaxAttempts || stopRetrying
		s.emitRenewalAudit(ctx, cert, action, AuditOutcomeFailure, fmt.Sprintf("target_id=%s attempt=%d/%d %s", target.ID, attempt, renewalInstallMaxAttempts, detail))
		if final {
			s.emitRenewalAudit(ctx, cert, "certificate.renew_execute_gave_up", AuditOutcomeFailure,
				fmt.Sprintf("target_id=%s attempts exhausted (%d); the host is still serving the previous certificate", target.ID, renewalInstallMaxAttempts))
			announceRenewalFailed(ctx, s.notifProvider, cert, st.lastFailure, now) // W32-28
		}
		recordRenewalExecuteFailure(ctx, cert.FingerprintSHA256, target.ID, attempt, renewalInstallMaxAttempts,
			strings.TrimPrefix(action, "certificate."), detail, now.Add(installBackoff(pol.base, pol.retryCap, attempt)), final)
		return autoRenewOutcome{attempted: true, pending: !final, gaveUp: final, finalFailure: final}
	}

	renewFP, err := s.renewalTail(ctx, cert)
	if err != nil {
		logging.Warnf("renewal scheduler: resolving renewal chain for %s failed: %v", cert.FingerprintSHA256, err)
		return fail("certificate.renew_execute_failed", err.Error())
	}
	result, err := s.renewalExecutor.ExecuteRenewal(ctx, renewFP, target, profileFromTarget(target))
	if err != nil {
		var rl *acmeRateLimitError
		if errors.As(err, &rl) { // W26-28: deferred, not failed
			s.emitRenewalAudit(ctx, cert, "acme.upstream.ratelimited", AuditOutcomeSkipped,
				fmt.Sprintf("connector=%s retry_at=%s", rl.ConnectorID, rl.RetryAt.UTC().Format(time.RFC3339)))
			acmeAlert("acme.upstream.ratelimited", cert.FingerprintSHA256, rl.Error())
			s.noteGateWake(rl.RetryAt)
			return autoRenewOutcome{pending: true}
		}
		if out, ok := s.deferredOutcome(ctx, cert, target, err); ok {
			return out
		}
		logging.Warnf("renewal scheduler: auto-renew failed for %s on %s (attempt %d/%d): %v", cert.FingerprintSHA256, target.Name, attempt, renewalInstallMaxAttempts, err)
		return fail("certificate.renew_execute_failed", err.Error())
	}
	installed := result.InstallOutcome == "installed_verified" || result.InstallOutcome == "installed"
	if !result.Renewed || !installed {
		logging.Infof("renewal scheduler: auto-renew partial for %s on %s (attempt %d/%d): renewed=%v install=%s %s",
			cert.FingerprintSHA256, target.Name, attempt, renewalInstallMaxAttempts, result.Renewed, result.InstallOutcome, result.InstallDetail)
		stopRetrying = result.InstallOutcome == "rollback_failed"
		return fail("certificate.renew_execute_partial",
			fmt.Sprintf("renewed=%v new_fingerprint=%s install=%s %s", result.Renewed, result.NewFingerprint, result.InstallOutcome, result.InstallDetail))
	}
	logging.Infof("renewal scheduler: auto-renewed %s -> %s on %s (%s, attempt %d)",
		cert.FingerprintSHA256, result.NewFingerprint, target.Name, result.InstallOutcome, attempt)
	s.emitRenewalAudit(ctx, cert, "certificate.renew_execute", AuditOutcomeSuccess,
		fmt.Sprintf("new_fingerprint=%s install=%s target_id=%s target=%s attempt=%d", result.NewFingerprint, result.InstallOutcome, target.ID, target.Name, attempt))
	clearRenewalExecuteFailure(ctx, cert.FingerprintSHA256, target.ID)
	if renewFP != cert.FingerprintSHA256 {
		// Earlier failed attempts moved the chain tail; the executor reported
		// the tail, so also close tickets keyed on the original (W32-28).
		orig := result
		orig.PredecessorFingerprint = cert.FingerprintSHA256
		notifyRenewalVerified(ctx, orig)
	}
	return autoRenewOutcome{renewed: true, attempted: true, newFingerprint: result.NewFingerprint}
}

func buildRenewalNotificationMessage(cert CertificateItem, daysLeft int) string {
	return "Certificate renewal reminder: " + cert.CommonName +
		" expires in " + strconv.Itoa(daysLeft) + " day(s). " +
		"Fingerprint: " + cert.FingerprintSHA256 + ". " +
		"Please renew before expiry to avoid service disruption."
}

func buildExpiredNotificationMessage(cert CertificateItem, expiry time.Time) string {
	return "Certificate EXPIRED: " + cert.CommonName +
		" expired " + expiry.UTC().Format("2006-01-02") + ". " +
		"Fingerprint: " + cert.FingerprintSHA256 + ". " +
		"Renew or replace it now to restore service."
}

type silenceMemoKey struct{}

// silenceMemo holds one tick's silence verdicts. A CA or template silence is
// asked about once per distinct id per tick instead of once per candidate
// certificate (M6); thousands of candidates share a handful of CAs.
type silenceMemo struct {
	mu sync.Mutex
	m  map[string]bool
}

func withSilenceMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, silenceMemoKey{}, &silenceMemo{m: map[string]bool{}})
}

// memoizedIsSilenced answers from the tick's memo when ctx carries one. Only
// successful lookups are remembered, so a transient store error is retried
// for the next candidate rather than pinned for the whole tick.
func memoizedIsSilenced(ctx context.Context, store NotificationSilenceStore, targetType, targetID string) (bool, error) {
	memo, _ := ctx.Value(silenceMemoKey{}).(*silenceMemo)
	if memo == nil {
		return store.IsSilenced(ctx, targetType, targetID)
	}
	key := targetType + "\x00" + targetID
	memo.mu.Lock()
	v, ok := memo.m[key]
	memo.mu.Unlock()
	if ok {
		return v, nil
	}
	silenced, err := store.IsSilenced(ctx, targetType, targetID)
	if err != nil {
		return false, err
	}
	memo.mu.Lock()
	memo.m[key] = silenced
	memo.mu.Unlock()
	return silenced, nil
}
