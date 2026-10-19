// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

type recordingChannel struct {
	mu     sync.Mutex
	events []delivery.Event
	err    error
}

func (c *recordingChannel) Name() string { return "rec" }
func (c *recordingChannel) Send(_ context.Context, ev delivery.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return c.err
}
func (c *recordingChannel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func installFailoverNotifier(t *testing.T) (*memAuditProvider, *recordingChannel) {
	t.Helper()
	audit := &memAuditProvider{}
	ch := &recordingChannel{}
	SetHAFailoverObserver(NewHAFailoverNotifier(audit, ch, "ops").Observe)
	t.Cleanup(func() { SetHAFailoverObserver(nil) })
	return audit, ch
}

func TestHAFailover_FirstAcquireAndSelfRenewDoNotEmit(t *testing.T) {
	audit, ch := installFailoverNotifier(t)
	db := newTestHADB(t)
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	a := newTestHACoordinatorAt(t, db, "replica-a", base)
	if ok, err := a.TryAcquire(ctx, "lock", 5*time.Minute); err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	a.now = func() time.Time { return base.Add(time.Minute) }
	if ok, err := a.TryAcquire(ctx, "lock", 5*time.Minute); err != nil || !ok {
		t.Fatalf("self renew: ok=%v err=%v", ok, err)
	}
	if n := len(audit.actions("ha.failover")); n != 0 || ch.count() != 0 {
		t.Fatalf("first acquire / self renew emitted: audit=%d alerts=%d", n, ch.count())
	}
}

func TestHAFailover_BlockedContenderDoesNotEmit(t *testing.T) {
	audit, ch := installFailoverNotifier(t)
	db := newTestHADB(t)
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	a := newTestHACoordinatorAt(t, db, "replica-a", base)
	if ok, _ := a.TryAcquire(ctx, "lock", 5*time.Minute); !ok {
		t.Fatal("a should acquire")
	}
	b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(time.Minute)) // lease still live
	if ok, _ := b.TryAcquire(ctx, "lock", 5*time.Minute); ok {
		t.Fatal("b must not steal a live lease")
	}
	if len(audit.actions("ha.failover")) != 0 || ch.count() != 0 {
		t.Fatal("losing contender emitted a failover")
	}
}

func TestHAFailover_TakeoverEmitsAuditAndAlertExactlyOnce(t *testing.T) {
	audit, ch := installFailoverNotifier(t)
	db := newTestHADB(t)
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	a := newTestHACoordinatorAt(t, db, "replica-a", base)
	if ok, _ := a.TryAcquire(ctx, "lock", 5*time.Minute); !ok {
		t.Fatal("a should acquire")
	}
	// a stops renewing; its lease lapses and b takes over, then keeps renewing.
	b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(10*time.Minute))
	for i := 0; i < 3; i++ {
		b.now = func() time.Time { return base.Add(10*time.Minute + time.Duration(i)*time.Minute) }
		if ok, err := b.TryAcquire(ctx, "lock", 5*time.Minute); err != nil || !ok {
			t.Fatalf("b tick %d: ok=%v err=%v", i, ok, err)
		}
	}

	entries := audit.actions("ha.failover")
	if len(entries) != 1 || ch.count() != 1 {
		t.Fatalf("want exactly one audit + one alert, got audit=%d alerts=%d", len(entries), ch.count())
	}
	e := entries[0]
	if e.ActorType != "system" || e.ResourceID != "lock" || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
	for _, want := range []string{`"previous_holder":"replica-a"`, `"new_holder":"replica-b"`, `"lease_age_seconds":600`} {
		if !strings.Contains(e.ChangeSummary, want) {
			t.Fatalf("details %s missing %s", e.ChangeSummary, want)
		}
	}
	if ev := ch.events[0]; ev.Subject != "scheduler.failover" || !strings.Contains(ev.Message, "scheduler.failover") || ev.Target != "ops" {
		t.Fatalf("unexpected alert: %+v", ev)
	}

	// b dies, a comes back later and takes over again: a second, distinct takeover.
	a.now = func() time.Time { return base.Add(time.Hour) }
	if ok, _ := a.TryAcquire(ctx, "lock", 5*time.Minute); !ok {
		t.Fatal("a should retake the lapsed lock")
	}
	if len(audit.actions("ha.failover")) != 2 || ch.count() != 2 {
		t.Fatalf("second takeover not reported once: audit=%d alerts=%d", len(audit.actions("ha.failover")), ch.count())
	}
}

func TestHAFailover_NoObserverNoPreRead(t *testing.T) {
	SetHAFailoverObserver(nil)
	db := newTestHADB(t)
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	a := newTestHACoordinatorAt(t, db, "replica-a", base)
	b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(time.Hour))
	ctx := context.Background()
	_, _ = a.TryAcquire(ctx, "lock", 5*time.Minute)
	if ok, err := b.TryAcquire(ctx, "lock", 5*time.Minute); err != nil || !ok {
		t.Fatalf("takeover without observer must still work: ok=%v err=%v", ok, err)
	}
}

// descAudit is an AuditProvider that honours Limit/Order newest-first.
type descAudit struct{ memAuditProvider }

func (d *descAudit) ListEntries(ctx context.Context, q AuditListQuery) (AuditListResult, error) {
	lim := q.Limit
	q.Limit = 0
	res, err := d.memAuditProvider.ListEntries(ctx, q)
	sort.SliceStable(res.Entries, func(i, j int) bool { return res.Entries[i].Timestamp > res.Entries[j].Timestamp })
	if lim > 0 && len(res.Entries) > lim {
		res.Entries = res.Entries[:lim]
	}
	return res, err
}

func addBackup(a *descAudit, at time.Time, outcome AuditOutcome) {
	_ = a.AppendEntry(context.Background(), AuditEntry{
		Timestamp: at.Format(time.RFC3339), Action: "backup.create", Outcome: outcome,
	})
}

func TestBackupStale_LatchAndRearm(t *testing.T) {
	audit := &descAudit{}
	ch := &recordingChannel{}
	s := newBackupStaleSweeper(audit, ch, "ops", 24*time.Hour)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	s.tick(ctx, t0)
	if ch.count() != 0 {
		t.Fatal("no backup ever taken: must not alert")
	}

	addBackup(audit, t0, AuditOutcomeSuccess)
	addBackup(audit, t0.Add(time.Hour), AuditOutcomeFailure) // failed backups do not count
	s.tick(ctx, t0.Add(23*time.Hour))
	if ch.count() != 0 {
		t.Fatal("fresh backup alerted")
	}
	s.tick(ctx, t0.Add(25*time.Hour))
	s.tick(ctx, t0.Add(26*time.Hour))
	s.tick(ctx, t0.Add(40*time.Hour))
	if ch.count() != 1 {
		t.Fatalf("want exactly one alert per stale episode, got %d", ch.count())
	}
	if ev := ch.events[0]; ev.Subject != "backup.stale" || !strings.Contains(ev.Message, "backup.stale") {
		t.Fatalf("unexpected alert: %+v", ev)
	}

	addBackup(audit, t0.Add(41*time.Hour), AuditOutcomeSuccess)
	s.tick(ctx, t0.Add(42*time.Hour)) // re-arms
	s.tick(ctx, t0.Add(70*time.Hour)) // stale again
	if ch.count() != 2 {
		t.Fatalf("want second alert after re-arm, got %d", ch.count())
	}
}

func TestBackupStale_SendFailureRetriesNextTick(t *testing.T) {
	audit := &descAudit{}
	ch := &recordingChannel{err: ErrNoConfiguredChannel}
	s := newBackupStaleSweeper(audit, ch, "ops", time.Hour)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	addBackup(audit, t0, AuditOutcomeSuccess)
	s.tick(context.Background(), t0.Add(2*time.Hour))
	ch.mu.Lock()
	ch.err = nil
	ch.mu.Unlock()
	s.tick(context.Background(), t0.Add(3*time.Hour))
	s.tick(context.Background(), t0.Add(4*time.Hour))
	if ch.count() != 2 { // one failed attempt, one delivered, then latched
		t.Fatalf("want 2 sends (fail then success), got %d", ch.count())
	}
}

func TestBackupStale_EnvDisabledAndDefault(t *testing.T) {
	audit := &descAudit{}
	t.Setenv("KRYPTKEEPER_BACKUP_STALE_HOURS", "0")
	if NewBackupStaleSweeperFromEnv(audit, nil, "") != nil {
		t.Fatal("0 must disable the sweeper")
	}
	t.Setenv("KRYPTKEEPER_BACKUP_STALE_HOURS", "")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	s := NewBackupStaleSweeperFromEnv(audit, nil, "")
	if s == nil || s.threshold != 24*time.Hour {
		t.Fatalf("default threshold want 24h, got %+v", s)
	}
	t.Setenv("KRYPTKEEPER_BACKUP_STALE_HOURS", "0.5")
	if s := NewBackupStaleSweeperFromEnv(audit, nil, ""); s == nil || s.threshold != 30*time.Minute {
		t.Fatalf("0.5h threshold wrong: %+v", s)
	}
}

func TestHAFailover_DeadHubWithFourLocksOneAlert(t *testing.T) {
	audit, ch := installFailoverNotifier(t)
	db := newTestHADB(t)
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	locks := []string{"slo", "renewal", "posture", "anomaly"}

	dead := newTestHACoordinatorAt(t, db, "replica-dead", base)
	for _, l := range locks {
		if ok, _ := dead.TryAcquire(ctx, l, 5*time.Minute); !ok {
			t.Fatalf("dead hub should acquire %s", l)
		}
	}
	live := newTestHACoordinatorAt(t, db, "replica-live", base.Add(10*time.Minute))
	for _, l := range locks {
		if ok, _ := live.TryAcquire(ctx, l, 5*time.Minute); !ok {
			t.Fatalf("live hub should take %s", l)
		}
	}
	if n := len(audit.actions("ha.failover")); n != 4 {
		t.Fatalf("want 4 audit rows, got %d", n)
	}
	if ch.count() != 1 {
		t.Fatalf("want 1 alert, got %d", ch.count())
	}
}

func TestNewHACoordinatorSharesProcessReplicaID(t *testing.T) {
	a, _ := newHACoordinatorID()
	b, _ := newHACoordinatorID()
	if a == "" || a != b {
		t.Fatalf("replica id must be stable per process: %q vs %q", a, b)
	}
}
