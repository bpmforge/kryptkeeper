// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newFreshRenewalAlertCooldownStore(t *testing.T) *sqliteRenewalAlertCooldownStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cooldown-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteRenewalAlertCooldownStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	return s
}

// TestRenewalAlertCooldownStore_SelfHealsSchemaOnFreshDB is the W1-06/G-33
// regression: a brand-new database with no pre-existing
// renewal_alert_cooldowns table must still work, and EnsureSchema must be
// idempotent.
func TestRenewalAlertCooldownStore_SelfHealsSchemaOnFreshDB(t *testing.T) {
	s := newFreshRenewalAlertCooldownStore(t)
	ctx := context.Background()

	_, ok, err := s.LastAlertedAt(ctx, "fp-unknown")
	if err != nil {
		t.Fatalf("LastAlertedAt on fresh db: %v", err)
	}
	if ok {
		t.Fatal("expected no record for an unknown fingerprint on a fresh db")
	}

	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}

// TestRenewalAlertCooldownStore_RecordAndRetrieve proves RecordAlerted is a
// real upsert — a second call for the same fingerprint updates the
// timestamp in place rather than erroring or duplicating.
func TestRenewalAlertCooldownStore_RecordAndRetrieve(t *testing.T) {
	s := newFreshRenewalAlertCooldownStore(t)
	ctx := context.Background()

	first := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := s.RecordAlerted(ctx, "fp-1", first); err != nil {
		t.Fatalf("record first: %v", err)
	}
	got, ok, err := s.LastAlertedAt(ctx, "fp-1")
	if err != nil || !ok {
		t.Fatalf("lookup after first record: ok=%v err=%v", ok, err)
	}
	if !got.Equal(first) {
		t.Errorf("expected %v, got %v", first, got)
	}

	second := first.Add(48 * time.Hour)
	if err := s.RecordAlerted(ctx, "fp-1", second); err != nil {
		t.Fatalf("record second (upsert): %v", err)
	}
	got, ok, err = s.LastAlertedAt(ctx, "fp-1")
	if err != nil || !ok {
		t.Fatalf("lookup after second record: ok=%v err=%v", ok, err)
	}
	if !got.Equal(second) {
		t.Errorf("expected the upsert to advance to %v, got %v", second, got)
	}
}

// TestIsWithinCooldown is the pure-function cooldown-window regression —
// tested without any DB access, mirroring FindingException.IsActive's
// pattern (W2-06).
func TestIsWithinCooldown(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	cooldown := 24 * time.Hour

	recent := now.Add(-1 * time.Hour)
	if !isWithinCooldown(recent, cooldown, now) {
		t.Error("expected an alert 1h ago (within a 24h cooldown) to still be in cooldown")
	}

	old := now.Add(-25 * time.Hour)
	if isWithinCooldown(old, cooldown, now) {
		t.Error("expected an alert 25h ago (past a 24h cooldown) to be out of cooldown")
	}

	exact := now.Add(-cooldown)
	if isWithinCooldown(exact, cooldown, now) {
		t.Error("expected an alert exactly at the cooldown boundary to be out of cooldown")
	}
}

// TestRenewalScheduler_CooldownSuppressesRepeatAlertWithinWindow is the
// W1-06/D-033 acceptance regression, proven with a REAL persisted store (not
// an in-memory stub) since the whole point of persisting is surviving a
// scheduler restart — a fresh RenewalScheduler instance sharing the same
// underlying DB must still honor a cooldown recorded by a PRIOR instance.
func TestRenewalScheduler_CooldownSuppressesRepeatAlertWithinWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cooldown-e2e.db")
	openStore := func() *sqliteRenewalAlertCooldownStore {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		s := &sqliteRenewalAlertCooldownStore{db: db}
		if err := s.EnsureSchema(context.Background()); err != nil {
			t.Fatalf("EnsureSchema: %v", err)
		}
		return s
	}

	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "cooldown-cert", CommonName: "cd", ValidUntil: soon, OwnerEmail: "owner@example.com"},
	}}

	// First scheduler instance: sends the reminder, records the cooldown.
	s1 := &RenewalScheduler{
		certProvider: certs, notifProvider: succeedingTestDeliveryNotificationProvider{}, auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: 24 * time.Hour, cooldown: 24 * time.Hour, cooldownStore: openStore(),
	}
	s1.runScan()
	if st := s1.Status(); st.LastNotifications != 1 {
		t.Fatalf("expected 1 notification on the first scan, got %d", st.LastNotifications)
	}

	// A SECOND, independent scheduler instance sharing the same DB — as if
	// the hub restarted — must still see the cooldown and suppress.
	s2 := &RenewalScheduler{
		certProvider: certs, notifProvider: succeedingTestDeliveryNotificationProvider{}, auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: 24 * time.Hour, cooldown: 24 * time.Hour, cooldownStore: openStore(),
	}
	s2.runScan()
	if st := s2.Status(); st.LastNotifications != 0 {
		t.Fatalf("expected the cooldown to suppress the repeat alert across a fresh scheduler instance, got %d notifications", st.LastNotifications)
	}
}
