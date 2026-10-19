// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/keystore"
)

// W9-06: pending_ceremony → active only on quorum.

const ceremonyTestSchema = `
CREATE TABLE IF NOT EXISTS key_ceremonies (
    id            TEXT PRIMARY KEY,
    ca_id         TEXT NOT NULL,
    ca_name       TEXT NOT NULL,
    common_name   TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    validity_days INTEGER NOT NULL CHECK (validity_days > 0),
    initiator     TEXT NOT NULL,
    approvers     TEXT NOT NULL,
    quorum        INTEGER NOT NULL CHECK (quorum >= 2),
    approvals     TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'completed', 'aborted', 'expired')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    reminder_sent_at TEXT
);`

func newCeremonyTestManager(t *testing.T) (*CeremonyManager, *Engine) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ceremony.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(ceremonyTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ceremony-test-passphrase-32-byt!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	engine := NewEngine(keys, NewMemStore())
	mgr, err := NewCeremonyManager(db, false, engine)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	return mgr, engine
}

func startTestCeremony(t *testing.T, mgr *CeremonyManager) Ceremony {
	t.Helper()
	c, err := mgr.StartRootCACeremony(RootCACeremonyParams{
		Name: "Ceremonial Root", CommonName: "Ceremonial Root CA",
		Algorithm: keystore.ECDSAP256, ValidityDays: 3650,
		Initiator: "ops-lead",
		Approvers: []string{"alice", "bob", "carol"}, Quorum: 2,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return c
}

func testIssuance(t *testing.T, engine *Engine, caID string) error {
	t.Helper()
	// A CSR the engine would sign if the CA were active.
	keys2, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ceremony-leaf-passphrase-32-byt!"))
	if err != nil {
		t.Fatalf("leaf keystore: %v", err)
	}
	defer keys2.Close()
	if _, err := keys2.GenerateKey("leaf", keystore.ECDSAP256); err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	signer, err := keys2.Signer("leaf")
	if err != nil {
		t.Fatalf("leaf signer: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, signer)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	_, err = engine.IssueCertificate(caID, IssuanceRequest{
		CSR: csr, Validity: 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	return err
}

func TestCeremonyCARefusedUntilQuorumThenActive(t *testing.T) {
	mgr, engine := newCeremonyTestManager(t)
	c := startTestCeremony(t, mgr)

	caObj, err := engine.GetCA(c.CAID)
	if err != nil {
		t.Fatalf("get ca: %v", err)
	}
	if caObj.Status != CAStatusPendingCeremony {
		t.Fatalf("CA must be born pending_ceremony, got %q", caObj.Status)
	}
	if err := testIssuance(t, engine, c.CAID); err == nil {
		t.Fatal("issuance from a pending_ceremony CA must be refused")
	}

	if _, err := mgr.Approve(c.ID, "alice"); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	// One approval < quorum: still refused.
	if err := testIssuance(t, engine, c.CAID); err == nil {
		t.Fatal("issuance before quorum must be refused")
	}

	final, err := mgr.Approve(c.ID, "bob")
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if final.Status != CeremonyCompleted {
		t.Fatalf("ceremony must complete on quorum, got %q", final.Status)
	}
	caObj, err = engine.GetCA(c.CAID)
	if err != nil {
		t.Fatalf("get ca: %v", err)
	}
	if caObj.Status != "active" {
		t.Fatalf("CA must be active on quorum, got %q", caObj.Status)
	}
	if err := testIssuance(t, engine, c.CAID); err != nil {
		t.Fatalf("issuance after quorum must succeed: %v", err)
	}
}

func TestCeremonyApprovalsMustBeDistinctAndEligible(t *testing.T) {
	mgr, _ := newCeremonyTestManager(t)
	c := startTestCeremony(t, mgr)

	if _, err := mgr.Approve(c.ID, "mallory"); err == nil {
		t.Fatal("non-eligible approver must be refused")
	}
	if _, err := mgr.Approve(c.ID, "alice"); err != nil {
		t.Fatalf("eligible approval: %v", err)
	}
	if _, err := mgr.Approve(c.ID, "alice"); err == nil {
		t.Fatal("the same identity approving twice must be refused — M-of-N means distinct people")
	}
}

func TestCeremonyQuorumRules(t *testing.T) {
	mgr, _ := newCeremonyTestManager(t)
	base := RootCACeremonyParams{
		Name: "R", CommonName: "R CA", Algorithm: keystore.ECDSAP256,
		ValidityDays: 365, Initiator: "ops",
	}

	p := base
	p.Approvers = []string{"alice", "bob"}
	p.Quorum = 1
	if _, err := mgr.StartRootCACeremony(p); err == nil {
		t.Fatal("quorum 1 must be refused — a one-person ceremony is not a ceremony")
	}
	p = base
	p.Approvers = []string{"alice", "bob"}
	p.Quorum = 3
	if _, err := mgr.StartRootCACeremony(p); err == nil {
		t.Fatal("quorum above the eligible-approver count must be refused")
	}
	p = base
	p.Approvers = []string{"alice", "alice"}
	p.Quorum = 2
	if _, err := mgr.StartRootCACeremony(p); err == nil {
		t.Fatal("duplicate approvers must be refused")
	}
}

func TestCeremonyAbortLeavesCAUnusable(t *testing.T) {
	mgr, engine := newCeremonyTestManager(t)
	c := startTestCeremony(t, mgr)

	if _, err := mgr.Abort(c.ID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if _, err := mgr.Approve(c.ID, "alice"); err == nil {
		t.Fatal("approvals on an aborted ceremony must be refused")
	}
	caObj, err := engine.GetCA(c.CAID)
	if err != nil {
		t.Fatalf("get ca: %v", err)
	}
	if caObj.Status != CAStatusPendingCeremony {
		t.Fatalf("aborted ceremony's CA must stay pending_ceremony, got %q", caObj.Status)
	}
	if err := testIssuance(t, engine, c.CAID); err == nil {
		t.Fatal("aborted ceremony's CA must never issue")
	}
}

func TestCeremonySurvivesManagerRestart(t *testing.T) {
	mgr, engine := newCeremonyTestManager(t)
	c := startTestCeremony(t, mgr)
	if _, err := mgr.Approve(c.ID, "alice"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	reloaded, err := NewCeremonyManager(mgr.db, false, engine)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, found, err := reloaded.Get(c.ID)
	if err != nil || !found {
		t.Fatalf("get after restart: %v %v", found, err)
	}
	if len(got.Approvals) != 1 || got.Approvals[0] != "alice" {
		t.Fatalf("approvals lost across restart: %v", got.Approvals)
	}
	if _, err := reloaded.Approve(c.ID, "bob"); err != nil {
		t.Fatalf("quorum after restart: %v", err)
	}
	caObj, _ := engine.GetCA(c.CAID)
	if caObj.Status != "active" {
		t.Fatalf("CA must activate across restarts, got %q", caObj.Status)
	}
}

// W23-07: TTL auto-abort and approver notifications.

type fakeNotifier struct {
	sent [][2]string // (approver, subject)
}

func (f *fakeNotifier) NotifyApprover(approver, subject, _ string) error {
	f.sent = append(f.sent, [2]string{approver, subject})
	return nil
}

func (f *fakeNotifier) approvers() map[string]int {
	out := map[string]int{}
	for _, s := range f.sent {
		out[s[0]]++
	}
	return out
}

func fixedClock(t0 time.Time) (func() time.Time, func(d time.Duration)) {
	cur := t0
	return func() time.Time { return cur }, func(d time.Duration) { cur = cur.Add(d) }
}

func TestCeremonyExpiresAfterTTLAndCANeverActivates(t *testing.T) {
	mgr, engine := newCeremonyTestManager(t)
	clock, advance := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mgr.SetClock(clock)
	c := startTestCeremony(t, mgr)

	advance(71 * time.Hour)
	if got, err := mgr.ExpireDue(); err != nil || len(got) != 0 {
		t.Fatalf("must not expire before TTL: %v %v", got, err)
	}
	advance(1*time.Hour + time.Minute)
	got, err := mgr.ExpireDue()
	if err != nil || len(got) != 1 || got[0].ID != c.ID {
		t.Fatalf("ExpireDue = %v, %v; want exactly %s", got, err, c.ID)
	}
	if again, _ := mgr.ExpireDue(); len(again) != 0 {
		t.Fatalf("second ExpireDue must be a no-op, got %v", again)
	}
	cur, _, _ := mgr.Get(c.ID)
	if cur.Status != CeremonyExpired {
		t.Fatalf("status = %q, want expired", cur.Status)
	}
	if _, err := mgr.Approve(c.ID, "alice"); err == nil {
		t.Fatal("approve on an expired ceremony must fail")
	}
	caObj, _ := engine.GetCA(c.CAID)
	if caObj.Status != CAStatusPendingCeremony {
		t.Fatalf("CA must stay pending_ceremony, got %q", caObj.Status)
	}
	if err := testIssuance(t, engine, c.CAID); err == nil {
		t.Fatal("issuance from an expired ceremony's CA must be refused")
	}
}

func TestCeremonyApproveAfterTTLExpiresInline(t *testing.T) {
	mgr, engine := newCeremonyTestManager(t)
	clock, advance := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mgr.SetClock(clock)
	c := startTestCeremony(t, mgr)
	if _, err := mgr.Approve(c.ID, "alice"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	advance(73 * time.Hour)
	// Quorum would be reached by this approval; the TTL must win.
	if _, err := mgr.Approve(c.ID, "bob"); err == nil {
		t.Fatal("approval past the TTL must be refused")
	}
	cur, _, _ := mgr.Get(c.ID)
	if cur.Status != CeremonyExpired {
		t.Fatalf("status = %q, want expired", cur.Status)
	}
	caObj, _ := engine.GetCA(c.CAID)
	if caObj.Status != CAStatusPendingCeremony {
		t.Fatalf("CA must not activate, got %q", caObj.Status)
	}
}

func TestCeremonyTTLConfigurableViaEnv(t *testing.T) {
	t.Setenv("KRYPTKEEPER_CEREMONY_TTL", "1h")
	if got := CeremonyTTLFromEnv(); got != time.Hour {
		t.Fatalf("ttl = %s, want 1h", got)
	}
	for _, bad := range []string{"", "banana", "0s", "-5h"} {
		t.Setenv("KRYPTKEEPER_CEREMONY_TTL", bad)
		if got := CeremonyTTLFromEnv(); got != 72*time.Hour {
			t.Fatalf("ttl for %q = %s, want 72h fallback", bad, got)
		}
	}
	t.Setenv("KRYPTKEEPER_CEREMONY_TTL", "1h")
	mgr, _ := newCeremonyTestManager(t)
	clock, advance := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mgr.SetClock(clock)
	startTestCeremony(t, mgr)
	advance(61 * time.Minute)
	if got, _ := mgr.ExpireDue(); len(got) != 1 {
		t.Fatalf("1h TTL must expire after 61m, got %d", len(got))
	}
}

func TestCeremonyNotifiesEveryApproverOnStart(t *testing.T) {
	mgr, _ := newCeremonyTestManager(t)
	n := &fakeNotifier{}
	mgr.SetNotifier(n)
	startTestCeremony(t, mgr)
	got := n.approvers()
	for _, a := range []string{"alice", "bob", "carol"} {
		if got[a] != 1 {
			t.Fatalf("approver %s notified %d times, want 1 (all: %v)", a, got[a], got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("only designated approvers may be notified, got %v", got)
	}
}

func TestCeremonyReminderAt24hBeforeExpiry(t *testing.T) {
	mgr, engine := newCeremonyTestManager(t)
	clock, advance := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mgr.SetClock(clock)
	n := &fakeNotifier{}
	mgr.SetNotifier(n)
	startTestCeremony(t, mgr)
	n.sent = nil

	advance(47 * time.Hour)
	if c, err := mgr.SendDueReminders(); err != nil || c != 0 || len(n.sent) != 0 {
		t.Fatalf("no reminder before T-24h: %d %v %v", c, err, n.sent)
	}
	advance(1 * time.Hour)
	c, err := mgr.SendDueReminders()
	if err != nil || c != 1 {
		t.Fatalf("reminder at T-24h: %d %v", c, err)
	}
	got := n.approvers()
	if len(got) != 3 || got["alice"] != 1 || got["bob"] != 1 || got["carol"] != 1 {
		t.Fatalf("reminder must reach exactly the 3 approvers once, got %v", got)
	}
	if c, _ := mgr.SendDueReminders(); c != 0 {
		t.Fatalf("second pass must not re-remind, got %d", c)
	}

	// reminder_sent_at is persisted: a restarted manager does not re-remind.
	reloaded, err := NewCeremonyManager(mgr.db, false, engine)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	reloaded.SetClock(clock)
	n2 := &fakeNotifier{}
	reloaded.SetNotifier(n2)
	if c, _ := reloaded.SendDueReminders(); c != 0 || len(n2.sent) != 0 {
		t.Fatalf("restart re-sent reminders: %d %v", c, n2.sent)
	}

	// Past expiry no reminder is sent either.
	mgr2, _ := newCeremonyTestManager(t)
	clock2, advance2 := fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mgr2.SetClock(clock2)
	n3 := &fakeNotifier{}
	mgr2.SetNotifier(n3)
	startTestCeremony(t, mgr2)
	n3.sent = nil
	advance2(80 * time.Hour)
	if c, _ := mgr2.SendDueReminders(); c != 0 || len(n3.sent) != 0 {
		t.Fatalf("no reminder after expiry, got %d", c)
	}
}
