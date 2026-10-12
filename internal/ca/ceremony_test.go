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
                  CHECK (status IN ('pending', 'completed', 'aborted')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
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
