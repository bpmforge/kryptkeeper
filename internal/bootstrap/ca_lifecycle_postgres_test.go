// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// Live-Postgres round trip over the certificate/CA surface beyond issuance:
// intermediate CA, issue, revoke, renew, ownership + estate edits, chain,
// download, issuance policy, key lifecycle policy and a root-CA ceremony.
func TestCertificateLifecycle_Postgres(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, true))
	rev := ca.NewDBRevocationStore(db, true)
	provider := NewCACertificateProvider(engine, rev, db, true)
	ctx := context.Background()

	root, err := engine.CreateRootCA("pg Root", pkix.Name{CommonName: "pg Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	inter, err := engine.CreateIntermediateCA("pg Intermediate", pkix.Name{CommonName: "pg Intermediate CA"},
		keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}
	if cas, err := engine.ListCAs(); err != nil || len(cas) != 2 {
		t.Fatalf("ListCAs: %d %v", len(cas), err)
	}
	if chain, err := engine.GetCAChain(inter.ID); err != nil || len(chain) != 2 {
		t.Fatalf("GetCAChain: %d %v", len(chain), err)
	}

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: inter.ID, CSRPEM: generateTestCSRPEM(t, "life.example.com", "life.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-life",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256

	if _, ok, err := provider.GetCertificate(ctx, fp); err != nil || !ok {
		t.Fatalf("GetCertificate: ok=%v err=%v", ok, err)
	}
	if _, ok, err := provider.GetCertificateChain(ctx, fp); err != nil || !ok {
		t.Fatalf("GetCertificateChain: ok=%v err=%v", ok, err)
	}
	if _, err := provider.DownloadCertificate(ctx, fp, "pem", true); err != nil {
		t.Fatalf("DownloadCertificate: %v", err)
	}
	if _, err := provider.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{
		OwnerEmail: "o@example.com", OwnerTeam: "plat", ServiceName: "svc", Labels: []string{"a", "b"},
	}); err != nil {
		t.Fatalf("UpdateOwnership: %v", err)
	}
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{ManagementState: "managed", RenewalMethod: "manual"}); err != nil {
		t.Fatalf("UpdateEstate: %v", err)
	}

	renewed, err := provider.RenewCertificate(ctx, fp, CertificateRenewRequest{
		CSRPEM: generateTestCSRPEM(t, "life.example.com", "life.example.com"),
	})
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}

	if _, err := provider.RevokeCertificate(ctx, renewed.CertificateItem.FingerprintSHA256,
		CertificateRevokeRequest{ReasonCode: 1, ReasonText: "test"}); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	entries, err := rev.ListRevoked(inter.ID)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListRevoked: %+v %v", entries, err)
	}

	// A fresh provider over the same DB must see issued + revoked state.
	provider2 := NewCACertificateProvider(ca.NewEngine(keys, ca.NewDBStore(db, true)), ca.NewDBRevocationStore(db, true), db, true)
	list, err := provider2.ListCertificates(ctx, CertificateListQuery{TeamID: "team-life"})
	if err != nil || list.Total < 2 {
		t.Fatalf("ListCertificates after restart: total=%d err=%v", list.Total, err)
	}

	// Issuance policy table.
	pe, err := ca.NewPolicyEngine(db, true)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := pe.UpsertPolicy(ca.IssuancePolicy{Name: "max90", Enabled: true, CAID: inter.ID,
		Rules: ca.PolicyRules{MaxValidityDays: 90}})
	if err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}
	if l, err := pe.ListPolicies(); err != nil || len(l) != 1 || !l[0].Enabled {
		t.Fatalf("ListPolicies: %+v %v", l, err)
	}
	if err := pe.DeletePolicy(pol.ID); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}

	// Key lifecycle policy rows.
	lm, err := NewKeyLifecycleManager(db, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := lm.SetPolicy(root.KeyID, "alice", []string{"bob"}, 365); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if err := lm.SetPolicy(root.KeyID, "alice", []string{"bob", "carol"}, 180); err != nil {
		t.Fatalf("SetPolicy (upsert): %v", err)
	}
	if kp, ok, err := lm.GetPolicy(root.KeyID); err != nil || !ok || kp.MaxAgeDays != 180 {
		t.Fatalf("GetPolicy: %+v ok=%v err=%v", kp, ok, err)
	}
	if _, err := lm.RunRotationSweep(ctx); err != nil {
		t.Fatalf("RunRotationSweep: %v", err)
	}

	// Root CA ceremony (quorum approval).
	cm, err := ca.NewCeremonyManager(db, true, engine)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cm.StartRootCACeremony(ca.RootCACeremonyParams{Name: "cer", CommonName: "Cer Root",
		Algorithm: keystore.ECDSAP256, ValidityDays: 365, Initiator: "alice", Approvers: []string{"bob", "carol"}, Quorum: 2})
	if err != nil {
		t.Fatalf("StartRootCACeremony: %v", err)
	}
	if _, err := cm.Approve(c.ID, "bob"); err != nil {
		t.Fatalf("Approve bob: %v", err)
	}
	done, err := cm.Approve(c.ID, "carol")
	if err != nil || done.Status != ca.CeremonyCompleted {
		t.Fatalf("Approve carol: %+v %v", done, err)
	}
	if l, err := cm.List(); err != nil || len(l) != 1 {
		t.Fatalf("ceremony List: %+v %v", l, err)
	}
}
