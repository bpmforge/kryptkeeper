// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// W5-05: policy-violating requests are refused AT ISSUANCE with a cited
// rule, through the real Engine.IssueCertificate path; rules are table
// rows, not compile-time.

const policyTestSchema = `
CREATE TABLE IF NOT EXISTS issuance_policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    ca_id      TEXT NOT NULL DEFAULT '',
    rules      TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);`

func newPolicyTestEngine(t *testing.T) (*Engine, *PolicyEngine, *CA) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(policyTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("policy-engine-test-passphrase-32"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	engine := NewEngine(keys, NewMemStore())
	pe, err := NewPolicyEngine(db, false)
	if err != nil {
		t.Fatalf("policy engine: %v", err)
	}
	engine.SetPolicyEngine(pe)

	caObj, err := engine.CreateRootCA("Policy Root", pkix.Name{CommonName: "Policy Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root ca: %v", err)
	}
	return engine, pe, caObj
}

func ecdsaCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("policy-leaf-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("leaf keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	if _, err := keys.GenerateKey("leaf", keystore.ECDSAP256); err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	signer, _ := keys.Signer("leaf")
	der, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, signer)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return csr
}

func rsaCSR(t *testing.T, bits int) *x509.CertificateRequest {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return csr
}

func issuePolicyTest(engine *Engine, caID string, csr *x509.CertificateRequest, validity time.Duration, isCA bool) error {
	_, err := engine.IssueCertificate(caID, IssuanceRequest{
		CSR: csr, Validity: validity,
		KeyUsage: x509.KeyUsageDigitalSignature,
		IsCA:     isCA,
	})
	return err
}

func TestPolicyRefusesViolationsWithCitedRule(t *testing.T) {
	engine, pe, caObj := newPolicyTestEngine(t)
	if _, err := pe.UpsertPolicy(IssuancePolicy{
		Name: "default", Enabled: true,
		Rules: PolicyRules{
			AllowedAlgorithms: []string{"ECDSA-P256", "RSA-4096"},
			MinRSABits:        3072,
			MaxValidityDays:   397,
		},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Compliant request issues.
	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 30*24*time.Hour, false); err != nil {
		t.Fatalf("compliant request refused: %v", err)
	}

	// Weak RSA: refused citing min_rsa_bits... via the allow-list first?
	// RSA-2048 maps into the allow-list check as RSA-2048 (not listed).
	err := issuePolicyTest(engine, caObj.ID, rsaCSR(t, 2048), 30*24*time.Hour, false)
	if err == nil {
		t.Fatal("weak RSA must be refused")
	}
	var pv *PolicyViolationError
	if !errors.As(err, &pv) {
		t.Fatalf("refusal must be a PolicyViolationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "allowed_algorithms") && !strings.Contains(err.Error(), "min_rsa_bits") {
		t.Fatalf("refusal must cite the rule, got: %v", err)
	}

	// Over-validity: refused citing max_validity_days.
	err = issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 3650*24*time.Hour, false)
	if err == nil || !strings.Contains(err.Error(), "max_validity_days") {
		t.Fatalf("over-validity must be refused citing the rule, got: %v", err)
	}

	// IsCA through the leaf path: refused citing allow_ca_certs.
	err = issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 30*24*time.Hour, true)
	if err == nil || !strings.Contains(err.Error(), "allow_ca_certs") {
		t.Fatalf("IsCA must be refused citing the rule, got: %v", err)
	}
}

func TestPolicyIsDataDrivenNotCompileTime(t *testing.T) {
	engine, pe, caObj := newPolicyTestEngine(t)

	// No policy rows: unrestricted (compatible default).
	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 3650*24*time.Hour, false); err != nil {
		t.Fatalf("no policies must mean no restriction: %v", err)
	}

	// A row UPDATE changes behaviour with no rebuild.
	pol, err := pe.UpsertPolicy(IssuancePolicy{
		Name: "tighten", Enabled: true,
		Rules: PolicyRules{MaxValidityDays: 90},
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 3650*24*time.Hour, false); err == nil {
		t.Fatal("same request must now be refused after the table changed")
	}

	// Disabling the policy (data change again) restores issuance.
	pol.Enabled = false
	if _, err := pe.UpsertPolicy(pol); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 3650*24*time.Hour, false); err != nil {
		t.Fatalf("disabled policy must not refuse: %v", err)
	}
}

func TestPolicyScopedToCA(t *testing.T) {
	engine, pe, caObj := newPolicyTestEngine(t)
	other, err := engine.CreateRootCA("Other Root", pkix.Name{CommonName: "Other Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("other ca: %v", err)
	}
	if _, err := pe.UpsertPolicy(IssuancePolicy{
		Name: "strict-for-one", Enabled: true, CAID: caObj.ID,
		Rules: PolicyRules{MaxValidityDays: 30},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 90*24*time.Hour, false); err == nil {
		t.Fatal("scoped policy must refuse on its CA")
	}
	if err := issuePolicyTest(engine, other.ID, ecdsaCSR(t), 90*24*time.Hour, false); err != nil {
		t.Fatalf("scoped policy must not apply to other CAs: %v", err)
	}
}

func TestPolicyGatesPQCAndHybridVariants(t *testing.T) {
	engine, pe, caObj := newPolicyTestEngine(t)
	if _, err := pe.UpsertPolicy(IssuancePolicy{
		Name: "classical-only", Enabled: true,
		Rules: PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256"}},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// A PQC request under a classical-only policy is refused by the
	// engine gate regardless of CSR mechanics — the algorithm comes from
	// the typed request, so no full ML-DSA CSR is needed to prove it.
	err := engine.checkIssuancePolicy(caObj.ID, IssuanceRequest{
		PQCCSR:   &PQCCertificateRequest{Algorithm: keystore.MLDSA65},
		Validity: 24 * time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_algorithms") {
		t.Fatalf("PQC request must be refused citing the rule, got: %v", err)
	}
	err = engine.checkIssuancePolicy(caObj.ID, IssuanceRequest{
		HybridCSR: &HybridCertificateRequest{Algorithm: keystore.HybridECDSAP256MLDSA65},
		Validity:  24 * time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_algorithms") {
		t.Fatalf("hybrid request must be refused citing the rule, got: %v", err)
	}
}

func TestPolicyFailsClosedWhenTableUnreadable(t *testing.T) {
	engine, pe, caObj := newPolicyTestEngine(t)
	// Simulate a broken policy store: drop the table out from under it.
	if _, err := pe.db.Exec(`ALTER TABLE issuance_policies RENAME TO issuance_policies_gone`); err != nil {
		t.Fatalf("rename: %v", err)
	}
	err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 24*time.Hour, false)
	if err == nil {
		t.Fatal("an unreadable policy table must refuse issuance, not allow it")
	}
	if !strings.Contains(err.Error(), "refusing issuance") {
		t.Fatalf("fail-closed refusal expected, got: %v", err)
	}
}
