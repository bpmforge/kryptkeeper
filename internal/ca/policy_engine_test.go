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

func TestEvaluateReturnsAllViolations(t *testing.T) {
	_, pe, caObj := newPolicyTestEngine(t)
	if _, err := pe.UpsertPolicy(IssuancePolicy{
		Name: "strict", Enabled: true,
		Rules: PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256"}, MinRSABits: 3072, MaxValidityDays: 30},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	v, err := pe.Evaluate(caObj.ID, PolicyInput{Algorithm: "RSA-2048", RSABits: 2048, Validity: 90 * 24 * time.Hour, IsCA: true})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if v.Allowed || len(v.Violations) != 4 {
		t.Fatalf("want 4 violations (all rules), got allowed=%v n=%d", v.Allowed, len(v.Violations))
	}
	if len(v.Evaluated) != 1 || v.Evaluated[0] != "strict" {
		t.Fatalf("evaluated = %v", v.Evaluated)
	}
	for _, viol := range v.Violations {
		if viol.PolicyID == "" || viol.Observed == "" {
			t.Fatalf("violation missing PolicyID/Observed: %+v", viol)
		}
	}
	ok, err := pe.Evaluate(caObj.ID, PolicyInput{Algorithm: "ECDSA-P256", Validity: 24 * time.Hour})
	if err != nil || !ok.Allowed {
		t.Fatalf("compliant input must be allowed: %+v %v", ok, err)
	}
}

func TestViolationIsErrPolicyViolation(t *testing.T) {
	var err error = &PolicyViolationError{Policy: "p", Rule: "r", Detail: "d"}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatal("PolicyViolationError must match ErrPolicyViolation")
	}
	if errors.Is(err, ErrInvalidCSR) {
		t.Fatal("must not match unrelated sentinels")
	}
}

func TestViolationHookFires(t *testing.T) {
	engine, pe, caObj := newPolicyTestEngine(t)
	if _, err := pe.UpsertPolicy(IssuancePolicy{Name: "p", Enabled: true, Rules: PolicyRules{MaxValidityDays: 1}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var calls int
	var gotCA, gotRule string
	pe.SetViolationHook(func(caID string, v *PolicyViolationError) { calls++; gotCA, gotRule = caID, v.Rule })
	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 48*time.Hour, false); err == nil {
		t.Fatal("must be refused")
	}
	if calls != 1 || gotCA != caObj.ID || gotRule != "max_validity_days" {
		t.Fatalf("hook calls=%d ca=%q rule=%q", calls, gotCA, gotRule)
	}
	if err := issuePolicyTest(engine, caObj.ID, ecdsaCSR(t), 12*time.Hour, false); err != nil {
		t.Fatalf("compliant: %v", err)
	}
	if calls != 1 {
		t.Fatalf("hook must not fire on success, calls=%d", calls)
	}
}

func TestGetPolicy(t *testing.T) {
	_, pe, _ := newPolicyTestEngine(t)
	pol, err := pe.UpsertPolicy(IssuancePolicy{Name: "g", Enabled: true, Rules: PolicyRules{MinRSABits: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := pe.GetPolicy(pol.ID)
	if err != nil || !ok || got.Name != "g" || got.Rules.MinRSABits != 4096 {
		t.Fatalf("get: %+v %v %v", got, ok, err)
	}
	if _, ok, err := pe.GetPolicy("nope"); ok || err != nil {
		t.Fatalf("missing: ok=%v err=%v", ok, err)
	}
}

// B2 (ADCS cutover rehearsal): the RSA floor migrated templates are raised to.
func TestRSAFloorIsStrictestEnabledPolicy(t *testing.T) {
	_, pe, _ := newPolicyTestEngine(t)
	if bits, name, err := pe.RSAFloor(); err != nil || bits != 0 || name != "" {
		t.Fatalf("no policies: %d %q %v", bits, name, err)
	}
	for _, pol := range []IssuancePolicy{
		{Name: "Baseline", Enabled: true, Rules: PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256", "RSA-3072", "RSA-4096"}, MinRSABits: 3072}},
		{Name: "AllowList", Enabled: true, Rules: PolicyRules{AllowedAlgorithms: []string{"RSA-2048", "RSA-4096"}}},
		{Name: "EcOnly", Enabled: true, Rules: PolicyRules{AllowedAlgorithms: []string{"ECDSA-P384"}}},
		{Name: "Disabled", Enabled: false, Rules: PolicyRules{MinRSABits: 8192}},
	} {
		if _, err := pe.UpsertPolicy(pol); err != nil {
			t.Fatal(err)
		}
	}
	bits, name, err := pe.RSAFloor()
	if err != nil || bits != 3072 || name != "Baseline" {
		t.Fatalf("floor: %d %q %v", bits, name, err)
	}
	if _, err := pe.UpsertPolicy(IssuancePolicy{Name: "Strict", Enabled: true, CAID: "ca-x", Rules: PolicyRules{AllowedAlgorithms: []string{"RSA-4096"}}}); err != nil {
		t.Fatal(err)
	}
	if bits, name, _ := pe.RSAFloor(); bits != 4096 || name != "Strict" {
		t.Fatalf("CA-scoped allow-list floor: %d %q", bits, name)
	}
}

func TestAcceptedRSABits(t *testing.T) {
	_, pe, caObj := newPolicyTestEngine(t)
	upsert := func(rules PolicyRules) {
		t.Helper()
		if _, err := pe.UpsertPolicy(IssuancePolicy{ID: "p1", Name: "Baseline", Enabled: true, Rules: rules}); err != nil {
			t.Fatal(err)
		}
	}
	probe := func(atLeast int, tmplAlgos []string) (int, bool, string) {
		t.Helper()
		bits, ok, reason, err := pe.AcceptedRSABits(caObj.ID, atLeast, tmplAlgos)
		if err != nil {
			t.Fatal(err)
		}
		return bits, ok, reason
	}

	if bits, ok, _ := probe(2048, nil); !ok || bits != 2048 {
		t.Fatalf("no policy: got %d %v, want 2048", bits, ok)
	}
	upsert(PolicyRules{MinRSABits: 3072})
	if bits, ok, _ := probe(2048, nil); !ok || bits != 3072 {
		t.Fatalf("min_rsa_bits 3072: got %d %v", bits, ok)
	}
	if bits, ok, _ := probe(4096, nil); !ok || bits != 4096 {
		t.Fatalf("template 4096: got %d %v", bits, ok)
	}
	// Templates usually list bare families (the lab's KKMachine is
	// ["RSA","ECDSA"]); a family entry admits every RSA size.
	if bits, ok, reason := probe(2048, []string{"RSA", "ECDSA"}); !ok || bits != 3072 {
		t.Fatalf("family allow-list under min_rsa_bits 3072: got %d %v %q", bits, ok, reason)
	}
	upsert(PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256", "RSA-4096"}})
	if bits, ok, _ := probe(2048, nil); !ok || bits != 4096 {
		t.Fatalf("allow-list RSA-4096 only: got %d %v", bits, ok)
	}
	if _, ok, reason := probe(2048, []string{"RSA-2048", "RSA-3072"}); ok || reason == "" {
		t.Fatalf("template and policy disjoint must refuse with a reason, got ok=%v reason=%q", ok, reason)
	}
	upsert(PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256"}})
	if _, ok, reason := probe(2048, nil); ok || !strings.Contains(reason, "allowed_algorithms") {
		t.Fatalf("ECDSA-only policy must refuse RSA citing the rule, got ok=%v reason=%q", ok, reason)
	}
}
