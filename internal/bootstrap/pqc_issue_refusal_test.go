// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// pqcRecAudit records appended audit entries (W31-06 asserts the refusal rows).
type pqcRecAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *pqcRecAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (a *pqcRecAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *pqcRecAudit) snapshot() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEntry(nil), a.entries...)
}

// hsmRefusingProvider simulates an engine path that hits the HSM PQC refusal.
type hsmRefusingProvider struct{ CertificateProvider }

func (hsmRefusingProvider) IssueCertificate(context.Context, CertificateIssueRequest) (CertificateIssueResult, error) {
	return CertificateIssueResult{}, fmt.Errorf("issue: %w", keystore.ErrPQCHSMUnsupported)
}

func issueRefusalPost(t *testing.T, provider CertificateProvider, audit *pqcRecAudit, req CertificateIssueRequest) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	token := waveExecuteToken(t, auth, "issuer", "pki-admin")
	mux := http.NewServeMux()
	registerCertificateHandlers(mux, auth, provider, audit, nil)
	b, _ := json.Marshal(map[string]string{"ca_id": req.CAID, "template_id": req.TemplateID, "csr_pem": req.CSRPEM, "team_id": req.TeamID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(b))
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func requireRefusalRow(t *testing.T, audit *pqcRecAudit, wantSummary string) {
	t.Helper()
	entries := audit.snapshot()
	if len(entries) != 1 {
		t.Fatalf("want exactly 1 audit row, got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Action != "certificate.issue_refused" || e.Outcome != AuditOutcomeDenied || e.ChangeSummary != wantSummary {
		t.Fatalf("audit row = %s/%s/%q, want certificate.issue_refused/denied/%q", e.Action, e.Outcome, e.ChangeSummary, wantSummary)
	}
}

func hybridCSRPEM(t *testing.T, keys keystore.Store, id string) string {
	t.Helper()
	if _, err := keys.GenerateKey(id, keystore.HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("generate hybrid key: %v", err)
	}
	loader, ok := keys.(keystore.HybridKeyLoader)
	if !ok {
		t.Fatal("keystore does not implement HybridKeyLoader")
	}
	pair, err := loader.LoadHybridKeyPair(id)
	if err != nil {
		t.Fatalf("load hybrid pair: %v", err)
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: id + ".example.com"}, nil, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: der}))
}

func TestIssueRefusal_AllowListOutsideTemplate(t *testing.T) {
	base, engine, keys := newTestMLDSACAProvider(t)
	templates := &fakeTemplateProvider{templates: map[string]TemplateItem{
		"tpl-ecdsa-only": {ID: "tpl-ecdsa-only", Active: true, ValidityPeriod: "2160h", AllowedAlgorithms: []string{"ECDSA"}},
	}}
	provider := WithTemplateProvider(base, templates)
	csr, _ := generateTestMLDSACSRPEM(t, keys, "allowlist.example.com", "allowlist.example.com")
	audit := &pqcRecAudit{}

	rec := issueRefusalPost(t, provider, audit, CertificateIssueRequest{CAID: getFirstCAID(t, engine), TemplateID: "tpl-ecdsa-only", CSRPEM: csr, TeamID: "team-1"})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "policy_violation") {
		t.Fatalf("status/body = %d %s, want 422 policy_violation", rec.Code, rec.Body.String())
	}
	requireRefusalRow(t, audit, "reason=allow_list algorithm="+string(keystore.MLDSA65))
}

// skipOrFailUnlessFIPS skips when the required GODEBUG fips140 mode is not
// active, except in CI (KRYPTKEEPER_REQUIRE_FIPS_TEST=1) where a misconfigured
// step must fail instead of silently skipping.
func skipOrFailUnlessFIPS(t *testing.T, active bool, mode string) {
	t.Helper()
	if active {
		return
	}
	if os.Getenv("KRYPTKEEPER_REQUIRE_FIPS_TEST") == "1" {
		t.Fatalf("KRYPTKEEPER_REQUIRE_FIPS_TEST=1 but GODEBUG=fips140=%s is not active", mode)
	}
	t.Skip("run with GODEBUG=fips140=" + mode)
}

func TestIssueRefusal_FIPSHybrid(t *testing.T) {
	skipOrFailUnlessFIPS(t, fips140.Enabled(), "on")
	provider, engine, keys := newTestMLDSACAProvider(t)
	csr := hybridCSRPEM(t, keys, "fips-hybrid")
	audit := &pqcRecAudit{}

	rec := issueRefusalPost(t, provider, audit, CertificateIssueRequest{CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: csr, TeamID: "team-1"})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "FIPS 140-3") {
		t.Fatalf("status/body = %d %s, want 422 citing FIPS 140-3", rec.Code, rec.Body.String())
	}
	requireRefusalRow(t, audit, "reason=fips algorithm="+string(keystore.HybridECDSAP256MLDSA65))
}

func TestIssueRefusal_FIPSOnlyMLDSA(t *testing.T) {
	skipOrFailUnlessFIPS(t, fips140.Enforced(), "only")
	// The software keystore cannot persist keys under fips140=only (its GCM
	// use is non-approved), so the key is generated in memory and the
	// provider is a nil stub: the refusal must fire before it is called.
	_, sk, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ML-DSA key: %v", err)
	}
	der, err := ca.CreateCertificateRequestMLDSA(pkix.Name{CommonName: "fips-only.example.com"}, []string{"fips-only.example.com"}, nil, sk, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "ML-DSA CERTIFICATE REQUEST", Bytes: der}))
	var provider CertificateProvider = hsmRefusingProvider{}
	audit := &pqcRecAudit{}

	rec := issueRefusalPost(t, provider, audit, CertificateIssueRequest{CAID: "ca-x", TemplateID: "tpl-tls", CSRPEM: csr, TeamID: "team-1"})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "FIPS 140-3") {
		t.Fatalf("status/body = %d %s, want 422 citing FIPS 140-3", rec.Code, rec.Body.String())
	}
	requireRefusalRow(t, audit, "reason=fips algorithm="+string(keystore.MLDSA65))
}

func TestIssueRefusal_NotInFIPSModeStillIssues(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("regression guard for non-FIPS mode")
	}
	provider, engine, keys := newTestMLDSACAProvider(t)
	csr, _ := generateTestMLDSACSRPEM(t, keys, "plain.example.com", "plain.example.com")
	audit := &pqcRecAudit{}

	rec := issueRefusalPost(t, provider, audit, CertificateIssueRequest{CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: csr, TeamID: "team-1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	for _, e := range audit.snapshot() {
		if e.Action == "certificate.issue_refused" {
			t.Fatalf("unexpected refusal row: %+v", e)
		}
	}
}

func TestIssueRefusal_HSMPQCCitesADR(t *testing.T) {
	base, engine, keys := newTestMLDSACAProvider(t)
	csr, _ := generateTestMLDSACSRPEM(t, keys, "hsm.example.com", "hsm.example.com")
	audit := &pqcRecAudit{}

	rec := issueRefusalPost(t, hsmRefusingProvider{base}, audit, CertificateIssueRequest{CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: csr, TeamID: "team-1"})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "ADR_PQC_KEYS_SOFTWARE_ONLY.md") {
		t.Fatalf("status/body = %d %s, want 422 citing the ADR", rec.Code, rec.Body.String())
	}
	requireRefusalRow(t, audit, "reason=hsm_pqc algorithm="+string(keystore.MLDSA65))
}
