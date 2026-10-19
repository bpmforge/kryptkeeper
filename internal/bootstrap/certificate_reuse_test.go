// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"

	_ "modernc.org/sqlite"
)

type reuseRig struct {
	p      *caCertificateProvider
	engine *ca.Engine
	caID   string
	tpls   *fakeTemplateProvider
}

func newReuseRig(t *testing.T) *reuseRig {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-reuse-passphrase-32-bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Reuse Root", pkix.Name{CommonName: "Reuse Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tpls := &fakeTemplateProvider{templates: map[string]TemplateItem{
		"tpl-a":       {ID: "tpl-a", Active: true},
		"tpl-b":       {ID: "tpl-b", Active: true},
		"tpl-approve": {ID: "tpl-approve", Active: true, RequireApproval: true},
	}}
	p := WithTemplateProvider(NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false), tpls).(*caCertificateProvider)
	return &reuseRig{p: p, engine: engine, caID: root.ID, tpls: tpls}
}

func reuseCSR(t *testing.T, key crypto.Signer, cn string, sans ...string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: sans}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (r *reuseRig) issue(t *testing.T, req CertificateIssueRequest) CertificateIssueResult {
	t.Helper()
	res, err := r.p.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return res
}

func TestIdempotentIssuance_SameKeyTemplateReturnsSameSerial(t *testing.T) {
	r := newReuseRig(t)
	csr := reuseCSR(t, newECKey(t), "a.example.com", "a.example.com")
	req := CertificateIssueRequest{CAID: r.caID, TemplateID: "tpl-a", CSRPEM: csr}
	first := r.issue(t, req)
	second := r.issue(t, req)
	if first.Reused || !second.Reused {
		t.Fatalf("reused flags: first=%v second=%v", first.Reused, second.Reused)
	}
	if first.SerialNumber != second.SerialNumber || first.FingerprintSHA256 != second.FingerprintSHA256 {
		t.Fatalf("serial changed: %s vs %s", first.SerialNumber, second.SerialNumber)
	}
}

func TestIdempotentIssuance_DifferentInputsIssueNew(t *testing.T) {
	r := newReuseRig(t)
	key := newECKey(t)
	base := CertificateIssueRequest{CAID: r.caID, TemplateID: "tpl-a", CSRPEM: reuseCSR(t, key, "a.example.com", "a.example.com")}
	first := r.issue(t, base)

	other, err := r.engine.CreateRootCA("Second Root", pkix.Name{CommonName: "Second Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]CertificateIssueRequest{
		"template": {CAID: r.caID, TemplateID: "tpl-b", CSRPEM: base.CSRPEM},
		"ca":       {CAID: other.ID, TemplateID: "tpl-a", CSRPEM: base.CSRPEM},
		"san":      {CAID: r.caID, TemplateID: "tpl-a", CSRPEM: reuseCSR(t, key, "a.example.com", "a.example.com", "b.example.com")},
		"cn":       {CAID: r.caID, TemplateID: "tpl-a", CSRPEM: reuseCSR(t, key, "z.example.com", "a.example.com")},
		"team":     {CAID: r.caID, TemplateID: "tpl-a", CSRPEM: base.CSRPEM, TeamID: "team-x"},
	}
	for name, req := range cases {
		got := r.issue(t, req)
		if got.Reused || got.SerialNumber == first.SerialNumber {
			t.Errorf("%s: reused=%v serial=%s (first %s), want a new serial", name, got.Reused, got.SerialNumber, first.SerialNumber)
		}
	}
}

func TestIdempotentIssuance_RevokedAndNearExpiryIssueNew(t *testing.T) {
	r := newReuseRig(t)
	req := CertificateIssueRequest{CAID: r.caID, TemplateID: "tpl-a", CSRPEM: reuseCSR(t, newECKey(t), "a.example.com", "a.example.com")}
	first := r.issue(t, req)

	// Near expiry: less than a third of the validity left.
	r.p.mu.Lock()
	sc := r.p.certs[first.FingerprintSHA256]
	cp := *sc.x509
	cp.NotBefore, cp.NotAfter = time.Now().Add(-89*24*time.Hour), time.Now().Add(time.Hour)
	sc.x509 = &cp
	r.p.mu.Unlock()
	second := r.issue(t, req)
	if second.Reused || second.SerialNumber == first.SerialNumber {
		t.Fatalf("near-expiry cert was reused")
	}

	if _, err := r.p.RevokeCertificate(context.Background(), second.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 0}); err != nil {
		t.Fatal(err)
	}
	third := r.issue(t, req)
	if third.Reused || third.SerialNumber == second.SerialNumber {
		t.Fatalf("revoked cert was reused")
	}
}

type reuseHTTP struct {
	*writeGateHarness
	rig   *reuseRig
	store *sqliteApprovalStore
	tok   string
	mux   *http.ServeMux
}

func newReuseHTTP(t *testing.T) *reuseHTTP {
	t.Helper()
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	rig := newReuseRig(t)
	store := newTestApprovalStore(t)
	registerCertificateHandlers(mux, h.auth, rig.p, h.audit, store)
	return &reuseHTTP{writeGateHarness: h, rig: rig, store: store, tok: h.key(t, "pki-admin"), mux: mux}
}

func (h *reuseHTTP) post(t *testing.T, tpl, csr string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"ca_id": h.rig.caID, "template_id": tpl, "csr_pem": csr})
	rec := h.do(h.tok, http.MethodPost, "/api/v1/certificates", b)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestIdempotentIssuanceHTTP_Second200SameSerialAudited(t *testing.T) {
	h := newReuseHTTP(t)
	csr := reuseCSR(t, newECKey(t), "a.example.com", "a.example.com")
	c1, b1 := h.post(t, "tpl-a", csr)
	c2, b2 := h.post(t, "tpl-a", csr)
	if c1 != http.StatusCreated || c2 != http.StatusOK {
		t.Fatalf("statuses %d, %d", c1, c2)
	}
	s1 := b1["data"].(map[string]any)["serial_number"]
	s2 := b2["data"].(map[string]any)["serial_number"]
	if s1 == nil || s1 != s2 {
		t.Fatalf("serials %v vs %v", s1, s2)
	}
	for _, e := range h.audit.entries {
		if e.Action == "certificate.issue" && e.Outcome == AuditOutcomeSuccess && strings.Contains(e.ChangeSummary, `"reused":true`) {
			if !strings.Contains(e.ChangeSummary, s1.(string)) {
				t.Errorf("audit detail %q lacks serial", e.ChangeSummary)
			}
			return
		}
	}
	t.Fatalf("no reused audit row: %+v", h.audit.entries)
}

func TestIdempotentIssuanceHTTP_ApprovalTemplate(t *testing.T) {
	h := newReuseHTTP(t)
	csr := reuseCSR(t, newECKey(t), "a.example.com", "a.example.com")
	c1, b1 := h.post(t, "tpl-approve", csr)
	c2, b2 := h.post(t, "tpl-approve", csr)
	if c1 != http.StatusAccepted || c2 != http.StatusAccepted || b1["approval_id"] != b2["approval_id"] {
		t.Fatalf("got %d %v / %d %v", c1, b1, c2, b2)
	}
	_, total, _ := h.store.List(context.Background(), "pending", 10, 0)
	if total != 1 {
		t.Fatalf("pending approvals = %d, want 1", total)
	}
	// A different key is a different request.
	_, b3 := h.post(t, "tpl-approve", reuseCSR(t, newECKey(t), "a.example.com", "a.example.com"))
	if b3["approval_id"] == b1["approval_id"] {
		t.Fatal("different key shared an approval")
	}

	// Once approved and issued, a repeat POST returns the issued cert.
	apr, _ := h.store.Get(context.Background(), b1["approval_id"].(string))
	issued, err := h.rig.p.IssueCertificate(context.WithValue(context.Background(), approvalBypassKey{}, true),
		CertificateIssueRequest{CSRPEM: apr.CSRPEM, CAID: apr.CAID, TemplateID: apr.TemplateID})
	if err != nil {
		t.Fatal(err)
	}
	c4, b4 := h.post(t, "tpl-approve", csr)
	if c4 != http.StatusOK || b4["data"].(map[string]any)["serial_number"] != issued.SerialNumber {
		t.Fatalf("repeat after issue: %d %v", c4, b4)
	}
}

// An approval-required request the engine policy refuses is a 422 and
// never queued.
func TestApprovalTemplatePolicyViolationRefusedNotQueued(t *testing.T) {
	h := newReuseHTTP(t)
	sqldb, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqldb.Close() })
	if err := db.RunMigrations(sqldb, "sqlite"); err != nil {
		t.Fatal(err)
	}
	pe, err := ca.NewPolicyEngine(sqldb, false)
	if err != nil {
		t.Fatal(err)
	}
	h.rig.engine.SetPolicyEngine(pe)
	if _, err := pe.UpsertPolicy(ca.IssuancePolicy{Name: "Baseline", Enabled: true, Rules: ca.PolicyRules{MinRSABits: 3072}}); err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	code, body := h.post(t, "tpl-approve", reuseCSR(t, rsaKey, "a.example.com", "a.example.com"))
	if code != http.StatusUnprocessableEntity || body["error"] != "policy_violation" {
		t.Fatalf("got %d %v", code, body)
	}
	if _, total, _ := h.store.List(context.Background(), "pending", 10, 0); total != 0 {
		t.Fatalf("approval queued despite policy violation: %d", total)
	}
}
