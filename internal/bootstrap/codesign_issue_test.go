// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// csCertProvider queues every request for approval until the approval
// bypass marker is present, exactly like the real provider's gate.
type csCertProvider struct {
	CertificateProvider
	tpl    TemplateItem
	issued int
	err    error
}

func (p *csCertProvider) IssueCertificate(ctx context.Context, _ CertificateIssueRequest) (CertificateIssueResult, error) {
	if p.err != nil {
		return CertificateIssueResult{}, p.err
	}
	if templateNeedsApproval(p.tpl) && ctx.Value(approvalBypassKey{}) == nil {
		return CertificateIssueResult{}, errApprovalRequired
	}
	p.issued++
	return CertificateIssueResult{CertificateItem: CertificateItem{FingerprintSHA256: "fp-cs", CommonName: "signer.example.com"}}, nil
}

type csFixture struct {
	h        *writeGateHarness
	mux      *http.ServeMux
	certs    *csCertProvider
	keys     keystore.Store
	hsm      keystore.Store
	approval ApprovalStore
}

func newCSFixture(t *testing.T, protected bool) *csFixture {
	t.Helper()
	h := newWriteGateHarness(t, nil)
	pass := []byte("passphrase-test-32chars-exactly!")
	sw, err := keystore.NewSoftwareStore(t.TempDir(), pass)
	if err != nil {
		t.Fatal(err)
	}
	f := &csFixture{h: h, hsm: sw}
	f.keys = sw
	if protected {
		// A software store under the "pkcs11" label stands in for the token;
		// the real non-extractable assertion is the pkcs11-tag test.
		f.keys, err = keystore.NewRouter("pkcs11", map[string]keystore.Store{"pkcs11": sw})
		if err != nil {
			t.Fatal(err)
		}
	}
	tpl := TemplateItem{ID: "tpl-cs", Active: true, RequireApproval: false, ExtendedKeyUsage: []string{"codeSigning"}}
	f.certs = &csCertProvider{tpl: tpl}
	tp := &fakeTemplateProvider{templates: map[string]TemplateItem{"tpl-cs": tpl, "tpl-web": {ID: "tpl-web", Active: true, ExtendedKeyUsage: []string{"serverAuth"}}}}
	f.approval = newTestApprovalStore(t)
	f.mux = http.NewServeMux()
	registerCodeSigningIssueHandler(f.mux, h.auth, f.certs, tp, f.approval, f.keys, h.audit)
	registerApprovalHandlers(f.mux, h.auth, f.approval, f.certs, tp, h.audit)
	return f
}

func (f *csFixture) token(t *testing.T, name, role string) string {
	t.Helper()
	_, tok, err := f.h.auth.CreateAPIKey("k-"+name, "p-"+name, role, nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *csFixture) do(tok, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *csFixture) hasAudit(action string, outcome AuditOutcome) bool {
	for _, e := range f.h.audit.entries {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

const csBody = `{"ca_id":"ca-1","template_id":"tpl-cs","common_name":"signer.example.com"}`

func TestCodeSigningTemplateAlwaysNeedsApproval(t *testing.T) {
	cs := TemplateItem{RequireApproval: false, ExtendedKeyUsage: []string{"Code Signing"}}
	if !templateNeedsApproval(cs) {
		t.Fatal("codeSigning template with require_approval=false must still need approval")
	}
	if templateNeedsApproval(TemplateItem{ExtendedKeyUsage: []string{"serverAuth"}}) {
		t.Fatal("serverAuth-only template must follow its own flag")
	}
	if !templateNeedsApproval(TemplateItem{RequireApproval: true, ExtendedKeyUsage: []string{"serverAuth"}}) {
		t.Fatal("explicit flag must still gate")
	}
}

func TestCodeSigningRequestYieldsZeroCertsUntilApproved(t *testing.T) {
	f := newCSFixture(t, true)
	requester := f.token(t, "req", "pki-admin")
	approver := f.token(t, "apr", "pki-admin")

	rec := f.do(requester, http.MethodPost, "/api/v1/codesign/requests", csBody)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
		KeyID      string `json:"key_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Status != "pending_approval" || resp.ApprovalID == "" || resp.KeyID == "" {
		t.Fatalf("body %s (%v)", rec.Body.String(), err)
	}
	if f.certs.issued != 0 {
		t.Fatalf("issued = %d before approval, want 0", f.certs.issued)
	}
	if apr, err := f.approval.Get(context.Background(), resp.ApprovalID); err != nil || apr.Status != "pending" || apr.CSRPEM == "" {
		t.Fatalf("approval row = %+v, %v", apr, err)
	}
	if !f.hasAudit("certificate.issue", AuditOutcomePendingApproval) || !f.hasAudit(auditCodesignKeyGen, AuditOutcomeSuccess) {
		t.Fatalf("missing audit rows: %+v", f.h.audit.entries)
	}

	path := "/api/v1/approvals/" + resp.ApprovalID + "/approve"
	if rec := f.do(requester, http.MethodPost, path, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: status %d, want 403", rec.Code)
	}
	if f.certs.issued != 0 {
		t.Fatal("self-approval issued a certificate")
	}
	if rec := f.do(approver, http.MethodPost, path, ""); rec.Code != http.StatusCreated {
		t.Fatalf("second user approve: status %d: %s", rec.Code, rec.Body.String())
	}
	if f.certs.issued != 1 {
		t.Fatalf("issued = %d after approval, want 1", f.certs.issued)
	}
}

func TestCodeSigningRequestRefusedWithoutProtectedStore(t *testing.T) {
	f := newCSFixture(t, false)
	rec := f.do(f.token(t, "req", "pki-admin"), http.MethodPost, "/api/v1/codesign/requests", csBody)
	if rec.Code != http.StatusUnprocessableEntity || !bytes.Contains(rec.Body.Bytes(), []byte("protected_store_required")) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !f.hasAudit(auditCodesignDeny, AuditOutcomeDenied) {
		t.Fatalf("no %s row: %+v", auditCodesignDeny, f.h.audit.entries)
	}
	if list, _ := f.keys.List(); len(list) != 0 {
		t.Fatalf("%d keys left behind", len(list))
	}
}

func TestCodeSigningDeniedRequestDeletesKey(t *testing.T) {
	f := newCSFixture(t, true)
	f.certs.err = ca.ErrPolicyViolation
	rec := f.do(f.token(t, "req", "pki-admin"), http.MethodPost, "/api/v1/codesign/requests", csBody)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !f.hasAudit(auditCodesignDeny, AuditOutcomeDenied) {
		t.Fatalf("no deny row: %+v", f.h.audit.entries)
	}
	if list, _ := f.keys.List(); len(list) != 0 {
		t.Fatalf("%d keys left behind after denial", len(list))
	}
}

func TestCodeSigningRequestRejectsNonCodeSigningTemplate(t *testing.T) {
	f := newCSFixture(t, true)
	body := `{"ca_id":"ca-1","template_id":"tpl-web","common_name":"x"}`
	rec := f.do(f.token(t, "req", "pki-admin"), http.MethodPost, "/api/v1/codesign/requests", body)
	if rec.Code != http.StatusUnprocessableEntity || !bytes.Contains(rec.Body.Bytes(), []byte("not_a_codesigning_template")) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if list, _ := f.keys.List(); len(list) != 0 {
		t.Fatal("key generated for a non code-signing template")
	}
}

func TestCodeSigningRejectionIsAudited(t *testing.T) {
	f := newCSFixture(t, true)
	rec := f.do(f.token(t, "req", "pki-admin"), http.MethodPost, "/api/v1/codesign/requests", csBody)
	var resp struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	rec = f.do(f.token(t, "apr", "pki-admin"), http.MethodPost, "/api/v1/approvals/"+resp.ApprovalID+"/reject", `{"reason":"no"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject status %d: %s", rec.Code, rec.Body.String())
	}
	if !f.hasAudit(auditCodesignDeny, AuditOutcomeDenied) {
		t.Fatalf("no %s row after approver reject: %+v", auditCodesignDeny, f.h.audit.entries)
	}
}

func TestPolicyCheckAuditsAndAlertsEveryViolator(t *testing.T) {
	var alerts []string
	old := codesignAlerter
	codesignAlerter = func(event, resourceID, _ string) { alerts = append(alerts, event+":"+resourceID) }
	t.Cleanup(func() { codesignAlerter = old })

	mk := func(fp string, bits int) CertificateItem {
		return CertificateItem{
			FingerprintSHA256: fp, CommonName: fp + ".example.com", PublicKeyAlgorithm: "RSA", KeySizeBits: bits,
			ExtendedKeyUsage: []string{"Code Signing"},
			ValidFrom:        time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
			ValidUntil:       time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		}
	}
	auth := newReportsTestAuth(t)
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	registerCodeSigningHandler(mux, auth, &reportCertProvider{items: []CertificateItem{mk("ok", 4096), mk("weak1", 2048), mk("weak2", 1024)}}, audit)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/inventory/code-signing/policy-check", []byte(`{"id":"p","min_rsa_key_size_bits":3072}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data CodeSigningPolicySummary }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Violating != 2 {
		t.Fatalf("violating = %d, want 2", resp.Data.Violating)
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts = %v, want exactly 2", alerts)
	}
	var ok bool
	for _, e := range audit.entries {
		if e.Action == auditCodesignPolicy && e.Outcome == AuditOutcomeSuccess {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("no codesign.policy.check row: %+v", audit.entries)
	}
}
