// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/sshkeys"
)

// W11-07: the SSH CA over HTTP against a REAL keystore — the CA key is
// generated on first use under the well-known id and reused; the issued
// cert verifies against the /ssh/ca authority line; the record lists by
// subject fingerprint (the sshkeys inventory link).

// sshTestTemplates is a file-backed template provider holding one template
// per interesting shape; ids are returned by name.
type sshTestTemplates struct {
	TemplateProvider
	ids map[string]string
}

func newSSHTestTemplates(t *testing.T) *sshTestTemplates {
	t.Helper()
	p := &fileTemplateProvider{filePath: filepath.Join(t.TempDir(), "templates.json")}
	if err := p.saveItems([]TemplateItem{}); err != nil {
		t.Fatalf("seed templates: %v", err)
	}
	st := &sshTestTemplates{TemplateProvider: p, ids: map[string]string{}}
	mk := func(name string, active bool, policy *sshkeys.Policy) {
		item, err := p.CreateTemplate(context.Background(), TemplateUpsertRequest{
			Name: name, DisplayName: name, KeyUsage: []string{"digitalSignature"}, ExtendedKeyUsage: []string{"clientAuth"},
			AllowedAlgorithms: []string{"ECDSA"}, ValidityPeriod: "P1D", Active: active, SSHPolicy: policy,
		})
		if err != nil {
			t.Fatalf("create template %s: %v", name, err)
		}
		st.ids[name] = item.ID
	}
	mk("ssh-user", true, &sshkeys.Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"deploy", "ops"}, MaxTTLHours: 8})
	mk("ssh-host", true, &sshkeys.Policy{CertTypes: []string{"host"}, HostPatterns: []string{"*.corp.example", "build01.corp.example"}, MaxTTLHours: 720})
	mk("no-policy", true, nil)
	mk("inactive", false, &sshkeys.Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"deploy"}, MaxTTLHours: 8})
	return st
}

func newSSHCertTestMuxWithTemplates(t *testing.T) (*http.ServeMux, *sshTestTemplates) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := NewAuthenticatorFromEnv()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ssh-ca-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	mux := http.NewServeMux()
	tpls := newSSHTestTemplates(t)
	RegisterSSHCertHandlers(mux, auth, keys, tpls, stubAuditProvider{})
	return mux, tpls
}

func sshDoJSON(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSSHCertIssueEndToEnd(t *testing.T) {
	mux, tpls := newSSHCertTestMuxWithTemplates(t)

	// The CA line the fleet trusts.
	caRec := sshDoJSON(t, mux, http.MethodGet, "/api/v1/ssh/ca", nil)
	if caRec.Code != http.StatusOK {
		t.Fatalf("ssh/ca: %d %s", caRec.Code, caRec.Body.String())
	}
	var caResp struct {
		AuthorityLine        string `json:"authority_line"`
		AuthorityFingerprint string `json:"authority_fingerprint"`
	}
	if err := json.Unmarshal(caRec.Body.Bytes(), &caResp); err != nil {
		t.Fatalf("decode ca: %v", err)
	}
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caResp.AuthorityLine))
	if err != nil {
		t.Fatalf("authority line unparseable: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)

	rec := sshDoJSON(t, mux, http.MethodPost, "/api/v1/ssh/certificates", map[string]any{
		"public_key":  string(ssh.MarshalAuthorizedKey(sshPub)),
		"cert_type":   "user",
		"key_id":      "alice@example.com",
		"principals":  []string{"deploy"},
		"ttl_hours":   4,
		"template_id": tpls.ids["ssh-user"],
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data SSHCertRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.TemplateID != tpls.ids["ssh-user"] {
		t.Fatalf("record template_id = %q, want %q", resp.Data.TemplateID, tpls.ids["ssh-user"])
	}
	if resp.Data.AuthorityFingerprint != caResp.AuthorityFingerprint {
		t.Fatalf("cert signed by %s, CA advertises %s", resp.Data.AuthorityFingerprint, caResp.AuthorityFingerprint)
	}

	// The issued cert VERIFIES against the advertised authority.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Data.CertificateLine))
	if err != nil {
		t.Fatalf("parse issued: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(caKey)
		},
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("issued cert does not verify against /ssh/ca: %v", err)
	}

	// The record lists by subject fingerprint — the inventory link.
	// The fingerprint is SHA256:<base64> — base64 '+' would decode as a
	// space in a query string, so it must be escaped (this test failed
	// exactly that way on an unlucky fingerprint before the escape).
	listRec := sshDoJSON(t, mux, http.MethodGet,
		"/api/v1/ssh/certificates?subject_fingerprint="+url.QueryEscape(resp.Data.SubjectFingerprint), nil)
	var listResp struct {
		Data []SSHCertRecord `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Data) != 1 || listResp.Data[0].Serial != resp.Data.Serial {
		t.Fatalf("subject-fingerprint listing wrong: %+v", listResp.Data)
	}
}

func sshIssueBody(t *testing.T, certType, keyID, templateID string, principals []string, ttl float64) map[string]any {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	body := map[string]any{
		"public_key": string(ssh.MarshalAuthorizedKey(sshPub)),
		"cert_type":  certType,
		"key_id":     keyID,
		"principals": principals,
	}
	if ttl != 0 {
		body["ttl_hours"] = ttl
	}
	if templateID != "" {
		body["template_id"] = templateID
	}
	return body
}

// A01S-4: the policy decides what may be signed. Root, wrong type, wrong
// host, over-TTL, no template and a template without a policy are all 400;
// the in-policy request is 201.
func TestSSHCertIssuanceConstrainedByTemplatePolicy(t *testing.T) {
	mux, tpls := newSSHCertTestMuxWithTemplates(t)
	user, host := tpls.ids["ssh-user"], tpls.ids["ssh-host"]
	cases := []struct {
		name       string
		body       map[string]any
		want       int
		wantInBody string
	}{
		{"user in policy", sshIssueBody(t, "user", "k1", user, []string{"deploy"}, 4), http.StatusCreated, ""},
		{"user two principals in policy", sshIssueBody(t, "user", "k2", user, []string{"deploy", "ops"}, 0), http.StatusCreated, ""},
		{"host exact", sshIssueBody(t, "host", "k3", host, []string{"build01.corp.example"}, 24), http.StatusCreated, ""},
		{"host wildcard one label", sshIssueBody(t, "host", "k4", host, []string{"web.corp.example"}, 0), http.StatusCreated, ""},
		{"root refused", sshIssueBody(t, "user", "k5", user, []string{"root"}, 1), http.StatusBadRequest, "not allowed"},
		{"admin refused", sshIssueBody(t, "user", "k6", user, []string{"root", "admin"}, 1), http.StatusBadRequest, "not allowed"},
		{"one bad principal poisons the request", sshIssueBody(t, "user", "k7", user, []string{"deploy", "root"}, 1), http.StatusBadRequest, "not allowed"},
		{"host cert from user-only template", sshIssueBody(t, "host", "k8", user, []string{"web.corp.example"}, 1), http.StatusBadRequest, "cert_type"},
		{"user cert from host-only template", sshIssueBody(t, "user", "k9", host, []string{"deploy"}, 1), http.StatusBadRequest, "cert_type"},
		{"host not matching pattern", sshIssueBody(t, "host", "k10", host, []string{"evil.example"}, 1), http.StatusBadRequest, "host pattern"},
		{"wildcard does not span two labels", sshIssueBody(t, "host", "k11", host, []string{"a.b.corp.example"}, 1), http.StatusBadRequest, "host pattern"},
		{"ttl over policy max is refused not clamped", sshIssueBody(t, "user", "k12", user, []string{"deploy"}, 9), http.StatusBadRequest, "maximum"},
		{"missing template_id", sshIssueBody(t, "user", "k13", "", []string{"deploy"}, 1), http.StatusBadRequest, "template_id is required"},
		{"unknown template", sshIssueBody(t, "user", "k14", "tpl-nope", []string{"deploy"}, 1), http.StatusBadRequest, "unknown template_id"},
		{"template without ssh_policy", sshIssueBody(t, "user", "k15", tpls.ids["no-policy"], []string{"deploy"}, 1), http.StatusBadRequest, "ssh_policy"},
		{"inactive template", sshIssueBody(t, "user", "k16", tpls.ids["inactive"], []string{"deploy"}, 1), http.StatusBadRequest, "ssh_policy"},
	}
	for _, c := range cases {
		rec := sshDoJSON(t, mux, http.MethodPost, "/api/v1/ssh/certificates", c.body)
		if rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, rec.Code, rec.Body.String(), c.want)
			continue
		}
		if c.wantInBody != "" && !strings.Contains(rec.Body.String(), c.wantInBody) {
			t.Errorf("%s: body %s lacks %q", c.name, rec.Body.String(), c.wantInBody)
		}
	}

	// A refused request signed nothing: only the four accepted ones are stored.
	listRec := sshDoJSON(t, mux, http.MethodGet, "/api/v1/ssh/certificates", nil)
	var listResp struct {
		Data []SSHCertRecord `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil || len(listResp.Data) != 4 {
		t.Fatalf("stored records: %v %d %s", err, len(listResp.Data), listRec.Body.String())
	}
	for _, r := range listResp.Data {
		if r.TemplateID == "" {
			t.Errorf("record %s lacks template_id", r.Serial)
		}
	}
}

func TestSSHCertTTLDefaultNeverExceedsPolicyMax(t *testing.T) {
	mux, tpls := newSSHCertTestMuxWithTemplates(t)
	rec := sshDoJSON(t, mux, http.MethodPost, "/api/v1/ssh/certificates",
		sshIssueBody(t, "user", "k", tpls.ids["ssh-user"], []string{"deploy"}, 0))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data SSHCertRecord `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Data.CertificateLine))
	if err != nil {
		t.Fatal(err)
	}
	cert := parsed.(*ssh.Certificate)
	// valid_after is backdated 1 minute and valid_before padded 1 minute.
	if span := int64(cert.ValidBefore) - int64(cert.ValidAfter); span > 8*3600+120 {
		t.Fatalf("validity %ds exceeds the 8h policy maximum", span)
	}
}

func TestSSHCertCeilingRefusedOverHTTP(t *testing.T) {
	mux, tpls := newSSHCertTestMuxWithTemplates(t)
	rec := sshDoJSON(t, mux, http.MethodPost, "/api/v1/ssh/certificates",
		sshIssueBody(t, "user", "bob", tpls.ids["ssh-user"], []string{"deploy"}, 48))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 ceiling refusal, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- W26-31: require_approval on SSH issuance --------------------------------

type sshApprovalFixture struct {
	mux                                   *http.ServeMux
	tpls                                  *fileTemplateProvider
	audit                                 *captureAudit
	approvals                             ApprovalStore
	tokAliceAcme, tokBobAcme, tokCarolGlx string
	approvalTplID, directTplID            string
}

func newSSHApprovalFixture(t *testing.T) *sshApprovalFixture {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	ctx := context.Background()
	ts := NewTenantStoreFromEnv()
	if ts == nil {
		t.Fatal("tenant store")
	}
	for _, n := range []string{"acme", "globex"} {
		if _, err := ts.CreateTenant(ctx, n, n); err != nil {
			t.Fatalf("tenant %s: %v", n, err)
		}
	}
	prev := activeTenantStore
	activeTenantStore = ts
	t.Cleanup(func() { activeTenantStore = prev })

	p := &fileTemplateProvider{filePath: filepath.Join(t.TempDir(), "templates.json")}
	if err := p.saveItems([]TemplateItem{}); err != nil {
		t.Fatalf("seed templates: %v", err)
	}
	mk := func(name string, approval bool, maxTTL float64) string {
		item, err := p.CreateTemplate(ctx, TemplateUpsertRequest{
			Name: name, DisplayName: name, KeyUsage: []string{"digitalSignature"}, ExtendedKeyUsage: []string{"clientAuth"},
			AllowedAlgorithms: []string{"ECDSA"}, ValidityPeriod: "P1D", Active: true, RequireApproval: approval,
			SSHPolicy: &sshkeys.Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"deploy", "ops"}, MaxTTLHours: maxTTL},
		})
		if err != nil {
			t.Fatalf("template %s: %v", name, err)
		}
		if err := ts.SetTemplateTenant(ctx, item.ID, "acme"); err != nil {
			t.Fatalf("map template: %v", err)
		}
		return item.ID
	}
	f := &sshApprovalFixture{tpls: p, audit: &captureAudit{}}
	f.approvalTplID = mk("ssh-approval", true, 8)
	f.directTplID = mk("ssh-direct", false, 8)

	auth := NewAuthenticatorFromEnv()
	key := func(principal, tenant string) string {
		_, tok, err := auth.CreateAPIKey(principal+"-key", principal, "pki-admin", []string{"*"}, "", tenant, time.Now())
		if err != nil {
			t.Fatalf("key %s: %v", principal, err)
		}
		return tok
	}
	f.tokAliceAcme, f.tokBobAcme, f.tokCarolGlx = key("alice", "acme"), key("bob", "acme"), key("carol", "globex")

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ssh-ca-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	f.approvals, err = newApprovalStoreFromEnv()
	if err != nil || f.approvals == nil {
		t.Fatalf("approval store: %v", err)
	}
	f.mux = http.NewServeMux()
	registerApprovalHandlers(f.mux, auth, f.approvals, nil, p, f.audit)
	RegisterSSHCertHandlers(f.mux, auth, keys, p, f.audit)
	return f
}

func (f *sshApprovalFixture) do(t *testing.T, method, path, token, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw := []byte(`{}`)
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant", tenant)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// request files an SSH issue request as alice and returns the approval id.
func (f *sshApprovalFixture) request(t *testing.T, tplID string, principals []string) (string, map[string]any) {
	t.Helper()
	body := sshIssueBody(t, "user", "alice-laptop", tplID, principals, 4)
	rec := f.do(t, http.MethodPost, "/api/v1/ssh/certificates", f.tokAliceAcme, "acme", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("request: expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Status != "pending_approval" || out.ApprovalID == "" {
		t.Fatalf("bad 202 body %s (%v)", rec.Body.String(), err)
	}
	return out.ApprovalID, body
}

func (f *sshApprovalFixture) sshRows(t *testing.T) []SSHCertRecord {
	t.Helper()
	rec := f.do(t, http.MethodGet, "/api/v1/ssh/certificates", f.tokAliceAcme, "acme", nil)
	var out struct {
		Data []SSHCertRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("list ssh certs: %v: %s", err, rec.Body.String())
	}
	return out.Data
}

func (f *sshApprovalFixture) auditHas(action string, outcome AuditOutcome) bool {
	for _, e := range f.audit.entries {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

func TestSSHApprovalRequiredPendingThenSecondPrincipalApproves(t *testing.T) {
	f := newSSHApprovalFixture(t)
	id, _ := f.request(t, f.approvalTplID, []string{"deploy"})
	if rows := f.sshRows(t); len(rows) != 0 {
		t.Fatalf("nothing may be signed while pending, got %d certs", len(rows))
	}
	if !f.auditHas("ssh_certificate.issue", AuditOutcomePendingApproval) {
		t.Fatal("202 must be audited as pending_approval")
	}

	list := f.do(t, http.MethodGet, "/api/v1/approvals?status=pending", f.tokAliceAcme, "acme", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"kind":"ssh"`) || !strings.Contains(list.Body.String(), id) {
		t.Fatalf("approvals list must show the ssh row: %d %s", list.Code, list.Body.String())
	}

	// Self-approval: refused, still pending.
	self := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokAliceAcme, "acme", nil)
	if self.Code != http.StatusForbidden || !strings.Contains(self.Body.String(), "own action") {
		t.Fatalf("self-approve: expected 403 refusal, got %d %s", self.Code, self.Body.String())
	}
	if rows := f.sshRows(t); len(rows) != 0 {
		t.Fatal("self-approval must not sign")
	}

	ok := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokBobAcme, "acme", nil)
	if ok.Code != http.StatusCreated {
		t.Fatalf("second principal approve: expected 201, got %d %s", ok.Code, ok.Body.String())
	}
	if !strings.HasPrefix(ok.Header().Get("Location"), "/api/v1/ssh/certificates?subject_fingerprint=") {
		t.Fatalf("Location = %q", ok.Header().Get("Location"))
	}
	var out struct {
		Data SSHCertRecord `json:"data"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out.Data.CertificateLine))
	if err != nil {
		t.Fatalf("certificate line does not parse: %v", err)
	}
	cert, isCert := pub.(*ssh.Certificate)
	if !isCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" || cert.CertType != ssh.UserCert {
		t.Fatalf("unexpected certificate %+v", pub)
	}
	if out.Data.Tenant != "acme" || out.Data.TemplateID != f.approvalTplID {
		t.Fatalf("record tenant/template = %q/%q", out.Data.Tenant, out.Data.TemplateID)
	}
	if rows := f.sshRows(t); len(rows) != 1 || rows[0].Serial != out.Data.Serial {
		t.Fatalf("expected the issued row to be stored, got %+v", rows)
	}
	if !f.auditHas("approval.approve", AuditOutcomeSuccess) || !f.auditHas("approval.approve", AuditOutcomeDenied) {
		t.Fatal("approve success and self-approval denial must both be audited")
	}

	again := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokBobAcme, "acme", nil)
	if again.Code != http.StatusConflict {
		t.Fatalf("approve again: expected 409, got %d", again.Code)
	}
	if rows := f.sshRows(t); len(rows) != 1 {
		t.Fatalf("a repeat approve must not sign again, got %d", len(rows))
	}
}

func TestSSHApprovalRejectIssuesNothing(t *testing.T) {
	f := newSSHApprovalFixture(t)
	id, _ := f.request(t, f.approvalTplID, []string{"ops"})
	rec := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/reject", f.tokBobAcme, "acme", map[string]string{"reason": "no"})
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	if rows := f.sshRows(t); len(rows) != 0 {
		t.Fatal("a rejected request must not sign")
	}
	if !f.auditHas("approval.reject", AuditOutcomeSuccess) {
		t.Fatal("reject must be audited")
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokBobAcme, "acme", nil); rec.Code != http.StatusConflict {
		t.Fatalf("approve after reject: expected 409, got %d", rec.Code)
	}
}

func TestSSHApprovalIsTenantIsolated(t *testing.T) {
	f := newSSHApprovalFixture(t)
	id, _ := f.request(t, f.approvalTplID, []string{"deploy"})

	list := f.do(t, http.MethodGet, "/api/v1/approvals", f.tokCarolGlx, "globex", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), id) {
		t.Fatalf("other tenant must not list the row: %d %s", list.Code, list.Body.String())
	}
	if rec := f.do(t, http.MethodGet, "/api/v1/approvals/"+id, f.tokCarolGlx, "globex", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("get across tenants: expected 403, got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokCarolGlx, "globex", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("approve across tenants: expected 403, got %d", rec.Code)
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/reject", f.tokCarolGlx, "globex", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reject across tenants: expected 403, got %d", rec.Code)
	}
	inbox := collectInboxForTest(t, f, f.tokCarolGlx)
	if inbox {
		t.Fatal("inbox leaked the ssh row across tenants")
	}
	if rows := f.sshRows(t); len(rows) != 0 {
		t.Fatal("cross-tenant attempts must not sign")
	}
	apr, err := f.approvals.Get(context.Background(), id)
	if err != nil || apr.Status != "pending" {
		t.Fatalf("row must still be pending: %+v %v", apr, err)
	}
	// The owning tenant's second principal still can.
	if rec := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokBobAcme, "acme", nil); rec.Code != http.StatusCreated {
		t.Fatalf("owner-tenant approve: %d %s", rec.Code, rec.Body.String())
	}
}

// collectInboxForTest reports whether the principal's inbox shows any item.
func collectInboxForTest(t *testing.T, f *sshApprovalFixture, token string) bool {
	t.Helper()
	items, err := collectInbox(context.Background(), AuthPrincipal{ID: "carol", Role: "pki-admin", Tenant: "globex", TenantScoped: true},
		f.approvals, nil, activeTenantStore, "", time.Now(), nil)
	if err != nil {
		t.Fatalf("collectInbox: %v", err)
	}
	return len(items) > 0
}

func TestSSHApprovalTemplateTTLCeilingCreatesNoApproval(t *testing.T) {
	f := newSSHApprovalFixture(t)
	body := sshIssueBody(t, "user", "alice-laptop", f.approvalTplID, []string{"deploy"}, 9) // template max is 8h
	rec := f.do(t, http.MethodPost, "/api/v1/ssh/certificates", f.tokAliceAcme, "acme", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
	_, total, err := f.approvals.List(context.Background(), "", 50, 0)
	if err != nil || total != 0 {
		t.Fatalf("a refused request must not create an approval: total=%d err=%v", total, err)
	}
	bad := sshIssueBody(t, "user", "alice-laptop", f.approvalTplID, []string{"deploy"}, 4)
	bad["public_key"] = "not a key"
	if rec := f.do(t, http.MethodPost, "/api/v1/ssh/certificates", f.tokAliceAcme, "acme", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad key: expected 400, got %d", rec.Code)
	}
	if _, total, _ := f.approvals.List(context.Background(), "", 50, 0); total != 0 {
		t.Fatal("a bad key must not create an approval")
	}
}

func TestSSHApprovalTemplateDisabledBeforeApprovalRefusesIssuance(t *testing.T) {
	f := newSSHApprovalFixture(t)
	id, _ := f.request(t, f.approvalTplID, []string{"deploy"})
	items, _ := f.tpls.loadItems()
	for i := range items {
		if items[i].ID == f.approvalTplID {
			items[i].Active = false
		}
	}
	if err := f.tpls.saveItems(items); err != nil {
		t.Fatalf("disable template: %v", err)
	}
	rec := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", f.tokBobAcme, "acme", nil)
	if rec.Code == http.StatusCreated {
		t.Fatalf("approval of a disabled template must not issue: %s", rec.Body.String())
	}
	if !f.auditHas("approval.approve", AuditOutcomeIssuanceFailed) {
		t.Fatal("the refused issuance must be audited")
	}
	if rows := f.sshRows(t); len(rows) != 0 {
		t.Fatal("no cert may exist")
	}
}

func TestSSHNoApprovalTemplateStillIssuesDirectly(t *testing.T) {
	f := newSSHApprovalFixture(t)
	body := sshIssueBody(t, "user", "alice-laptop", f.directTplID, []string{"deploy"}, 4)
	rec := f.do(t, http.MethodPost, "/api/v1/ssh/certificates", f.tokAliceAcme, "acme", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected direct 201, got %d %s", rec.Code, rec.Body.String())
	}
	if _, total, _ := f.approvals.List(context.Background(), "", 50, 0); total != 0 {
		t.Fatal("a direct issuance must not create an approval")
	}
}

func TestSSHApprovalColumnsAddedToPreexistingTable(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	s, err := newApprovalStoreFromEnv()
	if err != nil || s == nil {
		t.Fatalf("store: %v", err)
	}
	db := s.(*sqliteApprovalStore).db
	for _, stmt := range []string{
		"ALTER TABLE cert_approval_requests DROP COLUMN tenant",
		"ALTER TABLE cert_approval_requests DROP COLUMN request_json",
		"ALTER TABLE cert_approval_requests DROP COLUMN kind",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	for i := 0; i < 2; i++ { // second pass proves idempotence
		if err := s.EnsureSchema(context.Background()); err != nil {
			t.Fatalf("EnsureSchema pass %d: %v", i, err)
		}
	}
	if err := s.Create(context.Background(), ApprovalRequest{ID: "apr-x", TemplateID: "t", CAID: "c", Requester: "r", RequestedAt: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(context.Background(), "apr-x")
	if err != nil || got.Kind != "x509" {
		t.Fatalf("legacy row kind = %q err=%v", got.Kind, err)
	}
}
