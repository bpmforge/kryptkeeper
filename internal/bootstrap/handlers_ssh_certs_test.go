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

func newSSHCertTestMux(t *testing.T) *http.ServeMux {
	mux, _ := newSSHCertTestMuxWithTemplates(t)
	return mux
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
