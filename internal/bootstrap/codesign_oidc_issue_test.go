// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

// codesignHub is a fake CI issuer plus a real CA engine, certificate provider,
// trust store and the routes W29-12 adds, behind the real write gate.
type codesignHub struct {
	*codesignIdP
	engine   *ca.Engine
	provider CertificateProvider
	caID     string
	mux      http.Handler
	audit    *recordingAuditProvider
	auth     *Authenticator
	rec      ca.IssuedCertificateRecorder
}

type failingRecorder struct{}

func (failingRecorder) RecordIssuedCertificate(context.Context, string, *x509.Certificate, []byte, string) error {
	return errors.New("db: disk full")
}

func newCodesignHub(t *testing.T, rec func(real ca.IssuedCertificateRecorder) ca.IssuedCertificateRecorder) *codesignHub {
	t.Helper()
	idp := newCodesignIdP(t)
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	h := &codesignHub{codesignIdP: idp, engine: engine, provider: provider, caID: getFirstCAID(t, engine), audit: &recordingAuditProvider{}}
	h.auth = newReportsTestAuth(t)
	real := provider.(ca.IssuedCertificateRecorder)
	h.rec = real
	if rec != nil {
		h.rec = rec(real)
	}
	h.store = &dbCodesignTrustStore{db: db, ph: sqlitePlaceholder}
	if err := h.store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.v = NewCodesignOIDCVerifier(h.store)
	h.v.transport = idp.srv.Client().Transport
	h.v.now = idp.v.now
	pending := newCodesignPending(t)
	mux := http.NewServeMux()
	issuer := NewCodesignIssuer(h.v, engine, h.rec)
	registerCodesignIssueHandler(mux, issuer, h.audit)
	registerCodesignTrustRuleHandlers(mux, h.auth, engine, h.store, pending, h.audit)
	registerCodeSigningHandler(mux, h.auth, provider, h.audit)
	registerCertificateHandlers(mux, h.auth, provider, h.audit, nil)
	h.mux = withWriteAuthorization(mux, h.auth, nil, h.audit)
	return h
}

func (h *codesignHub) addRule(provider, aud, repo, ref string) CodesignTrustRule {
	h.t.Helper()
	r, err := h.store.CreateRule(context.Background(), CodesignTrustRule{
		Provider: provider, Issuer: h.issuer, Audience: aud, RepoPattern: repo, RefPattern: ref,
		CAID: h.caID, CreatedBy: "alice", ApprovedBy: "bob",
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func csrFor(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func p256CSR(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return csrFor(t, k)
}

func (h *codesignHub) post(path, bearer string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

type issueResp struct {
	Data struct {
		CertificatePEM string `json:"certificate_pem"`
		ChainPEM       string `json:"chain_pem"`
		Serial         string `json:"serial_number"`
		Fingerprint    string `json:"fingerprint_sha256"`
		Repo           string `json:"repo"`
		Ref            string `json:"ref"`
	} `json:"data"`
}

func (h *codesignHub) issue(tok, csr string) (*httptest.ResponseRecorder, issueResp) {
	h.t.Helper()
	rec := h.post("/api/v1/codesign/issue", "", map[string]string{"oidc_token": tok, "csr_pem": csr})
	var out issueResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestIssue_GitHubToken_YieldsBoundShortCert(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/*")
	rec, out := h.issue(h.token(nil), p256CSR(t))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("response must be Cache-Control: no-store")
	}
	c := parseCertPEM(t, out.Data.CertificatePEM)
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Fatalf("EKU = %v, want only codeSigning", c.ExtKeyUsage)
	}
	if v := c.NotAfter.Sub(c.NotBefore); v > 15*time.Minute {
		t.Fatalf("validity %s exceeds 15m", v)
	}
	if len(c.URIs) != 1 || c.URIs[0].String() != "https://github.com/acme/app@refs/heads/main" {
		t.Fatalf("URI SANs = %v", c.URIs)
	}
	if c.Subject.CommonName != "acme/app" || len(c.Subject.Organization) != 1 || c.Subject.Organization[0] != "Kryptkeeper CI" {
		t.Fatalf("subject = %s", c.Subject)
	}
	if len(c.DNSNames) != 0 || len(c.EmailAddresses) != 0 {
		t.Fatalf("CSR names leaked into SANs: %v %v", c.DNSNames, c.EmailAddresses)
	}
	if strings.Count(out.Data.ChainPEM, "BEGIN CERTIFICATE") < 1 {
		t.Fatal("chain_pem is empty")
	}
}

func TestIssue_ClaimSets_Table(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	h.addRule("gitlab", "lab-hub-gl", "group/sub/*", "refs/heads/main")
	_, gh := h.issue(h.token(nil), p256CSR(t))
	if got := parseCertPEM(t, gh.Data.CertificatePEM).URIs[0].String(); got != "https://github.com/acme/app@refs/heads/main" {
		t.Fatalf("github SAN = %s", got)
	}
	glTok := h.token(func(m map[string]any) {
		delete(m, "repository")
		m["project_path"] = "group/sub/proj"
		m["aud"] = "lab-hub-gl"
	})
	rec, gl := h.issue(glTok, p256CSR(t))
	if rec.Code != http.StatusCreated {
		t.Fatalf("gitlab issue: %d %s", rec.Code, rec.Body.String())
	}
	c := parseCertPEM(t, gl.Data.CertificatePEM)
	if want := h.issuer + "/group/sub/proj@refs/heads/main"; c.URIs[0].String() != want {
		t.Fatalf("gitlab SAN = %s, want %s", c.URIs[0], want)
	}
	if c.Subject.CommonName != "group/sub/proj" {
		t.Fatalf("gitlab CN = %s", c.Subject.CommonName)
	}
}

func (h *codesignHub) certCount() int {
	h.t.Helper()
	res, err := h.provider.ListCertificates(context.Background(), CertificateListQuery{})
	if err != nil {
		h.t.Fatal(err)
	}
	return res.Total
}

func TestIssue_Refusals_NoCert(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	replayTok := h.token(nil)
	if rec, _ := h.issue(replayTok, p256CSR(t)); rec.Code != http.StatusCreated {
		t.Fatalf("first use: %d", rec.Code)
	}
	before := h.certCount()
	cases := map[string]struct {
		tok    string
		reason string
	}{
		"wrong repo":       {h.token(func(m map[string]any) { m["repository"] = "evil/app" }), ReasonNoMatchingRule},
		"wrong ref":        {h.token(func(m map[string]any) { m["ref"] = "refs/heads/dev" }), ReasonNoMatchingRule},
		"replayed jti":     {replayTok, ReasonReplay},
		"untrusted issuer": {signTestRS256JWT(t, h.priv, codesignTestKID, h.claims(func(m map[string]any) { m["iss"] = "https://evil.example" })), ReasonUntrustedIssuer},
	}
	for name, c := range cases {
		auditBefore := len(h.audit.entries)
		rec, _ := h.issue(c.tok, p256CSR(t))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, rec.Code)
			continue
		}
		body := rec.Body.String()
		if strings.Contains(body, c.reason) || strings.Contains(body, "acme") || strings.Contains(body, "evil") {
			t.Errorf("%s: 401 body leaks the reason: %s", name, body)
		}
		var found bool
		for _, e := range h.audit.entries[auditBefore:] {
			if e.Action == "codesign.issue" && e.Outcome == AuditOutcomeDenied &&
				strings.Contains(e.ChangeSummary, "reason="+c.reason) && strings.Contains(e.ChangeSummary, "issuer=") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no denied codesign.issue audit with issuer+reason %s: %+v", name, c.reason, h.audit.entries[auditBefore:])
		}
	}
	if after := h.certCount(); after != before {
		t.Fatalf("refusals issued certificates: %d -> %d", before, after)
	}
}

func TestIssue_AuditHasRepoRefSerial(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	rec, out := h.issue(h.token(nil), p256CSR(t))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d", rec.Code)
	}
	var e *AuditEntry
	for i := range h.audit.entries {
		if h.audit.entries[i].Action == "codesign.issue" && h.audit.entries[i].Outcome == AuditOutcomeSuccess {
			e = &h.audit.entries[i]
		}
	}
	if e == nil {
		t.Fatal("no success audit row")
	}
	for _, want := range []string{`repo="acme/app"`, `ref="refs/heads/main"`, "serial=" + out.Data.Serial} {
		if !strings.Contains(e.ChangeSummary, want) {
			t.Errorf("audit detail lacks %s: %s", want, e.ChangeSummary)
		}
	}
	if e.ResourceID != out.Data.Fingerprint {
		t.Errorf("resource id %s != fingerprint %s", e.ResourceID, out.Data.Fingerprint)
	}
}

func TestIssue_RevokeViaExistingPath(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, out := h.issue(h.token(nil), p256CSR(t))
	rec := h.post("/api/v1/certificates/"+out.Data.Fingerprint+"/revoke", "reports-test-token", map[string]any{"reason_code": 1})
	if rec.Code >= 300 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	item, found, err := h.provider.GetCertificate(context.Background(), out.Data.Fingerprint)
	if err != nil || !found {
		t.Fatalf("get: %v %v", found, err)
	}
	if item.RevokedAt == nil {
		t.Fatal("inventory shows no revoked_at after revoke")
	}
}

func TestIssue_PolicyCheckStillEnforces(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	if rec, _ := h.issue(h.token(nil), p256CSR(t)); rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d", rec.Code)
	}
	violating := func(policy map[string]any) int {
		rec := h.post("/api/v1/inventory/code-signing/policy-check", "reports-test-token", policy)
		if rec.Code != http.StatusOK {
			t.Fatalf("policy-check: %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Data struct {
				Evaluated int `json:"evaluated"`
				Violating int `json:"violating"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Data.Evaluated != 1 {
			t.Fatalf("evaluated = %d, want the one issued cert", out.Data.Evaluated)
		}
		return out.Data.Violating
	}
	if n := violating(map[string]any{"allowed_algorithms": []string{"ECDSA"}, "max_validity_days": 1}); n != 0 {
		t.Errorf("compliant policy flagged %d", n)
	}
	if n := violating(map[string]any{"min_ec_key_size_bits": 521}); n != 1 {
		t.Errorf("P-256 cert must violate min EC 521, violating=%d", n)
	}
	if n := violating(map[string]any{"allowed_algorithms": []string{"RSA"}}); n != 1 {
		t.Errorf("ECDSA cert must violate an RSA-only allowlist, violating=%d", n)
	}
}

func TestIssue_RejectsWeakKeys(t *testing.T) {
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	for name, csr := range map[string]string{"ed25519": csrFor(t, edPriv), "rsa2048": csrFor(t, rsa2048), "p224": csrFor(t, p224), "garbage": "nope"} {
		before := h.certCount()
		tok := h.token(nil)
		rec, _ := h.issue(tok, csr)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
		if h.certCount() != before {
			t.Errorf("%s: a certificate was issued", name)
		}
		// A bad CSR must not burn the single-use token.
		if rec, _ := h.issue(tok, p256CSR(t)); rec.Code != http.StatusCreated {
			t.Errorf("%s: token burned by a rejected CSR (%d)", name, rec.Code)
		}
	}
}

func TestIssue_TTLClamp(t *testing.T) {
	cases := map[string]time.Duration{"": 14 * time.Minute, "1h": 14 * time.Minute, "1s": 30 * time.Second, "2m": 2 * time.Minute, "bogus": 14 * time.Minute}
	for env, want := range cases {
		t.Setenv(codesignTTLEnv, env)
		if got := codesignTTL(); got != want {
			t.Errorf("%q: ttl = %s, want %s", env, got, want)
		}
	}
	t.Setenv(codesignTTLEnv, "45s")
	h := newCodesignHub(t, nil)
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	_, out := h.issue(h.token(nil), p256CSR(t))
	c := parseCertPEM(t, out.Data.CertificatePEM)
	// Backdate is clamped to the (brand-new) CA's NotBefore, so the window is
	// the TTL plus at most the backdate -- never more.
	if v := c.NotAfter.Sub(c.NotBefore); v < 45*time.Second || v > 45*time.Second+codesignBackdate {
		t.Fatalf("validity = %s", v)
	}
}

func TestIssue_RecordFailureReturns503(t *testing.T) {
	h := newCodesignHub(t, func(ca.IssuedCertificateRecorder) ca.IssuedCertificateRecorder { return failingRecorder{} })
	h.addRule("github", "lab-hub", "acme/app", "refs/heads/main")
	rec, out := h.issue(h.token(nil), p256CSR(t))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if out.Data.CertificatePEM != "" || strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("an unrecorded certificate was handed out")
	}
	var audited bool
	for _, e := range h.audit.entries {
		if e.Action == "codesign.issue" && e.Outcome == AuditOutcomeFailure {
			audited = true
		}
	}
	if !audited {
		t.Fatal("record failure not audited")
	}
}

func TestIssue_UnavailableAndMethod(t *testing.T) {
	aud := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerCodesignIssueHandler(mux, nil, aud)
	for _, tc := range []struct {
		method string
		want   int
	}{{http.MethodPost, 503}, {http.MethodGet, 405}} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, "/api/v1/codesign/issue", strings.NewReader("{}")))
		if rec.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.method, rec.Code, tc.want)
		}
	}
	if len(aud.entries) != 2 {
		t.Fatalf("each outcome must be audited, got %d rows", len(aud.entries))
	}
}

func TestTrustRuleRoutes_ProposeIsPendingOnly(t *testing.T) {
	h := newCodesignHub(t, nil)
	rule := map[string]any{
		"provider": "github", "issuer": "https://token.actions.githubusercontent.com", "audience": "lab-hub",
		"repo_pattern": "acme/app", "ref_pattern": "refs/heads/main", "ca_id": h.caID, "rationale": "release signing",
	}
	rec := h.post("/api/v1/codesign/oidc-trust-rules", "reports-test-token", rule)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"pending"`) || !strings.Contains(rec.Body.String(), `"action_id"`) {
		t.Fatalf("body: %s", rec.Body.String())
	}
	if rules, _ := h.store.ListRules(context.Background()); len(rules) != 0 {
		t.Fatalf("rule exists before approval: %v", rules)
	}
	// Broad patterns and unknown CAs are refused and audited.
	bad := map[string]any{"provider": "github", "issuer": "https://x.example", "audience": "a", "repo_pattern": "*", "ref_pattern": "refs/heads/main", "ca_id": h.caID}
	if rec := h.post("/api/v1/codesign/oidc-trust-rules", "reports-test-token", bad); rec.Code != http.StatusBadRequest {
		t.Errorf("broad pattern: %d", rec.Code)
	}
	rule["ca_id"] = "no-such-ca"
	if rec := h.post("/api/v1/codesign/oidc-trust-rules", "reports-test-token", rule); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown ca: %d", rec.Code)
	}
	var proposes, failures int
	for _, e := range h.audit.entries {
		if e.Action == "codesign.trust_rule_propose" {
			proposes++
			if e.Outcome == AuditOutcomeFailure {
				failures++
			}
		}
	}
	if proposes != 3 || failures != 2 {
		t.Errorf("audit rows: %d proposes, %d failures (want 3, 2)", proposes, failures)
	}
}

func TestTrustRuleRoutes_ListAndDeleteAreTenantScoped(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	h := newCodesignHub(t, nil)
	ctx := context.Background()
	mine, _ := h.store.CreateRule(ctx, CodesignTrustRule{Provider: "github", Issuer: h.issuer, Audience: "a", RepoPattern: "acme/app",
		RefPattern: "refs/heads/main", CAID: h.caID, Tenant: "acme", CreatedBy: "a", ApprovedBy: "b"})
	other, _ := h.store.CreateRule(ctx, CodesignTrustRule{Provider: "github", Issuer: h.issuer, Audience: "a", RepoPattern: "globex/app",
		RefPattern: "refs/heads/main", CAID: h.caID, Tenant: "globex", CreatedBy: "a", ApprovedBy: "b"})

	// A tenant-scoped admin principal for acme.
	_, tok, err := h.auth.CreateAPIKey("acme-admin", "acme-admin", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		return rec
	}
	rec := get(http.MethodGet, "/api/v1/codesign/oidc-trust-rules")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), mine.ID) || strings.Contains(rec.Body.String(), other.ID) {
		t.Fatalf("list not tenant-filtered: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(http.MethodDelete, "/api/v1/codesign/oidc-trust-rules/"+other.ID); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: %d", rec.Code)
	}
	if _, found, _ := h.store.GetRule(ctx, other.ID); !found {
		t.Fatal("cross-tenant rule was deleted")
	}
	if rec := get(http.MethodDelete, "/api/v1/codesign/oidc-trust-rules/"+mine.ID); rec.Code != http.StatusNoContent {
		t.Fatalf("own-tenant delete: %d", rec.Code)
	}
	var deleted, notFound bool
	for _, e := range h.audit.entries {
		if e.Action == "codesign.trust_rule_delete" && e.Outcome == AuditOutcomeSuccess && e.ResourceID == mine.ID {
			deleted = true
		}
		if e.Action == "codesign.trust_rule_delete" && e.Outcome == AuditOutcomeFailure && e.ResourceID == other.ID {
			notFound = true
		}
	}
	if !deleted || !notFound {
		t.Fatalf("delete outcomes not audited: success=%v notfound=%v", deleted, notFound)
	}
}
