// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
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

type policyRig struct {
	mux    *http.ServeMux
	engine *ca.Engine
	pe     *ca.PolicyEngine
	caID   string
	audit  *recordingAuditProvider
	acme   string // tenant-scoped pki-admin token (multi-tenancy only)
	auth   *Authenticator
	cfg    *ServerConfig
}

// newPolicyRig migrates a real sqlite DB (so the baseline policy row exists,
// as on a fresh install), wires a real CA engine and mounts the admin API.
func newPolicyRig(t *testing.T, multiTenant bool) *policyRig {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	if multiTenant {
		t.Setenv("MULTI_TENANCY", "on")
	}
	sqldb, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqldb.Close() })
	if err := db.RunMigrations(sqldb, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("policy-handler-test-passphrase-32"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })
	engine := ca.NewEngine(keys, ca.NewMemStore())
	pe, err := ca.NewPolicyEngine(sqldb, false)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetPolicyEngine(pe)
	root, err := engine.CreateRootCA("Policy Root", pkix.Name{CommonName: "Policy Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	auth := NewAuthenticatorFromEnv()
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	opt := WithPolicyAdmin(auth, engine.PolicyEngine(), audit)
	if opt == nil {
		t.Fatal("WithPolicyAdmin returned nil for a live engine")
	}
	cfg := &ServerConfig{Mux: mux}
	opt(cfg)
	rig := &policyRig{mux: mux, engine: engine, pe: pe, caID: root.ID, audit: audit, auth: auth, cfg: cfg}
	if multiTenant {
		_, rig.acme, err = auth.CreateAPIKey("acme-svc", "svc-acme", "pki-admin", []string{"*"}, "", "acme", time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	return rig
}

func (g *policyRig) issueECDSA(t *testing.T, validity time.Duration) error {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.engine.IssueCertificate(g.caID, ca.IssuanceRequest{CSR: csr, Validity: validity, KeyUsage: x509.KeyUsageDigitalSignature})
	return err
}

func (g *policyRig) actions() []string {
	g.audit.mu.Lock()
	defer g.audit.mu.Unlock()
	var out []string
	for _, e := range g.audit.entries {
		out = append(out, e.Action+":"+string(e.Outcome))
	}
	return out
}

func policyData(t *testing.T, body string, into any) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if err := json.Unmarshal(env.Data, into); err != nil {
		t.Fatalf("decode data %q: %v", body, err)
	}
}

func TestPolicyCRUDRoundTripAndAudit(t *testing.T) {
	g := newPolicyRig(t, false)

	rec := doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies", "root-token", "", "")
	var list []ca.IssuancePolicy
	policyData(t, rec.Body.String(), &list)
	if len(list) != 1 || list[0].ID != "pol-baseline" {
		t.Fatalf("fresh install must list the baseline policy, got %+v", list)
	}

	rec = doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies", "root-token", "", `{"name":"p384-only","enabled":true,"rules":{"allowed_algorithms":["ECDSA-P384"],"max_validity_days":90}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created ca.IssuancePolicy
	policyData(t, rec.Body.String(), &created)
	if created.ID == "" || created.Name != "p384-only" || created.Rules.MaxValidityDays != 90 {
		t.Fatalf("created = %+v", created)
	}

	rec = doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/"+created.ID, "root-token", "", `{"rules":{"max_validity_days":30}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	var patched ca.IssuancePolicy
	policyData(t, rec.Body.String(), &patched)
	if patched.Rules.MaxValidityDays != 30 || len(patched.Rules.AllowedAlgorithms) != 1 || patched.Name != "p384-only" {
		t.Fatalf("PATCH must be partial; got %+v", patched)
	}

	rec = doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies/"+created.ID, "root-token", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "p384-only") {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec = doLeakJSON(g.mux, http.MethodDelete, "/api/v1/policies/"+created.ID, "root-token", "", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec = doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies/"+created.ID, "root-token", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", rec.Code)
	}
	if rec = doLeakJSON(g.mux, http.MethodDelete, "/api/v1/policies/nope", "root-token", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: %d", rec.Code)
	}

	got := strings.Join(g.actions(), " ")
	for _, want := range []string{"policy.create:success", "policy.update:success", "policy.delete:success"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit missing %s in %s", want, got)
		}
	}
	// The update row must carry the resulting rules so a tightening is reconstructible.
	for _, e := range g.audit.entries {
		if e.Action == "policy.update" && !strings.Contains(e.ChangeSummary, `"max_validity_days":30`) {
			t.Errorf("update change summary = %q", e.ChangeSummary)
		}
		if e.ResourceType != "policy" || e.ResourceID == "" {
			t.Errorf("bad audit resource: %+v", e)
		}
	}
}

func TestPolicyTightenedRuleBlocksNextIssueImmediately(t *testing.T) {
	g := newPolicyRig(t, false)
	if err := g.issueECDSA(t, 30*24*time.Hour); err != nil {
		t.Fatalf("baseline must allow a 30d ECDSA leaf: %v", err)
	}
	start := time.Now()
	if rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", "root-token", "", `{"rules":{"max_validity_days":10}}`); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	err := g.issueECDSA(t, 30*24*time.Hour)
	if time.Since(start) > time.Second {
		t.Fatalf("tightened rule took %s to apply", time.Since(start))
	}
	var pv *ca.PolicyViolationError
	if err == nil || !errors.As(err, &pv) || pv.Rule != "max_validity_days" || pv.PolicyID != "pol-baseline" {
		t.Fatalf("want max_validity_days refusal from pol-baseline, got %v", err)
	}
	if got := strings.Join(g.actions(), " "); !strings.Contains(got, "policy.violation:denied") {
		t.Fatalf("refusal must leave a policy.violation audit row: %s", got)
	}
	for _, e := range g.audit.entries {
		if e.Action == "policy.violation" && !strings.Contains(e.ChangeSummary, "max_validity_days") {
			t.Fatalf("violation summary must cite the rule: %q", e.ChangeSummary)
		}
	}
}

func TestPolicyDryRunReportsRuleWithoutIssuing(t *testing.T) {
	g := newPolicyRig(t, false)
	rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies/dry-run", "root-token", "", `{"algorithm":"RSA-2048","rsa_bits":2048,"validity_days":400,"is_ca":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Allowed    bool     `json:"allowed"`
		Evaluated  []string `json:"evaluated_policies"`
		Violations []struct {
			PolicyID, Policy, Rule, Detail, Observed string
		} `json:"violations"`
	}
	policyData(t, rec.Body.String(), &out)
	rules := map[string]bool{}
	for _, v := range out.Violations {
		rules[v.Rule] = true
		if v.Policy != "Baseline" {
			t.Errorf("violation must cite the policy name: %+v", v)
		}
	}
	if out.Allowed || !rules["allowed_algorithms"] || !rules["max_validity_days"] || !rules["allow_ca_certs"] {
		t.Fatalf("expected the baseline rules cited, got %+v", out)
	}
	if len(out.Evaluated) != 1 || out.Evaluated[0] != "Baseline" {
		t.Fatalf("evaluated = %v", out.Evaluated)
	}
	if got := strings.Join(g.actions(), " "); strings.Contains(got, "policy.") {
		t.Fatalf("dry-run must not write audit rows, got %s", got)
	}

	// An allowed request reports allowed=true.
	rec = doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies/dry-run", "root-token", "", `{"algorithm":"ECDSA-P256","validity_days":30}`)
	policyData(t, rec.Body.String(), &out)
	if !out.Allowed || len(out.Violations) != 0 {
		t.Fatalf("compliant dry-run: %+v", out)
	}
}

func TestPolicyDryRunClassifiesCSRByItsKeyNotClientStrings(t *testing.T) {
	g := newPolicyRig(t, false)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	// The client lies: claims ECDSA-P256. The 2048-bit RSA key must win.
	payload, _ := json.Marshal(map[string]any{"csr_pem": csrPEM, "algorithm": "ECDSA-P256", "validity_days": 30})
	rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies/dry-run", "root-token", "", string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"observed":"RSA-2048"`) || !strings.Contains(rec.Body.String(), `"allowed":false`) {
		t.Fatalf("CSR key must decide the algorithm: %s", rec.Body.String())
	}
	bad, _ := json.Marshal(map[string]any{"csr_pem": "not pem", "validity_days": 30})
	if rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies/dry-run", "root-token", "", string(bad)); rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage CSR: %d", rec.Code)
	}
}

func TestPolicyValidationAndMethodErrors(t *testing.T) {
	g := newPolicyRig(t, false)
	for name, body := range map[string]string{
		"bad algorithm":   `{"name":"x","rules":{"allowed_algorithms":["DES"]}}`,
		"empty name":      `{"name":"  "}`,
		"long name":       `{"name":"` + strings.Repeat("a", 121) + `"}`,
		"rsa too small":   `{"name":"x","rules":{"min_rsa_bits":1024}}`,
		"rsa too large":   `{"name":"x","rules":{"min_rsa_bits":99999}}`,
		"validity high":   `{"name":"x","rules":{"max_validity_days":3651}}`,
		"validity neg":    `{"name":"x","rules":{"max_validity_days":-1}}`,
		"unknown field":   `{"name":"x","bogus":1}`,
		"revert_to on 14": `{"name":"x","revert_to":"v1"}`,
	} {
		if rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies", "root-token", "", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", "root-token", "", `{"revert_to":"v1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("a non-numeric revert_to must be 400, got %d", rec.Code)
	}
	if rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/nope", "root-token", "", `{"enabled":false}`); rec.Code != http.StatusNotFound {
		t.Errorf("PATCH unknown: %d", rec.Code)
	}
	if rec := doLeakJSON(g.mux, http.MethodPut, "/api/v1/policies", "root-token", "", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT collection: %d", rec.Code)
	}
	if rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies/dry-run", "root-token", "", `{"validity_days":30}`); rec.Code != http.StatusBadRequest {
		t.Errorf("dry-run without csr/algorithm: %d", rec.Code)
	}
}

func TestPolicyAPIRequiresAdminAndAuth(t *testing.T) {
	g := newPolicyRig(t, false)
	if rec := doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies", "wrong", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	auth := NewAuthenticatorFromEnv()
	_, viewer, err := auth.CreateAPIKey("viewer", "svc-viewer", "pki-viewer", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A second mux bound to this authenticator so the minted key resolves.
	mux := http.NewServeMux()
	WithPolicyAdmin(auth, g.pe, g.audit)(&ServerConfig{Mux: mux})
	for _, c := range []struct{ m, p, b string }{
		{http.MethodGet, "/api/v1/policies", ""},
		{http.MethodPost, "/api/v1/policies", `{"name":"x"}`},
		{http.MethodPatch, "/api/v1/policies/pol-baseline", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/policies/pol-baseline", ""},
		{http.MethodPost, "/api/v1/policies/dry-run", `{"algorithm":"ECDSA-P256"}`},
	} {
		if rec := doLeakJSON(mux, c.m, c.p, viewer, "", c.b); rec.Code != http.StatusForbidden {
			t.Errorf("non-admin %s %s: want 403, got %d", c.m, c.p, rec.Code)
		}
	}
	if _, found, _ := g.pe.GetPolicy("pol-baseline"); !found {
		t.Fatal("a forbidden DELETE must not delete")
	}
}

// Policies govern every tenant's issuance, so with multi-tenancy on a
// tenant-scoped admin is refused on every verb and nothing changes.
func TestPolicyAPIGlobalSuperAdminOnlyWhenMultiTenant(t *testing.T) {
	g := newPolicyRig(t, true)
	for _, c := range []struct{ m, p, b string }{
		{http.MethodGet, "/api/v1/policies", ""},
		{http.MethodGet, "/api/v1/policies/pol-baseline", ""},
		{http.MethodPost, "/api/v1/policies", `{"name":"x"}`},
		{http.MethodPatch, "/api/v1/policies/pol-baseline", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/policies/pol-baseline", ""},
		{http.MethodPost, "/api/v1/policies/dry-run", `{"algorithm":"ECDSA-P256"}`},
	} {
		if rec := doLeakJSON(g.mux, c.m, c.p, g.acme, "", c.b); rec.Code != http.StatusForbidden {
			t.Errorf("tenant admin %s %s: want 403, got %d %s", c.m, c.p, rec.Code, rec.Body.String())
		}
	}
	pol, found, err := g.pe.GetPolicy("pol-baseline")
	if err != nil || !found || !pol.Enabled {
		t.Fatalf("baseline must be untouched: %+v %v %v", pol, found, err)
	}
	if got := strings.Join(g.actions(), " "); !strings.Contains(got, "policy.update:denied") || !strings.Contains(got, "policy.delete:denied") {
		t.Errorf("tenant denials must be audited: %s", got)
	}
	if rec := doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies", "root-token", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("super-admin read: %d", rec.Code)
	}
	if rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", "root-token", "", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("super-admin patch: %d", rec.Code)
	}
}

func TestWithPolicyAdminNilEngine(t *testing.T) {
	if WithPolicyAdmin(nil, nil, nil) != nil {
		t.Fatal("nil policy engine must yield a nil option")
	}
}
