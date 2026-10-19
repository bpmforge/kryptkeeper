// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func cmdbSeedCert(p *caCertificateProvider, fp, cn string, sans []string, team, source string) {
	p.mu.Lock()
	p.addLocked(fp, &storedCert{item: CertificateItem{
		FingerprintSHA256: fp, SerialNumber: fp, CommonName: cn, SubjectAltNames: sans,
		CAID: "ca-A", CreatedAt: "2026-08-19T10:00:00Z", ValidUntil: "2030-01-01T00:00:00Z",
		RenewalStatus: "active", OwnerTeam: team, OwnershipSource: source, ServiceName: "svc-" + fp,
		OwnerEmail: "keep@example.com",
	}})
	p.mu.Unlock()
}

type cmdbEnv struct {
	mux   *http.ServeMux
	p     *caCertificateProvider
	audit *recordingAuditProvider
}

func newCMDBEnv(t *testing.T) cmdbEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	p := NewCACertificateProvider(nil, nil, nil, false).(*caCertificateProvider)
	cmdbSeedCert(p, "fp-host", "web.example.com", []string{"web.example.com"}, "", "")
	cmdbSeedCert(p, "fp-ip", "ip-cert", []string{"10.1.2.3"}, "", "")
	cmdbSeedCert(p, "fp-cidr", "cidr-cert", []string{"192.168.5.9"}, "", "")
	cmdbSeedCert(p, "fp-none", "other.test", nil, "", "")
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterOwnershipCMDBHandlers(mux, NewAuthenticatorFromEnv(), p, audit)
	return cmdbEnv{mux: mux, p: p, audit: audit}
}

func (e cmdbEnv) post(t *testing.T, query, contentType, body, token string) (*httptest.ResponseRecorder, cmdbImportResult) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ownership/cmdb-import"+query, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	var resp struct {
		Data cmdbImportResult `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp.Data
}

func (e cmdbEnv) item(t *testing.T, fp string) CertificateItem {
	t.Helper()
	it, ok, err := e.p.GetCertificate(context.Background(), fp)
	if err != nil || !ok {
		t.Fatalf("get %s: %v %v", fp, ok, err)
	}
	return it.CertificateItem
}

const cmdbRulesJSON = `{"rules":[
 {"match":"host","value":"WEB.example.com","owner_team":"web","owner_email":"web@example.com"},
 {"match":"ip","value":"10.1.2.3","owner_team":"net"},
 {"match":"cidr","value":"192.168.0.0/16","owner_team":"lab","owner_email":"lab@example.com"}]}`

func TestCMDBImportAssignsMatchingCerts(t *testing.T) {
	e := newCMDBEnv(t)
	rec, res := e.post(t, "", "application/json", cmdbRulesJSON, "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	if res.Rules != 3 || res.Matched != 3 || res.Assigned != 3 {
		t.Fatalf("result = %+v", res)
	}
	for fp, team := range map[string]string{"fp-host": "web", "fp-ip": "net", "fp-cidr": "lab"} {
		it := e.item(t, fp)
		if it.OwnerTeam != team || it.OwnershipSource != OwnershipSourceCMDB {
			t.Errorf("%s: team=%q source=%q", fp, it.OwnerTeam, it.OwnershipSource)
		}
		if it.ServiceName != "svc-"+fp {
			t.Errorf("%s: service name clobbered: %q", fp, it.ServiceName)
		}
	}
	if got := e.item(t, "fp-ip").OwnerEmail; got != "keep@example.com" {
		t.Errorf("rule without email must keep the existing one, got %q", got)
	}
	if e.item(t, "fp-none").OwnerTeam != "" {
		t.Error("unmatched cert changed")
	}
	if e.audit.count("ownership.cmdb_import") != 1 {
		t.Fatalf("want one ownership.cmdb_import audit row, got %d", e.audit.count("ownership.cmdb_import"))
	}
}

func TestCMDBImportCSV(t *testing.T) {
	e := newCMDBEnv(t)
	csvBody := "match,value,owner_team,owner_email\nhost,web.example.com,web,web@example.com\nip,10.1.2.3,net,\ncidr,192.168.0.0/16,lab,lab@example.com\n"
	rec, res := e.post(t, "", "text/csv; charset=utf-8", csvBody, "test-token")
	if rec.Code != http.StatusOK || res.Assigned != 3 {
		t.Fatalf("csv import: %d %+v %s", rec.Code, res, rec.Body.String())
	}
	if e.item(t, "fp-cidr").OwnershipSource != OwnershipSourceCMDB {
		t.Fatal("csv import did not record source=cmdb")
	}
	if rec, _ := e.post(t, "", "text/csv", "host,val,team\nx,y,z\n", "test-token"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad csv header: %d", rec.Code)
	}
}

func TestManualPatchOverridesCMDBAndFlipsSource(t *testing.T) {
	e := newCMDBEnv(t)
	e.post(t, "", "application/json", cmdbRulesJSON, "test-token")

	if _, err := e.p.UpdateOwnership(context.Background(), "fp-host", CertificateOwnershipRequest{OwnerTeam: "humans", ServiceName: "svc-fp-host"}); err != nil {
		t.Fatal(err)
	}
	it := e.item(t, "fp-host")
	if it.OwnerTeam != "humans" || it.OwnershipSource != OwnershipSourceManual {
		t.Fatalf("after manual patch: team=%q source=%q", it.OwnerTeam, it.OwnershipSource)
	}
	_, res := e.post(t, "", "application/json", cmdbRulesJSON, "test-token")
	if res.SkippedManual != 1 {
		t.Fatalf("second import SkippedManual = %d, want 1 (%+v)", res.SkippedManual, res)
	}
	if e.item(t, "fp-host").OwnerTeam != "humans" {
		t.Fatal("import overwrote a manual owner")
	}
	// Re-import of cmdb values stays allowed and idempotent.
	if res.Assigned != 2 {
		t.Fatalf("cmdb-owned certs must be re-assignable, assigned=%d", res.Assigned)
	}
}

func TestCMDBImportLegacyOwnerWithoutSourceIsNotOverwritten(t *testing.T) {
	e := newCMDBEnv(t)
	cmdbSeedCert(e.p, "fp-legacy", "legacy.example.com", []string{"legacy.example.com"}, "old-team", "")
	_, res := e.post(t, "", "application/json", `{"rules":[{"match":"host","value":"legacy.example.com","owner_team":"new"}]}`, "test-token")
	if res.SkippedManual != 1 || e.item(t, "fp-legacy").OwnerTeam != "old-team" {
		t.Fatalf("legacy owner overwritten: %+v", res)
	}
}

func TestCMDBImportValidation(t *testing.T) {
	e := newCMDBEnv(t)
	many := make([]string, 1001)
	for i := range many {
		many[i] = fmt.Sprintf(`{"match":"host","value":"h%d.example.com","owner_team":"t"}`, i)
	}
	cases := map[string]string{
		"bad match":    `{"rules":[{"match":"dns","value":"a","owner_team":"t"}]}`,
		"bad cidr":     `{"rules":[{"match":"cidr","value":"10.0.0.0/99","owner_team":"t"}]}`,
		"bad ip":       `{"rules":[{"match":"ip","value":"999.1.1.1","owner_team":"t"}]}`,
		"empty team":   `{"rules":[{"match":"host","value":"a.example.com","owner_team":" "}]}`,
		"bad email":    `{"rules":[{"match":"host","value":"a.example.com","owner_team":"t","owner_email":"nope"}]}`,
		"bare star":    `{"rules":[{"match":"host","value":"*","owner_team":"t"}]}`,
		"no rules":     `{"rules":[]}`,
		"not json":     `hello`,
		"too many":     `{"rules":[` + strings.Join(many, ",") + `]}`,
		"mid wildcard": `{"rules":[{"match":"host","value":"a.*.example.com","owner_team":"t"}]}`,
	}
	for name, body := range cases {
		if rec, _ := e.post(t, "", "application/json", body, "test-token"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
	if rec, _ := e.post(t, "", "application/json", cmdbRulesJSON, "wrong-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", rec.Code)
	}
	if rec := httptest.NewRecorder(); true {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ownership/cmdb-import", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		e.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET: %d, want 405", rec.Code)
		}
	}
}

func TestCMDBImportDryRun(t *testing.T) {
	e := newCMDBEnv(t)
	rec, res := e.post(t, "?dry_run=true", "application/json", cmdbRulesJSON, "test-token")
	if rec.Code != http.StatusOK || !res.DryRun || res.Assigned != 3 {
		t.Fatalf("dry run: %d %+v", rec.Code, res)
	}
	for _, fp := range []string{"fp-host", "fp-ip", "fp-cidr"} {
		if it := e.item(t, fp); it.OwnerTeam != "" || it.OwnershipSource != "" {
			t.Errorf("dry run changed %s", fp)
		}
	}
	if len(e.audit.entries) != 0 {
		t.Fatalf("dry run wrote audit rows: %+v", e.audit.entries)
	}
}

func TestCMDBHostWildcard(t *testing.T) {
	cases := []struct {
		rule, name string
		want       bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"web.example.com", "WEB.example.com", true},
	}
	for _, c := range cases {
		if got := cmdbHostMatches(c.rule, c.name); got != c.want {
			t.Errorf("%s vs %s = %v", c.rule, c.name, got)
		}
	}
}

// Tenant isolation: an acme import must never reach globex's certificate,
// and a fingerprint row naming it is rejected per row.
func TestCMDBImportIsTenantScoped(t *testing.T) {
	setupTenantWritePathTest(t)
	auth := NewAuthenticatorFromEnv()
	acmeToken := cmdbAPIKey(t, auth, "pki-admin", "acme")
	globexToken := cmdbAPIKey(t, auth, "pki-admin", "globex")
	provider := NewFileCertificateProviderFromEnv()
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterOwnershipCMDBHandlers(mux, auth, provider, audit)
	// The tenant store is process-global state in production wiring; the
	// full-stack setup above installed it.
	if activeTenantStore == nil {
		t.Fatal("tenant store not active")
	}

	do := func(token, body string) (int, cmdbImportResult) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ownership/cmdb-import", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var resp struct {
			Data cmdbImportResult `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec.Code, resp.Data
	}
	body := `{"rules":[
	 {"match":"host","value":"*.example.com","owner_team":"acme-team"},
	 {"match":"fingerprint","value":"fp-globex-cert","owner_team":"stolen"},
	 {"match":"fingerprint","value":"no-such-fp","owner_team":"x"}]}`

	// Row 1 hits fp-acme-cert first for acme; for globex the host rule hits its own.
	code, res := do(acmeToken, body)
	if code != http.StatusOK {
		t.Fatalf("acme import: %d", code)
	}
	if res.Matched != 1 || res.Assigned != 1 {
		t.Fatalf("acme result = %+v, want exactly its own cert", res)
	}
	if len(res.Rejected) != 2 || res.Rejected[0].Row != 2 || res.Rejected[1].Row != 3 || res.Rejected[0].Reason != res.Rejected[1].Reason {
		t.Fatalf("rejected rows = %+v, want rows 2 and 3 with identical reasons", res.Rejected)
	}
	acme, _, _ := provider.GetCertificate(context.Background(), "fp-acme-cert")
	globex, _, _ := provider.GetCertificate(context.Background(), "fp-globex-cert")
	if acme.OwnerTeam != "acme-team" || acme.OwnershipSource != OwnershipSourceCMDB {
		t.Fatalf("acme cert not assigned: %+v", acme.CertificateItem)
	}
	if globex.OwnerTeam != "" || globex.OwnershipSource != "" {
		t.Fatalf("globex cert touched by acme import: team=%q source=%q", globex.OwnerTeam, globex.OwnershipSource)
	}

	// And the mirror image: globex cannot reach acme's.
	code, res = do(globexToken, `{"rules":[{"match":"fingerprint","value":"fp-acme-cert","owner_team":"stolen"}]}`)
	if code != http.StatusOK || res.Assigned != 0 || len(res.Rejected) != 1 {
		t.Fatalf("globex cross-tenant: %d %+v", code, res)
	}
	if after, _, _ := provider.GetCertificate(context.Background(), "fp-acme-cert"); after.OwnerTeam != "acme-team" {
		t.Fatalf("globex import overwrote acme: %q", after.OwnerTeam)
	}
}

// Fail closed: tenancy on with no tenant store wired reaches no certificate.
func TestCMDBImportDeniesWhenTenantStoreMissing(t *testing.T) {
	setupTenantWritePathTest(t)
	auth := NewAuthenticatorFromEnv()
	acmeToken := cmdbAPIKey(t, auth, "pki-admin", "acme")
	provider := NewFileCertificateProviderFromEnv()
	mux := http.NewServeMux()
	RegisterOwnershipCMDBHandlers(mux, auth, provider, &recordingAuditProvider{})
	saved := activeTenantStore
	activeTenantStore = nil
	t.Cleanup(func() { activeTenantStore = saved })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ownership/cmdb-import", strings.NewReader(`{"rules":[{"match":"host","value":"*.example.com","owner_team":"t"}]}`))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var resp struct {
		Data cmdbImportResult `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Assigned != 0 || resp.Data.Matched != 0 {
		t.Fatalf("tenant-scoped import with no tenant store matched certs: %+v", resp.Data)
	}
}

func TestCMDBImportNonAdminForbidden(t *testing.T) {
	setupTenantWritePathTest(t)
	auth := NewAuthenticatorFromEnv()
	viewerToken := cmdbAPIKey(t, auth, "viewer", "acme")
	mux := http.NewServeMux()
	RegisterOwnershipCMDBHandlers(mux, auth, NewFileCertificateProviderFromEnv(), &recordingAuditProvider{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ownership/cmdb-import", strings.NewReader(cmdbRulesJSON))
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer import: %d, want 403", rec.Code)
	}
}

// cmdbAPIKey mints a key on this test's own Authenticator: keys are held per
// Authenticator instance, so the tokens setupTenantWritePathTest returns only
// work against its mux.
func cmdbAPIKey(t *testing.T, auth *Authenticator, role, tenant string) string {
	t.Helper()
	_, token, err := auth.CreateAPIKey(role+"-"+tenant, "svc-principal", role, []string{"*"}, "", tenant, time.Now())
	if err != nil {
		t.Fatalf("create %s/%s key: %v", role, tenant, err)
	}
	return token
}
