// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupTenantWritePathTest wires the full handler stack (RegisterHandlers)
// with API-key auth, MULTI_TENANCY on, and two tenants (acme/globex) each
// owning one CA/certificate/template. Returns the mux and a bearer token per
// tenant. W2-01: proves write paths and single-resource GETs are tenant
// enforced, not only list reads (which tenant_scoping_test.go already covers
// at the filter-function level).
// lastTenantWritePathViewerToken is the non-admin acme token minted by the
// most recent setupTenantWritePathTest call (test-file-local plumbing so the
// widely-used helper signature stays put).
var lastTenantWritePathViewerToken string

// lastTenantWritePathAuth lets tests mount extra handlers behind the same keys.
var lastTenantWritePathAuth *Authenticator

func setupTenantWritePathTest(t *testing.T) (mux *http.ServeMux, acmeToken, globexToken string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")

	dataDir := t.TempDir()
	t.Setenv("KRYPTKEEPER_DATA_DIR", dataDir)

	caFile := filepath.Join(dataDir, "cas.json")
	caBody := []byte(`[
{"id":"ca-acme","name":"acme-root","display_name":"Acme Root","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"software","certificate_fingerprint_sha256":"fp-ca-acme","certificate":{"fingerprint_sha256":"fp-ca-acme","subject_dn":"CN=Acme Root","valid_from":"2026-01-01T00:00:00Z","valid_until":"2036-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
{"id":"ca-globex","name":"globex-root","display_name":"Globex Root","type":"root","parent_ca_id":null,"status":"active","key_storage_type":"software","certificate_fingerprint_sha256":"fp-ca-globex","certificate":{"fingerprint_sha256":"fp-ca-globex","subject_dn":"CN=Globex Root","valid_from":"2026-01-01T00:00:00Z","valid_until":"2036-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256},"crl_distribution_points":[],"ocsp_service_url":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(caFile, caBody, 0o600); err != nil {
		t.Fatalf("write ca fixture: %v", err)
	}
	t.Setenv("APP_CA_FILE", caFile)

	certFile := filepath.Join(dataDir, "certificates.json")
	certBody := []byte(`[
{"fingerprint_sha256":"fp-acme-cert","serial_number":"01","common_name":"svc.acme.example.com","subject_dn":"CN=svc.acme.example.com","subject_alt_names":[],"issuer_cn":"Acme Root","issuer_dn":"CN=Acme Root","ca_id":"ca-acme","template_id":"tpl-acme","team_id":"svc-principal","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
{"fingerprint_sha256":"fp-globex-cert","serial_number":"02","common_name":"svc.globex.example.com","subject_dn":"CN=svc.globex.example.com","subject_alt_names":[],"issuer_cn":"Globex Root","issuer_dn":"CN=Globex Root","ca_id":"ca-globex","template_id":"tpl-globex","team_id":"svc-principal","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","key_size_bits":256,"signature_algorithm":"ecdsa-with-SHA256","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"chain_complete":true,"chain_trusted":true,"pqc_vulnerable":false,"risk_score":5,"risk_flags":[],"grade":"A","renewal_method":"manual","renewal_status":"active","source":"api","etag":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(certFile, certBody, 0o600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", certFile)

	tplFile := filepath.Join(dataDir, "templates.json")
	tplBody := []byte(`[
{"id":"tpl-acme","name":"tpl-acme","display_name":"Acme Template","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
{"id":"tpl-globex","name":"tpl-globex","display_name":"Globex Template","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"issued_count":0,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(tplFile, tplBody, 0o600); err != nil {
		t.Fatalf("write template fixture: %v", err)
	}
	t.Setenv("APP_TEMPLATE_FILE", tplFile)

	// Seed CA/template tenant mappings directly (W2-02 owns the auto-mapping
	// UX; here we just need the mapping to exist for the enforcement checks).
	tenantStore := NewTenantStoreFromEnv()
	if tenantStore == nil {
		t.Fatal("expected a DB-backed tenant store (KRYPTKEEPER_DATA_DIR set)")
	}
	ctx := context.Background()
	if _, err := tenantStore.CreateTenant(ctx, "acme", "Acme Corp"); err != nil {
		t.Fatalf("create tenant acme: %v", err)
	}
	if _, err := tenantStore.CreateTenant(ctx, "globex", "Globex Corp"); err != nil {
		t.Fatalf("create tenant globex: %v", err)
	}
	if err := tenantStore.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatalf("map ca-acme: %v", err)
	}
	if err := tenantStore.SetCATenant(ctx, "ca-globex", "globex"); err != nil {
		t.Fatalf("map ca-globex: %v", err)
	}
	if err := tenantStore.SetTemplateTenant(ctx, "tpl-acme", "acme"); err != nil {
		t.Fatalf("map tpl-acme: %v", err)
	}
	if err := tenantStore.SetTemplateTenant(ctx, "tpl-globex", "globex"); err != nil {
		t.Fatalf("map tpl-globex: %v", err)
	}

	auth := NewAuthenticatorFromEnv()
	_, acmeToken, err := auth.CreateAPIKey("acme-svc", "svc-principal", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create acme api key: %v", err)
	}
	_, globexToken, err = auth.CreateAPIKey("globex-svc", "svc-principal", "pki-admin", []string{"*"}, "", "globex", time.Now())
	if err != nil {
		t.Fatalf("create globex api key: %v", err)
	}
	// S-36/S-37: a NON-admin acme principal — team-scope confinement only
	// applies below the admin role now, so denial tests need this identity.
	_, acmeViewerToken, err := auth.CreateAPIKey("acme-viewer", "svc-principal", "viewer", []string{}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create acme viewer key: %v", err)
	}
	lastTenantWritePathViewerToken = acmeViewerToken
	lastTenantWritePathAuth = auth

	mux = http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForCA{}, stubAuditProviderForCA{}, NewFileCAProviderFromEnv(), NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)
	return mux, acmeToken, globexToken
}

// doTenantReq issues a request as the given token, scoped to the given
// X-Tenant (the "view-as" tenant a non-super-admin principal is pinned to —
// see resolvePrincipalTenancy). POST/PATCH/PUT get an empty JSON body so
// handlers that decode the body before checking access (e.g. handleReject)
// don't 400 before the tenant check under test ever runs.
func doTenantReq(mux *http.ServeMux, method, path, token, tenant string) *httptest.ResponseRecorder {
	var body *strings.Reader
	switch method {
	case http.MethodPost, http.MethodPatch, http.MethodPut:
		body = strings.NewReader(`{}`)
	default:
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant", tenant)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// stubCreatableCAProvider is a minimal CAProvider whose CreateCA actually
// succeeds — unlike fileCAProvider (used elsewhere in this file), which
// returns errCACreateUnsupported unconditionally, so it can't exercise the
// W2-02 create-time tenant-validate-then-map path.
type stubCreatableCAProvider struct{}

func (stubCreatableCAProvider) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{}, nil
}
func (stubCreatableCAProvider) GetCA(context.Context, string) (CAListItem, bool, error) {
	return CAListItem{}, false, nil
}
func (stubCreatableCAProvider) GetCAChain(context.Context, string) ([]CAListItem, bool, error) {
	return nil, false, nil
}
func (stubCreatableCAProvider) UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error) {
	return CAListItem{}, errCANotFound
}
func (stubCreatableCAProvider) DeleteCA(context.Context, string) error { return errCANotFound }
func (stubCreatableCAProvider) SuspendCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}
func (stubCreatableCAProvider) ActivateCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}
func (stubCreatableCAProvider) CreateCA(_ context.Context, req CACreateRequest) (CAListItem, error) {
	return CAListItem{ID: "ca-" + req.Name, Name: req.Name, Type: req.Type, Status: "active"}, nil
}

// TestCACreateValidatesXTenantAndAutoMaps is the W2-02 regression: a scoped
// principal's X-Tenant header must name a real tenant (rejected otherwise),
// and a successful create maps the new CA to that tenant, not DefaultTenant.
func TestCACreateValidatesXTenantAndAutoMaps(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	tenantStore := NewTenantStoreFromEnv()
	if tenantStore == nil {
		t.Fatal("expected a DB-backed tenant store")
	}
	ctx := context.Background()
	if _, err := tenantStore.CreateTenant(ctx, "acme", "Acme Corp"); err != nil {
		t.Fatalf("create tenant acme: %v", err)
	}

	auth := NewAuthenticatorFromEnv()
	_, acmeToken, err := auth.CreateAPIKey("acme-svc", "svc-principal", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create acme api key: %v", err)
	}

	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, stubCreatableCAProvider{}, tenantStore, stubAuditProviderForCA{})

	// A bogus X-Tenant is rejected before the CA is ever created. Post-W3-01,
	// an identity-bound scoped principal (acmeToken) can't even name another
	// tenant via X-Tenant at all (denied at the auth layer, tested
	// separately) — so the "unknown tenant" 400 from TenantExists (W2-02) is
	// only still reachable via a super-admin's view-as.
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/cas", strings.NewReader(`{"name":"bad","type":"root","algorithm":"ecdsaP256","subject_cn":"Bad Root"}`))
	badReq.Header.Set("Authorization", "Bearer root-token")
	badReq.Header.Set("X-Tenant", "no-such-tenant")
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("create with unknown X-Tenant: expected 400, got %d: %s", badRec.Code, badRec.Body.String())
	}

	// A real tenant succeeds and the new CA auto-maps to it, not DefaultTenant.
	goodReq := httptest.NewRequest(http.MethodPost, "/api/v1/cas", strings.NewReader(`{"name":"good","type":"root","algorithm":"ecdsaP256","subject_cn":"Good Root"}`))
	goodReq.Header.Set("Authorization", "Bearer "+acmeToken)
	goodReq.Header.Set("X-Tenant", "acme")
	goodRec := httptest.NewRecorder()
	mux.ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusCreated {
		t.Fatalf("create with valid X-Tenant: expected 201, got %d: %s", goodRec.Code, goodRec.Body.String())
	}

	mapped, err := tenantStore.CATenant(ctx, "ca-good")
	if err != nil {
		t.Fatalf("CATenant: %v", err)
	}
	if mapped != "acme" {
		t.Fatalf("expected new CA auto-mapped to acme, got %q", mapped)
	}

	// S-08/G-49: a principal with no identity-bound tenant resolves to
	// DefaultTenant. The auto-map write must be skipped entirely for this
	// case (it's already the correct unmapped fallback, and attempting it
	// would FK-violate against "default", which is never a real tenants
	// row) — no error should be logged either.
	_, unboundToken, err := auth.CreateAPIKey("unbound-svc", "svc-principal-2", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create unbound api key: %v", err)
	}
	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	unboundReq := httptest.NewRequest(http.MethodPost, "/api/v1/cas", strings.NewReader(`{"name":"unbound","type":"root","algorithm":"ecdsaP256","subject_cn":"Unbound Root"}`))
	unboundReq.Header.Set("Authorization", "Bearer "+unboundToken)
	unboundRec := httptest.NewRecorder()
	mux.ServeHTTP(unboundRec, unboundReq)
	if unboundRec.Code != http.StatusCreated {
		t.Fatalf("create with no identity-bound tenant: expected 201, got %d: %s", unboundRec.Code, unboundRec.Body.String())
	}
	if strings.Contains(logBuf.String(), "auto-map") {
		t.Fatalf("expected no auto-map attempt (and no error) for a DefaultTenant principal, got log output: %s", logBuf.String())
	}
	if mapped, err := tenantStore.CATenant(ctx, "ca-unbound"); err != nil || mapped != DefaultTenant {
		t.Fatalf("expected unmapped CA to resolve to DefaultTenant, got %q (err=%v)", mapped, err)
	}
}

func TestCAHandlersEnforceTenantOnWritePathsAndGet(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	// Same-tenant GET succeeds.
	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/cas/ca-acme", acmeToken, "acme"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant GET: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// Cross-tenant GET is denied.
	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/cas/ca-globex", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant GET: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// Cross-tenant suspend (write path) is denied.
	if rec := doTenantReq(mux, http.MethodPost, "/api/v1/cas/ca-globex/suspend", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant suspend: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// Same-tenant suspend succeeds.
	if rec := doTenantReq(mux, http.MethodPost, "/api/v1/cas/ca-acme/suspend", acmeToken, "acme"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant suspend: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCertificateHandlersEnforceTenantOnWritePathsAndGet(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/certificates/fp-acme-cert", acmeToken, "acme"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant GET: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/certificates/fp-globex-cert", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant GET: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// Cross-tenant revoke (write path) is denied.
	revokeBody := `{"reason_code":0}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/fp-globex-cert/revoke", strings.NewReader(revokeBody))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant revoke: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Issuance (create) is the one "create" path for certificates, since it
	// references two pre-existing, tenant-owned resources (CA + template).
	// acme's principal must not be able to issue against globex's CA, even
	// though the CSR itself is well-formed and the template is acme's own.
	issueCrossCA := `{"ca_id":"ca-globex","template_id":"tpl-acme","csr_pem":"placeholder"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(issueCrossCA))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant issuance (ca_id): expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Same check on template_id: acme's own CA, but globex's template.
	issueCrossTemplate := `{"ca_id":"ca-acme","template_id":"tpl-globex","csr_pem":"placeholder"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(issueCrossTemplate))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant issuance (template_id): expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTemplateCreateValidatesXTenantAndAutoMaps is the W2-02 regression for
// templates: a scoped principal's X-Tenant must name a real tenant (rejected
// otherwise), and a successful create maps the new template to that tenant.
// Unlike CA creation, fileTemplateProvider.CreateTemplate actually works, so
// this reuses the full setupTenantWritePathTest stack.
func TestTemplateCreateValidatesXTenantAndAutoMaps(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	templateBody := `{"name":"new-tpl","display_name":"New Template","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D"}`

	// Post-W3-01, only a super-admin's view-as can even name an unknown
	// tenant (an identity-bound scoped principal is denied at the auth layer
	// before this check ever runs — tested separately).
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(templateBody))
	badReq.Header.Set("Authorization", "Bearer root-token")
	badReq.Header.Set("X-Tenant", "no-such-tenant")
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("create with unknown X-Tenant: expected 400, got %d: %s", badRec.Code, badRec.Body.String())
	}

	goodReq := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(templateBody))
	goodReq.Header.Set("Authorization", "Bearer "+acmeToken)
	goodReq.Header.Set("X-Tenant", "acme")
	goodRec := httptest.NewRecorder()
	mux.ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusCreated {
		t.Fatalf("create with valid X-Tenant: expected 201, got %d: %s", goodRec.Code, goodRec.Body.String())
	}
	var resp struct {
		Data TemplateItem `json:"data"`
	}
	if err := json.Unmarshal(goodRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	tenantStore := NewTenantStoreFromEnv()
	if tenantStore == nil {
		t.Fatal("expected a DB-backed tenant store")
	}
	mapped, err := tenantStore.TemplateTenant(context.Background(), resp.Data.ID)
	if err != nil {
		t.Fatalf("TemplateTenant: %v", err)
	}
	if mapped != "acme" {
		t.Fatalf("expected new template auto-mapped to acme, got %q", mapped)
	}
}

// TestTemplateCloneAutoMapsToCreatorTenant proves clone (a template "created"
// via CloneTemplate rather than CreateTemplate — a separate provider method
// the auto-map above doesn't cover) also maps its output to the cloning
// principal's tenant, not DefaultTenant.
func TestTemplateCloneAutoMapsToCreatorTenant(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	cloneBody := `{"name":"acme-clone","display_name":"Acme Clone"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tpl-acme/clone", strings.NewReader(cloneBody))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("clone: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data TemplateItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode clone response: %v", err)
	}

	tenantStore := NewTenantStoreFromEnv()
	if tenantStore == nil {
		t.Fatal("expected a DB-backed tenant store")
	}
	mapped, err := tenantStore.TemplateTenant(context.Background(), resp.Data.ID)
	if err != nil {
		t.Fatalf("TemplateTenant: %v", err)
	}
	if mapped != "acme" {
		t.Fatalf("expected cloned template auto-mapped to acme, got %q", mapped)
	}
}

func TestTemplateHandlersEnforceTenantOnWritePathsAndGet(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/templates/tpl-acme", acmeToken, "acme"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant GET: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/templates/tpl-globex", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant GET: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// Cross-tenant delete (write path) is denied.
	if rec := doTenantReq(mux, http.MethodDelete, "/api/v1/templates/tpl-globex", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant delete: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApprovalHandlersEnforceTenantOnGetApproveReject(t *testing.T) {
	mux, acmeToken, globexToken := setupTenantWritePathTest(t)

	// newApprovalStoreFromEnv self-heals its own schema (S-06/G-47) — no
	// manual CREATE TABLE needed here against this fresh sqlite DB.
	approvalStore, err := newApprovalStoreFromEnv()
	if err != nil || approvalStore == nil {
		t.Fatalf("approval store: %v", err)
	}
	ctx := context.Background()
	acmeApproval := ApprovalRequest{
		ID: "apr-acme", TemplateID: "tpl-acme", CAID: "ca-acme", Requester: "svc-principal",
		Status: "pending", CSRPEM: "", RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := approvalStore.Create(ctx, acmeApproval); err != nil {
		t.Fatalf("seed acme approval: %v", err)
	}
	globexApproval := ApprovalRequest{
		ID: "apr-globex", TemplateID: "tpl-globex", CAID: "ca-globex", Requester: "svc-principal",
		Status: "pending", CSRPEM: "", RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := approvalStore.Create(ctx, globexApproval); err != nil {
		t.Fatalf("seed globex approval: %v", err)
	}

	// Same-tenant GET succeeds; cross-tenant GET is denied.
	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/approvals/apr-acme", acmeToken, "acme"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant approval GET: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doTenantReq(mux, http.MethodGet, "/api/v1/approvals/apr-globex", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant approval GET: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Cross-tenant approve is denied before it ever reaches issuance.
	if rec := doTenantReq(mux, http.MethodPost, "/api/v1/approvals/apr-globex/approve", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant approve: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Cross-tenant reject is denied; same-tenant reject (by the owning
	// tenant's principal) succeeds.
	if rec := doTenantReq(mux, http.MethodPost, "/api/v1/approvals/apr-globex/reject", acmeToken, "acme"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant reject: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doTenantReq(mux, http.MethodPost, "/api/v1/approvals/apr-globex/reject", globexToken, "globex"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant reject: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
