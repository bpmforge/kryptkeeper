// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTargetsTestMux(t *testing.T) (*http.ServeMux, *Authenticator, ManagedTargetStore, TenantStore, *sql.DB) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "targets-handler-test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	targetStore := &sqliteManagedTargetStore{db: db}
	if err := targetStore.EnsureSchema(t.Context()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS endpoints (
		id TEXT PRIMARY KEY, ip_address TEXT NOT NULL, hostname TEXT, port INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create endpoints table: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE IF NOT EXISTS agent_endpoints (
		agent_id TEXT NOT NULL, server_type TEXT, server_name TEXT)`); err != nil {
		t.Fatalf("create agent_endpoints table: %v", err)
	}

	tenantStore := &dbTenantStore{db: db, ph: sqlitePlaceholder}
	if err := tenantStore.EnsureSchema(t.Context()); err != nil {
		t.Fatalf("EnsureSchema tenant: %v", err)
	}

	mux := http.NewServeMux()
	registerTargetHandlers(mux, auth, targetStore, tenantStore, stubAuditProviderForCA{}, targetEgressDeps{})
	return mux, auth, targetStore, tenantStore, db
}

func doTargetsRequest(mux *http.ServeMux, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestTargetsHandler_CRUDRoundTrip proves create -> get -> list -> patch ->
// delete all work end to end through the real HTTP handlers.
func TestTargetsHandler_CRUDRoundTrip(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)

	createBody := `{"name":"Web01","host":"web01.example.com","discovery_mode":"network","install_mode":"ssh","renewal_method":"est"}`
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token", createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var createResp struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	id := createResp.Data.ID
	if id == "" || createResp.Data.Host != "web01.example.com" || createResp.Data.DiscoveryMode != "network" {
		t.Fatalf("unexpected create response: %+v", createResp.Data)
	}

	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id, "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var listResp struct {
		Data []ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(listResp.Data) != 1 {
		t.Fatalf("expected 1 target in list, got %d", len(listResp.Data))
	}

	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+id, "test-token", `{"install_mode":"acme"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var patchResp struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &patchResp); err != nil {
		t.Fatalf("unmarshal patch response: %v", err)
	}
	if patchResp.Data.InstallMode != "acme" || patchResp.Data.Host != "web01.example.com" {
		t.Fatalf("unexpected patch response: %+v", patchResp.Data)
	}

	rec = doTargetsRequest(mux, http.MethodDelete, "/api/v1/targets/"+id, "test-token", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id, "test-token", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want 404", rec.Code)
	}
}

// TestTargetsHandler_RequiresAuth proves the surface is not anonymously
// accessible.
func TestTargetsHandler_RequiresAuth(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestTargetsHandler_RejectsInvalidEnumAt400 proves the acceptance
// criterion "reject unknown modes at create/update (400)" end to end
// through the HTTP layer, not just the store.
func TestTargetsHandler_RejectsInvalidEnumAt400(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	body := `{"name":"Bad","host":"bad.example.com","discovery_mode":"carrier-pigeon"}`
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
}

// TestTargetsHandler_RequiresNameAndHost proves the two mandatory fields
// are actually enforced by the handler (not just by a DB NOT NULL that
// would otherwise surface as an opaque 503).
func TestTargetsHandler_RequiresNameAndHost(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token", `{"name":"","host":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
}

// TestTargetsHandler_RenewalThresholdDays is the W8-15 API-level proof:
// create can set a per-target renewal threshold, PATCH can change or clear
// it, and a negative value is rejected at create and update time (400, not
// a 503 from an unhandled DB CHECK violation).
func TestTargetsHandler_RenewalThresholdDays(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)

	createBody := `{"name":"Web01","host":"web01.example.com","renewal_threshold_days":14}`
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token", createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var createResp struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if createResp.Data.RenewalThresholdDays != 14 {
		t.Fatalf("create RenewalThresholdDays = %d, want 14", createResp.Data.RenewalThresholdDays)
	}
	id := createResp.Data.ID

	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+id, "test-token", `{"renewal_threshold_days":60}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var patchResp struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &patchResp); err != nil {
		t.Fatalf("unmarshal patch response: %v", err)
	}
	if patchResp.Data.RenewalThresholdDays != 60 {
		t.Fatalf("patch RenewalThresholdDays = %d, want 60", patchResp.Data.RenewalThresholdDays)
	}

	rec = doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token",
		`{"name":"Bad","host":"bad.example.com","renewal_threshold_days":-5}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with negative threshold status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}

	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+id, "test-token", `{"renewal_threshold_days":-1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch with negative threshold status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
}

// TestTargetsHandler_TenantIsolation is the acceptance-critical test: a
// principal scoped to tenant A cannot see, get, patch, or delete a target
// created under tenant B.
func TestTargetsHandler_TenantIsolation(t *testing.T) {
	mux, auth, _, tenantStore, _ := newTargetsTestMux(t)
	t.Setenv("MULTI_TENANCY", "on")

	ctx := t.Context()
	if _, err := tenantStore.CreateTenant(ctx, "tenant-a", "Tenant A"); err != nil {
		t.Fatalf("CreateTenant a: %v", err)
	}
	if _, err := tenantStore.CreateTenant(ctx, "tenant-b", "Tenant B"); err != nil {
		t.Fatalf("CreateTenant b: %v", err)
	}

	_, tokenA, err := auth.CreateAPIKey("user-a", "user-a", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey a: %v", err)
	}
	_, tokenB, err := auth.CreateAPIKey("user-b", "user-b", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey b: %v", err)
	}

	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", tokenA,
		`{"name":"A's target","host":"a.example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create as tenant A status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.Data.Tenant != "tenant-a" {
		t.Fatalf("created target's tenant = %q, want tenant-a (stamped from the creating principal)", created.Data.Tenant)
	}
	id := created.Data.ID

	// Tenant B must not see it in list.
	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets", tokenB, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list as tenant B status = %d", rec.Code)
	}
	var listB struct {
		Data []ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listB); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(listB.Data) != 0 {
		t.Fatalf("tenant B's list leaked tenant A's target: %+v", listB.Data)
	}

	// Tenant B must not be able to GET it directly by ID either.
	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id, tokenB, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("get as tenant B status = %d, want 403", rec.Code)
	}

	// ...nor PATCH it.
	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+id, tokenB, `{"host":"hijacked.example.com"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("patch as tenant B status = %d, want 403", rec.Code)
	}

	// ...nor DELETE it.
	rec = doTargetsRequest(mux, http.MethodDelete, "/api/v1/targets/"+id, tokenB, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete as tenant B status = %d, want 403", rec.Code)
	}

	// Tenant A can still see its own target.
	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+id, tokenA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get as tenant A status = %d, want 200", rec.Code)
	}
}

// TestTargetsHandler_EndpointsJoin proves acceptance #2's join: GET
// /api/v1/targets/{id}/endpoints resolves the target's declared Host
// against both endpoints (scanned) and agent_endpoints (agent-reported).
func TestTargetsHandler_EndpointsJoin(t *testing.T) {
	mux, _, _, _, db := newTargetsTestMux(t)
	ctx := t.Context()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO endpoints (id, ip_address, hostname, port) VALUES (?, ?, ?, ?)`,
		"ep-1", "10.0.0.5", "join-test.example.com", 443); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO agent_endpoints (agent_id, server_type, server_name) VALUES (?, ?, ?)`,
		"agent-1", "nginx", "join-test.example.com"); err != nil {
		t.Fatalf("insert agent_endpoint: %v", err)
	}

	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", "test-token",
		`{"name":"Join Test","host":"join-test.example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+created.Data.ID+"/endpoints", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("endpoints status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var matchResp struct {
		Data []ManagedTargetEndpointMatch `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &matchResp); err != nil {
		t.Fatalf("unmarshal endpoints response: %v", err)
	}
	if len(matchResp.Data) != 2 {
		t.Fatalf("expected 2 endpoint matches, got %d: %+v", len(matchResp.Data), matchResp.Data)
	}
}

// TestTargetsHandler_EndpointsJoinDeniedAcrossTenants proves acceptance #3
// (NFR-P2): the endpoints join for a target you cannot see is denied, not
// silently returned -- the join has no tenant column of its own, so this
// gate is the ONLY thing enforcing tenant scope on it.
func TestTargetsHandler_EndpointsJoinDeniedAcrossTenants(t *testing.T) {
	mux, auth, _, tenantStore, _ := newTargetsTestMux(t)
	t.Setenv("MULTI_TENANCY", "on")
	ctx := t.Context()

	if _, err := tenantStore.CreateTenant(ctx, "tenant-a", "Tenant A"); err != nil {
		t.Fatalf("CreateTenant a: %v", err)
	}
	if _, err := tenantStore.CreateTenant(ctx, "tenant-b", "Tenant B"); err != nil {
		t.Fatalf("CreateTenant b: %v", err)
	}
	_, tokenA, err := auth.CreateAPIKey("user-a", "user-a", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey a: %v", err)
	}
	_, tokenB, err := auth.CreateAPIKey("user-b", "user-b", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey b: %v", err)
	}

	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", tokenA,
		`{"name":"A's target","host":"a-join.example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data ManagedTarget `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rec = doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+created.Data.ID+"/endpoints", tokenB, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("endpoints join as tenant B status = %d, want 403", rec.Code)
	}
}

// TestTargetsHandler_StoreUnavailableReturns503 proves the surface fails
// closed with a real 503, not a panic or a silent empty success, when the
// store is nil (DB unavailable).
func TestTargetsHandler_StoreUnavailableReturns503(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerTargetHandlers(mux, auth, nil, nil, stubAuditProviderForCA{}, targetEgressDeps{})

	rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets", "test-token", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
