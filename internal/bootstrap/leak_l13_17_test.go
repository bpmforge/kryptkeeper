// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func leakDo(mux http.Handler, method, path, token, tenant, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestLeakL13_SearchScopedToTenant(t *testing.T) {
	mux, acmeTok, _ := setupTenantWritePathTest(t)
	rec := leakDo(mux, http.MethodGet, "/api/v1/search?q=globex", acmeTok, "acme", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("search: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "globex") {
		t.Fatalf("acme search leaked globex rows: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodGet, "/api/v1/search?q=acme", acmeTok, "acme", ""); !strings.Contains(rec.Body.String(), "acme") {
		t.Fatalf("acme must still find its own rows: %s", rec.Body.String())
	}
}

func TestLeakL14_CBOMScopedToTenant(t *testing.T) {
	mux, acmeTok, _ := setupTenantWritePathTest(t)
	rec := leakDo(mux, http.MethodGet, "/api/v1/cbom", acmeTok, "acme", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("cbom: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "fp-globex-cert") {
		t.Fatalf("acme CBOM leaked globex certificate: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "fp-acme-cert") {
		t.Fatalf("acme CBOM lost its own certificate: %s", rec.Body.String())
	}
}

func TestLeakL15_SSHCertListScopedToTenant(t *testing.T) {
	setupTenantWritePathTest(t)
	auth := NewAuthenticatorFromEnv()
	_, acmeTok, err := auth.CreateAPIKey("acme-ssh", "svc-principal", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store := newSSHCertStoreFromEnv()
	if store == nil {
		t.Fatal("ssh cert store")
	}
	for _, c := range []struct{ serial, tenant string }{{"1", "acme"}, {"2", "globex"}} {
		if err := store.insert(context.Background(), SSHCertRecord{
			Serial: c.serial, CertType: "user", KeyID: "k" + c.serial, Principals: []string{"p"},
			ValidAfter: "a", ValidBefore: "b", SubjectFingerprint: "s", AuthorityFingerprint: "a",
			CertificateLine: "line", Tenant: c.tenant, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	RegisterSSHCertHandlers(mux, auth, nil, nil, stubAuditProviderForCA{})
	rec := leakDo(mux, http.MethodGet, "/api/v1/ssh/certificates", acmeTok, "acme", "")
	var body struct {
		Data []SSHCertRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Data) != 1 || body.Data[0].Tenant != "acme" {
		t.Fatalf("expected only acme ssh cert, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLeakL16_ConnectorsScopedToTenant(t *testing.T) {
	mux, acmeTok, globexTok := setupTenantWritePathTest(t)
	rec := leakDo(mux, http.MethodPost, "/api/v1/connectors", globexTok, "globex", `{"name":"gx-conn","type":"internal","config_json":"{}"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed connector: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data ConnectorRecord `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	gx := created.Data.ID

	if rec := leakDo(mux, http.MethodGet, "/api/v1/connectors", acmeTok, "acme", ""); strings.Contains(rec.Body.String(), gx) {
		t.Fatalf("acme listed globex connector: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/connectors/"+gx, acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: want 404, got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodGet, "/api/v1/connectors", globexTok, "globex", ""); !strings.Contains(rec.Body.String(), gx) {
		t.Fatalf("globex lost its connector: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/connectors/"+gx, globexTok, "globex", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("own delete: %d", rec.Code)
	}
}

func TestLeakL17_InventorySourcesScopedToTenant(t *testing.T) {
	mux, acmeTok, globexTok := setupTenantWritePathTest(t)
	rec := leakDo(mux, http.MethodPost, "/api/v1/inventory-sources", globexTok, "globex", `{"name":"gx-src","type":"adcs_export","config_json":"{}"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed source: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data InventorySourceRecord `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	gx := created.Data.ID

	if rec := leakDo(mux, http.MethodGet, "/api/v1/inventory-sources", acmeTok, "acme", ""); strings.Contains(rec.Body.String(), gx) {
		t.Fatalf("acme listed globex source: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodPost, "/api/v1/inventory-sources/"+gx+"/sync", acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant sync: want 404, got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/inventory-sources/"+gx, acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: want 404, got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/inventory-sources/"+gx, globexTok, "globex", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("own delete: %d", rec.Code)
	}
}
