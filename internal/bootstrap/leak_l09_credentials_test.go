// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLeakL09_CredentialsScopedToTenant(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	auth := NewAuthenticatorFromEnv()
	_, acmeTok, _ := auth.CreateAPIKey("acme-adm", "acme-adm", "pki-admin", []string{"*"}, "", "acme", time.Now())
	_, globexTok, _ := auth.CreateAPIKey("globex-adm", "globex-adm", "pki-admin", []string{"*"}, "", "globex", time.Now())

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "l09.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	targets := &sqliteManagedTargetStore{db: db}
	if err := targets.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	creds := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := creds.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, auth, creds, stubAuditProvider{}, nil)
	registerTargetHandlers(mux, auth, targets, nil, stubAuditProvider{}, targetEgressDeps{credentials: creds})

	body := `{"name":"gx-cred","credential_type":"` + CredentialTypeSSHKey + `","payload":` + string(testSSHCredentialJSON(t)) + `}`
	rec := leakDo(mux, http.MethodPost, "/api/v1/credentials", globexTok, "globex", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data OutboundCredentialMeta `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	gx := created.Data.ID
	if created.Data.Tenant != "globex" {
		t.Fatalf("credential must be stamped with creator tenant, got %q", created.Data.Tenant)
	}

	if rec := leakDo(mux, http.MethodGet, "/api/v1/credentials", acmeTok, "acme", ""); strings.Contains(rec.Body.String(), gx) {
		t.Fatalf("acme listed globex credential: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodPost, "/api/v1/targets", acmeTok, "acme",
		`{"name":"x","host":"h","install_mode":"ssh","credential_ref":"`+gx+`"}`); rec.Code == http.StatusCreated {
		t.Fatalf("acme borrowed globex credential into a target: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodPost, "/api/v1/credentials/"+gx+"/preflight", acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant preflight: want 404 got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/credentials/"+gx, acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: want 404 got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodPost, "/api/v1/targets", globexTok, "globex",
		`{"name":"x","host":"h","install_mode":"ssh","credential_ref":"`+gx+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("owner must still use its credential: %d %s", rec.Code, rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/credentials/"+gx, globexTok, "globex", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("own delete: %d", rec.Code)
	}
}
