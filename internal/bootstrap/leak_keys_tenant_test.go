// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

type keysLeakEnv struct {
	mux          *http.ServeMux
	acme, globex string
	acmeCAKey    string
	globexCAKey  string
	pendingStore PendingActionStore
	auth         *Authenticator
	keys         keystore.Store
}

func setupKeysLeakEnv(t *testing.T) *keysLeakEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	ts := NewTenantStoreFromEnv()
	ctx := context.Background()
	for _, id := range []string{"acme", "globex"} {
		if _, err := ts.CreateTenant(ctx, id, id); err != nil {
			t.Fatalf("create tenant %s: %v", id, err)
		}
	}
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(nil) })

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("leak-keys-test-passphrase-32b!!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	caStore := ca.NewMemStore()
	engine := ca.NewEngine(keys, caStore)
	acmeCA, err := engine.CreateRootCA("Acme", pkix.Name{CommonName: "Acme"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatalf("acme CA: %v", err)
	}
	globexCA, err := engine.CreateRootCA("Globex", pkix.Name{CommonName: "Globex"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatalf("globex CA: %v", err)
	}
	if err := ts.SetCATenant(ctx, acmeCA.ID, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := ts.SetCATenant(ctx, globexCA.ID, "globex"); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.GenerateKey("ssh-ca", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	SetActiveCAStore(caStore)
	t.Cleanup(func() { SetActiveCAStore(nil) })

	auth := NewAuthenticatorFromEnv()
	_, acme, err := auth.CreateAPIKey("acme-svc", "svc-acme", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, globex, err := auth.CreateAPIKey("globex-svc", "svc-globex", "pki-admin", []string{"*"}, "", "globex", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProviderForCA{}, "")
	registerKeyCustodyHandler(mux, auth, keys, nil, stubAuditProviderForCA{})
	registerKeyEscrowHandlers(mux, auth, keys, stubAuditProviderForCA{})
	return &keysLeakEnv{mux: mux, acme: acme, globex: globex, acmeCAKey: acmeCA.KeyID, globexCAKey: globexCA.KeyID, pendingStore: NewPendingActionStoreFromEnv(), auth: auth, keys: keys}
}

// TestLeakL04_KeystoreScopedToOwningTenant: another tenant's CA key, ssh-ca and
// unmapped keys are invisible and unexportable to a tenant admin.
func TestLeakL04_KeystoreScopedToOwningTenant(t *testing.T) {
	e := setupKeysLeakEnv(t)
	rec := doLeakJSON(e.mux, http.MethodGet, "/api/v1/keys", e.acme, "", "")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, e.acmeCAKey) {
		t.Fatalf("acme should list own CA key: %d %s", rec.Code, body)
	}
	if strings.Contains(body, e.globexCAKey) || strings.Contains(body, "ssh-ca") {
		t.Fatalf("acme sees foreign/unmapped keys: %s", body)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/keys/" + e.globexCAKey},
		{http.MethodGet, "/api/v1/keys/ssh-ca"},
		{http.MethodPost, "/api/v1/keys/" + e.globexCAKey + "/export"},
		{http.MethodPost, "/api/v1/keys/ssh-ca/export"},
		{http.MethodPost, "/api/v1/keys/" + e.globexCAKey + "/rotate"},
		{http.MethodDelete, "/api/v1/keys/" + e.globexCAKey},
	} {
		r := doLeakJSON(e.mux, tc.method, tc.path, e.acme, "", `{"passphrase":"correct horse battery"}`)
		if r.Code != http.StatusNotFound {
			t.Errorf("%s %s: want 404, got %d %s", tc.method, tc.path, r.Code, r.Body.String())
		}
	}
	if r := doLeakJSON(e.mux, http.MethodGet, "/api/v1/keys/"+e.acmeCAKey, e.acme, "", ""); r.Code != http.StatusOK {
		t.Errorf("own CA key GET: %d", r.Code)
	}
	if r := doLeakJSON(e.mux, http.MethodGet, "/api/v1/keys/"+e.globexCAKey, "root-token", "", ""); r.Code != http.StatusOK {
		t.Errorf("super-admin GET: %d", r.Code)
	}
	// Not attributable to one tenant => super-admin only.
	for _, p := range []string{"/api/v1/keys", "/api/v1/keys/escrow"} {
		if r := doLeakJSON(e.mux, http.MethodPost, p, e.acme, "", `{"id":"x","algorithm":"ecdsa-p256","key_id":"`+e.acmeCAKey+`"}`); r.Code != http.StatusForbidden {
			t.Errorf("POST %s as tenant admin: want 403, got %d %s", p, r.Code, r.Body.String())
		}
	}
}

// TestLeakL04_KeyGrantStampedWithOwningTenant: an export grant for a tenant's CA
// key is visible only to that tenant's approvers and names the owner.
func TestLeakL04_KeyGrantStampedWithOwningTenant(t *testing.T) {
	e := setupKeysLeakEnv(t)
	r := doLeakJSON(e.mux, http.MethodPost, "/api/v1/keys/"+e.acmeCAKey+"/export", e.acme, "", `{"passphrase":"correct horse battery"}`)
	if r.Code != http.StatusAccepted {
		t.Fatalf("propose: %d %s", r.Code, r.Body.String())
	}
	list, err := e.pendingStore.List(context.Background(), "")
	if err != nil || len(list) != 1 {
		t.Fatalf("pending list: %v %v", list, err)
	}
	if list[0].Tenant != "acme" || !strings.Contains(list[0].Rationale, "acme") {
		t.Fatalf("grant tenant/rationale = %q / %q", list[0].Tenant, list[0].Rationale)
	}
	if got := filterPendingActionsByTenant(AuthPrincipal{Tenant: "globex", TenantScoped: true}, list); len(got) != 0 {
		t.Fatalf("globex approver can see acme's key grant")
	}
	// A super-admin proposal for a globex key must be stamped globex, not default.
	r = doLeakJSON(e.mux, http.MethodPost, "/api/v1/keys/"+e.globexCAKey+"/export", "root-token", "", `{"passphrase":"correct horse battery"}`)
	if r.Code != http.StatusAccepted {
		t.Fatalf("super-admin propose: %d %s", r.Code, r.Body.String())
	}
	list, _ = e.pendingStore.List(context.Background(), "")
	var found bool
	for _, a := range list {
		if strings.Contains(string(a.Params), e.globexCAKey) {
			found = true
			if a.Tenant != "globex" {
				t.Fatalf("globex key grant stamped %q", a.Tenant)
			}
		}
	}
	if !found {
		t.Fatal("globex grant missing")
	}
}

// TestLeakL05_KeyCustodyReportScopedToTenant: the custody report omits other
// tenants' keys and unmapped keys.
func TestLeakL05_KeyCustodyReportScopedToTenant(t *testing.T) {
	e := setupKeysLeakEnv(t)
	r := doLeakJSON(e.mux, http.MethodGet, "/api/v1/reports/key-custody", e.acme, "", "")
	body := r.Body.String()
	if r.Code != http.StatusOK || !strings.Contains(body, e.acmeCAKey) {
		t.Fatalf("acme report: %d %s", r.Code, body)
	}
	if strings.Contains(body, e.globexCAKey) || strings.Contains(body, "ssh-ca") {
		t.Fatalf("custody report leaks keys: %s", body)
	}
	r = doLeakJSON(e.mux, http.MethodGet, "/api/v1/reports/key-custody", "root-token", "", "")
	if !strings.Contains(r.Body.String(), e.globexCAKey) || !strings.Contains(r.Body.String(), "ssh-ca") {
		t.Fatalf("super-admin report incomplete: %s", r.Body.String())
	}
}

// TestLeakL04_W23KeyRoutesScopedToOwningTenant: the W23 per-key routes
// (policy, compromise, cancel-deletion) hide another tenant's key as 404.
func TestLeakL04_W23KeyRoutesScopedToOwningTenant(t *testing.T) {
	e := setupKeysLeakEnv(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/keys/" + e.globexCAKey + "/policy", ""},
		{http.MethodPut, "/api/v1/keys/" + e.globexCAKey + "/policy", `{"owner":"mallory"}`},
		{http.MethodPost, "/api/v1/keys/" + e.globexCAKey + "/compromise", ""},
		{http.MethodPost, "/api/v1/keys/" + e.globexCAKey + "/cancel-deletion", ""},
		{http.MethodGet, "/api/v1/keys/ssh-ca/policy", ""},
	} {
		r := doLeakJSON(e.mux, tc.method, tc.path, e.acme, "", tc.body)
		if r.Code != http.StatusNotFound {
			t.Errorf("%s %s: want 404, got %d %s", tc.method, tc.path, r.Code, r.Body.String())
		}
	}
	if r := doLeakJSON(e.mux, http.MethodGet, "/api/v1/keys/"+e.acmeCAKey+"/policy", e.acme, "", ""); r.Code == http.StatusNotFound && strings.Contains(r.Body.String(), "key not found") {
		t.Errorf("own key policy hidden: %d %s", r.Code, r.Body.String())
	}
}
