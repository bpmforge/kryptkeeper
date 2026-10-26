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

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W36-02: POST /api/v1/cas/external and the connector delete guard.

type externalCAEnv struct {
	mux   *http.ServeMux
	store ConnectorStore
	audit *recordingAuditProvider
	admin string
	root  string
}

func newExternalCAEnv(t *testing.T, dualControl string) *externalCAEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", dualControl)
	auth := NewAuthenticatorFromEnv()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("external-ca-test-pass-32bytes!!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Close() })
	provider := NewEngineCAProvider(ca.NewEngine(keys, ca.NewMemStore()))
	store := newConnectorTestStore(t)
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	tenants := NewTenantStoreFromEnv()
	registerExternalCAHandlers(mux, auth, provider, store, nil, tenants, audit)
	registerConnectorHandlers(mux, auth, store, nil, nil, audit, provider)
	_, _, rootPEM := testRoot(t, "Customer Root", 1, false)
	return &externalCAEnv{mux: mux, store: store, audit: audit, admin: mintAdminToken(t, auth, "alice", ""), root: rootPEM}
}

func (e *externalCAEnv) do(method, path string, body map[string]any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(e.admin, method, path, raw))
	return rec
}

func (e *externalCAEnv) connector(t *testing.T, typ, id string) string {
	t.Helper()
	cfg := `{"base_url":"https://upstream.example.test","endpoint_url":"https://upstream.example.test/scep","username":"svc","template_name":"WebServer"}`
	if typ == "internal" {
		cfg = "{}"
	}
	rec, err := e.store.Create(context.Background(), ConnectorRecord{ID: "conn-" + id, Name: id, Type: typ, ConfigJSON: cfg, CredentialRef: "cred-1"})
	if err != nil {
		t.Fatal(err)
	}
	return rec.ID
}

func TestExternalCACreateAndConnectorDeleteGuard(t *testing.T) {
	e := newExternalCAEnv(t, "false")
	conn := e.connector(t, "est", "main")

	rec := e.do(http.MethodPost, "/api/v1/cas/external", map[string]any{"name": "Customer CA", "connector_id": conn, "trust_pem": e.root})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Data CAListItem }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	d := out.Data
	if d.Type != "external" || d.KeyStorageType != "external" || d.ConnectorID != conn || d.OCSPServiceURL != nil || len(d.CRLDistributionPoints) != 0 {
		t.Fatalf("item = %+v", d)
	}
	var detail string
	for _, a := range e.audit.entries {
		if a.Action == "ca.external.create" && a.Outcome == AuditOutcomeSuccess {
			detail = a.ChangeSummary
		}
	}
	if !strings.Contains(detail, conn) || !strings.Contains(detail, "trust_fingerprints") {
		t.Errorf("audit detail = %q", detail)
	}

	del := e.do(http.MethodDelete, "/api/v1/connectors/"+conn, nil)
	if del.Code != http.StatusConflict || !strings.Contains(del.Body.String(), "connector is used by external CA Customer CA ("+d.ID+")") {
		t.Fatalf("delete: %d %s", del.Code, del.Body.String())
	}
	free := e.connector(t, "est", "free")
	if del := e.do(http.MethodDelete, "/api/v1/connectors/"+free, nil); del.Code != http.StatusNoContent {
		t.Fatalf("unused connector delete: %d %s", del.Code, del.Body.String())
	}
}

func TestExternalCACreateValidation(t *testing.T) {
	e := newExternalCAEnv(t, "false")
	est := e.connector(t, "est", "main")
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"missing name", map[string]any{"connector_id": est, "trust_pem": e.root}, "required"},
		{"missing trust", map[string]any{"name": "x", "connector_id": est}, "required"},
		{"unknown connector", map[string]any{"name": "x", "connector_id": "nope", "trust_pem": e.root}, "unknown connector"},
		{"bad trust", map[string]any{"name": "x", "connector_id": est, "trust_pem": "not pem"}, "invalid external CA"},
	}
	for _, c := range cases {
		rec := e.do(http.MethodPost, "/api/v1/cas/external", c.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	for _, typ := range []string{"internal", "scep", "wstep"} {
		id := e.connector(t, typ, typ)
		rec := e.do(http.MethodPost, "/api/v1/cas/external", map[string]any{"name": "x", "connector_id": id, "trust_pem": e.root})
		want := externalConnectorTypeError(typ).Error()
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), strings.ReplaceAll(want, "'", "\\u0027")) && !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %s", typ, rec.Code, rec.Body.String())
		}
	}
	if rec := e.do(http.MethodGet, "/api/v1/cas/external", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	unauth := httptest.NewRecorder()
	e.mux.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/api/v1/cas/external", strings.NewReader("{}")))
	if unauth.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", unauth.Code)
	}
}

func TestExternalBindingTenantError(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	scoped := AuthPrincipal{Tenant: "acme"}
	global := AuthPrincipal{Tenant: DefaultTenant, SuperAdmin: true}
	own := ConnectorRecord{Tenant: "acme"}
	cases := []struct {
		name  string
		pd    AuthPrincipal
		rec   ConnectorRecord
		creds OutboundCredentialStore
		bad   bool
	}{
		{"own connector", scoped, own, nil, false},
		{"foreign connector", scoped, ConnectorRecord{Tenant: "globex"}, nil, true},
		{"default connector for scoped", scoped, ConnectorRecord{}, nil, true},
		{"own credential", scoped, ConnectorRecord{Tenant: "acme", CredentialRef: "c"}, fakeCredMeta{tenant: "acme"}, false},
		{"foreign credential", scoped, ConnectorRecord{Tenant: "acme", CredentialRef: "c"}, fakeCredMeta{tenant: "globex"}, true},
		{"default credential, scoped", scoped, ConnectorRecord{Tenant: "acme", CredentialRef: "c"}, fakeCredMeta{tenant: DefaultTenant}, true},
		{"default credential, bypass", global, ConnectorRecord{Tenant: "acme", CredentialRef: "c"}, fakeCredMeta{tenant: DefaultTenant}, false},
		{"foreign credential, bypass", global, ConnectorRecord{Tenant: "acme", CredentialRef: "c"}, fakeCredMeta{tenant: "globex"}, true},
	}
	for _, c := range cases {
		if err := externalBindingTenantError(r, c.pd, c.rec, c.creds); (err != nil) != c.bad {
			t.Errorf("%s: err = %v, want error=%v", c.name, err, c.bad)
		}
	}
}

func TestExternalCACreateUnderDualControlIsProposed(t *testing.T) {
	e := newExternalCAEnv(t, "unset")
	conn := e.connector(t, "est", "main")
	rec := e.do(http.MethodPost, "/api/v1/cas/external", map[string]any{"name": "Customer CA", "connector_id": conn, "trust_pem": e.root})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202 proposal, got %d %s", rec.Code, rec.Body.String())
	}
}
