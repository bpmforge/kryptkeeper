// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sourceAPI struct {
	t   *testing.T
	mux *http.ServeMux
	env *extEnv
	// tenant, when set, sends X-Tenant so the bootstrap super-admin is scoped
	// to one tenant and filtered like any other principal.
	tenant string
}

func newSourceAPI(t *testing.T) *sourceAPI {
	t.Helper()
	e := newExtEnv(t)
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, auth, e.store, stubAuditProvider{}, nil)
	registerCredentialSourceHandlers(mux, auth, e.sources, e.store, stubAuditProvider{}, nil)
	return &sourceAPI{t: t, mux: mux, env: e}
}

func (a *sourceAPI) do(method, path string, body any) (int, string) {
	a.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rec := httptest.NewRecorder()
	req := authedReq(method, path, raw)
	if a.tenant != "" {
		req.Header.Set("X-Tenant", a.tenant)
	}
	a.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func dataOf(t *testing.T, body string) map[string]any {
	t.Helper()
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out.Data
}

// The whole operator path, through the API only: a local login credential, a
// source, a test of a reference, an external credential, then use.
func TestCredentialSourceAPIEndToEnd(t *testing.T) {
	a := newSourceAPI(t)
	a.env.vault.put("ssh/web1", sshSecret())

	code, body := a.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "vault login", "credential_type": "api_token", "payload": map[string]string{"token": fakeKVToken},
	})
	if code != http.StatusCreated {
		t.Fatalf("login credential: %d %s", code, body)
	}
	loginID := dataOf(t, body)["id"].(string)

	code, body = a.do(http.MethodPost, "/api/v1/credential-sources", map[string]any{
		"name": "prod vault", "kind": "vault_kv2", "credential_ref": loginID,
		"config": map[string]any{"base_url": a.env.vault.ts.URL, "ca_cert_pem": a.env.vault.caPEM(), "mount": "secret"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create source: %d %s", code, body)
	}
	srcID := dataOf(t, body)["id"].(string)
	if strings.Contains(body, fakeKVToken) {
		t.Fatal("a source response carried the login token")
	}

	code, body = a.do(http.MethodGet, "/api/v1/credential-sources", nil)
	if code != http.StatusOK || !strings.Contains(body, srcID) || strings.Contains(body, fakeKVToken) {
		t.Fatalf("list: %d %s", code, body)
	}

	// Test a reference: field names come back, values never.
	ref := map[string]any{"credential_type": "ssh_key", "reference": map[string]string{"path": "ssh/web1"}, "static": sshStatic}
	code, body = a.do(http.MethodPost, "/api/v1/credential-sources/"+srcID+"/test", ref)
	d := dataOf(t, body)
	if code != http.StatusOK || d["ok"] != true || strings.Contains(body, fakeKVSecretKey) || !strings.Contains(body, "private_key_pem") {
		t.Fatalf("test: %d %s", code, body)
	}
	code, body = a.do(http.MethodPost, "/api/v1/credential-sources/"+srcID+"/test",
		map[string]any{"credential_type": "ssh_key", "reference": map[string]string{"path": "ssh/nope"}})
	d = dataOf(t, body)
	if code != http.StatusOK || d["ok"] != false || !strings.Contains(body, "nothing at secret/ssh/nope") {
		t.Fatalf("test of a missing path: %d %s", code, body)
	}

	// External credential: no payload, only the reference.
	code, body = a.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "web1 ssh", "credential_type": "ssh_key", "source": "external", "source_id": srcID,
		"reference": map[string]string{"path": "ssh/web1"}, "static": sshStatic,
	})
	if code != http.StatusCreated || strings.Contains(body, fakeKVSecretKey) {
		t.Fatalf("create external: %d %s", code, body)
	}
	credID := dataOf(t, body)["id"].(string)
	got, err := a.env.store.Resolve(t.Context(), credID)
	if err != nil || !strings.Contains(string(got), fakeKVSecretKey) {
		t.Fatalf("resolve: %v", err)
	}
	code, body = a.do(http.MethodGet, "/api/v1/credentials", nil)
	if code != http.StatusOK || !strings.Contains(body, `"source":"external"`) || strings.Contains(body, fakeKVSecretKey) {
		t.Fatalf("list credentials: %d %s", code, body)
	}

	// The source cannot be deleted while a credential uses it.
	if code, _ = a.do(http.MethodDelete, "/api/v1/credential-sources/"+srcID, nil); code != http.StatusConflict {
		t.Fatalf("delete in use: %d", code)
	}
	if code, _ = a.do(http.MethodDelete, "/api/v1/credentials/"+credID, nil); code != http.StatusNoContent {
		t.Fatalf("delete credential: %d", code)
	}
	if code, _ = a.do(http.MethodDelete, "/api/v1/credential-sources/"+srcID, nil); code != http.StatusNoContent {
		t.Fatalf("delete source: %d", code)
	}
}

func TestCredentialSourceAPIRefusals(t *testing.T) {
	a := newSourceAPI(t)
	_, body := a.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "ssh", "credential_type": "ssh_key", "payload": map[string]string{"user": "root", "private_key_pem": "FAKE", "host_public_key": fakeKVHostKey},
	})
	sshCred := dataOf(t, body)["id"].(string)
	_, body = a.do(http.MethodPost, "/api/v1/credentials", map[string]any{"name": "login", "credential_type": "api_token", "payload": map[string]string{"token": "t"}})
	login := dataOf(t, body)["id"].(string)
	cfg := map[string]any{"base_url": a.env.vault.ts.URL}

	for name, req := range map[string]map[string]any{
		"login of the wrong type": {"name": "s", "kind": "vault_kv2", "credential_ref": sshCred, "config": cfg},
		"unknown login":           {"name": "s", "kind": "vault_kv2", "credential_ref": "cred-nope", "config": cfg},
		"bad kind":                {"name": "s", "kind": "ldap", "credential_ref": login, "config": cfg},
		"no base url":             {"name": "s", "kind": "vault_kv2", "credential_ref": login, "config": map[string]any{}},
		"bad pinned CA":           {"name": "s", "kind": "vault_kv2", "credential_ref": login, "config": map[string]any{"base_url": a.env.vault.ts.URL, "ca_cert_pem": "not pem"}},
		"plugins are off":         {"name": "s", "kind": "plugin", "credential_ref": login, "config": map[string]any{"plugin_id": "kryptkeeper.cyberark-ccp"}},
	} {
		if code, body := a.do(http.MethodPost, "/api/v1/credential-sources", req); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}

	// A source whose login is itself external is refused.
	_, body = a.do(http.MethodPost, "/api/v1/credential-sources", map[string]any{"name": "ok", "kind": "vault_kv2", "credential_ref": login, "config": cfg})
	srcID := dataOf(t, body)["id"].(string)
	_, body = a.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "ext", "credential_type": "api_token", "source": "external", "source_id": srcID, "reference": map[string]string{"path": "login/token"}})
	extLogin := dataOf(t, body)["id"].(string)
	if code, body := a.do(http.MethodPost, "/api/v1/credential-sources", map[string]any{"name": "loop", "kind": "vault_kv2", "credential_ref": extLogin, "config": cfg}); code != http.StatusBadRequest || !strings.Contains(body, "local credential") {
		t.Errorf("external login: %d %s", code, body)
	}

	// External credentials take no payload, an existing source, and no secret in static.
	for name, req := range map[string]map[string]any{
		"payload with external": {"name": "x", "credential_type": "ssh_key", "source": "external", "source_id": srcID, "reference": map[string]string{"path": "p"}, "payload": map[string]string{"k": "v"}},
		"unknown source":        {"name": "x", "credential_type": "ssh_key", "source": "external", "source_id": "csrc-nope", "reference": map[string]string{"path": "p"}},
		"secret in static":      {"name": "x", "credential_type": "ssh_key", "source": "external", "source_id": srcID, "reference": map[string]string{"path": "p"}, "static": map[string]string{"password": "p"}},
		"no reference":          {"name": "x", "credential_type": "ssh_key", "source": "external", "source_id": srcID},
		"bad source value":      {"name": "x", "credential_type": "ssh_key", "source": "cloud", "payload": map[string]string{"k": "v"}},
	} {
		if code, body := a.do(http.MethodPost, "/api/v1/credentials", req); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if code, _ := a.do(http.MethodPost, "/api/v1/credential-sources/csrc-nope/test", map[string]any{"credential_type": "ssh_key", "reference": map[string]string{"path": "p"}}); code != http.StatusNotFound {
		t.Errorf("test of an unknown source: %d", code)
	}
	if code, _ := a.do(http.MethodDelete, "/api/v1/credential-sources/csrc-nope", nil); code != http.StatusNotFound {
		t.Errorf("delete of an unknown source: %d", code)
	}
}

func TestCredentialSourceAPIHidesOtherTenantsSources(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	a := newSourceAPI(t)
	a.tenant = DefaultTenant
	other := a.env.source("other-tenant", `{"token":"`+fakeKVToken+`"}`, nil)
	_, body := a.do(http.MethodGet, "/api/v1/credential-sources", nil)
	if strings.Contains(body, other.ID) {
		t.Fatalf("another tenant's source is listed: %s", body)
	}
	if code, _ := a.do(http.MethodDelete, "/api/v1/credential-sources/"+other.ID, nil); code != http.StatusNotFound {
		t.Fatalf("delete across tenants: %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/api/v1/credential-sources/"+other.ID+"/test", map[string]any{"credential_type": "ssh_key", "reference": map[string]string{"path": "p"}}); code != http.StatusNotFound {
		t.Fatalf("test across tenants: %d", code)
	}
	if code, _ := a.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "x", "credential_type": "ssh_key", "source": "external", "source_id": other.ID, "reference": map[string]string{"path": "p"}}); code != http.StatusBadRequest {
		t.Fatalf("external credential on another tenant's source: %d", code)
	}
}
