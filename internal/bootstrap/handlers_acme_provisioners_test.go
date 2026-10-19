// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/acme"
)

func newACMEProvisionerMux(t *testing.T) (*http.ServeMux, *Authenticator, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	RegisterACMEProvisionerHandlers(mux, auth, acme.NewMemProvisionerStore(),
		func(id string) bool { return id == "ca-1" }, nil, "https://hub.example/", audit)
	return mux, auth, audit
}

func provBody(name string) map[string]any {
	return map[string]any{"name": name, "ca_id": "ca-1", "allow_names": []string{"*.internal", "host.example.com"}, "challenges": []string{"dns-01"}}
}

func TestACMEProvisionerCRUDRoundTrip(t *testing.T) {
	mux, _, audit := newACMEProvisionerMux(t)
	const base = "/api/v1/acme/provisioners"

	rec := scepAPI(t, mux, http.MethodPost, base, "test-token", provBody("internal-tls"))
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"directory_url":"https://hub.example/acme/internal-tls/directory"`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodPost, base, "test-token", provBody("internal-tls")); rec.Code != http.StatusConflict {
		t.Errorf("duplicate: %d, want 409", rec.Code)
	}
	if rec := scepAPI(t, mux, http.MethodGet, base, "test-token", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"data":[{`) {
		t.Errorf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodGet, base+"/internal-tls", "test-token", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "host.example.com") {
		t.Errorf("get: %d %s", rec.Code, rec.Body.String())
	}
	upd := provBody("ignored")
	upd["allow_names"], upd["challenges"] = []string{"*.corp"}, []string{}
	rec = scepAPI(t, mux, http.MethodPut, base+"/internal-tls", "test-token", upd)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"*.corp"`) || !strings.Contains(rec.Body.String(), `"name":"internal-tls"`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodPut, base+"/nope", "test-token", upd); rec.Code != http.StatusNotFound {
		t.Errorf("update unknown: %d, want 404", rec.Code)
	}
	if rec := scepAPI(t, mux, http.MethodGet, base+"/nope", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get unknown: %d, want 404", rec.Code)
	}
	if rec := scepAPI(t, mux, http.MethodDelete, base+"/internal-tls", "test-token", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d, want 204", rec.Code)
	}
	if rec := scepAPI(t, mux, http.MethodDelete, base+"/internal-tls", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete twice: %d, want 404", rec.Code)
	}

	bad := map[string]map[string]any{
		"empty allow-list": {"name": "a", "ca_id": "ca-1", "allow_names": []string{}},
		"bad entry":        {"name": "a", "ca_id": "ca-1", "allow_names": []string{"Bad.Example"}},
		"reserved name":    {"name": "order", "ca_id": "ca-1", "allow_names": []string{"*.x"}},
		"tls-alpn-01":      {"name": "a", "ca_id": "ca-1", "allow_names": []string{"*.x"}, "challenges": []string{"tls-alpn-01"}},
		"unknown ca":       {"name": "a", "ca_id": "ca-9", "allow_names": []string{"*.x"}},
	}
	for name, body := range bad {
		if rec := scepAPI(t, mux, http.MethodPost, base, "test-token", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	if rec := scepAPI(t, mux, http.MethodPost, base, "test-token", bad["bad entry"]); !strings.Contains(rec.Body.String(), "Bad.Example") {
		t.Errorf("400 should name the entry: %s", rec.Body.String())
	}

	seen := map[string]bool{}
	for _, e := range audit.entries {
		if e.Action == "" || e.Outcome == "" || e.ResourceType != acmeProvisionerResource {
			t.Fatalf("incomplete audit entry %+v", e)
		}
		seen[e.Action+"/"+string(e.Outcome)] = true
	}
	for _, want := range []string{"acme.provisioner.create/success", "acme.provisioner.create/failure",
		"acme.provisioner.update/success", "acme.provisioner.update/failure",
		"acme.provisioner.delete/success", "acme.provisioner.delete/failure"} {
		if !seen[want] {
			t.Errorf("missing audit row %s", want)
		}
	}
}

func TestACMEProvisionerRequiresPKIAdmin(t *testing.T) {
	mux, auth, audit := newACMEProvisionerMux(t)
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	calls := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/acme/provisioners"}, {http.MethodPost, "/api/v1/acme/provisioners"},
		{http.MethodGet, "/api/v1/acme/provisioners/x"}, {http.MethodPut, "/api/v1/acme/provisioners/x"},
		{http.MethodDelete, "/api/v1/acme/provisioners/x"},
	}
	for _, c := range calls {
		if rec := scepAPI(t, mux, c.method, c.path, opKey, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as operator: %d, want 403", c.method, c.path, rec.Code)
		}
		if rec := scepAPI(t, mux, c.method, c.path, "", map[string]any{}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: %d, want 401", c.method, c.path, rec.Code)
		}
	}
	denied := 0
	for _, e := range audit.entries {
		if e.Outcome == AuditOutcomeDenied {
			denied++
		}
	}
	if denied != 2*len(calls) {
		t.Errorf("denied audit rows = %d, want %d", denied, 2*len(calls))
	}
}
