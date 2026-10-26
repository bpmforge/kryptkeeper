// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/scep"
)

func newSCEPLabelMux(t *testing.T) (*http.ServeMux, *Authenticator, *scep.MemLabelStore, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_BASE_URL", "https://hub.example.com/")
	auth := NewAuthenticatorFromEnv()
	store := scep.NewMemLabelStore()
	audit := &scepRecordingAudit{}
	tpls := &fakeTemplateProvider{templates: map[string]TemplateItem{"tmpl-a": {}}}
	creds := &renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeAPIToken}, payload: []byte(`{"client_secret":"very-secret-value"}`)}
	mux := http.NewServeMux()
	RegisterSCEPLabelHandlers(mux, auth, store, tpls, creds, audit)
	return mux, auth, store, audit
}

func validLabelBody() map[string]any {
	return map[string]any{"label": "corp", "mode": "intune", "template_id": "tmpl-a", "intune_tenant_id": "contoso.onmicrosoft.com",
		"intune_client_id": "11111111-2222-3333-4444-555555555555", "credential_ref": "cred-1", "issuing_authority": "Kryptkeeper CA"}
}

func TestSCEPLabelCreateListDelete(t *testing.T) {
	mux, _, _, audit := newSCEPLabelMux(t)
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/scep/labels", "test-token", validLabelBody())
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"url":"https://hub.example.com/scep/corp"`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodGet, "/api/v1/scep/labels", "test-token", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "corp") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodDelete, "/api/v1/scep/labels/corp", "test-token", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	var actions []string
	for _, e := range audit.entries {
		if e.ResourceType != "scep_label" {
			t.Errorf("audit resource type %q", e.ResourceType)
		}
		if strings.Contains(e.ChangeSummary, "very-secret-value") {
			t.Fatal("secret in audit")
		}
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"scep.label.create", "scep.label.delete"} {
		if !strings.Contains(strings.Join(actions, " "), want) {
			t.Errorf("no %s audit row in %v", want, actions)
		}
	}
}

func TestSCEPLabelRefusals(t *testing.T) {
	mux, auth, _, audit := newSCEPLabelMux(t)
	_, operatorKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	scepAPI(t, mux, http.MethodPost, "/api/v1/scep/labels", "test-token", validLabelBody())
	with := func(k string, v any) map[string]any {
		b := validLabelBody()
		b[k] = v
		return b
	}
	cases := []struct {
		name, method, path, token string
		body                      any
		want                      int
	}{
		{"anonymous", http.MethodPost, "/api/v1/scep/labels", "", validLabelBody(), http.StatusUnauthorized},
		{"operator", http.MethodPost, "/api/v1/scep/labels", operatorKey, with("label", "x"), http.StatusForbidden},
		{"operator list", http.MethodGet, "/api/v1/scep/labels", operatorKey, nil, http.StatusForbidden},
		{"duplicate", http.MethodPost, "/api/v1/scep/labels", "test-token", validLabelBody(), http.StatusConflict},
		{"underscore label", http.MethodPost, "/api/v1/scep/labels", "test-token", with("label", "mscep_admin"), http.StatusBadRequest},
		{"bad mode", http.MethodPost, "/api/v1/scep/labels", "test-token", with("mode", "static"), http.StatusBadRequest},
		{"tenant path trick", http.MethodPost, "/api/v1/scep/labels", "test-token", with("intune_tenant_id", "../x"), http.StatusBadRequest},
		{"no client", http.MethodPost, "/api/v1/scep/labels", "test-token", with("intune_client_id", ""), http.StatusBadRequest},
		{"no credential", http.MethodPost, "/api/v1/scep/labels", "test-token", with("credential_ref", ""), http.StatusBadRequest},
		{"unknown template", http.MethodPost, "/api/v1/scep/labels", "test-token", with("template_id", "nope"), http.StatusBadRequest},
		{"delete unknown", http.MethodDelete, "/api/v1/scep/labels/ghost", "test-token", nil, http.StatusNotFound},
		{"operator delete", http.MethodDelete, "/api/v1/scep/labels/corp", operatorKey, nil, http.StatusForbidden},
		{"put not offered", http.MethodPut, "/api/v1/scep/labels/corp", "test-token", validLabelBody(), http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		if rec := scepAPI(t, mux, c.method, c.path, c.token, c.body); rec.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
	if len(audit.entries) < len(cases) {
		t.Errorf("only %d audit rows for %d requests", len(audit.entries), len(cases))
	}
}

func TestSCEPLabelWrongCredentialTypeRefused(t *testing.T) {
	_, auth, _, _ := newSCEPLabelMux(t)
	mux := http.NewServeMux()
	// An ssh_key credential must not be usable as an Entra app credential.
	RegisterSCEPLabelHandlers(mux, auth, scep.NewMemLabelStore(), &fakeTemplateProvider{templates: map[string]TemplateItem{"tmpl-a": {}}},
		&renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeSSHKey}}, &scepRecordingAudit{})
	if rec := scepAPI(t, mux, http.MethodPost, "/api/v1/scep/labels", "test-token", validLabelBody()); rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}
