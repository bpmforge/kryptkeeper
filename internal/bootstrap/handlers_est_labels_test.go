// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/est"
)

func newESTLabelMux(t *testing.T) (*http.ServeMux, *Authenticator, *est.MemLabelStore, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_BASE_URL", "https://hub.example.com/")
	auth := NewAuthenticatorFromEnv()
	store := est.NewMemLabelStore()
	audit := &scepRecordingAudit{}
	tpls := &fakeTemplateProvider{templates: map[string]TemplateItem{"tmpl-a": {}, "tmpl-b": {}}}
	mux := http.NewServeMux()
	RegisterESTLabelHandlers(mux, auth, store, tpls, audit)
	return mux, auth, store, audit
}

func TestESTLabelCRUD(t *testing.T) {
	mux, _, _, audit := newESTLabelMux(t)
	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/est/labels", "test-token",
		map[string]any{"label": "iot", "template_id": "tmpl-a", "description": "sensors"})
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"url":"https://hub.example.com/.well-known/est/iot/"`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodGet, "/api/v1/est/labels", "test-token", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "iot") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodGet, "/api/v1/est/labels/iot", "test-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	rec = scepAPI(t, mux, http.MethodPut, "/api/v1/est/labels/iot", "test-token", map[string]any{"template_id": "tmpl-b", "description": "x"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tmpl-b") {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scepAPI(t, mux, http.MethodDelete, "/api/v1/est/labels/iot", "test-token", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := scepAPI(t, mux, http.MethodGet, "/api/v1/est/labels/iot", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", rec.Code)
	}
	var actions []string
	for _, e := range audit.entries {
		if e.ResourceType != "est_label" {
			t.Errorf("audit resource type %q", e.ResourceType)
		}
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"est.label.create", "est.label.update", "est.label.delete"} {
		if !strings.Contains(strings.Join(actions, " "), want) {
			t.Errorf("no %s audit row in %v", want, actions)
		}
	}
}

func TestESTLabelRefusals(t *testing.T) {
	mux, auth, _, audit := newESTLabelMux(t)
	_, operatorKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	scepAPI(t, mux, http.MethodPost, "/api/v1/est/labels", "test-token", map[string]any{"label": "dup", "template_id": "tmpl-a"})
	for _, tc := range []struct {
		name, method, path, token string
		body                      map[string]any
		want                      int
	}{
		{"anonymous", http.MethodPost, "/api/v1/est/labels", "", map[string]any{"label": "x", "template_id": "tmpl-a"}, http.StatusUnauthorized},
		{"operator", http.MethodPost, "/api/v1/est/labels", operatorKey, map[string]any{"label": "x", "template_id": "tmpl-a"}, http.StatusForbidden},
		{"operator list", http.MethodGet, "/api/v1/est/labels", operatorKey, nil, http.StatusForbidden},
		{"template missing", http.MethodPost, "/api/v1/est/labels", "test-token", map[string]any{"label": "x", "template_id": "nope"}, http.StatusBadRequest},
		{"no template", http.MethodPost, "/api/v1/est/labels", "test-token", map[string]any{"label": "x"}, http.StatusBadRequest},
		{"reserved", http.MethodPost, "/api/v1/est/labels", "test-token", map[string]any{"label": "cacerts", "template_id": "tmpl-a"}, http.StatusBadRequest},
		{"malformed", http.MethodPost, "/api/v1/est/labels", "test-token", map[string]any{"label": "Bad_One", "template_id": "tmpl-a"}, http.StatusBadRequest},
		{"duplicate", http.MethodPost, "/api/v1/est/labels", "test-token", map[string]any{"label": "dup", "template_id": "tmpl-a"}, http.StatusConflict},
		{"update unknown", http.MethodPut, "/api/v1/est/labels/ghost", "test-token", map[string]any{"template_id": "tmpl-a"}, http.StatusNotFound},
		{"update template missing", http.MethodPut, "/api/v1/est/labels/dup", "test-token", map[string]any{"template_id": "nope"}, http.StatusBadRequest},
		{"update label mismatch", http.MethodPut, "/api/v1/est/labels/dup", "test-token", map[string]any{"label": "other", "template_id": "tmpl-a"}, http.StatusBadRequest},
		{"delete unknown", http.MethodDelete, "/api/v1/est/labels/ghost", "test-token", nil, http.StatusNotFound},
		{"get unknown", http.MethodGet, "/api/v1/est/labels/ghost", "test-token", nil, http.StatusNotFound},
	} {
		before := len(audit.entries)
		if rec := scepAPI(t, mux, tc.method, tc.path, tc.token, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
		if tc.method != http.MethodGet && len(audit.entries) == before {
			t.Errorf("%s: no audit row", tc.name)
		}
	}
}
