// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type enrollEnv struct {
	mux      *http.ServeMux
	auth     *Authenticator
	store    AgentStore
	audit    *recordingAuditProvider
	adminTok string
	viewTok  string
}

// newEnrollEnv builds the agent routes with registration CLOSED (the default:
// no open flag, no secrets) and an admin + a viewer API key.
func newEnrollEnv(t *testing.T, store AgentStore) *enrollEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", agentTestToken)
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "off")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "")
	auth := NewAuthenticatorFromEnv()
	_, adminTok, err := auth.CreateAPIKey("enr-admin", "enr-admin", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, viewTok, err := auth.CreateAPIKey("enr-viewer", "enr-viewer", "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerAgentHandlers(mux, auth, store, audit)
	return &enrollEnv{mux: mux, auth: auth, store: store, audit: audit, adminTok: adminTok, viewTok: viewTok}
}

func (e *enrollEnv) do(method, path, bearer, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *enrollEnv) hasAudit(action string, outcome AuditOutcome) bool {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	for _, en := range e.audit.entries {
		if en.Action == action && en.Outcome == outcome {
			return true
		}
	}
	return false
}

// storeVariants runs fn against the in-memory and sqlite stores.
func storeVariants(t *testing.T, fn func(t *testing.T, store AgentStore)) {
	t.Run("mem", func(t *testing.T) { fn(t, NewAgentStore()) })
	t.Run("sqlite", func(t *testing.T) { fn(t, newTestDBAgentStore(t)) })
}

func TestRegister_NoEvidence_401_ByDefault(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		e := newEnrollEnv(t, store)
		w := e.do("POST", "/api/v1/agent/register", "", `{"name":"x"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
		if !e.hasAudit("agent.register", AuditOutcomeDenied) {
			t.Fatal("denial not audited")
		}
		w = e.do("POST", "/api/v1/agent/register", "", `{"name":"x","enrollment_secret":"nope"}`, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("bad evidence want 403, got %d", w.Code)
		}
	})
}

func TestRegister_OpenFlag_AllowsLegacy(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
		auth := newAgentTestAuth(t)
		mux := http.NewServeMux()
		registerAgentHandlers(mux, auth, store, stubAuditProvider{})
		req := httptest.NewRequest("POST", "/api/v1/agent/register", bytes.NewBufferString(`{"name":"legacy"}`))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("legacy open: %d", w.Code)
		}
	})
}

func TestRegister_ExistingAgentsKeepWorking(t *testing.T) {
	storeVariants(t, func(t *testing.T, store AgentStore) {
		id, tok, err := store.register("old-agent", AgentTypeLinux)
		if err != nil {
			t.Fatal(err)
		}
		e := newEnrollEnv(t, store) // registration closed
		w := e.do("POST", "/api/v1/agent/heartbeat", "", "", map[string]string{"X-Agent-ID": id, "X-Agent-Token": tok})
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d", w.Code)
		}
	})
}
