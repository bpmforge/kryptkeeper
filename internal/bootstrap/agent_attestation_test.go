// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// W5-07: agent registration is closed by default; secrets or the
// explicit migration flag open it.

func newAttestationMux(t *testing.T) *http.ServeMux {
	t.Helper()
	store := NewAgentStore()
	mux := http.NewServeMux()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "attestation-test-token")
	auth := NewAuthenticatorFromEnv()
	registerAgentHandlers(mux, auth, store, stubAuditProvider{})
	return mux
}

func postRegister(t *testing.T, mux *http.ServeMux, body map[string]string, header string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", bytes.NewReader(raw))
	if header != "" {
		req.Header.Set("X-Enrollment-Secret", header)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAgentRegistrationClosedByDefault(t *testing.T) {
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	mux := newAttestationMux(t)

	// W33-24: no evidence at all is 401; presented-but-invalid stays 403.
	rec := postRegister(t, mux, map[string]string{"name": "anon", "type": "linux"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous registration must be refused by default, got %d: %s", rec.Code, rec.Body.String())
	}
	// The operator hint lives in the server log; an unauthenticated caller
	// must not learn which env vars gate enrollment (FB-14 / EH-004).
	if strings.Contains(rec.Body.String(), "KRYPTKEEPER_") {
		t.Fatalf("refusal must not echo gate internals to the caller, got: %s", rec.Body.String())
	}
}

func TestAgentRegistrationRequiresMatchingSecret(t *testing.T) {
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "prov-secret-one, prov-secret-two")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	mux := newAttestationMux(t)

	// Missing secret: refused (401, no evidence presented — W33-24).
	rec := postRegister(t, mux, map[string]string{"name": "a1", "type": "linux"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing secret must be refused, got %d", rec.Code)
	}
	// Wrong secret: refused.
	rec = postRegister(t, mux, map[string]string{"name": "a1", "type": "linux", "enrollment_secret": "guess"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong secret must be refused, got %d", rec.Code)
	}
	// Correct secret in body: enrolled.
	rec = postRegister(t, mux, map[string]string{"name": "a1", "type": "linux", "enrollment_secret": "prov-secret-one"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid secret must enrol, got %d: %s", rec.Code, rec.Body.String())
	}
	// Rotation: the second configured secret also works, via the header.
	rec = postRegister(t, mux, map[string]string{"name": "a2", "type": "linux"}, "prov-secret-two")
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotated secret must enrol, got %d: %s", rec.Code, rec.Body.String())
	}
	// The token contract is intact.
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["agent_id"] == "" || resp["token"] == "" {
		t.Fatalf("registration response contract broken: %s", rec.Body.String())
	}
}

func TestAgentRegistrationSecretsWinOverOpenFlag(t *testing.T) {
	// Once secrets exist they are REQUIRED, even if someone forgot to
	// remove the migration flag.
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "the-secret")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	mux := newAttestationMux(t)

	rec := postRegister(t, mux, map[string]string{"name": "sneaky", "type": "linux"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("secrets must override the open flag, got %d", rec.Code)
	}
	rec = postRegister(t, mux, map[string]string{"name": "legit", "type": "linux", "enrollment_secret": "the-secret"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid secret must still enrol, got %d", rec.Code)
	}
}

func TestAgentRegistrationLegacyOpenFlagPreservesOldBehaviour(t *testing.T) {
	// The documented migration bridge: existing provisioning keeps
	// working while secrets are rolled out.
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	mux := newAttestationMux(t)

	rec := postRegister(t, mux, map[string]string{"name": "legacy", "type": "linux"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("open-registration flag must preserve legacy behaviour, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---- W29-06: per-agent single-use enrollment tokens ----

type recAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *recAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (a *recAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}
func (a *recAudit) has(action string, outcome AuditOutcome) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

type tokenEnv struct {
	mux             *http.ServeMux
	store           AgentStore
	audit           *recAudit
	adminTok, vwTok string
}

func newTokenEnv(t *testing.T, store AgentStore) *tokenEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "attestation-test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	auth := NewAuthenticatorFromEnv()
	_, admin, err := auth.CreateAPIKey("a", "a", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, viewer, err := auth.CreateAPIKey("v", "v", "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := &tokenEnv{mux: http.NewServeMux(), store: store, audit: &recAudit{}, adminTok: admin, vwTok: viewer}
	registerAgentHandlers(e.mux, auth, store, e.audit)
	return e
}

func (e *tokenEnv) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *tokenEnv) mint(t *testing.T, body string) (id, token string) {
	t.Helper()
	rec := e.do(http.MethodPost, "/api/v1/agent/enrollment-tokens", e.adminTok, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mint response must be no-store")
	}
	var resp struct {
		Data struct{ ID, Token string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !strings.HasPrefix(resp.Data.Token, "kkenr_") {
		t.Fatalf("bad mint body: %s", rec.Body.String())
	}
	return resp.Data.ID, resp.Data.Token
}

func eachAgentStore(t *testing.T, f func(t *testing.T, store AgentStore)) {
	t.Run("mem", func(t *testing.T) { f(t, NewAgentStore()) })
	t.Run("db", func(t *testing.T) { f(t, newTestDBAgentStore(t)) })
}

func TestEnrollmentTokenRedeemOnce(t *testing.T) {
	eachAgentStore(t, func(t *testing.T, store AgentStore) {
		e := newTokenEnv(t, store)
		_, tok := e.mint(t, `{"label":"web-01"}`)
		rec := e.do(http.MethodPost, "/api/v1/agent/register", "", `{"name":"web-01","type":"linux","enrollment_token":"`+tok+`"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("first redeem: %d %s", rec.Code, rec.Body.String())
		}
		var resp map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["agent_id"] == "" || resp["token"] == "" {
			t.Fatalf("no per-agent credentials: %s", rec.Body.String())
		}
		rec = e.do(http.MethodPost, "/api/v1/agent/register", "", `{"name":"web-02","enrollment_token":"`+tok+`"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("second redeem must be refused, got %d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), tok) {
			t.Fatal("refusal leaked the token")
		}
		if !e.audit.has("agent.register", AuditOutcomeSuccess) || !e.audit.has("agent.register", AuditOutcomeDenied) {
			t.Fatal("register success and refusal must both be audited")
		}
	})
}

func TestEnrollmentTokenHeaderAndNoSecretFallback(t *testing.T) {
	e := newTokenEnv(t, NewAgentStore())
	_, tok := e.mint(t, `{}`)
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "shared-one")
	mux := http.NewServeMux()
	registerAgentHandlers(mux, NewAuthenticatorFromEnv(), e.store, e.audit)
	// Valid secret + bad token: the token path is exclusive, so refused.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(`{"name":"x","enrollment_secret":"shared-one"}`))
	req.Header.Set("X-Enrollment-Token", "kkenr_bogus")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad token must not fall back to the secret, got %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("X-Enrollment-Token", tok)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("header token must enrol, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestEnrollmentTokenExpired(t *testing.T) {
	eachAgentStore(t, func(t *testing.T, store AgentStore) {
		now := time.Now().UTC()
		_, secret, err := store.mintEnrollmentToken("x", "admin", DefaultTenant, time.Second, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.redeemEnrollmentToken(secret, "agent-x", now.Add(2*time.Second)); err != ErrEnrollmentTokenInvalid {
			t.Fatalf("expired token must be refused, got %v", err)
		}
		_, secret2, _ := store.mintEnrollmentToken("y", "admin", DefaultTenant, time.Hour, now)
		if _, err := store.redeemEnrollmentToken(secret2, "agent-y", now.Add(time.Minute)); err != nil {
			t.Fatalf("unexpired token must redeem: %v", err)
		}
	})
}

func TestEnrollmentTokenRevoked(t *testing.T) {
	eachAgentStore(t, func(t *testing.T, store AgentStore) {
		e := newTokenEnv(t, store)
		id, tok := e.mint(t, `{}`)
		if rec := e.do(http.MethodDelete, "/api/v1/agent/enrollment-tokens/"+id, e.adminTok, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("revoke: %d", rec.Code)
		}
		if rec := e.do(http.MethodDelete, "/api/v1/agent/enrollment-tokens/"+id, e.adminTok, ""); rec.Code != http.StatusConflict {
			t.Fatalf("re-revoke must 409, got %d", rec.Code)
		}
		if rec := e.do(http.MethodDelete, "/api/v1/agent/enrollment-tokens/aet-nope", e.adminTok, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("absent id must 404, got %d", rec.Code)
		}
		if rec := e.do(http.MethodPost, "/api/v1/agent/register", "", `{"name":"x","enrollment_token":"`+tok+`"}`); rec.Code != http.StatusForbidden {
			t.Fatalf("revoked token must be refused, got %d", rec.Code)
		}
		if !e.audit.has("agent.token_revoke", AuditOutcomeSuccess) || !e.audit.has("agent.token_revoke", AuditOutcomeFailure) {
			t.Fatal("agent.token_revoke success and failure must be audited")
		}
	})
}

func TestRevokeEnrollmentTokenAudits(t *testing.T) {
	e := newTokenEnv(t, NewAgentStore())
	id, _ := e.mint(t, `{}`)
	if rec := e.do(http.MethodDelete, "/api/v1/agent/enrollment-tokens/"+id, e.vwTok, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer revoke: %d", rec.Code)
	}
	if !e.audit.has("agent.token_revoke", AuditOutcomeDenied) {
		t.Fatal("denied revoke must be audited")
	}
}

func TestEnrollmentTokenNonAdminCannotMint(t *testing.T) {
	e := newTokenEnv(t, NewAgentStore())
	for _, tok := range []string{e.vwTok, ""} {
		rec := e.do(http.MethodPost, "/api/v1/agent/enrollment-tokens", tok, `{}`)
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
			t.Fatalf("non-admin mint must be refused, got %d", rec.Code)
		}
	}
	if rec := e.do(http.MethodGet, "/api/v1/agent/enrollment-tokens", e.vwTok, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer list: %d", rec.Code)
	}
	if !e.audit.has("agent.token_mint", AuditOutcomeDenied) {
		t.Fatal("denied mint must be audited")
	}
}

func TestEnrollmentTokenTTLValidation(t *testing.T) {
	e := newTokenEnv(t, NewAgentStore())
	for _, body := range []string{`{"ttl_seconds":604801}`, `{"ttl_seconds":-1}`, `not json`} {
		if rec := e.do(http.MethodPost, "/api/v1/agent/enrollment-tokens", e.adminTok, body); rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("%s: want 400, got %d", body, rec.Code)
		}
	}
	if !e.audit.has("agent.token_mint", AuditOutcomeFailure) {
		t.Fatal("rejected mint must be audited")
	}
}

func TestEnrollmentTokenNeverStoredPlain(t *testing.T) {
	s := newTestDBAgentStore(t)
	e := newTokenEnv(t, s)
	id, tok := e.mint(t, `{"label":"l"}`)
	var hash string
	if err := s.db.QueryRow("SELECT token_hash FROM agent_enrollment_tokens WHERE id = ?", id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == "" || hash == tok || strings.Contains(hash, tok) {
		t.Fatalf("token must be stored hashed, got %q", hash)
	}
	rec := e.do(http.MethodGet, "/api/v1/agent/enrollment-tokens", e.adminTok, "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), tok) || strings.Contains(rec.Body.String(), hash) {
		t.Fatalf("list must not expose secret or hash: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSharedSecretStillWorksAndWarns(t *testing.T) {
	buf := captureLog(t)
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "legacy-shared-secret-value")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "")
	mux := newAttestationMux(t)
	rec := postRegister(t, mux, map[string]string{"name": "a", "enrollment_secret": "legacy-shared-secret-value"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("shared secret must still enrol, got %d", rec.Code)
	}
	if !strings.Contains(buf.String(), "shared, reusable secret") {
		t.Fatalf("expected shared-secret warning, log: %s", buf.String())
	}
	if strings.Contains(buf.String(), "legacy-shared-secret-value") {
		t.Fatal("secret value must never be logged")
	}
}

func TestOpenRegistrationWarnsLoudly(t *testing.T) {
	buf := captureLog(t)
	t.Setenv("KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS", "some-secret")
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	_ = NewAgentEnrollmentGateFromEnv()
	if !strings.Contains(buf.String(), "WARNING: LOUD:") {
		t.Fatalf("open registration must warn loudly even with secrets set, log: %s", buf.String())
	}
	if strings.Contains(buf.String(), "some-secret") {
		t.Fatal("secret value must never be logged")
	}
}

func TestRegisterBadNameDoesNotBurnToken(t *testing.T) {
	e := newTokenEnv(t, NewAgentStore())
	_, tok := e.mint(t, `{}`)
	if rec := e.do(http.MethodPost, "/api/v1/agent/register", "", `{"enrollment_token":"`+tok+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if rec := e.do(http.MethodPost, "/api/v1/agent/register", "", `{"name":"ok","enrollment_token":"`+tok+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("token must still be usable, got %d", rec.Code)
	}
}
