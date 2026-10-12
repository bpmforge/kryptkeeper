// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// flakyUserProvider wraps a real in-memory provider and fails ListUsers on
// demand, which is how a user-DB outage looks to the auth path.
type flakyUserProvider struct {
	UserProvider
	mu   sync.Mutex
	fail bool
}

func (p *flakyUserProvider) setFail(v bool) {
	p.mu.Lock()
	p.fail = v
	p.mu.Unlock()
}

func (p *flakyUserProvider) ListUsers(ctx context.Context) ([]UserRecord, error) {
	p.mu.Lock()
	fail := p.fail
	p.mu.Unlock()
	if fail {
		return nil, errors.New("db: connection refused")
	}
	return p.UserProvider.ListUsers(ctx)
}

type recordingAuditProvider struct {
	stubAuditProvider
	mu      sync.Mutex
	entries []AuditEntry
}

func (p *recordingAuditProvider) AppendEntry(_ context.Context, e AuditEntry) error {
	p.mu.Lock()
	p.entries = append(p.entries, e)
	p.mu.Unlock()
	return nil
}

// ListEntries serves the recorded entries newest first, filtered by the query
// fields the renewal scheduler reads its attempt history with.
func (p *recordingAuditProvider) ListEntries(_ context.Context, q AuditListQuery) (AuditListResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []AuditEntry{}
	for i := len(p.entries) - 1; i >= 0; i-- {
		e := p.entries[i]
		if (q.ActorID != "" && e.ActorID != q.ActorID) || (q.ResourceID != "" && e.ResourceID != q.ResourceID) || (q.Action != "" && e.Action != q.Action) {
			continue
		}
		out = append(out, e)
	}
	return AuditListResult{Entries: out, Total: len(out), Limit: q.Limit}, nil
}

func (p *recordingAuditProvider) count(action string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// newFailClosedAuth builds a bootstrap-mode Authenticator with a bootstrap
// token, API key auth and a flaky store holding one deactivated user.
func newFailClosedAuth(t *testing.T) (*Authenticator, *flakyUserProvider, *recordingAuditProvider) {
	t.Helper()
	auth := newTestSCIMAuthenticator()
	auth.config.bootstrapToken = "bootstrap-secret"
	auth.config.apiKeyAuthEnabled = true
	auth.config.apiKeyPepper = "key-pepper"
	auth.config.apiKeys = map[string]apiKeyRecord{
		"k1": {Kid: "k1", PrincipalID: "svc-1", Role: "service-account", Active: true, SecretVerifier: apiKeyVerifier("s3cret", "key-pepper")},
	}
	store := &flakyUserProvider{UserProvider: &fileUserProvider{users: []UserRecord{
		{ID: "gone-user", Email: "gone@example.com", Role: "pki-operator", Status: "deactivated"},
		{ID: "live-user", Email: "live@example.com", Role: "pki-operator", Status: "active"},
	}}}
	auth.userProvider = store
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, store, audit)
	return auth, store, audit
}

func sessionRequest(t *testing.T, auth *Authenticator, sub string) *http.Request {
	t.Helper()
	tok, err := mintHS256JWT(sub, "pki-operator", auth.config.loginSigning, auth.config.jwtIssuer, auth.config.jwtAudience, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

func TestAuthMiddleware_UserStoreErrorFailsClosedForSessionPrincipals(t *testing.T) {
	auth, store, audit := newFailClosedAuth(t)
	store.setFail(true)

	// The deactivated user's JWT is still cryptographically valid; with the
	// store down the old code let it through.
	_, err := auth.AuthenticatePrincipalDetails(sessionRequest(t, auth, "gone-user"), time.Now())
	if !errors.Is(err, errUserStoreUnavailable) {
		t.Fatalf("store error must refuse a session principal with errUserStoreUnavailable, got %v", err)
	}
	// Even a user that is fine in the store cannot be vouched for.
	if _, err := auth.AuthenticatePrincipalDetails(sessionRequest(t, auth, "live-user"), time.Now()); err == nil {
		t.Fatal("session principal must be refused while the store is unreachable")
	}
	if audit.count("authz.userstore_error") != 1 {
		t.Fatalf("want exactly one throttled authz.userstore_error audit row, got %d", audit.count("authz.userstore_error"))
	}

	// Recovery: the deactivated user is refused on the merits, the live one passes.
	store.setFail(false)
	if _, err := auth.AuthenticatePrincipalDetails(sessionRequest(t, auth, "gone-user"), time.Now()); err == nil || errors.Is(err, errUserStoreUnavailable) {
		t.Fatalf("deactivated user must be refused as unauthorized, got %v", err)
	}
	if _, err := auth.AuthenticatePrincipalDetails(sessionRequest(t, auth, "live-user"), time.Now()); err != nil {
		t.Fatalf("live user must pass once the store is back: %v", err)
	}
}

func TestAuthMiddleware_UserStoreErrorDoesNotAffectBootstrapAPIKeyOrEnvAdmin(t *testing.T) {
	auth, store, _ := newFailClosedAuth(t)
	store.setFail(true)

	bootstrapReq := httptest.NewRequest(http.MethodGet, "/x", nil)
	bootstrapReq.Header.Set("Authorization", "Bearer bootstrap-secret")
	if _, err := auth.AuthenticatePrincipalDetails(bootstrapReq, time.Now()); err != nil {
		t.Fatalf("bootstrap token must keep working during a store outage: %v", err)
	}

	keyReq := httptest.NewRequest(http.MethodGet, "/x", nil)
	keyReq.Header.Set("Authorization", "Bearer kk_k1_s3cret")
	pd, err := auth.AuthenticatePrincipalDetails(keyReq, time.Now())
	if err != nil || pd.AuthType != "api-key" {
		t.Fatalf("API key must keep working during a store outage: %v (%+v)", err, pd)
	}

	// The env-configured login admin is not a store identity either.
	if _, err := auth.AuthenticatePrincipalDetails(sessionRequest(t, auth, "local-admin"), time.Now()); err != nil {
		t.Fatalf("env login admin must keep working during a store outage: %v", err)
	}
}

func TestRefresh_UserStoreErrorFailsClosedAndKeepsToken(t *testing.T) {
	auth, store, audit := newFailClosedAuth(t)
	now := time.Now()
	auth.refreshSessions["rfr_gone"] = refreshSession{PrincipalID: "gone-user", Role: "pki-operator", ExpiresAt: now.Add(time.Hour)}
	auth.refreshSessions["rfr_admin"] = refreshSession{PrincipalID: "local-admin", Role: "pki-admin", ExpiresAt: now.Add(time.Hour)}
	store.setFail(true)

	if _, _, _, _, err := auth.Refresh("rfr_gone", now); !errors.Is(err, errUserStoreUnavailable) {
		t.Fatalf("refresh of a store-managed session must fail closed, got %v", err)
	}
	if _, ok := auth.refreshSessions["rfr_gone"]; !ok {
		t.Fatal("a store outage must not consume the client's refresh token")
	}
	if _, _, _, _, err := auth.Refresh("rfr_admin", now); err != nil {
		t.Fatalf("env login admin refresh must survive a store outage: %v", err)
	}

	// Through the HTTP handler: 503, not a token.
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, store, audit)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"rfr_gone"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("refresh handler: want 503 without tokens, got %d %s", rec.Code, rec.Body.String())
	}

	// Once the store is back the deactivated user is refused on the merits.
	store.setFail(false)
	if _, _, _, _, err := auth.Refresh("rfr_gone", now); !errors.Is(err, errInvalidRefreshToken) {
		t.Fatalf("deactivated user's refresh must be refused, got %v", err)
	}
}

func TestAuthzCheck_UserStoreErrorReturns503(t *testing.T) {
	auth, store, _ := newFailClosedAuth(t)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, store, &recordingAuditProvider{})
	store.setFail(true)

	rec := httptest.NewRecorder()
	req := sessionRequest(t, auth, "gone-user")
	req.URL.Path = "/api/v1/authz-check"
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 from authz-check during a store outage, got %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap token must still pass authz-check during an outage, got %d", rec.Code)
	}
}

func TestPreAuthBodies_OversizeRejectedWith413(t *testing.T) {
	auth, store, audit := newFailClosedAuth(t)
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, store, audit)
	registerAgentHandlers(mux, auth, NewAgentStore(), audit)

	pad := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		name, method, path, body string
		scim                     bool
	}{
		{"login", http.MethodPost, "/api/v1/auth/login", `{"email":"` + pad(maxAuthBodyBytes) + `"}`, false},
		{"refresh", http.MethodPost, "/api/v1/auth/refresh", `{"refresh_token":"` + pad(maxAuthBodyBytes) + `"}`, false},
		{"agent register", http.MethodPost, "/api/v1/agent/register", `{"name":"` + pad(maxAgentSmallBodyBytes) + `"}`, false},
		{"scim create user", http.MethodPost, "/scim/v2/Users", `{"userName":"` + pad(maxSCIMBodyBytes) + `"}`, true},
		{"scim patch user", http.MethodPatch, "/scim/v2/Users/live-user", `{"Operations":[],"x":"` + pad(maxSCIMBodyBytes) + `"}`, true},
		{"scim create group", http.MethodPost, "/scim/v2/Groups", `{"displayName":"` + pad(maxSCIMBodyBytes) + `"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
			if tc.scim {
				req.Header.Set("Authorization", "Bearer "+testSCIMBearerToken)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("want 413, got %d: %.200s", rec.Code, rec.Body.String())
			}
		})
	}

	// A body inside the cap is still handled normally (400 for bad JSON, not 413).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed small body: want 400, got %d", rec.Code)
	}
}

// Externally issued jwt/oidc bearer tokens are not store identities: a store
// outage must not take them down (deployments may run them with no user DB),
// but a confirmed deactivation still denies them.
func TestAuthMiddleware_BearerTokensFailOpenOnStoreErrorButHonourDeactivation(t *testing.T) {
	auth, store, _ := newFailClosedAuth(t)
	auth.config.mode = "jwt"
	auth.config.jwtHS256Secret = "bearer-secret"
	req := func(sub string) *http.Request {
		tok, err := mintHS256JWT(sub, "", "bearer-secret", "", "", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}

	store.setFail(true)
	if _, err := auth.AuthenticatePrincipalDetails(req("gone-user"), time.Now()); err != nil {
		t.Fatalf("bearer principal must not be blocked by a store outage: %v", err)
	}
	store.setFail(false)
	if _, err := auth.AuthenticatePrincipalDetails(req("gone-user"), time.Now()); err == nil {
		t.Fatal("confirmed-deactivated bearer subject must still be denied")
	}
}

func TestAgentInventory_LargePushWithinCapAccepted(t *testing.T) {
	auth, _, audit := newFailClosedAuth(t)
	t.Setenv("KRYPTKEEPER_AGENT_OPEN_REGISTRATION", "true")
	store := NewAgentStore()
	mux := http.NewServeMux()
	registerAgentHandlers(mux, auth, store, audit)

	id, token, err := store.register("a", AgentTypeLinux)
	if err != nil {
		t.Fatal(err)
	}
	// ~1000 certs is far beyond the old implicit limit of "none" but well
	// inside the 2 MiB cap; it must not be rejected.
	var b strings.Builder
	b.WriteString(`{"certs":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"fingerprint":"fp` + strings.Repeat("0", 60) + `","subject":"CN=host.example.com","issuer":"CN=ca","source":"/etc/ssl/x.pem"}`)
	}
	b.WriteString(`]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/inventory", strings.NewReader(b.String()))
	req.Header.Set("X-Agent-ID", id)
	req.Header.Set("X-Agent-Token", token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("1000-cert inventory must be accepted, got %d: %.200s", rec.Code, rec.Body.String())
	}
}

func TestAgentErrors_DoNotEchoInternalText(t *testing.T) {
	auth, _, audit := newFailClosedAuth(t)
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"closed by default", map[string]string{"KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS": "", "KRYPTKEEPER_AGENT_OPEN_REGISTRATION": ""}},
		{"wrong secret", map[string]string{"KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS": "right-secret", "KRYPTKEEPER_AGENT_OPEN_REGISTRATION": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			mux := http.NewServeMux()
			registerAgentHandlers(mux, auth, NewAgentStore(), audit)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(`{"name":"x","enrollment_secret":"nope"}`))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status must stay 403, got %d", rec.Code)
			}
			body := rec.Body.String()
			for _, leak := range []string{"KRYPTKEEPER_", "SECRETS", "OPEN_REGISTRATION", "configure", "gate", "invalid or missing"} {
				if strings.Contains(body, leak) {
					t.Fatalf("response leaks %q: %s", leak, body)
				}
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
				t.Fatalf("agent errors must use the JSON envelope, got Content-Type %q", ct)
			}
		})
	}
}
