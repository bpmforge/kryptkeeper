// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSafeRelativeRedirect_OpenRedirectTable(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"/ok?x=1", "/ok?x=1"},
		{"/dashboard/certs#top", "/dashboard/certs#top"},
		{"/", "/"},
		{"//evil.example", "/fallback"},
		{`/\evil.example`, "/fallback"},
		{`/ok\..\evil`, "/fallback"},
		{"https://evil.example", "/fallback"},
		{"javascript:alert(1)", "/fallback"},
		{"/ok\r\nSet-Cookie: x=1", "/fallback"},
		{"/ok\x00", "/fallback"},
		{"/ok\x7f", "/fallback"},
		{"", "/fallback"},
		{"ok", "/fallback"},
	}
	for _, tc := range cases {
		if got := safeRelativeRedirect(tc.raw, "/fallback"); got != tc.want {
			t.Errorf("safeRelativeRedirect(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func sessionCookieSecure(t *testing.T, r *http.Request) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	setSessionCookie(rec, r, "tok", 60)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kk_token" {
			return c.Secure
		}
	}
	t.Fatal("no kk_token cookie set")
	return false
}

func TestSessionCookieSecure(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")

	plain := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	plain.RemoteAddr = "203.0.113.5:1234"
	if sessionCookieSecure(t, plain) {
		t.Error("plain HTTP from a direct client must not be Secure")
	}

	tlsReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	tlsReq.RemoteAddr = "203.0.113.5:1234"
	tlsReq.TLS = &tls.ConnectionState{}
	if !sessionCookieSecure(t, tlsReq) {
		t.Error("a request on the hub's own TLS listener must be Secure")
	}

	// Never drop Secure on TLS, whatever a (spoofable) header says.
	tlsReq.Header.Set("X-Forwarded-Proto", "http")
	if !sessionCookieSecure(t, tlsReq) {
		t.Error("X-Forwarded-Proto: http must not remove Secure from a TLS request")
	}

	spoofed := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	spoofed.RemoteAddr = "203.0.113.5:1234"
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	if sessionCookieSecure(t, spoofed) {
		t.Error("X-Forwarded-Proto from an untrusted peer must be ignored")
	}

	proxied := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	proxied.RemoteAddr = "10.1.2.3:1234"
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if !sessionCookieSecure(t, proxied) {
		t.Error("X-Forwarded-Proto: https from a trusted proxy must be Secure")
	}
}

func newLoginMux(t *testing.T) (*http.ServeMux, *Authenticator) {
	t.Helper()
	auth := &Authenticator{
		config: authValidatorConfig{
			loginEnabled:      true,
			loginSigning:      "signing-secret-0123456789abcdef0123456789",
			loginTTL:          5 * time.Minute,
			refreshTTL:        10 * time.Minute,
			loginPepper:       "pepper",
			apiKeyPepper:      "api-pepper",
			apiKeys:           map[string]apiKeyRecord{},
			loginUser:         loginCredential{Email: "admin@example.com", PasswordHash: apiKeyVerifier("correct-password", "pepper"), Role: "pki-admin", Subject: "team-1", Active: true},
			mode:              "bootstrap",
			bootstrapToken:    "bootstrap-token-0123456789abcdef0123456789",
			apiKeyAuthEnabled: true,
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
		userProvider:     &stubUserProvider{},
	}
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})
	return mux, auth
}

func TestSecurityHeaders_NoStoreOnSecretResponses(t *testing.T) {
	mux, _ := newLoginMux(t)
	handler := withSecurityHeaders(mux)

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct-password"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", login.Code, login.Body.String())
	}
	for _, rec := range []*httptest.ResponseRecorder{login} {
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
		if got := rec.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("Pragma = %q, want no-cache", got)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("missing X-Content-Type-Options: nosniff")
		}
		if rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Error("missing Referrer-Policy: no-referrer")
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Error("missing X-Frame-Options: DENY")
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Error("missing CSP frame-ancestors 'none'")
		}
		if rec.Header().Get("Strict-Transport-Security") != "" {
			t.Error("HSTS must not be sent over plain HTTP")
		}
	}

	var access string
	for _, c := range login.Result().Cookies() {
		if c.Name == "kk_token" {
			access = c.Value
		}
	}
	create := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"name":"k","principal_id":"svc-1","role":"service-account"}`))
	req.Header.Set("Authorization", "Bearer "+access)
	handler.ServeHTTP(create, req)
	if create.Code != http.StatusCreated {
		t.Fatalf("api-key create = %d: %s", create.Code, create.Body.String())
	}
	if got := create.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("api-key create Cache-Control = %q, want no-store", got)
	}
}

func TestSecurityHeaders_HSTSOnlyOnTLSAndNoStoreOnlyUnderAPI(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	secure := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	secure.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, secure)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS expected on a TLS request")
	}

	crl := httptest.NewRecorder()
	h.ServeHTTP(crl, httptest.NewRequest(http.MethodGet, "/crl/ca.crl", nil))
	if got := crl.Header().Get("Cache-Control"); got != "" {
		t.Errorf("non-API path must not get a Cache-Control default, got %q", got)
	}
}
