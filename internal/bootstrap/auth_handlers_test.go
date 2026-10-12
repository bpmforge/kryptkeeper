// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthHandlerReturnsUnauthorizedForInvalidCredentials(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_BOOTSTRAP_LOGIN_EMAIL", "admin@example.com")
	t.Setenv("APP_BOOTSTRAP_LOGIN_PASSWORD_HASH", "pbkdf2:sha256:29000$invalid$hash")

	auth := &Authenticator{
		config: authValidatorConfig{
			loginEnabled: true,
			loginSigning: "signing-secret",
			loginTTL:     5 * time.Minute,
			refreshTTL:   10 * time.Minute,
			loginPepper:  "pepper",
			loginUser: loginCredential{
				Email:        "admin@example.com",
				PasswordHash: apiKeyVerifier("correct-password", "pepper"),
				Role:         "pki-admin",
				Subject:      "team-1",
				Active:       true,
			},
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}

	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"wrong-password"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid credentials, got %d", rec.Code)
	}
	if got := rec.Body.String(); !strings.Contains(got, "invalid credentials") {
		t.Fatalf("expected login-specific unauthorized error body, got %s", got)
	}
	if got := rec.Body.String(); strings.Contains(got, "bearer token") {
		t.Fatalf("login failure must not mention bearer tokens, got %s", got)
	}
}

func TestAuthHandlerReturnsForbiddenForInactiveAccount(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := &Authenticator{
		config: authValidatorConfig{
			loginEnabled: true,
			loginSigning: "signing-secret",
			loginTTL:     5 * time.Minute,
			refreshTTL:   10 * time.Minute,
			loginPepper:  "pepper",
			loginUser: loginCredential{
				Email:        "admin@example.com",
				PasswordHash: apiKeyVerifier("correct-password", "pepper"),
				Role:         "pki-admin",
				Subject:      "team-1",
				Active:       false,
			},
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}

	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct-password"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for inactive account, got %d", rec.Code)
	}
	if got := rec.Body.String(); !strings.Contains(got, "account inactive") {
		t.Fatalf("expected account inactive error body, got %s", got)
	}
}

func TestAuthHandlerReturnsUnauthorizedForInvalidRefreshToken(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := &Authenticator{
		config:           authValidatorConfig{loginEnabled: true, loginSigning: "signing-secret", loginTTL: 5 * time.Minute, refreshTTL: 10 * time.Minute},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}

	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"invalid"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid refresh token, got %d", rec.Code)
	}
	if got := rec.Body.String(); !strings.Contains(got, "invalid refresh token") {
		t.Fatalf("expected refresh-specific unauthorized error body, got %s", got)
	}
	if got := rec.Body.String(); strings.Contains(got, "bearer token") {
		t.Fatalf("refresh failure must not mention bearer tokens, got %s", got)
	}
}

func TestAuthHandlerRateLimitsLoginAttempts(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := &Authenticator{
		config: authValidatorConfig{
			loginEnabled: true,
			loginSigning: "signing-secret",
			loginTTL:     5 * time.Minute,
			refreshTTL:   10 * time.Minute,
			loginPepper:  "pepper",
			loginUser: loginCredential{
				Email:        "admin@example.com",
				PasswordHash: apiKeyVerifier("correct-password", "pepper"),
				Role:         "pki-admin",
				Subject:      "team-1",
				Active:       true,
			},
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}

	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct-password"}`))
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected login attempt %d to succeed, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct-password"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after rate limit exceeded, got %d", rec.Code)
	}
}
