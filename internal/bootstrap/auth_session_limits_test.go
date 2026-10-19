// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// limitsAuth builds the authenticator from the environment so the assertions
// cover the shipped defaults, not a hand-set test config.
func limitsAuth(t *testing.T, env map[string]string) *Authenticator {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "limits-bootstrap-token-0123456789abcdef")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", testLoginSigning)
	for k, v := range env {
		t.Setenv(k, v)
	}
	auth := NewAuthenticatorFromEnv()
	// Refresh re-reads the user store; give it the one account these tests use
	// rather than whatever the environment's provider could reach.
	auth.userProvider = &stubUserProvider{users: []UserRecord{{ID: "user-1", Email: "u@example.com", Role: "pki-operator", Status: "active"}}}
	return auth
}

func TestSessionLimits_DefaultAccessTokenLifetimeIs15Minutes(t *testing.T) {
	auth := limitsAuth(t, nil)
	now := time.Now()
	access, ttl, _, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := decodeJWTPayloadClaims(access)
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := claims["exp"].(float64)
	if got := int64(exp) - now.Unix(); got != 900 || ttl != 900 {
		t.Fatalf("access token lifetime = %ds (reported %ds), want 900s (15 min)", got, ttl)
	}
}

func TestSessionLimits_IdleTimeout(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		after   time.Duration
		wantErr bool
	}{
		{"default 30 min: +29 min succeeds", nil, 29 * time.Minute, false},
		{"default 30 min: +31 min fails", nil, 31 * time.Minute, true},
		{"configured 60s: +2 min fails", map[string]string{"APP_AUTH_IDLE_TIMEOUT_SEC": "60"}, 2 * time.Minute, true},
		{"configured 60s: +30s succeeds", map[string]string{"APP_AUTH_IDLE_TIMEOUT_SEC": "60"}, 30 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := limitsAuth(t, tc.env)
			now := time.Now()
			_, _, refresh, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, _, err = auth.Refresh(refresh, now.Add(tc.after))
			if tc.wantErr != errors.Is(err, errInvalidRefreshToken) || (!tc.wantErr && err != nil) {
				t.Fatalf("Refresh after %s: err = %v, wantErr = %v", tc.after, err, tc.wantErr)
			}
		})
	}
}

func TestSessionLimits_RefreshRotationResetsIdleClockAndKillsOldToken(t *testing.T) {
	auth := limitsAuth(t, nil)
	now := time.Now()
	_, _, first, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, second, _, err := auth.Refresh(first, now.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if second == first {
		t.Fatal("refresh must rotate the token")
	}
	if _, _, _, _, err := auth.Refresh(first, now.Add(21*time.Minute)); !errors.Is(err, errInvalidRefreshToken) {
		t.Fatalf("reusing the rotated-out token: err = %v, want errInvalidRefreshToken", err)
	}
	// 20 + 25 = 45 minutes after login: past the idle window of the ORIGINAL
	// token, but only 25 minutes idle for the rotated one.
	if _, _, _, _, err := auth.Refresh(second, now.Add(45*time.Minute)); err != nil {
		t.Fatalf("rotated token within its own idle window: %v", err)
	}
}

func TestSessionLimits_LogoutRevokesRefreshToken(t *testing.T) {
	auth := limitsAuth(t, nil)
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})
	now := time.Now()

	_, _, viaBody, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"`+viaBody+`"}`)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if _, _, _, _, err := auth.Refresh(viaBody, now.Add(time.Minute)); !errors.Is(err, errInvalidRefreshToken) {
		t.Fatalf("Refresh after logout with a body-supplied token: err = %v, want errInvalidRefreshToken", err)
	}
}
