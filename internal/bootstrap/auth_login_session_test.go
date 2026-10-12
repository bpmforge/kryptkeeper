// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testLoginSigning = "signing-secret-0123456789abcdef0123456789"

func newLoginAuth(passwordHash string, users ...UserRecord) *Authenticator {
	return &Authenticator{
		config: authValidatorConfig{
			mode:           "bootstrap",
			bootstrapToken: "bootstrap-token-0123456789abcdef0123456789",
			loginEnabled:   true,
			loginSigning:   testLoginSigning,
			loginTTL:       5 * time.Minute,
			refreshTTL:     10 * time.Minute,
			loginPepper:    "pepper",
			loginUser:      loginCredential{Email: "admin@example.com", PasswordHash: passwordHash, Role: "pki-admin", Subject: "team-1", Active: true},
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
		userProvider:     &stubUserProvider{users: users},
	}
}

func TestLoginPasswordHash_LegacyHMACVerifiesAndIsRehashedToArgon2id(t *testing.T) {
	legacy := apiKeyVerifier("correct-password", "pepper")
	auth := newLoginAuth(legacy)
	now := time.Now()

	if _, _, _, _, _, err := auth.Login("admin@example.com", "wrong", now); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("wrong password: err = %v", err)
	}
	if got := auth.loginPasswordHash(); got != legacy {
		t.Fatalf("a failed login must not touch the verifier")
	}
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-password", now); err != nil {
		t.Fatalf("legacy hash must still verify once: %v", err)
	}
	upgraded := auth.loginPasswordHash()
	if !strings.HasPrefix(upgraded, "$argon2id$v=19$") {
		t.Fatalf("verifier not upgraded to Argon2id: %q", upgraded)
	}
	if auth.config.loginUser.PasswordHash != legacy {
		t.Fatal("the shared config must not be mutated (race with unlocked readers)")
	}
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-password", now); err != nil {
		t.Fatalf("login against the upgraded Argon2id verifier failed: %v", err)
	}
	if _, _, _, _, _, err := auth.Login("admin@example.com", "wrong", now); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("wrong password against Argon2id: err = %v", err)
	}
}

func TestLoginPasswordHash_ConfiguredArgon2idVerifies(t *testing.T) {
	hash, err := HashLoginPassword("correct-password", "pepper")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := HashLoginPassword("correct-password", "pepper")
	if hash == other {
		t.Fatal("salt must differ between hashes")
	}
	auth := newLoginAuth(hash)
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-password", time.Now()); err != nil {
		t.Fatalf("argon2id login: %v", err)
	}
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-passwor", time.Now()); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("near-miss password must fail: %v", err)
	}
	// A different pepper must not verify the same stored hash.
	auth.config.loginPepper = "other-pepper"
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-password", time.Now().Add(time.Hour)); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("wrong pepper must fail: %v", err)
	}
}

func TestVerifyLoginPassword_RejectsMalformedAndOutOfRangeHashes(t *testing.T) {
	for _, stored := range []string{
		"$argon2id$v=19$m=19456,t=2,p=1$short$AAAA",
		"$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$garbage",
	} {
		if ok, _ := verifyLoginPassword("x", "", stored); ok {
			t.Errorf("malformed hash %q must never match", stored)
		}
	}
}

func loginViaHandler(t *testing.T, mux *http.ServeMux) (access, refresh string, cookie *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct-password"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kk_token" {
			cookie = c
		}
	}
	return body.Data.AccessToken, body.Data.RefreshToken, cookie
}

func postRefresh(mux *http.ServeMux, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+token+`"}`)))
	return rec
}

func TestLogout_RevokesRefreshToken(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	_, refresh, cookie := loginViaHandler(t, mux)
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if got := postRefresh(mux, refresh); got.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout = %d, want 401", got.Code)
	}
}

func TestLogout_RevokesBodySuppliedRefreshTokenWithoutCookie(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	_, refresh, _ := loginViaHandler(t, mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"`+refresh+`"}`)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if got := postRefresh(mux, refresh); got.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout = %d, want 401", got.Code)
	}
}

func TestRefresh_ReResolvesRoleFromStore(t *testing.T) {
	auth := newLoginAuth("unused", UserRecord{ID: "user-1", Email: "u@example.com", Role: "pki-admin", Status: "active"})
	now := time.Now()
	_, _, refresh, _, err := auth.mintSessionForUser("user-1", "pki-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.userProvider.UpdateUser(context.Background(), "user-1", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	access, _, _, _, err := auth.Refresh(refresh, now)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := jwtRoleClaim(access); got != "viewer" {
		t.Fatalf("role after refresh = %q, want the store's current role", got)
	}
}

func TestRefresh_DisabledUserDenied(t *testing.T) {
	auth := newLoginAuth("unused", UserRecord{ID: "user-1", Email: "u@example.com", Role: "pki-admin", Status: "active"})
	now := time.Now()
	_, _, refresh, _, err := auth.mintSessionForUser("user-1", "pki-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.userProvider.UpdateUser(context.Background(), "user-1", "", "inactive"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := auth.Refresh(refresh, now); !errors.Is(err, errInvalidRefreshToken) {
		t.Fatalf("refresh for a disabled user: err = %v, want errInvalidRefreshToken", err)
	}
}

func TestRefresh_LocalUserFollowsConfig(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	now := time.Now()
	_, _, refresh, _, _, err := auth.Login("admin@example.com", "correct-password", now)
	if err != nil {
		t.Fatal(err)
	}
	auth.config.loginUser.Active = false
	if _, _, _, _, err := auth.Refresh(refresh, now); !errors.Is(err, errInvalidRefreshToken) {
		t.Fatalf("refresh for a deactivated local user: err = %v", err)
	}
}

func TestLogin_PerAccountBackoff(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	now := time.Now()
	for i := 0; i < loginBackoffThreshold; i++ {
		if _, _, _, _, _, err := auth.Login("admin@example.com", "wrong", now); !errors.Is(err, errInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Locked: even the right password is refused, with the same error.
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-password", now.Add(time.Second)); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("locked account must answer like a wrong password, got %v", err)
	}
	// Case-insensitive account key.
	if _, _, _, _, _, err := auth.Login("ADMIN@example.com", "correct-password", now.Add(time.Second)); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("lockout must not be bypassable by changing case, got %v", err)
	}
	// Once the window passes the account works again, and success clears it.
	later := now.Add(loginBackoffBase + time.Second)
	if _, _, _, _, _, err := auth.Login("admin@example.com", "correct-password", later); err != nil {
		t.Fatalf("login after the lockout window: %v", err)
	}
	if auth.loginLockedOut(loginAccountKey("admin@example.com"), later) {
		t.Fatal("success must clear the failure record")
	}
}

func TestLogin_BackoffGrowsAndIsBounded(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	now := time.Now()
	key := loginAccountKey("admin@example.com")
	for i := 0; i < 20; i++ {
		auth.recordLoginFailure(key, now)
	}
	if !auth.loginLockedOut(key, now.Add(loginBackoffMax-time.Second)) {
		t.Fatal("after many failures the lockout must reach the cap")
	}
	if auth.loginLockedOut(key, now.Add(loginBackoffMax+time.Second)) {
		t.Fatal("lockout must never exceed loginBackoffMax")
	}
}

func TestLogin_UnknownEmailTrackedLikeKnown(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	now := time.Now()
	for i := 0; i < loginBackoffThreshold; i++ {
		_, _, _, _, _, err := auth.Login("nobody@example.com", "wrong", now)
		if !errors.Is(err, errInvalidCredentials) {
			t.Fatalf("unknown email attempt %d: %v", i, err)
		}
	}
	_, _, _, _, _, err := auth.Login("nobody@example.com", "wrong", now.Add(time.Second))
	if !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("locked unknown email must give the same error as a known one: %v", err)
	}
	if !auth.loginLockedOut(loginAccountKey("nobody@example.com"), now.Add(time.Second)) {
		t.Fatal("unknown emails must be throttled too, or the lockout leaks which account exists")
	}
}

func TestLoginBackoff_TableIsBounded(t *testing.T) {
	auth := newLoginAuth("x")
	now := time.Now()
	for i := 0; i < maxLoginBackoffEntries+50; i++ {
		auth.recordLoginFailure(loginAccountKey(strings.Repeat("a", 1)+string(rune('a'+i%26))+time.Duration(i).String()), now)
	}
	if n := len(auth.hardening.login.backoff); n > maxLoginBackoffEntries {
		t.Fatalf("backoff table grew to %d entries", n)
	}
}

// An API key's PrincipalID is free text the minter chooses, so a key that
// names the admin's subject must not be able to end the admin's sessions.
func TestLogout_APIKeyCannotRevokeAnotherPrincipalsRefreshTokens(t *testing.T) {
	auth := newLoginAuth(apiKeyVerifier("correct-password", "pepper"))
	auth.config.apiKeyAuthEnabled = true
	auth.config.apiKeyPepper = "api-pepper"
	auth.config.apiKeys = map[string]apiKeyRecord{}
	_, token, err := auth.CreateAPIKey("k", "team-1", "service-account", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	_, refresh, _ := loginViaHandler(t, mux)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if pd, err := auth.AuthenticatePrincipalDetails(req, time.Now()); err != nil || pd.ID != "team-1" || pd.AuthType != "api-key" {
		t.Fatalf("test premise: the key must authenticate as team-1 via api-key, got %+v, %v", pd, err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if got := postRefresh(mux, refresh); got.Code != http.StatusOK {
		t.Fatalf("the admin's refresh token was revoked by an API key's logout: refresh = %d", got.Code)
	}
}
