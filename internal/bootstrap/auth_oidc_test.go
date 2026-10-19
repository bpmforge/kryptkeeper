// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- shared RS256 test-token helpers (used by auth_oidc_login_test.go too) ---

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

func buildTestJWKS(t *testing.T, kid string, pub *rsa.PublicKey) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "kid": kid, "n": n, "e": e},
		},
	}
	b, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return string(b)
}

func signTestRS256JWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- discoverOIDCEndpoints ---

func TestDiscoverOIDCEndpoints_ResolvesFromDiscoveryDocument(t *testing.T) {
	// Endpoints must sit on the discovery host (M-2), so the document is
	// built from the test server's own address.
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"` + server.URL + `/token","jwks_uri":"` + server.URL + `/jwks"}`))
	}))
	defer server.Close()

	cache, err := newManagedOIDCJWKSCache(server.URL, 2*time.Second, 5*time.Minute)
	if err != nil {
		t.Fatalf("newManagedOIDCJWKSCache: %v", err)
	}

	authEndpoint, tokenEndpoint, err := discoverOIDCEndpoints(cache)
	if err != nil {
		t.Fatalf("discoverOIDCEndpoints: %v", err)
	}
	if authEndpoint != "https://idp.example.com/authorize" {
		t.Errorf("authorization_endpoint = %q", authEndpoint)
	}
	if tokenEndpoint != server.URL+"/token" {
		t.Errorf("token_endpoint = %q", tokenEndpoint)
	}
}

func TestDiscoverOIDCEndpoints_MissingFieldsIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jwks_uri":"https://idp.example.com/jwks"}`))
	}))
	defer server.Close()

	cache, err := newManagedOIDCJWKSCache(server.URL, 2*time.Second, 5*time.Minute)
	if err != nil {
		t.Fatalf("newManagedOIDCJWKSCache: %v", err)
	}

	if _, _, err := discoverOIDCEndpoints(cache); err == nil {
		t.Fatal("expected an error when discovery document is missing authorization_endpoint/token_endpoint")
	}
}

// --- PKCE ---

// TestPKCECodeChallengeS256_MatchesRFC7636Vector uses RFC 7636 Appendix B's
// published verifier/challenge pair -- a discriminating test that would go
// red if the S256 computation were subtly wrong (e.g. std vs raw-url
// base64, or hashing the wrong input).
func TestPKCECodeChallengeS256_MatchesRFC7636Vector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := pkceCodeChallengeS256(verifier); got != wantChallenge {
		t.Fatalf("pkceCodeChallengeS256(%q) = %q, want %q", verifier, got, wantChallenge)
	}
}

func TestGeneratePKCECodeVerifier_UniqueAndRFCLength(t *testing.T) {
	v1, err := generatePKCECodeVerifier()
	if err != nil {
		t.Fatalf("generatePKCECodeVerifier: %v", err)
	}
	v2, err := generatePKCECodeVerifier()
	if err != nil {
		t.Fatalf("generatePKCECodeVerifier: %v", err)
	}
	if v1 == v2 {
		t.Fatal("two calls produced the same code_verifier -- crypto/rand not used correctly")
	}
	// RFC 7636 4.1: 43-128 characters.
	if len(v1) < 43 || len(v1) > 128 {
		t.Fatalf("code_verifier length %d outside RFC 7636's 43-128 range", len(v1))
	}
}

func TestGenerateOIDCLoginStateToken_Unique(t *testing.T) {
	s1, err := generateOIDCLoginStateToken()
	if err != nil {
		t.Fatalf("generateOIDCLoginStateToken: %v", err)
	}
	s2, err := generateOIDCLoginStateToken()
	if err != nil {
		t.Fatalf("generateOIDCLoginStateToken: %v", err)
	}
	if s1 == s2 {
		t.Fatal("two calls produced the same state -- crypto/rand not used correctly")
	}
}

// --- oidcLoginStateStore: single-use + expiring (acceptance #3) ---

func TestOIDCLoginStateStore_SingleUse(t *testing.T) {
	store := newOIDCLoginStateStore()
	now := time.Now()
	store.putFlow("state-1", oidcLoginState{codeVerifier: "verifier-1", expiresAt: now.Add(5 * time.Minute)}, now)

	flow, ok := store.takeFlow("state-1", now)
	verifier := flow.codeVerifier
	if !ok || verifier != "verifier-1" {
		t.Fatalf("first take: got (%q, %v), want (\"verifier-1\", true)", verifier, ok)
	}

	if _, ok := store.takeFlow("state-1", now); ok {
		t.Fatal("a replayed state must be rejected on the second take")
	}
}

func TestOIDCLoginStateStore_Expired(t *testing.T) {
	store := newOIDCLoginStateStore()
	now := time.Now()
	store.putFlow("state-1", oidcLoginState{codeVerifier: "verifier-1", expiresAt: now.Add(-time.Second)}, now)

	if _, ok := store.takeFlow("state-1", now); ok {
		t.Fatal("an expired state must be rejected")
	}
}

func TestOIDCLoginStateStore_UnknownState(t *testing.T) {
	store := newOIDCLoginStateStore()
	if _, ok := store.takeFlow("never-issued", time.Now()); ok {
		t.Fatal("an unknown state must be rejected")
	}
}

// --- token exchange (RFC 7636 4.5/4.6): mismatched code_verifier ---

func TestExchangeOIDCAuthorizationCode_RejectsMismatchedVerifier(t *testing.T) {
	const expectedVerifier = "expected-correct-verifier-0123456789012"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.PostForm.Get("code_verifier") != expectedVerifier {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"unused","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	_, err := exchangeOIDCAuthorizationCode(context.Background(), server.URL, "client-id", "client-secret", "https://kryptkeeper.example.com/callback", "auth-code", "the-wrong-verifier-abcdefghijklmno", 5*time.Second)
	if err == nil {
		t.Fatal("expected a mismatched code_verifier to fail the token exchange")
	}
}

func TestExchangeOIDCAuthorizationCode_AcceptsMatchingVerifier(t *testing.T) {
	const expectedVerifier = "expected-correct-verifier-0123456789012"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.PostForm.Get("code_verifier") != expectedVerifier {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"the-id-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	resp, err := exchangeOIDCAuthorizationCode(context.Background(), server.URL, "client-id", "client-secret", "https://kryptkeeper.example.com/callback", "auth-code", expectedVerifier, 5*time.Second)
	if err != nil {
		t.Fatalf("exchangeOIDCAuthorizationCode: %v", err)
	}
	if resp.IDToken != "the-id-token" {
		t.Fatalf("IDToken = %q", resp.IDToken)
	}
}
