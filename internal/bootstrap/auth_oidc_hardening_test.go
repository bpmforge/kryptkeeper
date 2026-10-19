// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// linkedUserProvider adds the identity-link capability dbUserProvider has to
// the in-memory provider, so the (issuer, sub) path can be exercised.
type linkedUserProvider struct {
	*fileUserProvider
	links map[string]string
}

func (p *linkedUserProvider) LinkOIDCIdentity(_ context.Context, userID, issuer, subject string) error {
	p.links[issuer+"|"+subject] = userID
	return nil
}

func (p *linkedUserProvider) FindByOIDCIdentity(ctx context.Context, issuer, subject string) (UserRecord, bool, error) {
	id, ok := p.links[issuer+"|"+subject]
	if !ok {
		return UserRecord{}, false, nil
	}
	users, _ := p.ListUsers(ctx)
	for _, u := range users {
		if u.ID == id {
			return u, true, nil
		}
	}
	return UserRecord{}, false, nil
}

func oidcCallbackStatus(t *testing.T, claims map[string]any, users UserProvider) (int, *testNonceIdP) {
	t.Helper()
	priv := generateTestRSAKey(t)
	idp := newTestOIDCNonceEndpoint(t, priv, claims)
	auth := newTestOIDCLoginAuthenticator(t, idp.URL, buildTestJWKS(t, testOIDCKID, &priv.PublicKey))
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, users, stubAuditProvider{})
	login := startOIDCLogin(t, mux, idp)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, login.callbackRequest())
	return rec.Code, idp
}

func aliceProvider() *fileUserProvider {
	return &fileUserProvider{users: []UserRecord{{ID: "user-1", Email: "alice@example.com", Role: "pki-admin", Status: "active"}}}
}

func TestOIDCLogin_EmailFallbackRequiresEmailVerified(t *testing.T) {
	for name, verified := range map[string]any{
		"false":          false,
		"absent":         nil,
		"string false":   "false",
		"unrelated type": 1,
	} {
		t.Run(name, func(t *testing.T) {
			claims := validIDTokenClaims(time.Now())
			delete(claims, "email_verified")
			if verified != nil {
				claims["email_verified"] = verified
			}
			if code, _ := oidcCallbackStatus(t, claims, aliceProvider()); code != http.StatusUnauthorized {
				t.Fatalf("unverified email must not resolve an account: got %d", code)
			}
		})
	}

	claims := validIDTokenClaims(time.Now())
	claims["email_verified"] = "true"
	if code, _ := oidcCallbackStatus(t, claims, aliceProvider()); code != http.StatusFound {
		t.Fatalf("email_verified \"true\" (string, as some IdPs send) must work: got %d", code)
	}
}

func TestOIDCLogin_UnverifiedEmailDoesNotLink_ButExistingLinkStillLogsIn(t *testing.T) {
	users := &linkedUserProvider{fileUserProvider: aliceProvider(), links: map[string]string{}}
	claims := validIDTokenClaims(time.Now())
	claims["email_verified"] = false
	if code, _ := oidcCallbackStatus(t, claims, users); code != http.StatusUnauthorized {
		t.Fatalf("unverified email: got %d, want 401", code)
	}
	if len(users.links) != 0 {
		t.Fatalf("an unverified email must never create an identity link: %v", users.links)
	}

	// Once (issuer, sub) is linked, the email claim is irrelevant.
	users.links[testOIDCIssuer+"|idp-subject-1"] = "user-1"
	if code, _ := oidcCallbackStatus(t, claims, users); code != http.StatusFound {
		t.Fatalf("a linked identity must log in without the email fallback: got %d", code)
	}
}

func TestOIDCLogin_LoginSetsBoundFlowCookieAndNonce(t *testing.T) {
	priv := generateTestRSAKey(t)
	idp := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))
	auth := newTestOIDCLoginAuthenticator(t, idp.URL, buildTestJWKS(t, testOIDCKID, &priv.PublicKey))
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, aliceProvider(), stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d", rec.Code)
	}
	var flow *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-"+oidcFlowCookieBase {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("expected a __Host- flow cookie over TLS")
	}
	if !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteLaxMode || flow.Path != "/" || flow.MaxAge <= 0 {
		t.Fatalf("flow cookie attributes wrong: %+v", flow)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "nonce=") {
		t.Fatalf("authorization URL carries no nonce: %s", loc)
	}
	if strings.Contains(loc, flow.Value) {
		t.Fatal("the cookie binding value must never be sent to the IdP")
	}

	plain := httptest.NewRecorder()
	mux.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	for _, c := range plain.Result().Cookies() {
		if c.Name == oidcFlowCookieBase && c.Secure {
			t.Fatal("flow cookie must not be Secure on plain HTTP (the browser would drop it)")
		}
	}
}

func TestOIDCCallback_RefusesBadStateAndCookieBinding(t *testing.T) {
	priv := generateTestRSAKey(t)
	idp := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))
	auth := newTestOIDCLoginAuthenticator(t, idp.URL, buildTestJWKS(t, testOIDCKID, &priv.PublicKey))
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, aliceProvider(), stubAuditProvider{})

	serve := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// Unknown state.
	bogus := oidcLoginStart{State: "not-a-state"}
	if rec := serve(bogus.callbackRequest()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown state: %d", rec.Code)
	}

	// Login-CSRF: the attacker started the login, the victim's browser (no
	// cookie, or its own different one) delivers the callback.
	attacker := startOIDCLogin(t, mux, idp)
	noCookie := attacker
	noCookie.Cookie = nil
	if rec := serve(noCookie.callbackRequest()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("callback without the flow cookie: %d", rec.Code)
	}
	if idp.hits != 0 {
		t.Fatal("a callback with no binding must be refused before the IdP is contacted")
	}

	attacker = startOIDCLogin(t, mux, idp)
	victim := startOIDCLogin(t, mux, idp)
	crossed := attacker
	crossed.Cookie = victim.Cookie
	if rec := serve(crossed.callbackRequest()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("callback with another login's cookie: %d", rec.Code)
	}
	// The victim's own flow is untouched and still completes.
	if rec := serve(victim.callbackRequest()); rec.Code != http.StatusFound {
		t.Fatalf("legitimate flow broke: %d", rec.Code)
	}
}

func TestOIDCCallback_NonceMustMatch(t *testing.T) {
	for name, nonce := range map[string]any{"wrong": "attacker-nonce", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			claims := validIDTokenClaims(time.Now())
			claims["nonce"] = nonce
			if code, _ := oidcCallbackStatus(t, claims, aliceProvider()); code != http.StatusUnauthorized {
				t.Fatalf("ID token with a %s nonce must be refused: got %d", name, code)
			}
		})
	}
}

// --- JWKS refetch throttle and https-only redirects ---

func newCountingIdP(t *testing.T, priv *rsa.PrivateKey) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/jwks") {
			_, _ = w.Write([]byte(buildTestJWKS(t, "known-kid", &priv.PublicKey)))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": srv.URL + "/jwks"})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestJWKS_UnknownKidRefetchIsThrottled(t *testing.T) {
	priv := generateTestRSAKey(t)
	srv, hits := newCountingIdP(t, priv)
	cache, err := newManagedOIDCJWKSCache(srv.URL+"/.well-known/openid-configuration", 2*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache.client.Transport = srv.Client().Transport

	t0 := time.Now()
	forged := signTestRS256JWT(t, priv, "forged-kid", map[string]any{"sub": "x", "exp": t0.Add(time.Hour).Unix()})

	// Prime the cache (one discovery + one JWKS request).
	if _, err := cache.getJWKS(context.Background(), false, t0); err != nil {
		t.Fatal(err)
	}
	primed := hits.Load()

	// A flood of unknown-kid tokens a minute later: at most one refetch.
	later := t0.Add(time.Minute)
	for i := 0; i < 50; i++ {
		if _, _, err := validateOIDCRS256JWTManaged(context.Background(), forged, cache, "", "", "", later); err == nil {
			t.Fatal("forged token accepted")
		}
	}
	if got := hits.Load() - primed; got > 2 {
		t.Fatalf("50 unknown-kid tokens caused %d IdP requests, want at most one refetch (2 requests)", got)
	}

	// Still inside the window: no further refetch at all.
	before := hits.Load()
	for i := 0; i < 10; i++ {
		_, _, _ = validateOIDCRS256JWTManaged(context.Background(), forged, cache, "", "", "", later.Add(5*time.Second))
	}
	if hits.Load() != before {
		t.Fatalf("refetch inside the throttle window: %d new requests", hits.Load()-before)
	}

	// After the window a refetch is allowed again (key rotation still works).
	_, _, _ = validateOIDCRS256JWTManaged(context.Background(), forged, cache, "", "", "", later.Add(jwksForcedRefreshInterval+time.Second))
	if hits.Load() == before {
		t.Fatal("throttle never lets a rotated key be picked up")
	}
}

func TestJWKS_ConcurrentUnknownKidCoalesces(t *testing.T) {
	priv := generateTestRSAKey(t)
	srv, hits := newCountingIdP(t, priv)
	cache, err := newManagedOIDCJWKSCache(srv.URL+"/.well-known/openid-configuration", 2*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache.client.Transport = srv.Client().Transport
	t0 := time.Now()
	if _, err := cache.getJWKS(context.Background(), false, t0); err != nil {
		t.Fatal(err)
	}
	primed := hits.Load()
	forged := signTestRS256JWT(t, priv, "forged-kid", map[string]any{"sub": "x", "exp": t0.Add(time.Hour).Unix()})

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _, _ = validateOIDCRS256JWTManaged(context.Background(), forged, cache, "", "", "", t0.Add(time.Minute))
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	if got := hits.Load() - primed; got > 2 {
		t.Fatalf("20 concurrent unknown-kid tokens caused %d IdP requests, want one coalesced refetch", got)
	}
}

func TestJWKS_RedirectToHTTPIsRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the downgraded http endpoint must never be contacted")
		_, _ = w.Write([]byte(`{"jwks_uri":"https://idp.example/jwks"}`))
	}))
	t.Cleanup(plain.Close)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/discovery", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	cache, err := newManagedOIDCJWKSCache(redirector.URL+"/.well-known/openid-configuration", 2*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache.client.Transport = redirector.Client().Transport
	if _, err := cache.getJWKS(context.Background(), false, time.Now()); err == nil {
		t.Fatal("an https -> http redirect on the discovery fetch must fail")
	}

	// The token exchange carries the client secret, so it gets the same rule.
	if _, err := exchangeOIDCAuthorizationCode(context.Background(), redirector.URL+"/token", "cid", "secret", "https://kk/cb", "code", "verifier", 2*time.Second); err == nil {
		t.Fatal("token exchange must not follow a redirect to http")
	}
}
