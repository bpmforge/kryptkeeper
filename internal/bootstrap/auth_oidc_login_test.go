// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testOIDCIssuer = "https://idp.example.com/"
const testOIDCClientID = "test-client-id"
const testOIDCKID = "test-kid-1"

func newTestOIDCLoginAuthenticator(t *testing.T, tokenEndpointURL string, jwksJSON string) *Authenticator {
	t.Helper()
	return &Authenticator{
		config: authValidatorConfig{
			mode:                      "bootstrap",
			loginEnabled:              true,
			loginSigning:              "signing-secret",
			jwtIssuer:                 "kryptkeeper",
			jwtAudience:               "kryptkeeper-clients",
			loginTTL:                  5 * time.Minute,
			refreshTTL:                10 * time.Minute,
			oidcLoginEnabled:          true,
			oidcClientID:              testOIDCClientID,
			oidcClientSecret:          "test-client-secret",
			oidcRedirectURL:           "https://kryptkeeper.example.com/api/v1/auth/oidc/callback",
			oidcAuthorizationEndpoint: "https://idp.example.com/authorize",
			oidcTokenEndpoint:         tokenEndpointURL,
			oidcLoginScopes:           "openid email profile",
			oidcLoginStateTTL:         5 * time.Minute,
			oidcPostLoginRedirectURL:  "/",
			oidcIssuer:                testOIDCIssuer,
			oidcJWKSJSON:              jwksJSON,
			tenantClaim:               "tenant",
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}
}

// testNonceIdP is a fake IdP token endpoint that signs its ID token at
// request time, because the nonce it must echo only exists once the browser
// has been sent to the authorization endpoint.
type testNonceIdP struct {
	*httptest.Server
	mu     sync.Mutex
	nonce  string
	hits   int
	claims map[string]any
}

// newTestOIDCNonceEndpoint signs claims with priv (adding the login's nonce
// unless claims already carry a "nonce" of their own).
func newTestOIDCNonceEndpoint(t *testing.T, priv *rsa.PrivateKey, claims map[string]any) *testNonceIdP {
	t.Helper()
	idp := &testNonceIdP{claims: claims}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		idp.hits++
		c := make(map[string]any, len(idp.claims)+1)
		for k, v := range idp.claims {
			c[k] = v
		}
		if _, ok := c["nonce"]; !ok && idp.nonce != "" {
			c["nonce"] = idp.nonce
		}
		idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcTokenResponse{IDToken: signTestRS256JWT(t, priv, testOIDCKID, c), TokenType: "Bearer", ExpiresIn: 3600})
	}))
	t.Cleanup(idp.Close)
	return idp
}

// oidcLoginStart is what the browser holds after /api/v1/auth/oidc/login.
type oidcLoginStart struct {
	State  string
	Nonce  string
	Cookie *http.Cookie
}

func (l oidcLoginStart) callbackPath() string {
	return "/api/v1/auth/oidc/callback?state=" + url.QueryEscape(l.State) + "&code=test-auth-code"
}

// callbackRequest is the IdP's redirect back, carrying the browser's cookie.
func (l oidcLoginStart) callbackRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, l.callbackPath(), nil)
	if l.Cookie != nil {
		req.AddCookie(l.Cookie)
	}
	return req
}

// startOIDCLogin drives the real /api/v1/auth/oidc/login redirect and
// returns the state value the server generated, so the test can simulate
// the IdP calling back with it.
func startOIDCLogin(t *testing.T, mux *http.ServeMux, idps ...*testNonceIdP) oidcLoginStart {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /api/v1/auth/oidc/login: expected 302, got %d (%s)", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location header: %v", err)
	}
	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("expected a non-empty state in the authorization redirect")
	}
	nonce := location.Query().Get("nonce")
	if nonce == "" {
		t.Fatal("expected a non-empty nonce in the authorization redirect")
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, oidcFlowCookieBase) {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("expected the login redirect to set the flow cookie")
	}
	for _, idp := range idps {
		idp.mu.Lock()
		idp.nonce = nonce
		idp.mu.Unlock()
	}
	return oidcLoginStart{State: state, Nonce: nonce, Cookie: cookie}
}

func validIDTokenClaims(now time.Time) map[string]any {
	return map[string]any{
		"sub":            "idp-subject-1",
		"iss":            testOIDCIssuer,
		"aud":            testOIDCClientID,
		"exp":            now.Add(10 * time.Minute).Unix(),
		"email":          "alice@example.com",
		"email_verified": true,
	}
}

// TestOIDCLoginFlow_HappyPath_EstablishesSessionAuthzCheckAccepts is the
// acceptance #1/#2 discriminating test: the callback must establish the
// exact session POST /api/v1/auth/login issues, provable by that session's
// cookie subsequently authenticating against /api/v1/authz-check.
func TestOIDCLoginFlow_HappyPath_EstablishesSessionAuthzCheckAccepts(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)

	callbackReq := login.callbackRequest()
	callbackRec := httptest.NewRecorder()
	mux.ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (%s)", callbackRec.Code, callbackRec.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == "kk_token" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("expected callback to set a kk_token session cookie")
	}

	authzReq := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	authzReq.AddCookie(sessionCookie)
	authzRec := httptest.NewRecorder()
	mux.ServeHTTP(authzRec, authzReq)

	if authzRec.Code != http.StatusOK {
		t.Fatalf("authz-check with oidc-issued session cookie: expected 200, got %d (%s)", authzRec.Code, authzRec.Body.String())
	}
	var body struct {
		Authenticated bool   `json:"authenticated"`
		Principal     string `json:"principal"`
	}
	if err := json.Unmarshal(authzRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode authz-check response: %v", err)
	}
	if !body.Authenticated || body.Principal != "user-1" {
		t.Fatalf("authz-check body = %+v, want authenticated for principal user-1", body)
	}
}

// TestOIDCLoginFlow_DeniesUnprovisionedIdentity proves acceptance #2/#4's
// "no just-in-time provisioning": an IdP identity with no matching
// UserRecord must be denied, not auto-created.
func TestOIDCLoginFlow_DeniesUnprovisionedIdentity(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	req := login.callbackRequest()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unprovisioned identity, got %d (%s)", rec.Code, rec.Body.String())
	}
	if hasSessionCookie(rec) {
		t.Fatal("no session cookie must be set when login is denied")
	}
}

// TestOIDCLoginFlow_DeprovisionedAccountAlreadyDeniesLogin proves the
// deprovisioned-account check runs even at login time, not only on
// already-issued sessions.
func TestOIDCLoginFlow_DeprovisionedAccountAlreadyDeniesLogin(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "deactivated"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	req := login.callbackRequest()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a deprovisioned account, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestOIDCLoginFlow_DeprovisionAfterLogin_AuthzCheckFails is acceptance #4's
// discriminating test at the OIDC-session layer: deprovisioning a user AFTER
// they already hold a valid, unexpired session must revoke access on the
// very next authz-check.
func TestOIDCLoginFlow_DeprovisionAfterLogin_AuthzCheckFails(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	callbackReq := login.callbackRequest()
	callbackRec := httptest.NewRecorder()
	mux.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d", callbackRec.Code)
	}
	var sessionCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == "kk_token" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected a session cookie from the callback")
	}

	// Sanity: the session works before deprovisioning.
	preReq := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	preReq.AddCookie(sessionCookie)
	preRec := httptest.NewRecorder()
	mux.ServeHTTP(preRec, preReq)
	if preRec.Code != http.StatusOK {
		t.Fatalf("expected the fresh session to authenticate, got %d", preRec.Code)
	}

	if err := userProvider.DeactivateUser(preReq.Context(), "user-1"); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	postReq := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	postReq.AddCookie(sessionCookie)
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after deprovisioning the still-valid session's owner, got %d (%s)", postRec.Code, postRec.Body.String())
	}
}

// TestOIDCLoginFlow_RejectsReplayedState is acceptance #3's replay case.
func TestOIDCLoginFlow_RejectsReplayedState(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)

	first := login.callbackRequest()
	firstRec := httptest.NewRecorder()
	mux.ServeHTTP(firstRec, first)
	if firstRec.Code != http.StatusFound {
		t.Fatalf("first callback: expected 302, got %d (%s)", firstRec.Code, firstRec.Body.String())
	}

	replay := login.callbackRequest()
	replayRec := httptest.NewRecorder()
	mux.ServeHTTP(replayRec, replay)
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed state: expected 401, got %d (%s)", replayRec.Code, replayRec.Body.String())
	}
}

// TestOIDCLoginFlow_RejectsExpiredState is acceptance #3's expiry case.
func TestOIDCLoginFlow_RejectsExpiredState(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	auth.config.oidcLoginStateTTL = time.Nanosecond
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	time.Sleep(time.Millisecond)

	req := login.callbackRequest()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired state: expected 401, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestOIDCLoginFlow_RejectsTokenEndpointRejection is acceptance #3's
// mismatched-code_verifier case observed at the handler level: RFC 7636 4.6
// has the IdP itself detect a code_verifier that doesn't hash to the
// code_challenge it recorded and reject the exchange -- from our server's
// perspective that is indistinguishable from any other token-endpoint
// rejection, so this simulates it via the token endpoint returning an error
// response. TestExchangeOIDCAuthorizationCode_RejectsMismatchedVerifier
// (auth_oidc_test.go) separately proves the actual verifier comparison.
func TestOIDCLoginFlow_RejectsTokenEndpointRejection(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux)
	req := login.callbackRequest()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("rejected token exchange: expected 401, got %d (%s)", rec.Code, rec.Body.String())
	}
	if hasSessionCookie(rec) {
		t.Fatal("no session cookie must be set when the token exchange fails")
	}
}

// TestOIDCLoginFlow_RejectsInvalidIDToken is acceptance #3's issuer/audience/
// signature case: an ID token signed with a DIFFERENT key than the
// configured JWKS must fail closed.
func TestOIDCLoginFlow_RejectsInvalidIDToken(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)

	wrongKey := generateTestRSAKey(t)
	tokenServer := newTestOIDCNonceEndpoint(t, wrongKey, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	req := login.callbackRequest()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid id token signature: expected 401, got %d (%s)", rec.Code, rec.Body.String())
	}
	if hasSessionCookie(rec) {
		t.Fatal("no session cookie must be set when id token validation fails")
	}
}

// TestOIDCLoginFlow_RejectsWrongIssuer covers the issuer half of #3's
// "issuer/audience/signature" wording independently of signature validity.
func TestOIDCLoginFlow_RejectsWrongIssuer(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	claims := validIDTokenClaims(time.Now())
	claims["iss"] = "https://not-the-configured-idp.example.com/"
	tokenServer := newTestOIDCNonceEndpoint(t, priv, claims)

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	req := login.callbackRequest()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong issuer: expected 401, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestOIDCLoginFlow_LoginDisabled_ServiceUnavailable(t *testing.T) {
	auth := newTestOIDCLoginAuthenticator(t, "http://unused.invalid", "{}")
	auth.config.oidcLoginEnabled = false
	userProvider := &fileUserProvider{}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when oidc login is disabled, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "kk_token") {
		t.Fatal("unexpected cookie reference in disabled-login response")
	}
}

// TestOIDCLoginFlow_NonAdminRoleDeniedCanManageDiscovery mirrors S-34's
// TestPkiViewerSessionDeniedCanManageDiscovery (auth_test.go): the test this
// ticket's unblock note asked for. Before mintSessionForUser threaded the
// SCIM-resolved UserRecord.Role into mintHS256JWT, every OIDC-authenticated
// caller minted the identical claim-less session shape regardless of role,
// which -- prior to S-34's fix landing -- resolved to pki-admin on every
// SUBSEQUENT request. Checking the login response body alone would not have
// caught that: the escalation only shows up when the session is
// re-authenticated later, which is what this test does instead.
func TestOIDCLoginFlow_NonAdminRoleDeniedCanManageDiscovery(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-viewer", Status: "active"},
	}}

	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	login := startOIDCLogin(t, mux, tokenServer)
	callbackReq := login.callbackRequest()
	callbackRec := httptest.NewRecorder()
	mux.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (%s)", callbackRec.Code, callbackRec.Body.String())
	}

	var accessToken string
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == "kk_token" {
			accessToken = c.Value
		}
	}
	if accessToken == "" {
		t.Fatal("expected callback to set a kk_token session cookie")
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), time.Now())
	if err != nil {
		t.Fatalf("authenticate oidc session on a subsequent request: %v", err)
	}
	if pd.Role != "pki-viewer" {
		t.Fatalf("oidc session resolved role = %q, want pki-viewer", pd.Role)
	}
	if canManageDiscovery(pd) {
		t.Fatalf("oidc-authenticated pki-viewer session was allowed to manage discovery: %+v", pd)
	}
}

// oidcRequestFromIP builds an SSO request as if it came from a specific
// client IP, so the per-IP rate-limit tests below can prove the bucket is
// keyed by caller and not global.
func oidcRequestFromIP(target string, remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = remoteAddr + ":40000"
	return req
}

// TestOIDCLogin_RateLimitedPerClientIP covers the unauthenticated /login
// endpoint. Without a throttle, an anonymous caller allocates an
// oidcLoginStateStore entry per request that only a matching callback ever
// removes -- so the store grows for free. /api/v1/auth/login and /refresh
// already limit per client IP (handlers_auth.go); these two endpoints are
// reachable by exactly the same anonymous caller and must too.
func TestOIDCLogin_RateLimitedPerClientIP(t *testing.T) {
	t.Setenv("API_RATE_LIMIT_OIDC_LOGIN_PER_MIN", "3")

	auth := newTestOIDCLoginAuthenticator(t, "https://idp.example.com/token", "")
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, oidcRequestFromIP("/api/v1/auth/oidc/login", "198.51.100.7"))
		if rec.Code != http.StatusFound {
			t.Fatalf("request %d within the limit: expected 302, got %d (%s)", i+1, rec.Code, rec.Body.String())
		}
	}

	overRec := httptest.NewRecorder()
	mux.ServeHTTP(overRec, oidcRequestFromIP("/api/v1/auth/oidc/login", "198.51.100.7"))
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("request over the limit: expected 429, got %d (%s)", overRec.Code, overRec.Body.String())
	}

	// A throttled flooder must not deny SSO to everybody else.
	otherRec := httptest.NewRecorder()
	mux.ServeHTTP(otherRec, oidcRequestFromIP("/api/v1/auth/oidc/login", "203.0.113.9"))
	if otherRec.Code != http.StatusFound {
		t.Fatalf("different client IP: expected 302, got %d (%s)", otherRec.Code, otherRec.Body.String())
	}
}

// TestOIDCCallback_RateLimitedBeforeContactingIdP is the discriminating test
// for the second half of the finding: /callback makes an outbound POST to the
// configured IdP's token endpoint, so an unthrottled caller can use
// Kryptkeeper as an unmetered proxy against someone else's IdP. Counting the
// fake IdP's hits -- not just the status code -- is what proves the throttle
// fires BEFORE the exchange rather than after it.
func TestOIDCCallback_RateLimitedBeforeContactingIdP(t *testing.T) {
	t.Setenv("API_RATE_LIMIT_OIDC_CALLBACK_PER_MIN", "2")

	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	tokenServer := newTestOIDCNonceEndpoint(t, priv, validIDTokenClaims(time.Now()))

	auth := newTestOIDCLoginAuthenticator(t, tokenServer.URL, jwksJSON)
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Role: "pki-operator", Status: "active"},
	}}
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	// Each round needs its own state: it is single-use.
	for i := 0; i < 2; i++ {
		login := startOIDCLogin(t, mux, tokenServer)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, withLoginCookie(oidcRequestFromIP(login.callbackPath(), "198.51.100.7"), login))
		if rec.Code != http.StatusFound {
			t.Fatalf("callback %d within the limit: expected 302, got %d (%s)", i+1, rec.Code, rec.Body.String())
		}
	}
	if tokenServer.hits != 2 {
		t.Fatalf("expected the 2 allowed callbacks to reach the IdP token endpoint, got %d hits", tokenServer.hits)
	}

	login := startOIDCLogin(t, mux, tokenServer)
	overRec := httptest.NewRecorder()
	mux.ServeHTTP(overRec, withLoginCookie(oidcRequestFromIP(login.callbackPath(), "198.51.100.7"), login))
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("callback over the limit: expected 429, got %d (%s)", overRec.Code, overRec.Body.String())
	}
	if tokenServer.hits != 2 {
		t.Fatalf("a throttled callback still reached the IdP token endpoint: %d hits, want 2 -- the limit must be checked before the exchange", tokenServer.hits)
	}
	if hasSessionCookie(overRec) {
		t.Fatal("a throttled callback must not set a session cookie")
	}
}

// TestOIDCLoginStateStore_SweepsExpiredAndBoundsTotalSize covers what the
// per-IP limit provably cannot: entries outlive the request that created
// them, so a rate limit bounds one caller's RATE while the store's SIZE is
// still unbounded across callers and across time.
func TestOIDCLoginStateStore_SweepsExpiredAndBoundsTotalSize(t *testing.T) {
	store := newOIDCLoginStateStore()
	now := time.Now()
	ttl := 5 * time.Minute

	for i := 0; i < maxPendingOIDCLogins; i++ {
		if !store.putFlow(fmt.Sprintf("state-%d", i), oidcLoginState{codeVerifier: "verifier", expiresAt: now.Add(ttl)}, now) {
			t.Fatalf("put %d: refused below the cap of %d", i, maxPendingOIDCLogins)
		}
	}
	if store.putFlow("state-over-cap", oidcLoginState{codeVerifier: "verifier", expiresAt: now.Add(ttl)}, now) {
		t.Fatalf("expected put to be refused at the cap of %d entries", maxPendingOIDCLogins)
	}

	// Refused, not evicted: an earlier in-flight login must survive, or one
	// caller filling the store could cancel another operator's SSO login.
	if _, ok := store.takeFlow("state-0", now); !ok {
		t.Fatal("a pending login was evicted to make room; put must refuse instead")
	}

	// Once entries expire, the store must recover without a background sweeper.
	later := now.Add(ttl).Add(time.Second)
	if !store.putFlow("state-after-expiry", oidcLoginState{codeVerifier: "verifier", expiresAt: later.Add(ttl)}, later) {
		t.Fatal("expected put to succeed after expired entries were swept")
	}
	store.mu.Lock()
	remaining := len(store.entries)
	store.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("expected the sweep to drop every expired entry, %d remain", remaining)
	}
}

// TestOIDCLogin_RateLimitedViaProductionWiring drives the wiring handlers.go
// actually uses (NewAuthenticatorFromEnv + registerAuthHandlers) rather than a
// hand-built Authenticator. Every other test here injects config directly, and
// that shape is exactly what hid the two-instance UserProvider drift earlier
// in this ticket: a limit that is only ever set by a test is not a limit.
func TestOIDCLogin_RateLimitedViaProductionWiring(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")
	t.Setenv("APP_OIDC_LOGIN_ENABLED", "true")
	t.Setenv("APP_OIDC_CLIENT_ID", testOIDCClientID)
	t.Setenv("APP_OIDC_REDIRECT_URL", "https://kryptkeeper.example.com/api/v1/auth/oidc/callback")
	t.Setenv("APP_OIDC_AUTHORIZATION_ENDPOINT", "https://idp.example.com/authorize")
	t.Setenv("APP_OIDC_TOKEN_ENDPOINT", "https://idp.example.com/token")
	// Static JWKS so NewAuthenticatorFromEnv builds no discovery cache and the
	// test touches no network (MASTER_PROMPT: no live network in unit tests).
	priv := generateTestRSAKey(t)
	t.Setenv("APP_OIDC_JWKS_JSON", buildTestJWKS(t, testOIDCKID, &priv.PublicKey))
	t.Setenv("API_RATE_LIMIT_OIDC_LOGIN_PER_MIN", "1")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	firstRec := httptest.NewRecorder()
	mux.ServeHTTP(firstRec, oidcRequestFromIP("/api/v1/auth/oidc/login", "198.51.100.7"))
	if firstRec.Code != http.StatusFound {
		t.Fatalf("first login through production wiring: expected 302, got %d (%s)", firstRec.Code, firstRec.Body.String())
	}

	secondRec := httptest.NewRecorder()
	mux.ServeHTTP(secondRec, oidcRequestFromIP("/api/v1/auth/oidc/login", "198.51.100.7"))
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second login through production wiring: expected 429, got %d (%s)", secondRec.Code, secondRec.Body.String())
	}
}

// oidcRequestBehindTrustedProxy simulates a request as nginx.conf's
// `proxy_set_header X-Real-IP $remote_addr` would present it: the peer is
// the (to-be-trusted) proxy, and X-Real-IP carries the real caller.
func oidcRequestBehindTrustedProxy(target, proxyAddr, realIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = proxyAddr + ":40000"
	req.Header.Set("X-Real-IP", realIP)
	return req
}

// TestOIDCLogin_DefaultLimitStaysOrgWideSafeWithoutTrustedProxy is W6-12
// acceptance #3's "do not lower the 120/min unconditionally" case: with
// APP_TRUSTED_PROXY_CIDRS unset (default empty, matching every deployment
// that has not opted into W6-11's trust config), the OIDC login endpoint
// must still allow the full defaultOIDCLoginLimit (120) org-wide bucket --
// exactly what W6-02 raised the number to preserve.
func TestOIDCLogin_DefaultLimitStaysOrgWideSafeWithoutTrustedProxy(t *testing.T) {
	auth := newTestOIDCLoginAuthenticator(t, "https://idp.example.com/token", "")
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	for i := 0; i < defaultOIDCLoginLimit; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, oidcRequestFromIP("/api/v1/auth/oidc/login", "198.51.100.7"))
		if rec.Code != http.StatusFound {
			t.Fatalf("request %d of %d (within the org-wide default): expected 302, got %d (%s)", i+1, defaultOIDCLoginLimit, rec.Code, rec.Body.String())
		}
	}
	overRec := httptest.NewRecorder()
	mux.ServeHTTP(overRec, oidcRequestFromIP("/api/v1/auth/oidc/login", "198.51.100.7"))
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("request %d: expected the org-wide default to be exhausted (429), got %d", defaultOIDCLoginLimit+1, overRec.Code)
	}
}

// TestOIDCLogin_TrustedProxyWithRealIPUsesLowerPerClientLimit is acceptance
// #3's positive case: once APP_TRUSTED_PROXY_CIDRS is configured AND the
// request actually carries X-Real-IP from that trusted peer (per-client
// keying genuinely active for this request per perClientKeyingActive), the
// much lower defaultOIDCLoginLimitPerClient applies instead of 120 -- and a
// DIFFERENT client behind the same trusted proxy is unaffected, proving the
// bucket is truly per-caller now.
func TestOIDCLogin_TrustedProxyWithRealIPUsesLowerPerClientLimit(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	auth := newTestOIDCLoginAuthenticator(t, "https://idp.example.com/token", "")
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	for i := 0; i < defaultOIDCLoginLimitPerClient; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/login", "10.0.0.5", "203.0.113.10"))
		if rec.Code != http.StatusFound {
			t.Fatalf("request %d of %d (within the per-client default): expected 302, got %d (%s)", i+1, defaultOIDCLoginLimitPerClient, rec.Code, rec.Body.String())
		}
	}
	overRec := httptest.NewRecorder()
	mux.ServeHTTP(overRec, oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/login", "10.0.0.5", "203.0.113.10"))
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("request %d: expected the per-client default to be exhausted (429), got %d", defaultOIDCLoginLimitPerClient+1, overRec.Code)
	}

	otherClientRec := httptest.NewRecorder()
	mux.ServeHTTP(otherClientRec, oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/login", "10.0.0.5", "203.0.113.99"))
	if otherClientRec.Code != http.StatusFound {
		t.Fatalf("a different real client behind the same trusted proxy: expected 302, got %d (%s)", otherClientRec.Code, otherClientRec.Body.String())
	}
}

// TestOIDCLogin_TrustedProxyConfiguredButNoRealIPHeaderStaysOrgWideSafe is the
// fallback hole acceptance #3 must not fall into: an operator can mark their
// proxy trusted (APP_TRUSTED_PROXY_CIDRS set) while running one that does not
// actually set X-Real-IP on a given request. clientIP(r) then still falls
// back to the peer address for that request, so perClientKeyingActive must
// say false and the ORG-WIDE default (120) must still apply -- using the
// lower per-client default here would silently reproduce W6-02's org-wide
// lockout at a smaller ceiling for exactly the deployment that thought it had
// opted out of it.
func TestOIDCLogin_TrustedProxyConfiguredButNoRealIPHeaderStaysOrgWideSafe(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	auth := newTestOIDCLoginAuthenticator(t, "https://idp.example.com/token", "")
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	// Peer is inside the trusted CIDR, but no X-Real-IP header is set --
	// clientIP falls back to the peer, so this must behave like the
	// org-wide-unconfigured case, not the per-client case.
	for i := 0; i < defaultOIDCLoginLimitPerClient; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, oidcRequestFromIP("/api/v1/auth/oidc/login", "10.0.0.5"))
		if rec.Code != http.StatusFound {
			t.Fatalf("request %d of %d (must still be within the org-wide default, not the lower per-client one): expected 302, got %d (%s)", i+1, defaultOIDCLoginLimitPerClient, rec.Code, rec.Body.String())
		}
	}
	// One more than the per-client default must still succeed: proves the
	// org-wide 120 ceiling is in effect, not the lower 20.
	stillOKRec := httptest.NewRecorder()
	mux.ServeHTTP(stillOKRec, oidcRequestFromIP("/api/v1/auth/oidc/login", "10.0.0.5"))
	if stillOKRec.Code != http.StatusFound {
		t.Fatalf("request %d without X-Real-IP: expected 302 (org-wide default still applies), got %d (%s)", defaultOIDCLoginLimitPerClient+1, stillOKRec.Code, stillOKRec.Body.String())
	}
}

// TestOIDCLogin_ExplicitEnvOverrideWinsEvenWithTrustedProxy proves an
// operator's explicit API_RATE_LIMIT_OIDC_LOGIN_PER_MIN always wins over
// either default, regardless of trusted-proxy configuration -- the
// config-aware fallback in oidcLoginLimitForRequest must never shadow an
// explicit operator choice.
func TestOIDCLogin_ExplicitEnvOverrideWinsEvenWithTrustedProxy(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")
	t.Setenv("API_RATE_LIMIT_OIDC_LOGIN_PER_MIN", "150")

	auth := newTestOIDCLoginAuthenticator(t, "https://idp.example.com/token", "")
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	for i := 0; i < 150; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/login", "10.0.0.5", "203.0.113.10"))
		if rec.Code != http.StatusFound {
			t.Fatalf("request %d of 150 (explicit override must exceed the built-in per-client default of %d): expected 302, got %d (%s)", i+1, defaultOIDCLoginLimitPerClient, rec.Code, rec.Body.String())
		}
	}
	overRec := httptest.NewRecorder()
	mux.ServeHTTP(overRec, oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/login", "10.0.0.5", "203.0.113.10"))
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 151: expected the explicit override to be exhausted (429), got %d", overRec.Code)
	}
}

// TestOidcCallbackLimitForRequest_ConfigAware is the callback endpoint's
// counterpart to the /login end-to-end tests above, exercised directly
// against oidcCallbackLimitForRequest rather than through the full
// state-store/token-exchange flow (each iteration of which needs its own
// single-use state, already covered by
// TestOIDCCallback_RateLimitedBeforeContactingIdP): org-wide default without
// trust, the lower per-client default with trust AND X-Real-IP present, the
// org-wide default again when trust is configured but the header is absent
// (the same fallback hole /login's tests guard), and an explicit override
// winning regardless.
func TestOidcCallbackLimitForRequest_ConfigAware(t *testing.T) {
	orgWide := oidcRequestFromIP("/api/v1/auth/oidc/callback", "198.51.100.7")
	if got := oidcCallbackLimitForRequest(orgWide); got != defaultOIDCCallbackLimit {
		t.Fatalf("expected org-wide default %d without a trusted proxy, got %d", defaultOIDCCallbackLimit, got)
	}

	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")
	trusted := oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/callback", "10.0.0.5", "203.0.113.10")
	if got := oidcCallbackLimitForRequest(trusted); got != defaultOIDCCallbackLimitPerClient {
		t.Fatalf("expected per-client default %d behind a trusted proxy with X-Real-IP, got %d", defaultOIDCCallbackLimitPerClient, got)
	}

	noHeader := oidcRequestFromIP("/api/v1/auth/oidc/callback", "10.0.0.5")
	if got := oidcCallbackLimitForRequest(noHeader); got != defaultOIDCCallbackLimit {
		t.Fatalf("expected org-wide default %d when trust is configured but X-Real-IP is absent, got %d", defaultOIDCCallbackLimit, got)
	}

	t.Setenv("API_RATE_LIMIT_OIDC_CALLBACK_PER_MIN", "77")
	if got := oidcCallbackLimitForRequest(trusted); got != 77 {
		t.Fatalf("expected an explicit override to win over both defaults, got %d", got)
	}
}

// TestPerClientKeyingActive_AgreesWithClientIP_OnMalformedRealIP proves
// perClientKeyingActive's ceiling decision never disagrees with clientIP's
// actual bucket-key decision. FB-10: a malformed forwarded address is
// rejected by the shared resolver, so the bucket is the peer's (org-wide) and
// the lower per-client ceiling must NOT apply -- applying it would throttle
// every user behind the proxy at the per-client rate.
func TestPerClientKeyingActive_AgreesWithClientIP_OnMalformedRealIP(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	req := oidcRequestBehindTrustedProxy("/api/v1/auth/oidc/login", "10.0.0.5", "not-an-ip")

	if perClientKeyingActive(req) {
		t.Fatal("expected perClientKeyingActive to be false for a malformed X-Real-IP")
	}
	if got := clientIP(req); got != "10.0.0.5" {
		t.Fatalf("expected clientIP to fall back to the peer for a malformed header, got %q", got)
	}
}

func withLoginCookie(req *http.Request, l oidcLoginStart) *http.Request {
	if l.Cookie != nil {
		req.AddCookie(l.Cookie)
	}
	return req
}

// hasSessionCookie reports whether rec issued a kk_token cookie; the flow
// cookie's clearing Set-Cookie on a denied callback is expected and harmless.
func hasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kk_token" && c.Value != "" {
			return true
		}
	}
	return false
}
