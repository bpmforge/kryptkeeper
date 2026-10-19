// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/clientip"
)

const (
	// Per-source ceilings for the two UNAUTHENTICATED SSO endpoints, reusing
	// the same bucket mechanism /api/v1/auth/login and /api/v1/auth/refresh
	// already apply (handlers_auth.go). Unthrottled, an anonymous caller can
	// grow oidcLoginStateStore for free (a /login allocates an entry that only
	// a matching callback removes) and can drive /callback to make the server
	// issue token-endpoint POSTs to the configured IdP on demand -- using
	// Kryptkeeper as an unmetered proxy against someone else's IdP.
	//
	// Higher than login's 10/min deliberately. clientIP (auth_rate_limit.go)
	// reads only r.RemoteAddr UNLESS the peer is a configured trusted proxy
	// that also supplied X-Real-IP (W6-11), and the shipped topology proxies
	// /api/ through nginx (docker-compose.yml, nginx.conf), so an operator who
	// has not configured APP_TRUSTED_PROXY_CIDRS still sees ONE bucket for the
	// whole organisation, not one per operator. These are also the only auth
	// path in an SSO-only deployment (APP_AUTH_LOGIN_ENABLED unset), where a
	// morning login wave is concurrent by nature. Both bounds that matter
	// survive the larger number: maxPendingOIDCLogins is the memory bound, and
	// the callback's pre-exchange placement is the proxy-abuse bound (an
	// abuser needs one /login per /callback, so both buckets apply). See the
	// shared-bucket note filed as W6-11.
	defaultOIDCLoginLimit    = 120
	defaultOIDCCallbackLimit = 120

	// defaultOIDCLoginLimitPerClient/defaultOIDCCallbackLimitPerClient apply
	// ONLY when perClientKeyingActive(r) is true for the specific request
	// being throttled (W6-12): the peer is a configured trusted proxy AND
	// THAT peer actually supplied X-Real-IP on THAT request, so clientIP(r)
	// really does resolve to the caller rather than collapsing to the proxy's
	// own address. Checking per request rather than "is
	// APP_TRUSTED_PROXY_CIDRS merely non-empty" matters: an operator can mark
	// their proxy trusted while running one that never sets X-Real-IP, in
	// which case every request from it would STILL collapse to one shared
	// identity -- lowering the ceiling for that case would reproduce exactly
	// the org-wide lockout W6-02 raised 120 to prevent, just at a smaller
	// number. Chosen well above login's 10/min (an OIDC round trip is not a
	// password guess, and legitimate retries -- an IdP hiccup, a user
	// switching devices mid-flow -- are more common here) but far below the
	// org-wide 120, now that per-client keying is genuinely in effect for
	// this request.
	defaultOIDCLoginLimitPerClient    = 20
	defaultOIDCCallbackLimitPerClient = 20

	// maxPendingOIDCLogins bounds the store's TOTAL size, across every client
	// and all time -- the per-IP limit only bounds one caller's rate, so it
	// alone cannot cap a store whose entries outlive the request that made
	// them. Deliberately a constant and not an env knob: a tunable ceiling is
	// a disablable ceiling, and this is the last line of defence.
	maxPendingOIDCLogins = 4096
)

// perClientKeyingActive reports whether clientIP(r) (auth_rate_limit.go) will
// resolve THIS SPECIFIC request to its real caller rather than falling back
// to the peer address -- true only when the peer matches a configured
// trusted-proxy CIDR AND the request carried a usable forwarded address.
// Deciding per request, rather than merely checking whether
// APP_TRUSTED_PROXY_CIDRS has a value, is deliberate: a trusted CIDR does not
// guarantee every request through it carries the header (a misconfigured or
// partially-deployed proxy might not set it), and treating "trust
// configured" as "keying is active" would silently apply a lower, unsafe
// ceiling to requests that are, in practice, still org-wide.
//
// It asks the same resolver clientIP uses, so the two cannot disagree: a
// malformed forwarded value is rejected by both and falls back to the peer.
func perClientKeyingActive(r *http.Request) bool {
	_, forwarded := clientip.FromEnv().Resolve(r)
	return forwarded
}

// oidcLoginLimitForRequest resolves the per-window ceiling for r: an
// operator's explicit API_RATE_LIMIT_OIDC_LOGIN_PER_MIN always wins when set,
// otherwise the fallback is defaultOIDCLoginLimitPerClient when per-client
// keying is active for r and defaultOIDCLoginLimit (the org-wide-safe
// default) otherwise.
func oidcLoginLimitForRequest(r *http.Request) int {
	fallback := defaultOIDCLoginLimit
	if perClientKeyingActive(r) {
		fallback = defaultOIDCLoginLimitPerClient
	}
	return intFromEnvOrDefault("API_RATE_LIMIT_OIDC_LOGIN_PER_MIN", fallback)
}

// oidcCallbackLimitForRequest is oidcLoginLimitForRequest's callback-endpoint
// counterpart.
func oidcCallbackLimitForRequest(r *http.Request) int {
	fallback := defaultOIDCCallbackLimit
	if perClientKeyingActive(r) {
		fallback = defaultOIDCCallbackLimitPerClient
	}
	return intFromEnvOrDefault("API_RATE_LIMIT_OIDC_CALLBACK_PER_MIN", fallback)
}

// oidcLoginState is what /api/v1/auth/oidc/login stashes server-side, keyed
// by the opaque `state` value handed to the browser, so the callback can
// redeem it without trusting anything the client sends back except that
// opaque value (acceptance #3).
type oidcLoginState struct {
	codeVerifier string
	// nonce is sent to the IdP and must come back in the ID token, and
	// bindingHash is the SHA-256 of the random value held only in the
	// initiating browser's flow cookie (A2A7-007): together they tie a
	// callback to the browser that started the login.
	nonce       string
	bindingHash [sha256.Size]byte
	expiresAt   time.Time
}

// oidcLoginStateStore holds pending PKCE logins in memory, matching the
// existing durability tradeoff Authenticator.refreshSessions already makes
// for local login (auth_bootstrap.go) -- both are short-lived, single-node
// state, not something this ticket introduces as a new pattern. It is
// created fresh per registerOIDCLoginHandlers call and closed over by the
// handlers, never a package global (CLAUDE.md: no new global state).
type oidcLoginStateStore struct {
	mu      sync.Mutex
	entries map[string]oidcLoginState
}

func newOIDCLoginStateStore() *oidcLoginStateStore {
	return &oidcLoginStateStore{entries: map[string]oidcLoginState{}}
}

// putFlow stores a pending login flow (verifier, nonce and cookie binding). It
// sweeps entries that have already expired, then refuses to store past
// maxPendingOIDCLogins, returning false when full. Sweeping on write rather
// than from a goroutine keeps this store's lifetime tied to the handlers that
// close over it (no background state to stop); it is O(n) with n bounded by
// the cap, so the work is bounded too.
//
// Full means reject the NEW login rather than evict an existing one: eviction
// would let any caller cancel another operator's in-flight SSO login, turning
// a memory bound into a cross-user denial primitive. A rejected login is
// retryable and the store drains as entries reach oidcLoginStateTTL.
func (s *oidcLoginStateStore) putFlow(state string, flow oidcLoginState, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= maxPendingOIDCLogins {
		return false
	}
	s.entries[state] = flow
	return true
}

// takeFlow returns the stored flow for state and unconditionally deletes the
// entry -- single-use, so a replayed state (the same value presented a second
// time) always misses. ok is false for an unknown, already-consumed, or
// expired state; callers deliberately cannot tell those apart, so there is no
// oracle for probing which states were ever valid (acceptance #3: fail closed
// uniformly).
func (s *oidcLoginStateStore) takeFlow(state string, now time.Time) (oidcLoginState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[state]
	if !ok {
		return oidcLoginState{}, false
	}
	delete(s.entries, state)
	if !now.Before(entry.expiresAt) {
		return oidcLoginState{}, false
	}
	return entry, true
}

const oidcFlowCookieBase = "kk_oidc_flow"

// oidcFlowCookieName uses the __Host- prefix whenever the cookie is Secure:
// the prefix forbids a Domain attribute and a non-root Path, so a sibling
// subdomain cannot plant the binding value.
func oidcFlowCookieName(secure bool) string {
	if secure {
		return "__Host-" + oidcFlowCookieBase
	}
	return oidcFlowCookieBase
}

// setOIDCFlowCookie binds the pending login to this browser. SameSite=Lax is
// the strictest value that still arrives on the IdP's top-level GET redirect
// back to the callback.
func setOIDCFlowCookie(w http.ResponseWriter, r *http.Request, binding string, ttl time.Duration) {
	secure := requestIsSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookieName(secure),
		Value:    binding,
		Path:     "/",
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

func clearOIDCFlowCookie(w http.ResponseWriter, r *http.Request) {
	secure := requestIsSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookieName(secure),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

// oidcFlowBindingMatches reports whether the browser's flow cookie is the one
// that started this login.
func oidcFlowBindingMatches(r *http.Request, flow oidcLoginState) bool {
	cookie, err := r.Cookie(oidcFlowCookieName(requestIsSecure(r)))
	if err != nil || cookie.Value == "" {
		return false
	}
	got := sha256.Sum256([]byte(cookie.Value))
	return subtle.ConstantTimeCompare(got[:], flow.bindingHash[:]) == 1
}

func generatePKCECodeVerifier() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func pkceCodeChallengeS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func generateOIDCLoginStateToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// discoverOIDCEndpoints fetches the IdP's discovery document to resolve
// authorization_endpoint/token_endpoint when they are not explicitly
// configured, reusing managedOIDCJWKSCache's own bounded HTTPS JSON fetch
// (auth_oidc.go) rather than a second HTTP client -- the cache already holds
// the discovery URL and a timeout-bounded client for exactly this document.
func discoverOIDCEndpoints(cache *managedOIDCJWKSCache) (string, string, error) {
	var discovery struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := cache.fetchJSON(context.Background(), cache.discoveryURL, &discovery); err != nil {
		return "", "", fmt.Errorf("fetch oidc discovery: %w", err)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return "", "", fmt.Errorf("discovery document missing authorization_endpoint/token_endpoint")
	}
	// The token endpoint receives the auth code and client_secret, so it must
	// be https. It is deliberately not pinned to the discovery host: major
	// IdPs serve it elsewhere (Google: accounts.google.com discovery,
	// oauth2.googleapis.com token), and the egress-guarded runtime client
	// already refuses metadata and link-local destinations at dial time.
	if err := requireHTTPSURL(discovery.TokenEndpoint); err != nil {
		return "", "", fmt.Errorf("invalid token_endpoint: %w", err)
	}
	// The exchange client admits loopback when the token endpoint is loopback,
	// so a remote IdP's document must not be able to name one.
	if isLoopbackURL(discovery.TokenEndpoint) && !isLoopbackURL(cache.discoveryURL) {
		return "", "", fmt.Errorf("invalid token_endpoint: loopback endpoint from a non-loopback discovery document")
	}
	return discovery.AuthorizationEndpoint, discovery.TokenEndpoint, nil
}

type oidcTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// exchangeOIDCAuthorizationCode redeems an authorization code at the IdP's
// token endpoint per RFC 6749 4.1.3 + RFC 7636 4.5 (PKCE code_verifier). A
// verifier that does not hash to the code_challenge originally sent is
// rejected by the IdP itself here, surfacing as a non-200 response
// (acceptance #3's "mismatched code_verifier" failure mode).
func exchangeOIDCAuthorizationCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, redirectURL, code, codeVerifier string, timeout time.Duration) (oidcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURL)
	form.Set("client_id", clientID)
	form.Set("code_verifier", codeVerifier)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := oidcRuntimeClient(timeout, tokenEndpoint)
	resp, err := client.Do(req)
	if err != nil {
		return oidcTokenResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oidcTokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp oidcTokenResponse
	bodyReader := io.LimitReader(resp.Body, 1<<20)
	if err := json.NewDecoder(bodyReader).Decode(&tokenResp); err != nil {
		return oidcTokenResponse{}, fmt.Errorf("invalid token response json: %w", err)
	}
	if strings.TrimSpace(tokenResp.IDToken) == "" {
		return oidcTokenResponse{}, fmt.Errorf("token response missing id_token")
	}
	return tokenResp, nil
}

// decodeJWTPayloadClaims reads claims out of an ID token that has ALREADY
// passed validateOIDCRS256JWT/validateOIDCRS256JWTManaged (signature, issuer,
// audience, expiry all checked). It exists only because that shared
// validator intentionally returns just (sub, tenant) -- extending its return
// shape would ripple into the bearer-token call sites it also serves. This
// performs no verification of its own; it is claim extraction on an
// already-trusted token, not a second verification path (acceptance #1).
func decodeJWTPayloadClaims(token string) (map[string]any, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("jwt must have 3 segments")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt payload encoding")
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, fmt.Errorf("invalid jwt payload json")
	}
	return claims, nil
}

// mintSessionForUser establishes the same session/token
// POST /api/v1/auth/login issues (acceptance #2): the identical HS256 JWT +
// opaque refresh-token mechanism (mintHS256JWT/generateOpaqueToken,
// a.refreshSessions -- all defined in auth_bootstrap.go and identity types
// in auth.go, reused here rather than reimplemented), so downstream
// authz-check/refresh/logout treat an OIDC-authenticated caller identically
// to a local-login one. subject is this codebase's own user ID (not the
// IdP's `sub`), so a principal's ID at authz-check time is always a
// UserProvider-resolvable identifier. role is the SCIM-resolved
// UserRecord.Role (S-34): mintHS256JWT embeds it as the session's "role"
// claim, and authenticateBootstrap rejects any session JWT with no role
// claim, so a caller passing an empty role here would mint a token that
// could never authenticate on a subsequent request -- refused up front
// instead, matching this ticket's fail-closed acceptance criterion.
func (a *Authenticator) mintSessionForUser(subject string, role string, now time.Time) (string, int64, string, int64, error) {
	if strings.TrimSpace(a.config.loginSigning) == "" {
		return "", 0, "", 0, errAuthUnavailable
	}
	if strings.TrimSpace(role) == "" {
		return "", 0, "", 0, errAuthUnavailable
	}
	accessToken, err := mintHS256JWT(subject, role, a.config.loginSigning, a.config.jwtIssuer, a.config.jwtAudience, now.Add(a.config.loginTTL))
	if err != nil {
		return "", 0, "", 0, err
	}
	refreshToken, err := generateOpaqueToken("rfr")
	if err != nil {
		return "", 0, "", 0, err
	}

	a.refreshMu.Lock()
	a.refreshSessions[refreshToken] = refreshSession{PrincipalID: subject, Role: role, ExpiresAt: now.Add(a.config.refreshTTL)}
	a.refreshMu.Unlock()

	return accessToken, int64(a.config.loginTTL / time.Second), refreshToken, int64(a.config.refreshTTL / time.Second), nil
}

// registerOIDCLoginHandlers wires the browser-facing SSO login flow (GET so
// a plain redirect from the operator's browser and from the IdP's callback
// both work with no JS/fetch required). userProvider resolves the OIDC
// identity to an already-provisioned Kryptkeeper account (SCIM's job, not
// this handler's -- acceptance #2/#4: no just-in-time account creation here,
// so an IdP identity with no matching account is rejected, not auto-invited).
func registerOIDCLoginHandlers(mux *http.ServeMux, auth *Authenticator, userProvider UserProvider, auditProvider AuditProvider) {
	stateStore := newOIDCLoginStateStore()

	mux.HandleFunc("/api/v1/auth/oidc/login", getOnly(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		cfg := auth.config

		// First thing after the method gate, before any state is allocated --
		// mirrors /api/v1/auth/login (handlers_auth.go). No audit event on a
		// 429, matching that handler: the point of the throttle is to stop
		// doing work for this caller, and audit records are append-only, so
		// emitting one per throttled request would hand an anonymous flooder a
		// write amplifier into the audit store.
		if !auth.allowRateLimit("oidc-login:"+clientIP(r), oidcLoginLimitForRequest(r), time.Minute, now) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}

		if !cfg.oidcLoginEnabled || cfg.oidcClientID == "" || cfg.oidcRedirectURL == "" || cfg.oidcAuthorizationEndpoint == "" {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.login", "auth", "oidc-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}

		codeVerifier, err := generatePKCECodeVerifier()
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.login", "auth", "oidc-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}
		state, err := generateOIDCLoginStateToken()
		var nonce, binding string
		if err == nil {
			nonce, err = generateOIDCLoginStateToken()
		}
		if err == nil {
			binding, err = generateOIDCLoginStateToken()
		}
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.login", "auth", "oidc-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}
		flow := oidcLoginState{codeVerifier: codeVerifier, nonce: nonce, bindingHash: sha256.Sum256([]byte(binding)), expiresAt: now.Add(cfg.oidcLoginStateTTL)}
		if !stateStore.putFlow(state, flow, now) {
			// Pending-login table is at maxPendingOIDCLogins. Fail closed: no
			// redirect is issued, so no login proceeds without server-side
			// PKCE state. Audited (unlike the throttle above) because this is
			// a service-degradation condition an operator needs to see, and
			// the per-IP limit already bounds how often it can be reached.
			emitAuditEvent(r, auditProvider, "", "auth.oidc.login", "auth", "oidc-login", AuditOutcomeFailure)
			writeTooManyRequests(w, "too many pending oidc logins")
			return
		}

		authorizationURL, err := url.Parse(cfg.oidcAuthorizationEndpoint)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.login", "auth", "oidc-login", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}
		query := authorizationURL.Query()
		query.Set("response_type", "code")
		query.Set("client_id", cfg.oidcClientID)
		query.Set("redirect_uri", cfg.oidcRedirectURL)
		query.Set("scope", cfg.oidcLoginScopes)
		query.Set("state", state)
		query.Set("nonce", nonce)
		query.Set("code_challenge", pkceCodeChallengeS256(codeVerifier))
		query.Set("code_challenge_method", "S256")
		authorizationURL.RawQuery = query.Encode()

		setOIDCFlowCookie(w, r, binding, cfg.oidcLoginStateTTL)
		emitAuditEvent(r, auditProvider, "", "auth.oidc.login", "auth", "oidc-login", AuditOutcomeSuccess)
		http.Redirect(w, r, authorizationURL.String(), http.StatusFound)
	}))

	mux.HandleFunc("/api/v1/auth/oidc/callback", getOnly(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		cfg := auth.config

		// Ahead of stateStore.take() on purpose: a throttled request must not
		// consume (and thereby destroy) a legitimate single-use state, and
		// must not reach exchangeOIDCAuthorizationCode, which is the outbound
		// POST to the IdP an unthrottled caller would be spending on our
		// behalf.
		if !auth.allowRateLimit("oidc-callback:"+clientIP(r), oidcCallbackLimitForRequest(r), time.Minute, now) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}

		if !cfg.oidcLoginEnabled || cfg.oidcClientID == "" || cfg.oidcRedirectURL == "" || cfg.oidcTokenEndpoint == "" {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}

		if idpError := strings.TrimSpace(r.URL.Query().Get("error")); idpError != "" {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		flow, ok := stateStore.takeFlow(state, now)
		if !ok {
			// Covers both a replayed state (already consumed) and an
			// expired one (acceptance #3) -- take() does not distinguish.
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// The state is spent either way. A callback whose browser did not
		// start this login (no cookie, or someone else's) is a login-CSRF
		// attempt: refuse before spending an IdP round trip on it.
		clearOIDCFlowCookie(w, r)
		if !oidcFlowBindingMatches(r, flow) {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		tokenResp, err := exchangeOIDCAuthorizationCode(r.Context(), cfg.oidcTokenEndpoint, cfg.oidcClientID, cfg.oidcClientSecret, cfg.oidcRedirectURL, code, flow.codeVerifier, 5*time.Second)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		// ID-token audience is the OAuth client_id, not the API audience
		// bearer tokens use (APP_OIDC_AUDIENCE) -- fall back to it only if
		// no client ID is configured.
		expectedAudience := firstNonEmpty(cfg.oidcClientID, cfg.oidcAudience)

		var sub string
		if cfg.oidcJWKSJSON != "" {
			sub, _, err = validateOIDCRS256JWT(tokenResp.IDToken, cfg.oidcJWKSJSON, cfg.oidcIssuer, expectedAudience, cfg.tenantClaim, now)
		} else if auth.oidcJWKSCache != nil {
			sub, _, err = validateOIDCRS256JWTManaged(r.Context(), tokenResp.IDToken, auth.oidcJWKSCache, cfg.oidcIssuer, expectedAudience, cfg.tenantClaim, now)
		} else {
			err = fmt.Errorf("oidc jwks not configured")
		}
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		claims, err := decodeJWTPayloadClaims(tokenResp.IDToken)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// The nonce is the IdP's proof that this ID token was minted for the
		// authorization request this browser started. A flow with no nonce
		// (never produced by the login handler) fails closed.
		tokenNonce, _ := claims["nonce"].(string)
		if flow.nonce == "" || subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(flow.nonce)) != 1 {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		emailClaim, _ := claims["email"].(string)
		email := strings.TrimSpace(emailClaim)

		user, found, err := resolveOIDCUser(r.Context(), userProvider, cfg.oidcIssuer, sub, email, claimIsTrue(claims["email_verified"]))
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeFailure)
			writeServiceUnavailable(w, "user lookup unavailable")
			return
		}
		if !found {
			// No SCIM-provisioned account for this identity -- provisioning
			// is SCIM's job, not this login flow's (acceptance #2/#4: no
			// just-in-time account creation).
			emitAuditEvent(r, auditProvider, "", "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if isDeprovisionedStatus(user.Status) {
			emitAuditEvent(r, auditProvider, user.ID, "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		if linker, ok := userProvider.(OIDCIdentityLinker); ok {
			// Best-effort: recording the identity link speeds up future
			// logins (FindByOIDCIdentity instead of an email scan) but a
			// failure here must not block a login that already succeeded.
			_ = linker.LinkOIDCIdentity(r.Context(), user.ID, cfg.oidcIssuer, sub) // best-effort (see comment above)
		}

		sessionRole, roleOK, err := auth.ssoSessionRole(r.Context(), user, roleClaimValues(claims[cfg.roleClaim]))
		if err != nil {
			emitAuditEvent(r, auditProvider, user.ID, "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}
		if !roleOK {
			emitAuditEvent(r, auditProvider, user.ID, "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeDenied)
			writeForbidden(w, msgSSONoRoleMapped)
			return
		}

		accessToken, accessTTL, _, _, err := auth.mintSessionForUser(user.ID, sessionRole, now)
		if err != nil {
			emitAuditEvent(r, auditProvider, user.ID, "auth.oidc.callback", "auth", "oidc-callback", AuditOutcomeFailure)
			writeServiceUnavailable(w, "oidc login unavailable")
			return
		}

		setSessionCookie(w, r, accessToken, accessTTL)
		emitAuditEvent(r, auditProvider, user.ID, "auth.oidc.login", "auth", "oidc-login", AuditOutcomeSuccess)
		http.Redirect(w, r, safeRelativeRedirect(cfg.oidcPostLoginRedirectURL, "/"), http.StatusFound)
	}))
}

// resolveOIDCUser looks a user up by OIDC identity first (when the provider
// supports it -- dbUserProvider only) and falls back to an email match
// (works against any UserProvider, including the in-memory file adapter).
//
// The email fallback is also the first-login account link (LinkOIDCIdentity
// then makes it permanent), so it requires email_verified=true and a non-empty
// email: an IdP that lets a user set an unverified address would otherwise
// hand them whichever account owns it (A2A7-006 / A07-3). An IdP that omits
// email_verified needs its accounts pre-linked by (issuer, sub).
func resolveOIDCUser(ctx context.Context, userProvider UserProvider, issuer, subject, email string, emailVerified bool) (UserRecord, bool, error) {
	if linker, ok := userProvider.(OIDCIdentityLinker); ok {
		if user, found, err := linker.FindByOIDCIdentity(ctx, issuer, subject); err != nil {
			return UserRecord{}, false, err
		} else if found {
			return user, true, nil
		}
	}
	if email == "" || !emailVerified {
		return UserRecord{}, false, nil
	}
	return findUserByEmail(ctx, userProvider, email)
}

// claimIsTrue reads a boolean-ish ID token claim. email_verified is a JSON
// boolean per OIDC Core 5.1, but some IdPs (Cognito, Azure AD in places) send
// the string "true"; anything else, including absence, is false.
func claimIsTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

func isDeprovisionedStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "deactivated", "inactive", "deprovisioned":
		return true
	}
	return false
}

// scimAuthorized checks SCIM's own shared-secret bearer token -- a trust
// boundary deliberately separate from Authenticator.AuthenticatePrincipal
// (acceptance #5): an ordinary operator session (cookie or API key) is never
// even inspected here, so it cannot satisfy this check by construction.
func scimAuthorized(auth *Authenticator, r *http.Request) bool {
	expected := strings.TrimSpace(auth.scimEffectiveToken(r.Context()))
	if expected == "" {
		return false
	}
	got, err := parseBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
