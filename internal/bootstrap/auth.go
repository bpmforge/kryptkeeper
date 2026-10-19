// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthType is how a principal authenticated. It is a closed set: code that
// grants authority per kind (the egress stamp, separation of duties) switches
// on it exhaustively and refuses a kind it does not know.
type AuthType string

const (
	AuthTypeBootstrap AuthType = "bootstrap" // the raw bootstrap/root token
	AuthTypeAPIKey    AuthType = "api-key"   // a stored API key
	AuthTypeLocal     AuthType = "local"     // a login session (local, OIDC-callback and SAML logins all mint this)
	AuthTypeJWT       AuthType = "jwt"       // externally issued HS256 bearer
	AuthTypeOIDC      AuthType = "oidc"      // externally issued RS256 bearer
)

type AuthPrincipal struct {
	ID       string
	Role     string
	Scopes   []string
	AuthType AuthType
	// Multi-tenancy (v2.2). When MULTI_TENANCY is off, every principal resolves
	// to DefaultTenant + SuperAdmin so behavior is single-tenant.
	Tenant     string
	SuperAdmin bool
	// TenantScoped is true when read filtering should be applied to this
	// principal's Tenant. Non-super principals are always scoped; a super-admin
	// is scoped only when they explicitly pick a tenant (X-Tenant "view-as"),
	// keeping SuperAdmin (identity) separate from the current view.
	TenantScoped bool
	// Kid is the API key's id when AuthType is "api-key"; it resolves the
	// exact record (PrincipalID is free text and not unique) for the
	// separation-of-duties check.
	Kid string
}

type apiKeyRecord struct {
	Name           string   `json:"name"`
	Kid            string   `json:"kid"`
	SecretVerifier string   `json:"secret_verifier"`
	PrincipalID    string   `json:"principal_id"`
	Role           string   `json:"role"`
	Scopes         []string `json:"scopes"`
	Active         bool     `json:"active"`
	CreatedAt      string   `json:"created_at"`
	LastUsedAt     string   `json:"last_used_at"`
	ExpiresAt      string   `json:"expires_at"`
	// Tenant is this key's identity-bound tenant (W3-01) — empty means
	// DefaultTenant. Unlike the pre-W3-01 model, this does NOT come from the
	// caller's X-Tenant header; it's fixed at key-creation time.
	Tenant string `json:"tenant,omitempty"`
	// CreatedBy is the canonical human who minted this key (FG-2 / A07-4).
	// PrincipalID is free text chosen by the minter, so it cannot establish
	// who is behind the key; approval separation of duties follows this
	// field instead. Empty for keys loaded from operator config.
	CreatedBy string `json:"created_by,omitempty"`
}

type refreshSession struct {
	PrincipalID string
	Role        string
	ExpiresAt   time.Time
}

type loginCredential struct {
	Email        string
	PasswordHash string
	Role         string
	Subject      string
	Active       bool
}

type managedOIDCJWKSCache struct {
	client       *http.Client
	discoveryURL string
	ttl          time.Duration

	mu        sync.RWMutex
	jwksJSON  string
	expiresAt time.Time
	// lastAttempt is when the IdP was last asked (success or failure); it is
	// what throttles forced refreshes (A2A7-004). fetchMu serialises fetches
	// without holding mu, so cached reads never wait on the IdP.
	lastAttempt time.Time
	fetchMu     sync.Mutex
	// forceInterval overrides jwksForcedRefreshInterval (tests only).
	forceInterval time.Duration
}

type Authenticator struct {
	// required: stores /readyz must see up (D-290-A); see required_store.go.
	required         requiredStores
	config           authValidatorConfig
	oidcJWKSCache    *managedOIDCJWKSCache
	discoveryEnabled bool
	refreshMu        sync.Mutex
	refreshSessions  map[string]refreshSession
	apiKeyMu         sync.RWMutex
	touchWG          sync.WaitGroup // in-flight last_used_at writes (tests wait on it)
	// apiKeyStore persists minted keys (nil: memory only). persistedKids and
	// lastTouch are guarded by apiKeyMu.
	apiKeyStore   apiKeyStore
	persistedKids map[string]bool
	lastTouch     map[string]time.Time
	// revokePending holds kids revoked in memory whose DB write failed.
	revokePending    map[string]bool
	rateLimitMu      sync.Mutex
	rateLimitBuckets map[string][]time.Time
	// hardening holds the FG-7 login/session state (Argon2id upgrade, account
	// backoff, SAML request/replay guards); its zero value is usable.
	hardening authHardeningState
	// userProvider is consulted so a SCIM-deprovisioned principal (W6-02
	// acceptance #4) loses access everywhere authenticatePrincipal's result
	// is trusted, not just at /api/v1/authz-check's own separate check
	// (handlers_auth.go). Nil in tests that construct an Authenticator
	// directly without a UserProvider -- principalIsDeprovisioned treats
	// that as "no deprovisioning to enforce" rather than panicking.
	userProvider UserProvider
	// userStoreErrMu guards userStoreErrAt, which throttles the log line and
	// audit row for user-store failures (see reportUserStoreError).
	// auditProvider is the sink for that row; registerAuthHandlers sets it
	// during route wiring, before the server accepts requests.
	userStoreErrMu sync.Mutex
	userStoreErrAt time.Time
	auditProvider  AuditProvider
	// roleStore resolves custom role names for grant checks (TM-08). May be nil
	// (store unavailable): custom roles are then unknown and cannot be granted.
	roleStore *CustomRoleStore
	// configStore resolves DB overrides for the bearer-token OIDC
	// issuer/audience/JWKS quartet (W8-13). May be nil (store unavailable),
	// in which case ssoBearerConfigSnapshot always falls back to the
	// env-derived bootstrap default frozen in config at construction --
	// the pre-W8-13 behavior.
	configStore ConfigStore
	// customRoleLookup is consulted only by ValidationReport (see
	// SetCustomRoleLookup in auth_role_map.go).
	customRoleLookup func(name string) (bool, error)
	// ssoConfigMu guards the TTL-cached snapshot below.
	// AuthenticatePrincipalDetails runs on every authenticated request
	// (including requests that end up failing auth), so a config-store read
	// on every call would violate acceptance #3's request-hot-path bound --
	// this polls at most once per ssoBearerConfigTTL instead, the same
	// posture as configuredDiscoveryProvider (discovery_provider.go).
	ssoConfigMu        sync.Mutex
	ssoConfigCheckedAt time.Time
	ssoConfigCached    ssoBearerConfig
	// ssoConfigNow is time.Now by default; tests override it to advance the
	// TTL window without a real sleep.
	ssoConfigNow func() time.Time
	// liveCfg is the TTL-cached SAML/SCIM overlay (W33-04); see auth_config.go.
	liveCfg liveAuthConfig
}

// ssoBearerConfig is the TTL-cached, store-resolved snapshot of the three
// settings that gate bearer-token OIDC validation (W8-13 acceptance #1/#2).
// Distinct from the browser-facing OIDC SSO *login* flow's ID-token checks
// (auth_oidc_login.go), which read cfg.oidcIssuer/oidcAudience/oidcJWKSJSON
// directly and are out of this ticket's write_scope.
type ssoBearerConfig struct {
	oidcIssuer   string
	oidcAudience string
	oidcJWKSJSON string
}

// ssoBearerConfigTTL bounds how often ssoBearerConfigSnapshot re-checks the
// config store for an override -- see Authenticator.ssoConfigMu's comment.
const ssoBearerConfigTTL = 30 * time.Second

// ssoBearerConfigSnapshot returns the effective oidcIssuer/oidcAudience/
// oidcJWKSJSON: a.configStore's DB override when present, else the env-
// derived bootstrap default in a.config -- re-resolved at most once per
// ssoBearerConfigTTL (W8-13 acceptance #2's "next auth check... with no
// server restart", bounded per acceptance #3).
func (a *Authenticator) ssoBearerConfigSnapshot(ctx context.Context) ssoBearerConfig {
	a.ssoConfigMu.Lock()
	defer a.ssoConfigMu.Unlock()

	now := time.Now()
	if a.ssoConfigNow != nil {
		now = a.ssoConfigNow()
	}
	if !a.ssoConfigCheckedAt.IsZero() && now.Sub(a.ssoConfigCheckedAt) < ssoBearerConfigTTL {
		return a.ssoConfigCached
	}
	a.ssoConfigCheckedAt = now
	a.ssoConfigCached = ssoBearerConfig{
		oidcIssuer:   resolveSSOConfigString(ctx, a.configStore, "sso.oidc_issuer", a.config.oidcIssuer),
		oidcAudience: resolveSSOConfigString(ctx, a.configStore, "sso.oidc_audience", a.config.oidcAudience),
		oidcJWKSJSON: resolveSSOConfigSecret(ctx, a.configStore, "sso.oidc_jwks_json", a.config.oidcJWKSJSON),
	}
	return a.ssoConfigCached
}

// resolveSSOConfigString returns store's non-secret DB override for key if
// one is set, else fallback (the env-derived bootstrap default already
// resolved onto a.config). store may be nil (config store unavailable), in
// which case this always returns fallback, matching pre-W8-13 behavior.
func resolveSSOConfigString(ctx context.Context, store ConfigStore, key, fallback string) string {
	if store != nil {
		if entry, ok, err := store.Get(ctx, key); err == nil && ok && entry.HasValue {
			return entry.Value
		}
	}
	return fallback
}

// resolveSSOConfigSecret is resolveSSOConfigString for a SECRET key: it
// decrypts store's DB override via Resolve (the internal-consumer path
// ConfigStore.Resolve's doc comment describes) instead of reading the
// write-only Get/Value surface the HTTP API uses.
func resolveSSOConfigSecret(ctx context.Context, store ConfigStore, key, fallback string) string {
	if store != nil {
		if plaintext, err := store.Resolve(ctx, key); err == nil {
			return string(plaintext)
		}
	}
	return fallback
}

func (a *Authenticator) AuthenticatePrincipal(r *http.Request, now time.Time) (string, error) {
	principal, err := a.AuthenticatePrincipalDetails(r, now)
	if err != nil {
		return "", err
	}
	return principal.ID, nil
}

func (a *Authenticator) AuthenticatePrincipalDetails(r *http.Request, now time.Time) (AuthPrincipal, error) {
	cfg := a.config
	cfg.apiKeys = a.apiKeysSnapshot()
	// Bearer-token OIDC validation (the "oidc" branch of authenticatePrincipal
	// below) is the only consumer of oidcIssuer/oidcAudience/oidcJWKSJSON in
	// this method, so the snapshot read is gated on cfg.mode to avoid the
	// mutex/TTL check on every bootstrap- or jwt-mode request too (W8-13).
	if cfg.mode == "oidc" {
		snap := a.ssoBearerConfigSnapshot(r.Context())
		cfg.oidcIssuer = snap.oidcIssuer
		cfg.oidcAudience = snap.oidcAudience
		cfg.oidcJWKSJSON = snap.oidcJWKSJSON
	}
	pd, err := authenticatePrincipal(r, cfg, a.oidcJWKSCache, now)
	if err != nil {
		return pd, err
	}
	if pd.AuthType == AuthTypeAPIKey && pd.Kid != "" {
		// Off the request path: a stalled core DB must not delay authentication.
		a.touchWG.Add(1)
		go func() {
			defer a.touchWG.Done()
			a.touchAPIKey(pd.Kid, now)
		}()
	}
	// A deprovisioned SCIM/OIDC-managed principal's session JWT is still
	// cryptographically valid, so this is the one place that matters: every
	// protected handler resolves its caller through this method (or
	// AuthenticatePrincipal, which delegates to it), so rejecting here revokes
	// access everywhere at once instead of at a single endpoint.
	//
	// A user-store *error* fails CLOSED for login-minted sessions (FB-03 /
	// A2A7-009): treating "could not check" as "not deprovisioned" would let a
	// deactivated user back in for the length of any outage, or whenever an
	// attacker can exhaust the user DB's pool. Other principals fail open on
	// an error, as before: the raw bootstrap token and API keys skip the
	// lookup entirely (a user-DB outage must not lock out the paths an
	// operator needs to diagnose that outage), and externally issued
	// jwt/oidc bearer tokens are not store identities, so deployments that
	// run them without a user DB keep working. A *confirmed* deprovisioned
	// match still denies every class that is looked up.
	if a.userProvider != nil && !principalSkipsUserStore(pd) {
		rec, found, derr := lookupPrincipalUser(r.Context(), a.userProvider, pd.ID)
		deprovisioned := found && isDeprovisionedStatus(rec.Status)
		if derr != nil {
			if a.principalUsesUserStore(pd) {
				a.reportUserStoreError(r, pd.ID, derr)
				return AuthPrincipal{}, errUserStoreUnavailable
			}
		} else if deprovisioned {
			return AuthPrincipal{}, fmt.Errorf("unauthorized")
		} else if found && rec.Tenant != "" && a.principalUsesUserStore(pd) {
			// L-18: a login session takes its tenant from the account, not
			// from anything the client presents.
			pd.Tenant = rec.Tenant
		}
	}
	resolved, rerr := resolvePrincipalTenancy(pd, r)
	if rerr == nil {
		recordAuditTenant(r, resolved.Tenant)
	}
	return resolved, rerr
}

// errTenantMismatch is returned when a tenant-scoped principal's X-Tenant
// header names a tenant other than the one bound to their identity (W3-01).
var errTenantMismatch = fmt.Errorf("tenant mismatch")

// resolvePrincipalTenancy stamps the tenant + super-admin flag on a principal.
// When MULTI_TENANCY is off, every principal is super-admin in DefaultTenant, so
// no isolation is applied (single-tenant behavior). When on: the bootstrap/root
// token is super-admin, and X-Tenant is purely a "view-as" selection for it
// (no membership check — a super-admin can view any tenant). Every other
// principal's tenant is identity-bound (W3-01: from the API key record or a
// JWT/OIDC tenant claim, set on pd.Tenant by authenticatePrincipal before this
// runs) — X-Tenant is honored for them only as a no-op confirmation of their
// own tenant; targeting any OTHER tenant is denied, not silently re-pinned.
//
// AuthType "bootstrap" is reserved for the raw bootstrap/root token (S-34) — a
// login-session JWT authenticated via the same "bootstrap" auth mode carries
// AuthType "local" instead (matching what Login() already stamps on its
// response principal), precisely so a non-admin session (e.g. pki-viewer)
// can never resolve to super-admin just by sharing the auth mode with the
// true root token.
func resolvePrincipalTenancy(pd AuthPrincipal, r *http.Request) (AuthPrincipal, error) {
	if !multiTenancyEnabled() {
		pd.Tenant = DefaultTenant
		pd.SuperAdmin = true
		pd.TenantScoped = false
		return pd, nil
	}
	pd.SuperAdmin = pd.AuthType == AuthTypeBootstrap
	header := strings.TrimSpace(r.Header.Get("X-Tenant"))

	if pd.SuperAdmin {
		if header == "" || header == "*" {
			pd.Tenant = DefaultTenant
			pd.TenantScoped = false
			return pd, nil
		}
		pd.Tenant = header
		pd.TenantScoped = true
		return pd, nil
	}

	identityTenant := pd.Tenant
	if identityTenant == "" {
		identityTenant = DefaultTenant
	}
	pd.TenantScoped = true
	if header != "" && header != "*" && header != identityTenant {
		return AuthPrincipal{}, errTenantMismatch
	}
	pd.Tenant = identityTenant
	return pd, nil
}

func (a *Authenticator) Mode() string {
	return a.config.mode
}

func (a *Authenticator) DiscoveryEnabled() bool {
	return a.discoveryEnabled
}

// errCrossSiteCookie is returned when the session cookie arrives on a
// state-changing request that a browser marked (or whose Origin shows) as not
// same-origin. Callers see it as an authentication failure.
var errCrossSiteCookie = fmt.Errorf("cross-site cookie request refused")

// crossSiteCookieRequest is the F9 defence in depth behind the cookie's
// SameSite=Strict: a request that authenticates with the kk_token cookie (no
// Authorization header) and uses an unsafe method must be same-origin.
// SameSite alone does not cover a same-site foreign origin (a sibling
// subdomain with XSS or a takeover), which still sends the cookie.
//
// Sec-Fetch-Site, set by the browser and not forgeable from page script, is
// authoritative when present: same-origin and none (user-initiated) pass,
// same-site and cross-site fail. Without it (older browsers) the Origin header
// must match the request host, or the X-Forwarded-Host of a fronting proxy.
// A request with neither header is not a browser fetch (curl, a script, a
// server-to-server client), and CSRF needs a browser to attach the cookie, so
// it is allowed rather than breaking cookie-bearing CLI use.
func crossSiteCookieRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	if _, err := parseBearerToken(r.Header.Get("Authorization")); err == nil {
		return false // header auth is not ambient; the browser never adds it
	}
	if c, err := r.Cookie("kk_token"); err != nil || c.Value == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "same-origin", "none":
		return false
	case "":
	default:
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return true // "null" and malformed origins are never ours
	}
	if strings.EqualFold(u.Host, r.Host) {
		return false
	}
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" && strings.EqualFold(u.Host, fwd) {
		return false
	}
	return true
}

func authenticatePrincipal(r *http.Request, cfg authValidatorConfig, oidcJWKSCache *managedOIDCJWKSCache, now time.Time) (AuthPrincipal, error) {
	token, err := parseBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		// Fall back to httpOnly session cookie set by the login endpoint.
		if cookie, cookieErr := r.Cookie("kk_token"); cookieErr == nil && cookie.Value != "" {
			if crossSiteCookieRequest(r) {
				return AuthPrincipal{}, errCrossSiteCookie
			}
			token = cookie.Value
		} else {
			return AuthPrincipal{}, fmt.Errorf("unauthorized")
		}
	}

	if cfg.apiKeyAuthEnabled && strings.HasPrefix(token, "kk_") {
		principal, ok, err := validateAPIKeyToken(token, cfg, now)
		if err != nil {
			return AuthPrincipal{}, err
		}
		if ok {
			return principal, nil
		}
	}

	switch cfg.mode {
	case "jwt":
		if cfg.jwtHS256Secret == "" {
			return AuthPrincipal{}, fmt.Errorf("unauthorized")
		}

		sub, tenant, err := validateHS256JWT(token, cfg.jwtHS256Secret, cfg.jwtIssuer, cfg.jwtAudience, cfg.tenantClaim, now)
		if err != nil {
			return AuthPrincipal{}, err
		}
		return cfg.bearerPrincipal(token, sub, tenant, AuthTypeJWT)
	case "oidc":
		// W33-06: with the local password login enabled, a local login-session
		// JWT (break-glass) must still authenticate when the IdP side is
		// broken, or a bad SSO override could never be reset. Only a token
		// signed with the login secret passes; nothing else is relaxed.
		if p, ok := localSessionPrincipal(token, cfg); ok {
			return p, nil
		}
		// Fail closed at request time too: the DB overrides for issuer and
		// audience can be cleared after startup validation passed, and an
		// unset audience would accept any token the IdP ever signed (A02-4).
		if cfg.oidcIssuer == "" || cfg.oidcAudience == "" {
			return AuthPrincipal{}, fmt.Errorf("unauthorized")
		}
		if cfg.oidcJWKSJSON != "" {
			sub, tenant, err := validateOIDCRS256JWT(token, cfg.oidcJWKSJSON, cfg.oidcIssuer, cfg.oidcAudience, cfg.tenantClaim, now)
			if err != nil {
				return AuthPrincipal{}, err
			}
			return cfg.bearerPrincipal(token, sub, tenant, AuthTypeOIDC)
		}
		if oidcJWKSCache != nil {
			sub, tenant, err := validateOIDCRS256JWTManaged(r.Context(), token, oidcJWKSCache, cfg.oidcIssuer, cfg.oidcAudience, cfg.tenantClaim, now)
			if err != nil {
				return AuthPrincipal{}, err
			}
			return cfg.bearerPrincipal(token, sub, tenant, AuthTypeOIDC)
		}
		return AuthPrincipal{}, fmt.Errorf("unauthorized")
	case "bootstrap":
		sub, role, authType, err := authenticateBootstrap(r, cfg)
		if err != nil {
			return AuthPrincipal{}, err
		}
		scopes := []string{}
		if isAdminRole(role) {
			scopes = []string{"*"}
		}
		return AuthPrincipal{ID: sub, Role: role, Scopes: scopes, AuthType: AuthType(authType)}, nil
	default:
		return AuthPrincipal{}, fmt.Errorf("unauthorized")
	}
}

func parseBearerToken(authHeader string) (string, error) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return "", fmt.Errorf("invalid authorization header")
	}
	return parts[1], nil
}

func audienceMatches(audClaim any, expectedAudience string) bool {
	switch aud := audClaim.(type) {
	case string:
		return aud == expectedAudience
	case []any:
		for _, item := range aud {
			if audValue, ok := item.(string); ok && audValue == expectedAudience {
				return true
			}
		}
	}
	return false
}

func (a *Authenticator) apiKeysSnapshot() map[string]apiKeyRecord {
	a.apiKeyMu.RLock()
	defer a.apiKeyMu.RUnlock()

	copied := make(map[string]apiKeyRecord, len(a.config.apiKeys))
	for kid, record := range a.config.apiKeys {
		recordCopy := record
		recordCopy.Scopes = append([]string(nil), record.Scopes...)
		copied[kid] = recordCopy
	}
	return copied
}

// localSessionPrincipal validates a local-login session JWT in oidc mode.
func localSessionPrincipal(token string, cfg authValidatorConfig) (AuthPrincipal, bool) {
	if !cfg.loginEnabled || strings.TrimSpace(cfg.loginSigning) == "" {
		return AuthPrincipal{}, false
	}
	sub, _, err := validateHS256JWT(token, cfg.loginSigning, cfg.jwtIssuer, cfg.jwtAudience, "", time.Now())
	if err != nil {
		return AuthPrincipal{}, false
	}
	role := strings.TrimSpace(jwtRoleClaim(token))
	if role == "" {
		return AuthPrincipal{}, false
	}
	scopes := []string{}
	if isAdminRole(role) {
		scopes = []string{"*"}
	}
	return AuthPrincipal{ID: sub, Role: role, Scopes: scopes, AuthType: AuthTypeLocal}, true
}
