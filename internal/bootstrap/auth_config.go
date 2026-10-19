// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/logging"
)

type authValidatorConfig struct {
	mode           string
	bootstrapToken string
	// bootstrapTokenDisabled (KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN) makes the
	// raw bootstrap token never authenticate; login sessions still do (A07-6).
	bootstrapTokenDisabled bool
	jwtHS256Secret         string
	jwtIssuer              string
	jwtAudience            string
	oidcIssuer             string
	oidcAudience           string
	oidcJWKSJSON           string
	loginEnabled           bool
	loginSigning           string
	loginTTL               time.Duration
	refreshTTL             time.Duration
	// idleTimeout bounds how long a refresh token may sit unused: Refresh
	// refuses a session whose last issue is older than this (0 disables).
	idleTimeout       time.Duration
	loginUser         loginCredential
	loginPepper       string
	apiKeyPepper      string
	apiKeys           map[string]apiKeyRecord
	apiKeyAuthEnabled bool
	// tenantClaim is the JWT/OIDC claim name carrying a scoped principal's
	// identity-bound tenant (W3-01). No standard claim exists across IdPs
	// (tenant/tid/org all appear in the wild) so it's configurable rather
	// than guessed; defaults to "tenant".
	tenantClaim string

	// roleClaim/roleMap grant roles to jwt/oidc bearer tokens (owner decision
	// on A02-3/A02-4). Without a match a token is "viewer". roleMapErr holds a
	// parse failure so ValidationReport can make it fatal instead of silently
	// running with no mapping.
	roleClaim  string
	roleMap    []roleMapEntry
	roleMapErr string
	// unmappedRole is APP_AUTH_UNMAPPED_ROLE: "read-only" opts into a viewer
	// for identities whose groups map to nothing; anything else denies.
	unmappedRole string

	// OIDC SSO login (W6-02): the browser-facing authorization-code+PKCE
	// flow, distinct from oidcIssuer/oidcAudience/oidcJWKSJSON above (which
	// gate *bearer-token* validation for service-to-service calls). The
	// login flow reuses those same fields for ID-token issuer/audience/JWKS
	// checks (acceptance #1), plus the fields below for the parts bearer
	// validation never needed: where to send the browser, and how to
	// authenticate at the token endpoint.
	oidcLoginEnabled          bool
	oidcClientID              string
	oidcClientSecret          string
	oidcRedirectURL           string
	oidcAuthorizationEndpoint string
	oidcTokenEndpoint         string
	oidcLoginScopes           string
	oidcLoginStateTTL         time.Duration
	oidcPostLoginRedirectURL  string

	// SCIM 2.0 provisioning (W6-02): a trust boundary separate from normal
	// operator sessions (acceptance #5) -- its own shared-secret bearer
	// token, never validated through Authenticator.AuthenticatePrincipal.
	scimBearerToken  string
	scimDefaultRole  string
	scimGroupRoleMap map[string]string

	// SAML SSO login (W6-09): a third browser login path alongside password
	// login and OIDC SSO above, built on gosaml2 (an operator-supplied IdP,
	// never Kryptkeeper acting as one). Establishes the exact same
	// mintSessionForUser session OIDC login does (auth_saml.go), so S-34
	// role claims, deprovisioning and tenancy all apply unchanged
	// (acceptance #5). samlIDPCertificates is the operator-supplied IdP
	// signing certificate store (acceptance #6) -- never hardcoded.
	//
	// Operator-facing env vars (acceptance #6's "documented" -- env.example
	// is out of this ticket's write_scope, so this comment block is the
	// authoritative list): APP_SAML_LOGIN_ENABLED (bool, default false),
	// APP_SAML_IDP_SSO_URL (the IdP's SSO redirect endpoint, must be https
	// unless localhost), APP_SAML_IDP_ISSUER (the IdP's entity ID),
	// APP_SAML_SP_ISSUER (this deployment's own SP entity ID),
	// APP_SAML_ACS_URL (must be https unless localhost, and should equal
	// this deployment's /api/v1/auth/saml/acs), APP_SAML_AUDIENCE (optional,
	// defaults to APP_SAML_SP_ISSUER), APP_SAML_IDP_CERTIFICATE (one or more
	// concatenated PEM-encoded X.509 certificates -- the IdP's signing
	// certificate(s), parsed by parseSAMLIDPCertificatesPEM in auth_saml.go),
	// APP_SAML_POST_LOGIN_REDIRECT_URL (optional, default "/").
	samlLoginEnabled         bool
	samlIDPSSOURL            string
	samlIDPIssuer            string
	samlSPIssuer             string
	samlACSURL               string
	samlAudience             string
	samlIDPCertificates      []*x509.Certificate
	samlPostLoginRedirectURL string
}

// anyLoginFlowEnabled reports whether any session-issuing login flow --
// local password, OIDC SSO, or SAML SSO -- is on. authenticateBootstrap's
// login-session-JWT gate (auth_bootstrap.go) asks this instead of
// enumerating the flags itself, so adding a fourth login flow only requires
// setting its own flag here rather than risking the "login succeeds, every
// subsequent request 401s" bug this fixes for the third time (W6-02: OIDC,
// W6-13: SAML).
func (cfg authValidatorConfig) anyLoginFlowEnabled() bool {
	return cfg.loginEnabled || cfg.oidcLoginEnabled || cfg.samlLoginEnabled
}

func NewAuthenticatorFromEnv() *Authenticator {
	bootstrapToken := os.Getenv("APP_BOOTSTRAP_TOKEN")
	bootstrapToken = strings.TrimSpace(bootstrapToken)
	bootstrapTokenDisabled := envFlagTrue("KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN")
	if bootstrapTokenDisabled {
		logging.Warnf("notice: KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN is set; the raw bootstrap token will not authenticate (login sessions, API keys and bearer tokens still do)")
	}
	authMode := os.Getenv("AUTH_MODE")
	if authMode == "" {
		authMode = "bootstrap"
	} else if authMode != "bootstrap" && authMode != "jwt" && authMode != "oidc" {
		logging.Warnf("unknown AUTH_MODE=%q; auth checks will fail closed", authMode)
	}
	jwtHS256Secret := os.Getenv("APP_JWT_HS256_SECRET")
	jwtIssuer := os.Getenv("APP_JWT_ISSUER")
	jwtAudience := os.Getenv("APP_JWT_AUDIENCE")
	oidcIssuer := os.Getenv("APP_OIDC_ISSUER")
	oidcAudience := os.Getenv("APP_OIDC_AUDIENCE")
	oidcJWKSJSON := os.Getenv("APP_OIDC_JWKS_JSON")
	oidcDiscoveryURL := os.Getenv("APP_OIDC_DISCOVERY_URL")
	loginEnabled := false
	if raw := strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_ENABLED")); raw != "" {
		loginEnabled = strings.EqualFold(raw, "true") || raw == "1"
	}
	loginUser := loginCredential{
		Email:        strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_EMAIL")),
		PasswordHash: strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_PASSWORD_HASH")),
		Role:         firstNonEmpty(os.Getenv("APP_AUTH_LOGIN_ROLE"), "pki-admin"),
		Subject:      strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_SUBJECT")),
		Active:       true,
	}
	if raw := strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_ACTIVE")); raw != "" {
		loginUser.Active = strings.EqualFold(raw, "true") || raw == "1"
	}
	oidcLoginEnabled := false
	if raw := strings.TrimSpace(os.Getenv("APP_OIDC_LOGIN_ENABLED")); raw != "" {
		oidcLoginEnabled = strings.EqualFold(raw, "true") || raw == "1"
	}
	oidcClientID := strings.TrimSpace(os.Getenv("APP_OIDC_CLIENT_ID"))
	oidcClientSecret := strings.TrimSpace(os.Getenv("APP_OIDC_CLIENT_SECRET"))
	oidcRedirectURL := strings.TrimSpace(os.Getenv("APP_OIDC_REDIRECT_URL"))
	oidcAuthorizationEndpoint := strings.TrimSpace(os.Getenv("APP_OIDC_AUTHORIZATION_ENDPOINT"))
	oidcTokenEndpoint := strings.TrimSpace(os.Getenv("APP_OIDC_TOKEN_ENDPOINT"))
	oidcLoginScopes := firstNonEmpty(strings.TrimSpace(os.Getenv("APP_OIDC_LOGIN_SCOPES")), "openid email profile")
	oidcPostLoginRedirectURL := firstNonEmpty(strings.TrimSpace(os.Getenv("APP_OIDC_POST_LOGIN_REDIRECT_URL")), "/")

	scimBearerToken := strings.TrimSpace(os.Getenv("APP_SCIM_TOKEN"))
	scimDefaultRole := strings.TrimSpace(os.Getenv("APP_SCIM_DEFAULT_ROLE"))
	scimGroupRoleMap := map[string]string{}
	if raw := strings.TrimSpace(os.Getenv("APP_SCIM_GROUP_ROLE_MAP_JSON")); raw != "" {
		var configured map[string]string
		if err := json.Unmarshal([]byte(raw), &configured); err != nil {
			logging.Warnf("invalid APP_SCIM_GROUP_ROLE_MAP_JSON; SCIM group role mapping disabled: %v", err)
		} else {
			for group, role := range configured {
				group = strings.TrimSpace(group)
				role = strings.TrimSpace(role)
				if group == "" || role == "" {
					continue
				}
				scimGroupRoleMap[group] = role
			}
		}
	}

	samlLoginEnabled := false
	if raw := strings.TrimSpace(os.Getenv("APP_SAML_LOGIN_ENABLED")); raw != "" {
		samlLoginEnabled = strings.EqualFold(raw, "true") || raw == "1"
	}
	samlIDPSSOURL := strings.TrimSpace(os.Getenv("APP_SAML_IDP_SSO_URL"))
	samlIDPIssuer := strings.TrimSpace(os.Getenv("APP_SAML_IDP_ISSUER"))
	samlSPIssuer := strings.TrimSpace(os.Getenv("APP_SAML_SP_ISSUER"))
	samlACSURL := strings.TrimSpace(os.Getenv("APP_SAML_ACS_URL"))
	samlAudience := strings.TrimSpace(os.Getenv("APP_SAML_AUDIENCE"))
	samlIDPCertificates := parseSAMLIDPCertificatesPEM(os.Getenv("APP_SAML_IDP_CERTIFICATE"))
	samlPostLoginRedirectURL := firstNonEmpty(strings.TrimSpace(os.Getenv("APP_SAML_POST_LOGIN_REDIRECT_URL")), "/")
	if err := requireHTTPSURL(samlIDPSSOURL); samlIDPSSOURL != "" && err != nil {
		logging.Warnf("invalid APP_SAML_IDP_SSO_URL; saml login will fail closed: %v", err)
		samlIDPSSOURL = ""
	}
	if err := requireHTTPSURL(samlACSURL); samlACSURL != "" && err != nil {
		logging.Warnf("invalid APP_SAML_ACS_URL; saml login will fail closed: %v", err)
		samlACSURL = ""
	}

	apiKeyPepper := strings.TrimSpace(os.Getenv("APP_API_KEY_PEPPER"))
	apiKeyAuthEnabled := false
	if raw := strings.TrimSpace(os.Getenv("APP_API_KEY_AUTH_ENABLED")); raw != "" {
		apiKeyAuthEnabled = strings.EqualFold(raw, "true") || raw == "1"
	}
	apiKeys := map[string]apiKeyRecord{}
	if raw := strings.TrimSpace(os.Getenv("APP_API_KEYS_JSON")); raw != "" {
		var configured []apiKeyRecord
		if err := json.Unmarshal([]byte(raw), &configured); err != nil {
			logging.Warnf("invalid APP_API_KEYS_JSON; api key auth disabled: %v", err)
		} else {
			for _, item := range configured {
				kid := strings.TrimSpace(item.Kid)
				if kid == "" || strings.TrimSpace(item.SecretVerifier) == "" || strings.TrimSpace(item.PrincipalID) == "" {
					continue
				}
				item.Kid = kid
				apiKeys[kid] = item
			}
		}
	}
	roleMap, roleMapParseErr := parseRoleMapJSON(os.Getenv("APP_AUTH_ROLE_MAP_JSON"))
	roleMapErr := ""
	if roleMapParseErr != nil {
		roleMapErr = roleMapParseErr.Error()
	}
	config := authValidatorConfig{
		roleClaim:      strings.TrimSpace(os.Getenv("APP_AUTH_ROLE_CLAIM")),
		roleMap:        roleMap,
		roleMapErr:     roleMapErr,
		mode:           authMode,
		bootstrapToken: bootstrapToken,
		jwtHS256Secret: jwtHS256Secret,

		bootstrapTokenDisabled: bootstrapTokenDisabled,
		jwtIssuer:              jwtIssuer,
		jwtAudience:            jwtAudience,
		oidcIssuer:             oidcIssuer,
		oidcAudience:           oidcAudience,
		oidcJWKSJSON:           oidcJWKSJSON,
		loginEnabled:           loginEnabled,
		loginSigning:           strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_SIGNING_SECRET")),
		loginTTL:               readEnvSeconds("APP_AUTH_ACCESS_TTL_SEC", 900),
		refreshTTL:             readEnvSeconds("APP_AUTH_REFRESH_TTL_SEC", 2592000),
		idleTimeout:            readEnvSeconds("APP_AUTH_IDLE_TIMEOUT_SEC", 1800),
		unmappedRole:           strings.ToLower(strings.TrimSpace(os.Getenv("APP_AUTH_UNMAPPED_ROLE"))),
		loginUser:              loginUser,
		loginPepper:            strings.TrimSpace(os.Getenv("APP_AUTH_LOGIN_PASSWORD_PEPPER")),
		apiKeyPepper:           apiKeyPepper,
		apiKeys:                apiKeys,
		apiKeyAuthEnabled:      apiKeyAuthEnabled,
		tenantClaim:            firstNonEmpty(strings.TrimSpace(os.Getenv("APP_AUTH_TENANT_CLAIM")), "tenant"),

		oidcLoginEnabled:          oidcLoginEnabled,
		oidcClientID:              oidcClientID,
		oidcClientSecret:          oidcClientSecret,
		oidcRedirectURL:           oidcRedirectURL,
		oidcAuthorizationEndpoint: oidcAuthorizationEndpoint,
		oidcTokenEndpoint:         oidcTokenEndpoint,
		oidcLoginScopes:           oidcLoginScopes,
		oidcLoginStateTTL:         readEnvSeconds("APP_OIDC_LOGIN_STATE_TTL_SEC", 300),
		oidcPostLoginRedirectURL:  oidcPostLoginRedirectURL,

		scimBearerToken:  scimBearerToken,
		scimDefaultRole:  scimDefaultRole,
		scimGroupRoleMap: scimGroupRoleMap,

		samlLoginEnabled:         samlLoginEnabled,
		samlIDPSSOURL:            samlIDPSSOURL,
		samlIDPIssuer:            samlIDPIssuer,
		samlSPIssuer:             samlSPIssuer,
		samlACSURL:               samlACSURL,
		samlAudience:             samlAudience,
		samlIDPCertificates:      samlIDPCertificates,
		samlPostLoginRedirectURL: samlPostLoginRedirectURL,
	}
	if authMode == "bootstrap" && bootstrapToken == "" && !bootstrapTokenDisabled {
		logging.Warnf("AUTH_MODE=bootstrap but APP_BOOTSTRAP_TOKEN is not set; bootstrap auth will fail closed")
	}
	if loginEnabled {
		if loginUser.Email == "" || loginUser.PasswordHash == "" || loginUser.Subject == "" || config.loginSigning == "" {
			logging.Warnf("login enabled but required login env values are missing; login endpoint will fail closed")
		}
	}
	if samlLoginEnabled {
		if samlIDPSSOURL == "" || samlIDPIssuer == "" || samlSPIssuer == "" || samlACSURL == "" || len(samlIDPCertificates) == 0 || config.loginSigning == "" {
			logging.Warnf("SAML login enabled but required configuration is incomplete; saml endpoints will fail closed")
		}
	}
	if len(apiKeys) > 0 && apiKeyPepper == "" {
		logging.Warnf("API keys configured without APP_API_KEY_PEPPER; api-key auth will fail closed")
	}
	if len(apiKeys) > 0 && !apiKeyAuthEnabled {
		logging.Warnf("API keys configured but APP_API_KEY_AUTH_ENABLED is false; api-key auth path disabled")
	}

	var oidcJWKSCache *managedOIDCJWKSCache
	// The SSO login flow's ID-token validation reuses this same cache
	// (acceptance #1), so it must exist under AUTH_MODE=bootstrap too --
	// login-issued sessions are only ever validated via authenticateBootstrap
	// (auth_bootstrap.go), never via the "oidc" bearer-token branch, so
	// oidcLoginEnabled is a second, independent trigger for building it.
	if (authMode == "oidc" || oidcLoginEnabled) && oidcJWKSJSON == "" {
		if oidcDiscoveryURL == "" && oidcIssuer != "" {
			oidcDiscoveryURL = strings.TrimRight(oidcIssuer, "/") + "/.well-known/openid-configuration"
		}
		if oidcDiscoveryURL != "" {
			oidcHTTPTimeout := readEnvSeconds("APP_OIDC_HTTP_TIMEOUT_SEC", 2)
			oidcJWKSTTL := readEnvSeconds("APP_OIDC_JWKS_TTL_SEC", 300)
			cache, err := newManagedOIDCJWKSCache(oidcDiscoveryURL, oidcHTTPTimeout, oidcJWKSTTL)
			if err != nil {
				logging.Infof("invalid OIDC managed JWKS configuration: %v", err)
			} else {
				oidcJWKSCache = cache
			}
		}
	}

	if oidcLoginEnabled {
		if oidcAuthorizationEndpoint == "" || oidcTokenEndpoint == "" {
			if oidcJWKSCache != nil {
				resolvedAuthEndpoint, resolvedTokenEndpoint, err := discoverOIDCEndpoints(oidcJWKSCache)
				if err != nil {
					logging.Warnf("OIDC login enabled but discovery endpoint lookup failed; login will fail closed: %v", err)
				} else {
					if oidcAuthorizationEndpoint == "" {
						oidcAuthorizationEndpoint = resolvedAuthEndpoint
					}
					if oidcTokenEndpoint == "" {
						oidcTokenEndpoint = resolvedTokenEndpoint
					}
				}
			}
		}
		if err := requireHTTPSURL(oidcAuthorizationEndpoint); oidcAuthorizationEndpoint != "" && err != nil {
			logging.Warnf("invalid APP_OIDC_AUTHORIZATION_ENDPOINT; login will fail closed: %v", err)
			oidcAuthorizationEndpoint = ""
		}
		if err := requireHTTPSURL(oidcTokenEndpoint); oidcTokenEndpoint != "" && err != nil {
			logging.Warnf("invalid APP_OIDC_TOKEN_ENDPOINT; login will fail closed: %v", err)
			oidcTokenEndpoint = ""
		}
		if oidcClientID == "" || oidcRedirectURL == "" || oidcAuthorizationEndpoint == "" || oidcTokenEndpoint == "" || config.loginSigning == "" {
			logging.Warnf("OIDC login enabled but required configuration is incomplete; login endpoint will fail closed")
		}
		config.oidcAuthorizationEndpoint = oidcAuthorizationEndpoint
		config.oidcTokenEndpoint = oidcTokenEndpoint
	}

	return &Authenticator{
		config:           config,
		oidcJWKSCache:    oidcJWKSCache,
		discoveryEnabled: oidcJWKSCache != nil,
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
		// registerAuthHandlers (handlers_auth.go) reuses this exact instance
		// for SCIM/OIDC login registration rather than minting its own, so a
		// SCIM DeactivateUser write and this Authenticator's deprovision check
		// (AuthenticatePrincipalDetails/Refresh) observe the same store even in
		// the in-memory dev-mode default. APP_USER_PROVIDER=db is unaffected
		// since all instances read/write the same physical tables regardless
		// of which object holds them. See the KNOWN LIVE GAP comment on
		// registerAuthHandlers (handlers_auth.go) -- handlers.go:102 still
		// wires the admin console's own, disconnected instance, out of this
		// ticket's write_scope to fix.
		userProvider: NewUserProviderFromEnv(),
		// configStore backs ssoBearerConfigSnapshot's live re-reads of the
		// bearer-token OIDC issuer/audience/JWKS quartet (W8-13, auth.go).
		// May be nil (no passphrase configured) -- nil-tolerant like every
		// other newXFromEnv consumer of this store.
		configStore: newConfigStoreFromEnv(),
	}
}

func envFlagTrue(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	return strings.EqualFold(raw, "true") || raw == "1"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func readEnvSeconds(name string, defaultSeconds int) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return time.Duration(defaultSeconds) * time.Second
	}

	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		logging.Infof("invalid %s=%q, using default %ds", name, raw, defaultSeconds)
		return time.Duration(defaultSeconds) * time.Second
	}

	return time.Duration(seconds) * time.Second
}

func requireHTTPSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Host == "" {
		return fmt.Errorf("must be absolute https url")
	}

	if parsed.Scheme == "https" {
		return nil
	}

	hostname := parsed.Hostname()
	if parsed.Scheme == "http" && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1") {
		return nil
	}

	return fmt.Errorf("must be absolute https url")
}

// liveAuthConfig is the TTL-cached overlay of registry overrides for the
// SAML and SCIM settings (W33-04), refreshed at most once per
// ssoBearerConfigTTL, mirroring ssoBearerConfigSnapshot.
type liveAuthConfig struct {
	mu        sync.Mutex
	checkedAt time.Time
	saml      authValidatorConfig
	scimToken string
}

// liveSnapshot returns the cached overlay, re-resolving it when stale.
func (a *Authenticator) liveSnapshot(ctx context.Context) (authValidatorConfig, string) {
	l := &a.liveCfg
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if a.ssoConfigNow != nil {
		now = a.ssoConfigNow()
	}
	if !l.checkedAt.IsZero() && now.Sub(l.checkedAt) < ssoBearerConfigTTL {
		return l.saml, l.scimToken
	}
	l.checkedAt = now

	cfg := a.config
	s := a.configStore
	cfg.samlIDPSSOURL = resolveSSOConfigString(ctx, s, "saml.idp_sso_url", cfg.samlIDPSSOURL)
	cfg.samlIDPIssuer = resolveSSOConfigString(ctx, s, "saml.idp_issuer", cfg.samlIDPIssuer)
	cfg.samlSPIssuer = resolveSSOConfigString(ctx, s, "saml.sp_entity_id", cfg.samlSPIssuer)
	if pem := strings.TrimSpace(resolveSSOConfigString(ctx, s, "saml.idp_certificate", "")); pem != "" {
		if certs := parseSAMLIDPCertificatesPEM(pem); len(certs) > 0 {
			cfg.samlIDPCertificates = certs
		}
	}
	// An override is held to the same https requirement as the env value.
	if cfg.samlIDPSSOURL != a.config.samlIDPSSOURL && requireHTTPSURL(cfg.samlIDPSSOURL) != nil {
		cfg.samlIDPSSOURL = ""
	}
	l.saml = cfg

	token := strings.TrimSpace(resolveSSOConfigSecret(ctx, s, "scim.token", a.config.scimBearerToken))
	enabled := token != ""
	if raw := strings.TrimSpace(resolveSSOConfigString(ctx, s, "scim.enabled", os.Getenv("APP_SCIM_ENABLED"))); raw != "" {
		enabled = strings.EqualFold(raw, "true") || raw == "1"
	}
	if !enabled || token == "" { // enabled with an empty token fails closed
		token = ""
	}
	l.scimToken = token
	return l.saml, l.scimToken
}

// samlEffectiveConfig is a.config with the registry's SAML overrides overlaid.
func (a *Authenticator) samlEffectiveConfig(ctx context.Context) authValidatorConfig {
	cfg, _ := a.liveSnapshot(ctx)
	return cfg
}

// scimEffectiveToken is the SCIM bearer token in force, or "" when SCIM is
// disabled or has no token.
func (a *Authenticator) scimEffectiveToken(ctx context.Context) string {
	_, tok := a.liveSnapshot(ctx)
	return tok
}

// W33-06: break-glass guard for SSO overrides.

var (
	errSSOGuardNoLocalAdmin = errors.New("an enabled local admin is required before changing SSO settings (set APP_AUTH_LOGIN_* and APP_AUTH_BREAKGLASS_EMAIL)")
	errSSOGuardDiscovery    = errors.New("OIDC discovery test failed; override not saved")
)

// oidcProbeClient fetches the admin-supplied discovery URL. The URL is
// attacker-influenceable (an admin account takeover must not become an SSRF
// primitive), so it runs on the egress-policy client: https only, link-local
// and cloud-metadata addresses always refused, loopback refused, redirects
// refused, 3 s timeout. Tests replace it.
var oidcProbeClient = egress.NewClient(egress.PolicyFromEnv(egress.Policy{
	AllowPrivate: true, // on-prem IdPs live on private space; KRYPTKEEPER_EGRESS_DENY_PRIVATE tightens it
	RequireHTTPS: true,
	MaxRedirects: 0,
	Timeout:      3 * time.Second,
}))

// hasEnabledLocalAdmin reports whether the static local login user is an
// enabled admin with a password verifier, i.e. an identity that does not
// depend on the IdP.
func (a *Authenticator) hasEnabledLocalAdmin() bool {
	c := a.config
	return c.loginEnabled && c.loginUser.Active && isAdminRole(c.loginUser.Role) &&
		strings.TrimSpace(c.loginUser.Email) != "" && a.loginPasswordHash() != ""
}

// ssoOverrideGuard refuses a set of an SSO key that could lock every login
// out. It runs before anything is persisted. Reset (DELETE) is never guarded.
func (a *Authenticator) ssoOverrideGuard(ctx context.Context, key, value string) error {
	if !ssoLockoutGuardedKeys[key] {
		return nil
	}
	if !a.hasEnabledLocalAdmin() {
		return errSSOGuardNoLocalAdmin
	}
	value = strings.TrimSpace(value)
	switch key {
	case "sso.oidc_issuer":
		if value == "" {
			return nil // clearing is a rollback
		}
		discovery := resolveSSOConfigString(ctx, a.configStore, "sso.oidc_discovery_url", os.Getenv("APP_OIDC_DISCOVERY_URL"))
		if strings.TrimSpace(discovery) == "" {
			discovery = strings.TrimRight(value, "/") + "/.well-known/openid-configuration"
		}
		return probeOIDCDiscovery(ctx, value, strings.TrimSpace(discovery))
	case "sso.oidc_discovery_url":
		if value == "" {
			return nil
		}
		issuer := resolveSSOConfigString(ctx, a.configStore, "sso.oidc_issuer", a.config.oidcIssuer)
		return probeOIDCDiscovery(ctx, strings.TrimSpace(issuer), value)
	}
	return nil
}

// probeOIDCDiscovery GETs discoveryURL and requires a 200 JSON document whose
// issuer matches and which names a jwks_uri. Failure causes are deliberately
// coarse: the response body is never reflected.
func probeOIDCDiscovery(ctx context.Context, issuer, discoveryURL string) error {
	if err := requireHTTPSURL(discoveryURL); err != nil {
		return fmt.Errorf("%w: discovery url %v", errSSOGuardDiscovery, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("%w: invalid discovery url", errSSOGuardDiscovery)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := oidcProbeClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: discovery endpoint unreachable or blocked", errSSOGuardDiscovery)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: discovery endpoint returned HTTP %d", errSSOGuardDiscovery, resp.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("%w: discovery document is not valid JSON", errSSOGuardDiscovery)
	}
	if strings.TrimSpace(doc.Issuer) == "" || strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return fmt.Errorf("%w: discovery issuer does not match the configured issuer", errSSOGuardDiscovery)
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return fmt.Errorf("%w: discovery document has no jwks_uri", errSSOGuardDiscovery)
	}
	return nil
}
