// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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
	loginUser              loginCredential
	loginPepper            string
	apiKeyPepper           string
	apiKeys                map[string]apiKeyRecord
	apiKeyAuthEnabled      bool
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
		log.Printf("notice: KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN is set; the raw bootstrap token will not authenticate (login sessions, API keys and bearer tokens still do)")
	}
	authMode := os.Getenv("AUTH_MODE")
	if authMode == "" {
		authMode = "bootstrap"
	} else if authMode != "bootstrap" && authMode != "jwt" && authMode != "oidc" {
		log.Printf("warning: unknown AUTH_MODE=%q; auth checks will fail closed", authMode)
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
	scimDefaultRole := firstNonEmpty(strings.TrimSpace(os.Getenv("APP_SCIM_DEFAULT_ROLE")), "pki-viewer")
	scimGroupRoleMap := map[string]string{}
	if raw := strings.TrimSpace(os.Getenv("APP_SCIM_GROUP_ROLE_MAP_JSON")); raw != "" {
		var configured map[string]string
		if err := json.Unmarshal([]byte(raw), &configured); err != nil {
			log.Printf("warning: invalid APP_SCIM_GROUP_ROLE_MAP_JSON; SCIM group role mapping disabled: %v", err)
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
		log.Printf("warning: invalid APP_SAML_IDP_SSO_URL; saml login will fail closed: %v", err)
		samlIDPSSOURL = ""
	}
	if err := requireHTTPSURL(samlACSURL); samlACSURL != "" && err != nil {
		log.Printf("warning: invalid APP_SAML_ACS_URL; saml login will fail closed: %v", err)
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
			log.Printf("warning: invalid APP_API_KEYS_JSON; api key auth disabled: %v", err)
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
		log.Printf("warning: AUTH_MODE=bootstrap but APP_BOOTSTRAP_TOKEN is not set; bootstrap auth will fail closed")
	}
	if loginEnabled {
		if loginUser.Email == "" || loginUser.PasswordHash == "" || loginUser.Subject == "" || config.loginSigning == "" {
			log.Printf("warning: login enabled but required login env values are missing; login endpoint will fail closed")
		}
	}
	if samlLoginEnabled {
		if samlIDPSSOURL == "" || samlIDPIssuer == "" || samlSPIssuer == "" || samlACSURL == "" || len(samlIDPCertificates) == 0 || config.loginSigning == "" {
			log.Printf("warning: SAML login enabled but required configuration is incomplete; saml endpoints will fail closed")
		}
	}
	if len(apiKeys) > 0 && apiKeyPepper == "" {
		log.Printf("warning: API keys configured without APP_API_KEY_PEPPER; api-key auth will fail closed")
	}
	if len(apiKeys) > 0 && !apiKeyAuthEnabled {
		log.Printf("warning: API keys configured but APP_API_KEY_AUTH_ENABLED is false; api-key auth path disabled")
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
				log.Printf("invalid OIDC managed JWKS configuration: %v", err)
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
					log.Printf("warning: OIDC login enabled but discovery endpoint lookup failed; login will fail closed: %v", err)
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
			log.Printf("warning: invalid APP_OIDC_AUTHORIZATION_ENDPOINT; login will fail closed: %v", err)
			oidcAuthorizationEndpoint = ""
		}
		if err := requireHTTPSURL(oidcTokenEndpoint); oidcTokenEndpoint != "" && err != nil {
			log.Printf("warning: invalid APP_OIDC_TOKEN_ENDPOINT; login will fail closed: %v", err)
			oidcTokenEndpoint = ""
		}
		if oidcClientID == "" || oidcRedirectURL == "" || oidcAuthorizationEndpoint == "" || oidcTokenEndpoint == "" || config.loginSigning == "" {
			log.Printf("warning: OIDC login enabled but required configuration is incomplete; login endpoint will fail closed")
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
		log.Printf("invalid %s=%q, using default %ds", name, raw, defaultSeconds)
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
