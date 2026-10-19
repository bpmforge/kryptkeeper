// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuthenticatorFromEnvDiscoveryEnabledUsesManagedOIDCDiscovery(t *testing.T) {
	t.Setenv("AUTH_MODE", "oidc")
	t.Setenv("APP_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("APP_OIDC_DISCOVERY_URL", "")
	t.Setenv("APP_OIDC_JWKS_JSON", "")
	t.Setenv("APP_OIDC_HTTP_TIMEOUT_SEC", "1")
	t.Setenv("APP_OIDC_JWKS_TTL_SEC", "1")

	auth := NewAuthenticatorFromEnv()

	if !auth.DiscoveryEnabled() {
		t.Fatalf("expected discovery to be enabled when managed OIDC discovery is active")
	}
}

func TestNewAuthenticatorFromEnvDiscoveryEnabledIsFalseForStaticJWKS(t *testing.T) {
	t.Setenv("AUTH_MODE", "oidc")
	t.Setenv("APP_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("APP_OIDC_JWKS_JSON", `{"keys":[{"kty":"RSA","kid":"1"}]}`)

	auth := NewAuthenticatorFromEnv()

	if auth.DiscoveryEnabled() {
		t.Fatalf("expected discovery to be disabled when static JWKS is configured")
	}
}

func TestNewAuthenticatorFromEnvDiscoveryEnabledIsFalseOutsideOIDC(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")
	t.Setenv("APP_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("APP_OIDC_JWKS_JSON", "")

	auth := NewAuthenticatorFromEnv()

	if auth.DiscoveryEnabled() {
		t.Fatalf("expected discovery to be disabled when auth mode is not oidc")
	}
}

// TestNewAuthenticatorFromEnv_OIDCJWKSCacheBuiltUnderBootstrapMode is the
// regression test for the AUTH_MODE contradiction: OIDC SSO login sessions
// are only ever validated via authenticateBootstrap (AUTH_MODE=bootstrap),
// but ID-token validation (acceptance #1) needs a JWKS source. Before this
// fix, the cache was only built when AUTH_MODE=oidc, which would leave
// oidcJWKSCache nil under bootstrap mode and make every OIDC login fail
// closed on ID-token validation with no way to succeed.
func TestNewAuthenticatorFromEnv_OIDCJWKSCacheBuiltUnderBootstrapMode(t *testing.T) {
	var discovery *httptest.Server
	discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"` + discovery.URL + `/token","jwks_uri":"` + discovery.URL + `/jwks"}`))
	}))
	defer discovery.Close()

	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_OIDC_LOGIN_ENABLED", "true")
	t.Setenv("APP_OIDC_ISSUER", "https://idp.example.com/")
	t.Setenv("APP_OIDC_DISCOVERY_URL", discovery.URL)
	t.Setenv("APP_OIDC_CLIENT_ID", "test-client-id")
	t.Setenv("APP_OIDC_REDIRECT_URL", "https://kryptkeeper.example.com/api/v1/auth/oidc/callback")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")

	auth := NewAuthenticatorFromEnv()

	if auth.Mode() != "bootstrap" {
		t.Fatalf("Mode() = %q, want bootstrap", auth.Mode())
	}
	if auth.oidcJWKSCache == nil {
		t.Fatal("expected oidcJWKSCache to be built under AUTH_MODE=bootstrap when OIDC login is enabled")
	}
	if auth.config.oidcAuthorizationEndpoint != "https://idp.example.com/authorize" {
		t.Errorf("oidcAuthorizationEndpoint = %q", auth.config.oidcAuthorizationEndpoint)
	}
	if auth.config.oidcTokenEndpoint != discovery.URL+"/token" {
		t.Errorf("oidcTokenEndpoint = %q", auth.config.oidcTokenEndpoint)
	}
}

func TestNewAuthenticatorFromEnv_ExplicitEndpointsOverrideDiscovery(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_OIDC_LOGIN_ENABLED", "true")
	t.Setenv("APP_OIDC_ISSUER", "https://idp.example.com/")
	t.Setenv("APP_OIDC_CLIENT_ID", "test-client-id")
	t.Setenv("APP_OIDC_REDIRECT_URL", "https://kryptkeeper.example.com/api/v1/auth/oidc/callback")
	t.Setenv("APP_OIDC_AUTHORIZATION_ENDPOINT", "https://idp.example.com/authorize-explicit")
	t.Setenv("APP_OIDC_TOKEN_ENDPOINT", "https://idp.example.com/token-explicit")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")

	auth := NewAuthenticatorFromEnv()

	if auth.config.oidcAuthorizationEndpoint != "https://idp.example.com/authorize-explicit" {
		t.Errorf("oidcAuthorizationEndpoint = %q", auth.config.oidcAuthorizationEndpoint)
	}
	if auth.config.oidcTokenEndpoint != "https://idp.example.com/token-explicit" {
		t.Errorf("oidcTokenEndpoint = %q", auth.config.oidcTokenEndpoint)
	}
}

func TestNewAuthenticatorFromEnv_InsecureEndpointRejected(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_OIDC_LOGIN_ENABLED", "true")
	t.Setenv("APP_OIDC_CLIENT_ID", "test-client-id")
	t.Setenv("APP_OIDC_REDIRECT_URL", "https://kryptkeeper.example.com/api/v1/auth/oidc/callback")
	t.Setenv("APP_OIDC_AUTHORIZATION_ENDPOINT", "http://not-localhost.example.com/authorize")
	t.Setenv("APP_OIDC_TOKEN_ENDPOINT", "https://idp.example.com/token")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")

	auth := NewAuthenticatorFromEnv()

	if auth.config.oidcAuthorizationEndpoint != "" {
		t.Errorf("expected an insecure (non-localhost http) authorization endpoint to be rejected, got %q", auth.config.oidcAuthorizationEndpoint)
	}
}

func TestNewAuthenticatorFromEnv_SCIMGroupRoleMapParsed(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_SCIM_GROUP_ROLE_MAP_JSON", `{"kryptkeeper-admins":"pki-admin","kryptkeeper-operators":"pki-operator"}`)

	auth := NewAuthenticatorFromEnv()

	if got := auth.config.scimGroupRoleMap["kryptkeeper-admins"]; got != "pki-admin" {
		t.Errorf("scimGroupRoleMap[kryptkeeper-admins] = %q, want pki-admin", got)
	}
	if got := auth.config.scimGroupRoleMap["kryptkeeper-operators"]; got != "pki-operator" {
		t.Errorf("scimGroupRoleMap[kryptkeeper-operators] = %q, want pki-operator", got)
	}
}

func TestNewAuthenticatorFromEnv_InvalidSCIMGroupRoleMapJSONDoesNotCrash(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_SCIM_GROUP_ROLE_MAP_JSON", `not-json`)

	auth := NewAuthenticatorFromEnv()

	if len(auth.config.scimGroupRoleMap) != 0 {
		t.Errorf("expected an empty map for invalid JSON, got %+v", auth.config.scimGroupRoleMap)
	}
}

func TestNewAuthenticatorFromEnv_SCIMDefaultsApplied(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")

	auth := NewAuthenticatorFromEnv()

	if auth.config.scimDefaultRole != "" {
		t.Errorf("scimDefaultRole = %q, want no default (an ungrouped SCIM user has no role until mapped)", auth.config.scimDefaultRole)
	}
	if auth.config.scimBearerToken != "" {
		t.Errorf("expected no SCIM bearer token configured by default, got %q", auth.config.scimBearerToken)
	}
}

func pemEncodeCertForTest(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestNewAuthenticatorFromEnv_SAMLConfigParsed is acceptance #6: IdP
// metadata/certificate configuration is operator-supplied via auth_config.go
// (env vars here), and the IDP certificate store is populated from it
// rather than hardcoded.
func TestNewAuthenticatorFromEnv_SAMLConfigParsed(t *testing.T) {
	_, idpCert := generateTestSAMLIDPCert(t)

	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_SAML_LOGIN_ENABLED", "true")
	t.Setenv("APP_SAML_IDP_SSO_URL", "https://idp.example.com/saml/sso")
	t.Setenv("APP_SAML_IDP_ISSUER", "https://idp.example.com/saml/metadata")
	t.Setenv("APP_SAML_SP_ISSUER", "https://kryptkeeper.example.com/saml/sp")
	t.Setenv("APP_SAML_ACS_URL", "https://kryptkeeper.example.com/api/v1/auth/saml/acs")
	t.Setenv("APP_SAML_IDP_CERTIFICATE", pemEncodeCertForTest(t, idpCert.Raw))
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")

	auth := NewAuthenticatorFromEnv()

	if !auth.config.samlLoginEnabled {
		t.Fatal("expected samlLoginEnabled to be true")
	}
	if auth.config.samlIDPSSOURL != "https://idp.example.com/saml/sso" {
		t.Errorf("samlIDPSSOURL = %q", auth.config.samlIDPSSOURL)
	}
	if auth.config.samlIDPIssuer != "https://idp.example.com/saml/metadata" {
		t.Errorf("samlIDPIssuer = %q", auth.config.samlIDPIssuer)
	}
	if auth.config.samlSPIssuer != "https://kryptkeeper.example.com/saml/sp" {
		t.Errorf("samlSPIssuer = %q", auth.config.samlSPIssuer)
	}
	if auth.config.samlACSURL != "https://kryptkeeper.example.com/api/v1/auth/saml/acs" {
		t.Errorf("samlACSURL = %q", auth.config.samlACSURL)
	}
	if len(auth.config.samlIDPCertificates) != 1 {
		t.Fatalf("expected exactly one parsed IdP certificate, got %d", len(auth.config.samlIDPCertificates))
	}
	if !auth.config.samlIDPCertificates[0].Equal(idpCert) {
		t.Error("expected the parsed IdP certificate to match the configured PEM")
	}
	// Not explicitly set -- must default to samlSPIssuer, matching
	// samlServiceProviderFromConfig's firstNonEmpty(cfg.samlAudience,
	// cfg.samlSPIssuer) fallback (auth_saml.go).
	if auth.config.samlAudience != "" {
		t.Errorf("expected samlAudience to be empty (defaulted downstream), got %q", auth.config.samlAudience)
	}
	if sp := samlServiceProviderFromConfig(auth.config); sp == nil {
		t.Fatal("expected a fully-configured SAML authenticator to build a non-nil SAMLServiceProvider")
	} else if sp.AudienceURI != auth.config.samlSPIssuer {
		t.Errorf("expected AudienceURI to default to samlSPIssuer, got %q", sp.AudienceURI)
	}
}

func TestNewAuthenticatorFromEnv_SAMLInvalidCertificatePEMSkipped(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_SAML_LOGIN_ENABLED", "true")
	t.Setenv("APP_SAML_IDP_CERTIFICATE", "not a pem certificate")

	auth := NewAuthenticatorFromEnv()

	if len(auth.config.samlIDPCertificates) != 0 {
		t.Errorf("expected an invalid PEM block to be skipped, got %d certificates", len(auth.config.samlIDPCertificates))
	}
	if sp := samlServiceProviderFromConfig(auth.config); sp != nil {
		t.Error("expected samlServiceProviderFromConfig to fail closed (nil) with no valid IdP certificate")
	}
}

func TestNewAuthenticatorFromEnv_SAMLInsecureSSOURLRejected(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")
	t.Setenv("APP_SAML_LOGIN_ENABLED", "true")
	t.Setenv("APP_SAML_IDP_SSO_URL", "http://not-localhost.example.com/saml/sso")

	auth := NewAuthenticatorFromEnv()

	if auth.config.samlIDPSSOURL != "" {
		t.Errorf("expected an insecure (non-localhost http) IdP SSO URL to be rejected, got %q", auth.config.samlIDPSSOURL)
	}
}

func TestNewAuthenticatorFromEnv_SAMLDisabledByDefault(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")

	auth := NewAuthenticatorFromEnv()

	if auth.config.samlLoginEnabled {
		t.Error("expected samlLoginEnabled to default to false")
	}
	if got := len(auth.config.samlIDPCertificates); got != 0 {
		t.Errorf("expected no IdP certificates parsed by default, got %d", got)
	}
}

// TestNewAuthenticatorFromEnv_ConfigStoreWiredWhenPassphraseConfigured is
// the W8-13 acceptance #1 test for the SSO/OIDC consumer's construction
// side: the returned Authenticator must carry a real ConfigStore so
// ssoBearerConfigSnapshot (auth.go) has something to poll, whenever a
// credential-store passphrase is configured.
func TestNewAuthenticatorFromEnv_ConfigStoreWiredWhenPassphraseConfigured(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "test-passphrase-for-auth-config")
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")

	auth := NewAuthenticatorFromEnv()

	if auth.configStore == nil {
		t.Fatal("expected a real config store with passphrase + data dir configured")
	}
}

// TestNewAuthenticatorFromEnv_ConfigStoreNilWithoutPassphrase guards the
// nil-tolerant fallback: no passphrase configured means
// newConfigStoreFromEnv returns nil, and construction must not fail closed
// because of it -- ssoBearerConfigSnapshot's nil-store branch then keeps the
// pre-W8-13 env-only behavior.
func TestNewAuthenticatorFromEnv_ConfigStoreNilWithoutPassphrase(t *testing.T) {
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "")
	t.Setenv("KRYPTKEEPER_KEYSTORE_PASSPHRASE", "")
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-bootstrap-token")

	auth := NewAuthenticatorFromEnv()

	if auth.configStore != nil {
		t.Fatal("expected a nil config store with no passphrase configured")
	}
}
