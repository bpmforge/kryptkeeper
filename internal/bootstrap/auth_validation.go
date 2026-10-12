// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"strings"
)

// minHS256SecretBytes is the floor for any secret that signs session or
// bearer JWTs. Session JWTs carry a signed role claim, so a guessable secret
// lets anyone holding one token forge a pki-admin token offline (A02-3).
const minHS256SecretBytes = 32

// minBootstrapTokenChars is the length below which the raw bootstrap token is
// flagged. A warning, not an error: dev and test setups use short tokens.
const minBootstrapTokenChars = 32

// placeholderSecretPrefix marks the sample values shipped in env.example
// ("change-me-to-a-strong-secret"). Some are longer than the length floors, so
// a copied-and-forgotten sample would otherwise pass them (AS-01).
const placeholderSecretPrefix = "change-me"

// RejectPlaceholderSecret returns an error when value is still the sample
// placeholder from env.example. It is the single check used for every secret
// the hub refuses to start with: bootstrap token, login/JWT signing secrets,
// peppers and the keystore passphrase. The value is never echoed.
func RejectPlaceholderSecret(name, value string) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), placeholderSecretPrefix) {
		return fmt.Errorf("%s still has the sample placeholder value from env.example; generate a real one with: openssl rand -hex 32", name)
	}
	return nil
}

type StartupReport struct {
	Warnings []string
	Errors   []string
}

func (r *StartupReport) addWarning(msg string) {
	msg = strings.TrimSpace(msg)
	if msg != "" {
		r.Warnings = append(r.Warnings, msg)
	}
}

func (r *StartupReport) addError(msg string) {
	msg = strings.TrimSpace(msg)
	if msg != "" {
		r.Errors = append(r.Errors, msg)
	}
}

// FatalError returns nil when the report has no errors, otherwise one error
// listing every one of them so the operator can fix them in a single pass.
func (r StartupReport) FatalError() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return fmt.Errorf("%d auth configuration error(s):\n  - %s", len(r.Errors), strings.Join(r.Errors, "\n  - "))
}

func (a *Authenticator) ValidationReport() StartupReport {
	var report StartupReport
	if a == nil {
		report.addError("authenticator is nil")
		return report
	}
	cfg := a.config
	if !cfg.loginEnabled {
		report.addWarning("login endpoint is disabled")
	}
	if cfg.loginEnabled {
		if strings.TrimSpace(cfg.loginUser.Email) == "" {
			report.addError("APP_AUTH_LOGIN_EMAIL is missing")
		}
		if strings.TrimSpace(cfg.loginUser.PasswordHash) == "" {
			report.addError("APP_AUTH_LOGIN_PASSWORD_HASH is missing")
		}
		if strings.TrimSpace(cfg.loginUser.Subject) == "" {
			report.addError("APP_AUTH_LOGIN_SUBJECT is missing")
		}
		if strings.TrimSpace(cfg.loginSigning) == "" {
			report.addError("APP_AUTH_LOGIN_SIGNING_SECRET is missing")
		}
	}
	// The same secret signs the session JWT of every login flow (password,
	// OIDC SSO, SAML SSO), so the length floor applies whenever any is on.
	if cfg.anyLoginFlowEnabled() && cfg.loginSigning != "" && len(cfg.loginSigning) < minHS256SecretBytes {
		report.addError(fmt.Sprintf("APP_AUTH_LOGIN_SIGNING_SECRET is %d bytes; at least %d are required (generate one with: openssl rand -hex 32)", len(cfg.loginSigning), minHS256SecretBytes))
	}
	if cfg.mode == "jwt" && cfg.jwtHS256Secret != "" && len(cfg.jwtHS256Secret) < minHS256SecretBytes {
		report.addError(fmt.Sprintf("APP_JWT_HS256_SECRET is %d bytes; at least %d are required (generate one with: openssl rand -hex 32)", len(cfg.jwtHS256Secret), minHS256SecretBytes))
	}

	token := strings.TrimSpace(cfg.bootstrapToken)
	for _, sec := range []struct{ name, value string }{
		{"APP_AUTH_LOGIN_SIGNING_SECRET", cfg.loginSigning},
		{"APP_JWT_HS256_SECRET", cfg.jwtHS256Secret},
		{"APP_AUTH_LOGIN_PASSWORD_PEPPER", cfg.loginPepper},
		{"APP_API_KEY_PEPPER", cfg.apiKeyPepper},
	} {
		if err := RejectPlaceholderSecret(sec.name, sec.value); err != nil {
			report.addError(err.Error())
		}
	}
	if !cfg.bootstrapTokenDisabled {
		if err := RejectPlaceholderSecret("APP_BOOTSTRAP_TOKEN", token); err != nil {
			report.addError(err.Error())
		}
	}
	switch {
	case cfg.bootstrapTokenDisabled:
		report.addWarning("raw bootstrap token is disabled (KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN); only login sessions, API keys and bearer tokens authenticate")
		if token != "" {
			report.addWarning("APP_BOOTSTRAP_TOKEN is set but ignored because KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN is on")
		}
	case cfg.mode == "bootstrap" && token == "":
		// A login flow still authenticates without the raw token, so only an
		// install with no way in at all is an error.
		if cfg.anyLoginFlowEnabled() {
			report.addWarning("APP_BOOTSTRAP_TOKEN is missing in bootstrap auth mode; only login sessions will authenticate")
		} else {
			report.addError("APP_BOOTSTRAP_TOKEN is missing in bootstrap auth mode")
		}
	case cfg.mode == "bootstrap" && len(token) < minBootstrapTokenChars:
		report.addWarning(fmt.Sprintf("APP_BOOTSTRAP_TOKEN is only %d characters; use at least %d (generate one with: openssl rand -hex 32) or set KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=true once login is configured", len(token), minBootstrapTokenChars))
	}

	if strings.TrimSpace(cfg.apiKeyPepper) == "" && len(cfg.apiKeys) > 0 {
		// With API-key auth off the keys are inert, so a missing pepper only
		// matters (and only breaks anything) when they are live.
		if cfg.apiKeyAuthEnabled {
			report.addError("APP_API_KEY_PEPPER is missing while API keys are configured")
		} else {
			report.addWarning("APP_API_KEY_PEPPER is missing while API keys are configured")
		}
	}
	if len(cfg.apiKeys) > 0 && !cfg.apiKeyAuthEnabled {
		report.addWarning("API keys are configured but API key auth is disabled")
	}
	if a.oidcJWKSCache == nil && strings.EqualFold(cfg.mode, "oidc") && strings.TrimSpace(cfg.oidcJWKSJSON) == "" {
		report.addWarning("OIDC discovery is not enabled; static JWKS or discovery URL not configured")
	}
	if strings.EqualFold(cfg.mode, "oidc") {
		// Resolved the way requests resolve them (DB override, else env) so a
		// deployment configured purely through the config store is not
		// flagged. Without both, any token the IdP signs for any client would
		// authenticate (A02-4).
		ctx := context.Background()
		issuer := resolveSSOConfigString(ctx, a.configStore, "sso.oidc_issuer", cfg.oidcIssuer)
		audience := resolveSSOConfigString(ctx, a.configStore, "sso.oidc_audience", cfg.oidcAudience)
		if strings.TrimSpace(issuer) == "" {
			report.addError("APP_OIDC_ISSUER (or config key sso.oidc_issuer) is required in oidc auth mode")
		}
		if strings.TrimSpace(audience) == "" {
			report.addError("APP_OIDC_AUDIENCE (or config key sso.oidc_audience) is required in oidc auth mode")
		}
	}
	a.validateBearerRoleMap(&report)
	return report
}
