// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// bootstrapTokenMatches compares in constant time. Both sides are hashed first
// so ConstantTimeCompare always sees equal-length inputs (it returns early on
// a length mismatch, which would leak the configured token's length). An unset
// or disabled token never matches (A07-6).
func bootstrapTokenMatches(presented string, cfg authValidatorConfig) bool {
	if cfg.bootstrapTokenDisabled || cfg.bootstrapToken == "" {
		return false
	}
	got := sha256.Sum256([]byte(presented))
	want := sha256.Sum256([]byte(cfg.bootstrapToken))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// authenticateBootstrap returns the authenticated subject, its resolved
// role, and its auth type. The raw bootstrap token always resolves to
// (pki-admin, "bootstrap"), unchanged. A login-session JWT resolves to
// whatever role mintHS256JWT embedded in it (S-34), with auth type "local"
// — the same value Login() already stamps on the principal it returns, and
// deliberately distinct from "bootstrap" so resolvePrincipalTenancy (which
// grants super-admin only to AuthType "bootstrap") can never grant a session,
// admin-role or not, super-admin merely for sharing this auth mode with the
// true root token. A token with no role claim (e.g. one minted before this
// change) is rejected rather than defaulted to admin, since defaulting is
// exactly the escalation this fixes.
func authenticateBootstrap(r *http.Request, cfg authValidatorConfig) (string, string, string, error) {
	token := ""

	// Prefer Authorization header bearer token.
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Fall back to httpOnly session cookie set by the login endpoint.
	if token == "" {
		if cookie, err := r.Cookie("kk_token"); err == nil && cookie.Value != "" {
			token = cookie.Value
		}
	}

	if token == "" {
		return "", "", "", fmt.Errorf("unauthorized")
	}

	// Raw bootstrap token — always accepted, always pki-admin.
	if bootstrapTokenMatches(token, cfg) {
		return "bootstrap", "pki-admin", "bootstrap", nil
	}

	// Login-session JWT — accepted when any session-issuing login flow
	// (local-password, OIDC SSO, or SAML SSO) is enabled, and a signing
	// secret is set. The OIDC callback (auth_oidc_login.go) and the SAML
	// ACS endpoint (auth_saml.go) both mint the same session JWT Login()
	// does, so an SSO-only deployment must still be able to redeem it here
	// — gating solely on loginEnabled would mint a valid cookie at login
	// and then 401 every request after it (W6-02 for OIDC, W6-13 for
	// SAML). anyLoginFlowEnabled centralizes the check so a future login
	// flow only has to set its own flag rather than risk reintroducing
	// this bug a fourth time.
	if cfg.anyLoginFlowEnabled() && cfg.loginSigning != "" {
		sub, _, err := validateHS256JWT(token, cfg.loginSigning, cfg.jwtIssuer, cfg.jwtAudience, "", time.Now())
		if err == nil {
			role := strings.TrimSpace(jwtRoleClaim(token))
			if role == "" {
				return "", "", "", fmt.Errorf("unauthorized")
			}
			return sub, role, "local", nil
		}
	}

	return "", "", "", fmt.Errorf("unauthorized")
}
