// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// defaultBearerRole is what a valid AUTH_MODE=jwt / AUTH_MODE=oidc bearer token
// receives when no role mapping matches. It is read-only on purpose: before
// the owner decision recorded with A02-3/A02-4 every valid token became
// "service-account", which can issue and renew certificates, so a token minted
// for any other purpose could issue certificates.
const defaultBearerRole = "viewer"

// roleMapEntry is one pair of APP_AUTH_ROLE_MAP_JSON.
type roleMapEntry struct {
	ClaimValue string `json:"claim_value"`
	Role       string `json:"role"`
}

// parseRoleMapJSON decodes APP_AUTH_ROLE_MAP_JSON: an ordered array, because
// order is precedence. Unknown fields are refused so a typo such as "roles"
// cannot silently produce an empty mapping.
func parseRoleMapJSON(raw string) ([]roleMapEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	var entries []roleMapEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("APP_AUTH_ROLE_MAP_JSON must be a JSON array of {\"claim_value\",\"role\"} objects: %w", err)
	}
	for i := range entries {
		entries[i].ClaimValue = strings.TrimSpace(entries[i].ClaimValue)
		entries[i].Role = strings.TrimSpace(entries[i].Role)
	}
	return entries, nil
}

// roleClaimValues returns the string values of a claim that may be a single
// string or an array of strings; anything else yields nothing.
func roleClaimValues(claim any) []string {
	switch v := claim.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// roleGrantableByMap reports whether role may be granted to a bearer token
// through the map. mcp-agent is proposal-only and bound to its own token
// path; "bootstrap" is the reserved root identity.
func roleGrantableByMap(role string) bool {
	return role != RoleMCPAgent && role != "bootstrap"
}

// bearerRole resolves the role of a bearer token whose signature has already
// been verified. The first map entry whose claim_value appears in the token's
// role claim wins; no match, or no mapping configured, yields viewer.
func (cfg authValidatorConfig) bearerRole(token string) string {
	if cfg.roleClaim == "" || len(cfg.roleMap) == 0 {
		return defaultBearerRole
	}
	claims, err := decodeJWTPayloadClaims(token)
	if err != nil {
		return defaultBearerRole
	}
	have := roleClaimValues(claims[cfg.roleClaim])
	if len(have) == 0 {
		return defaultBearerRole
	}
	for _, entry := range cfg.roleMap {
		if entry.ClaimValue == "" || entry.Role == "" || !roleGrantableByMap(entry.Role) {
			continue
		}
		for _, v := range have {
			if v == entry.ClaimValue {
				return entry.Role
			}
		}
	}
	return defaultBearerRole
}

// bearerPrincipal builds the principal for a verified jwt/oidc bearer token.
func (cfg authValidatorConfig) bearerPrincipal(token, sub, tenant string, authType AuthType) AuthPrincipal {
	role := cfg.bearerRole(token)
	scopes := []string{}
	if isAdminRole(role) {
		scopes = []string{"*"}
	}
	return AuthPrincipal{ID: sub, Role: role, Scopes: scopes, AuthType: authType, Tenant: tenant}
}

// SetCustomRoleLookup lets ValidationReport confirm that a role named in
// APP_AUTH_ROLE_MAP_JSON is an existing custom role. Custom roles live in the
// database, which the Authenticator does not own, so main wires this in.
func (a *Authenticator) SetCustomRoleLookup(lookup func(name string) (bool, error)) {
	a.customRoleLookup = lookup
}

func (a *Authenticator) validateBearerRoleMap(report *StartupReport) {
	cfg := a.config
	if cfg.roleMapErr != "" {
		report.addError(cfg.roleMapErr)
		return
	}
	if len(cfg.roleMap) == 0 {
		if cfg.roleClaim != "" {
			report.addWarning("APP_AUTH_ROLE_CLAIM is set but APP_AUTH_ROLE_MAP_JSON is empty; every bearer token will be read-only (viewer)")
		}
		return
	}
	if cfg.roleClaim == "" {
		report.addError("APP_AUTH_ROLE_MAP_JSON is set but APP_AUTH_ROLE_CLAIM is empty")
	}
	if cfg.mode != "jwt" && cfg.mode != "oidc" {
		report.addWarning("APP_AUTH_ROLE_MAP_JSON only applies in AUTH_MODE=jwt or oidc and is ignored in " + cfg.mode + " mode")
	}
	for i, entry := range cfg.roleMap {
		switch {
		case entry.ClaimValue == "" || entry.Role == "":
			report.addError(fmt.Sprintf("APP_AUTH_ROLE_MAP_JSON entry %d needs a non-empty claim_value and role", i))
		case !roleGrantableByMap(entry.Role):
			report.addError(fmt.Sprintf("APP_AUTH_ROLE_MAP_JSON entry %d: role %q may not be granted through a bearer-token mapping", i, entry.Role))
		case !a.roleKnown(entry.Role, report):
			report.addError(fmt.Sprintf("APP_AUTH_ROLE_MAP_JSON entry %d: unknown role %q (must be a fixed role or an existing custom role)", i, entry.Role))
		}
	}
}

// roleKnown reports whether role is a compiled or custom role. A failing
// custom-role lookup is a warning, not an error: a transient DB problem must
// not stop the hub over a role the operator may well have defined.
func (a *Authenticator) roleKnown(role string, report *StartupReport) bool {
	if fixedRoles[role] {
		return true
	}
	if _, ok := legacyRolePermissions[role]; ok {
		return true
	}
	if a.customRoleLookup == nil {
		return false
	}
	found, err := a.customRoleLookup(role)
	if err != nil {
		report.addWarning(fmt.Sprintf("could not verify custom role %q from APP_AUTH_ROLE_MAP_JSON: %v", role, err))
		return true
	}
	return found
}
