// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// msgSSONoRoleMapped is the 403 body of a browser SSO login whose IdP groups
// map to no role. It names no group or role so the response leaks nothing.
const msgSSONoRoleMapped = "no Kryptkeeper role is mapped to your IdP groups; ask an administrator"

// errRoleUnmapped is returned for a verified bearer token whose claims map to
// no role while APP_AUTH_UNMAPPED_ROLE has not opted into read-only access.
var errRoleUnmapped = errors.New("no role mapped")

// unmappedRoleReadOnly is the one APP_AUTH_UNMAPPED_ROLE value that opts in.
const unmappedRoleReadOnly = "read-only"

// unmappedFallbackRole is what the opt-in grants: the read-only viewer. It was
// the silent default before W22-19; before the owner decision recorded with
// A02-3/A02-4 it was "service-account", which can issue certificates.
const unmappedFallbackRole = "viewer"

// RoleRequester (W33-22) is the app-owner role: it may file certificate
// requests for its own team and read its own requests and quota, nothing more.
// The write gate confines it to POST /api/v1/certificates (writeDecision).
const RoleRequester = "requester"

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

// roleResolution is the outcome of mapping IdP group values through the role map.
type roleResolution struct {
	Role         string
	MatchedClaim string
	Mapped       bool
}

// resolveRole returns the role of the first roleMap entry (order is
// precedence) whose claim_value is among claimValues. Entries naming a role
// that roleGrantableByMap refuses (mcp-agent, bootstrap) are skipped, so an
// IdP group can never confer a privileged identity.
func (cfg authValidatorConfig) resolveRole(claimValues []string) roleResolution {
	for _, entry := range cfg.roleMap {
		if entry.ClaimValue == "" || entry.Role == "" || !roleGrantableByMap(entry.Role) {
			continue
		}
		for _, v := range claimValues {
			if v == entry.ClaimValue {
				return roleResolution{Role: entry.Role, MatchedClaim: entry.ClaimValue, Mapped: true}
			}
		}
	}
	return roleResolution{}
}

// unmappedFallback is the role an unmapped identity receives: viewer only when
// the operator opted in with APP_AUTH_UNMAPPED_ROLE=read-only, otherwise "",
// meaning deny.
func (cfg authValidatorConfig) unmappedFallback() string {
	if cfg.unmappedRole == unmappedRoleReadOnly {
		return unmappedFallbackRole
	}
	return ""
}

// bearerRole resolves the role of a bearer token whose signature has already
// been verified. The first map entry whose claim_value appears in the token's
// role claim wins; no match (or no mapping configured) yields the opt-in
// fallback, which is "" (deny) unless APP_AUTH_UNMAPPED_ROLE=read-only.
func (cfg authValidatorConfig) bearerRole(token string) string {
	if cfg.roleClaim != "" && len(cfg.roleMap) > 0 {
		if claims, err := decodeJWTPayloadClaims(token); err == nil {
			if res := cfg.resolveRole(roleClaimValues(claims[cfg.roleClaim])); res.Mapped {
				return res.Role
			}
		}
	}
	return cfg.unmappedFallback()
}

// bearerPrincipal builds the principal for a verified jwt/oidc bearer token.
// Callers render any error as 401 like every other auth failure; the explicit
// 403 for an unmapped identity belongs to the browser SSO login flows.
func (cfg authValidatorConfig) bearerPrincipal(token, sub, tenant string, authType AuthType) (AuthPrincipal, error) {
	role := cfg.bearerRole(token)
	if role == "" {
		return AuthPrincipal{}, errRoleUnmapped
	}
	scopes := []string{}
	if isAdminRole(role) {
		scopes = []string{"*"}
	}
	return AuthPrincipal{ID: sub, Role: role, Scopes: scopes, AuthType: authType, Tenant: tenant}, nil
}

// ssoSessionRole decides the role of a browser SSO login for a provisioned
// user. Order: (1) a mapped IdP group wins and is persisted so refresh, which
// re-reads the user store, keeps it; (2) else the role already on the record
// (SCIM group map or operator-set); (3) else the opt-in fallback. ok=false
// means deny with 403. The role-map only applies when a roleClaim is configured.
func (a *Authenticator) ssoSessionRole(ctx context.Context, user UserRecord, groups []string) (string, bool, error) {
	cfg := a.config
	if cfg.roleClaim != "" && len(cfg.roleMap) > 0 {
		if res := cfg.resolveRole(groups); res.Mapped {
			if res.Role != user.Role && a.userProvider != nil {
				if _, err := a.userProvider.UpdateUser(ctx, user.ID, res.Role, ""); err != nil {
					return "", false, err
				}
			}
			return res.Role, true, nil
		}
	}
	if role := strings.TrimSpace(user.Role); role != "" {
		return role, true, nil
	}
	if fb := cfg.unmappedFallback(); fb != "" {
		return fb, true, nil
	}
	return "", false, nil
}

// roleMapPreviewMaxGroups / roleMapPreviewMaxGroupLen bound the preview query.
const (
	roleMapPreviewMaxGroups   = 50
	roleMapPreviewMaxGroupLen = 256
)

type roleMapPreview struct {
	Groups            []string `json:"groups"`
	Mapped            bool     `json:"mapped"`
	Role              string   `json:"role"`
	MatchedClaimValue string   `json:"matched_claim_value"`
	UnmappedPolicy    string   `json:"unmapped_policy"`
	EffectiveRole     string   `json:"effective_role"`
	WouldLogin        bool     `json:"would_login"`
}

// registerRoleMapPreviewHandler serves GET /api/v1/auth/role-map/preview. It
// lives under /api/v1/auth/** (permSelf in the write gate), so it authenticates
// and checks role-management rights itself. It reads instance-global auth
// config and no tenant data.
func registerRoleMapPreviewHandler(mux *http.ServeMux, auth *Authenticator, audit AuditProvider) {
	mux.HandleFunc("/api/v1/auth/role-map/preview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if !roleMayManageRoles(auth.roleStore, pd.Role) {
			emitAuditEvent(r, audit, pd.ID, "auth.role_map.preview", "auth", "role-map", AuditOutcomeDenied)
			writeForbidden(w, "role management permission required")
			return
		}
		// The map is instance-wide IdP policy; a tenant admin must not read it.
		if denyNonSuperAdminGlobal(w, r, audit, pd, "auth.role_map.preview", "auth", "role-map") {
			return
		}
		groups := []string{}
		if raw := strings.TrimSpace(r.URL.Query().Get("groups")); raw != "" {
			for _, g := range strings.Split(raw, ",") {
				if g = strings.TrimSpace(g); g != "" {
					groups = append(groups, g)
				}
			}
		}
		if len(groups) > roleMapPreviewMaxGroups {
			writeBadRequest(w, "too many groups")
			return
		}
		for _, g := range groups {
			if len(g) > roleMapPreviewMaxGroupLen {
				writeBadRequest(w, "group value too long")
				return
			}
		}
		cfg := auth.config
		res := cfg.resolveRole(groups)
		effective := res.Role
		if !res.Mapped {
			effective = cfg.unmappedFallback()
		}
		policy := "deny"
		if cfg.unmappedRole == unmappedRoleReadOnly {
			policy = unmappedRoleReadOnly
		}
		emitAuditEvent(r, audit, pd.ID, "auth.role_map.preview", "auth", "role-map", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			Data roleMapPreview `json:"data"`
		}{Data: roleMapPreview{
			Groups: groups, Mapped: res.Mapped, Role: res.Role, MatchedClaimValue: res.MatchedClaim,
			UnmappedPolicy: policy, EffectiveRole: effective, WouldLogin: effective != "",
		}}); err != nil {
			logging.Warnf("failed to encode GET /api/v1/auth/role-map/preview response: %v", err)
		}
	})
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
	if cfg.unmappedRole != "" && cfg.unmappedRole != "deny" && cfg.unmappedRole != unmappedRoleReadOnly {
		report.addWarning("APP_AUTH_UNMAPPED_ROLE must be \"deny\" or \"read-only\"; unrecognised value treated as deny")
	}
	if len(cfg.roleMap) == 0 {
		if cfg.roleClaim != "" {
			report.addWarning("APP_AUTH_ROLE_CLAIM is set but APP_AUTH_ROLE_MAP_JSON is empty; every bearer token will be refused unless APP_AUTH_UNMAPPED_ROLE=read-only")
		} else if (cfg.mode == "jwt" || cfg.mode == "oidc") && cfg.unmappedRole != unmappedRoleReadOnly {
			report.addWarning("AUTH_MODE=" + cfg.mode + " has no APP_AUTH_ROLE_MAP_JSON; every bearer token will be refused unless APP_AUTH_UNMAPPED_ROLE=read-only")
		}
		return
	}
	if cfg.roleClaim == "" {
		report.addError("APP_AUTH_ROLE_MAP_JSON is set but APP_AUTH_ROLE_CLAIM is empty")
	}
	if cfg.mode != "jwt" && cfg.mode != "oidc" && !cfg.oidcLoginEnabled && !cfg.samlLoginEnabled {
		report.addWarning("APP_AUTH_ROLE_MAP_JSON only applies to AUTH_MODE=jwt|oidc bearer tokens and OIDC/SAML browser login, and is ignored in " + cfg.mode + " mode")
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
