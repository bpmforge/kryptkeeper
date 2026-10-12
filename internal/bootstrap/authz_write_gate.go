// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// The write gate: one check in front of every handler, so a principal can
// change only what its permissions cover, even where a handler forgot its
// own role check. Probes of a real hub on 2026-10-09 found viewer and
// mcp-agent keys creating root CAs, templates, targets and SSH certificates
// for any user (W20-26), and a pki-operator inviting a new pki-admin user
// (W20-27), because those handlers only authenticated the caller. Handler
// checks stay (defense in depth); this gate only ever refuses.
//
// Every API write is classified by writeRoutes into the one permission it
// needs, from the closed vocabulary in authz_custom_roles.go. A write no
// rule matches is admin-only, and authz_write_gate_test.go fails when a
// route the server, the API spec or the UI uses has no explicit rule.

const (
	// permSelf: the route authenticates its callers its own way (login,
	// agent tokens, SCIM bearer) and the gate stays out of it.
	permSelf = "self"
	// permQuery: a POST that computes and changes nothing; any signed-in
	// principal may call it.
	permQuery = "query"
	// permAdmin: pki-admin (or the bootstrap token) only.
	permAdmin = "admin"
	// permPropose: a proposal into the human approval queue, which every
	// principal that may write, mcp-agent included, may make (D-029).
	permPropose = "propose"
)

// writeRoute classifies writes to paths matching pattern: segments, where
// "*" is one segment and a trailing "**" is any remainder (including none).
type writeRoute struct {
	pattern string
	perm    string
}

// writeRoutes is first-match-wins, so specific rules precede broader ones.
var writeRoutes = []writeRoute{
	// Self-authenticating. (SCIM is mounted at /scim/v2, outside /api/v1 and
	// so outside this gate, behind its own bearer token.)
	{"/api/v1/auth/**", permSelf},
	{"/api/v1/agent/**", permSelf},

	// Pure computations sent as POST.
	{"/api/v1/crypto-agility/roadmap", permQuery},
	{"/api/v1/inventory/code-signing/policy-check", permQuery},

	// The approval queue.
	{"/api/v1/pending-actions", permPropose},
	{"/api/v1/pending-actions/*/approve", "action.approve"},
	{"/api/v1/pending-actions/*/reject", "action.approve"},
	{"/api/v1/approvals/**", "action.approve"},

	// Certificates.
	{"/api/v1/certificates", "certificate.issue"},
	{"/api/v1/certificates/import", "certificate.issue"},
	{"/api/v1/certificates/bulk-import", "certificate.issue"},
	{"/api/v1/certificates/bulk-reissue", "certificate.renew"},
	{"/api/v1/certificates/bulk-revoke", "certificate.revoke"},
	{"/api/v1/certificates/*/revoke", "certificate.revoke"},
	{"/api/v1/certificates/*/renew", "certificate.renew"},
	{"/api/v1/certificates/*/ownership", "certificate.renew"},
	{"/api/v1/renewal/**", "certificate.renew"},
	{"/api/v1/estate/**", "certificate.renew"},
	{"/api/v1/ssh/certificates", "certificate.issue"},
	{"/api/v1/spiffe/svid", "certificate.issue"},
	{"/api/v1/spiffe/workload-svid", "certificate.issue"},
	// PQC waves plan and propose renewals; execution itself goes through
	// the approval queue.
	{"/api/v1/reports/pqc-waves/*/execute/*/approve", "action.approve"},
	{"/api/v1/reports/pqc-waves/**", "certificate.renew"},

	// CAs and issuance policy. Workload registration and AD template
	// publishing are guarded in their handlers by canApproveActions
	// (pki-admin, pki-operator); action.approve keeps that set.
	{"/api/v1/cas/**", "ca.manage"},
	{"/api/v1/templates/**", "ca.manage"},
	{"/api/v1/spiffe/**", "action.approve"},
	{"/api/v1/adsync/**", "action.approve"},

	// Keys.
	{"/api/v1/keys/byok/**", "action.approve"},
	{"/api/v1/keys/**", "key.manage"},
	{"/api/v1/ceremonies/**", "key.manage"},

	// Estate discovery and its plumbing.
	{"/api/v1/discovery/**", "discovery.manage"},
	{"/api/v1/inventory-sources/**", "discovery.manage"},
	{"/api/v1/inventory/**", "discovery.manage"},
	{"/api/v1/targets/**", "discovery.manage"},
	{"/api/v1/connectors/**", "discovery.manage"},
	{"/api/v1/nhi/**", "action.approve"},

	// Notifications, evidence delivery, integrations.
	{"/api/v1/notifications/**", "notification.manage"},
	{"/api/v1/reports/evidence/**", "notification.manage"},
	{"/api/v1/integrations/**", "notification.manage"},

	// Protocols, dashboard.
	{"/api/v1/protocols/**", "protocol.manage"},
	{"/api/v1/scep/**", "protocol.manage"},
	{"/api/v1/dashboard/**", "dashboard.manage"},

	// Identity and tenancy.
	{"/api/v1/users/**", "user.manage"},
	{"/api/v1/roles/**", "user.manage"},
	{"/api/v1/tenants/**", "tenant.manage"},

	// Admin-only, named so the coverage test sees them as decided.
	{"/api/v1/api-keys/**", permAdmin},
	{"/api/v1/credentials/**", permAdmin},
	{"/api/v1/config/**", permAdmin},
	{"/api/v1/admin/**", permAdmin},
	{"/api/v1/delivery-plugins/**", permAdmin},
}

// matchWriteRoute returns the rule for path, or ok=false (admin-only).
func matchWriteRoute(path string) (writeRoute, bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for _, rt := range writeRoutes {
		if routeMatches(strings.Split(strings.Trim(rt.pattern, "/"), "/"), segs) {
			return rt, true
		}
	}
	return writeRoute{}, false
}

func routeMatches(pattern, segs []string) bool {
	for i, p := range pattern {
		if p == "**" {
			return true
		}
		if i >= len(segs) || (p != "*" && p != segs[i]) {
			return false
		}
	}
	return len(pattern) == len(segs)
}

// legacyRolePermissions are the compiled roles fixedRolePermissions does not
// list, as their handlers already treat them (authz_ops.go).
var legacyRolePermissions = map[string][]string{
	"discovery-operator":    {"certificate.read", "report.read", "discovery.manage", "dashboard.manage"},
	"notification-operator": {"certificate.read", "report.read", "notification.manage", "dashboard.manage"},
	"protocol-operator":     {"certificate.read", "report.read", "protocol.manage"},
	// The names the UI, SCIM default and API docs use for the read-only roles.
	"pki-viewer":  {"certificate.read", "report.read"},
	"pki-auditor": {"certificate.read", "report.read", "audit.read"},
}

// operatorExtras are what authz_ops.go's canManage* helpers grant
// pki-operator beyond fixedRolePermissions.
var operatorExtras = []string{"notification.manage", "dashboard.manage", "protocol.manage"}

// scopePermissions maps API-key scopes onto the vocabulary, mirroring the
// scope checks in authz_ops.go. Those helpers treat "*" exactly like
// ops:write; it never meant users, tenants, CAs or keys, and must not here.
var scopePermissions = map[string][]string{
	"audit:read":          {"audit.read"},
	"*":                   {"discovery.manage", "notification.manage", "dashboard.manage", "protocol.manage"},
	"ops:write":           {"discovery.manage", "notification.manage", "dashboard.manage", "protocol.manage"},
	"discovery:write":     {"discovery.manage"},
	"notifications:write": {"notification.manage"},
	"dashboard:write":     {"dashboard.manage"},
	"protocol:write":      {"protocol.manage"},
}

// principalPermissions is everything pd may do. Unknown roles hold
// nothing; mcp-agent holds nothing beyond proposing, whatever its scopes.
func principalPermissions(pd AuthPrincipal, roles *CustomRoleStore) (perms map[string]bool, admin bool) {
	role := strings.TrimSpace(pd.Role)
	perms = map[string]bool{}
	if role == RoleMCPAgent {
		return perms, false
	}
	if role == "pki-admin" || role == "bootstrap" {
		admin = true
	}
	add := func(ps ...string) {
		for _, p := range ps {
			perms[p] = true
		}
	}
	if fixed := fixedRolePermissions(role); fixed != nil {
		add(fixed...)
		if role == "pki-operator" {
			add(operatorExtras...)
		}
	} else if legacy, ok := legacyRolePermissions[role]; ok {
		add(legacy...)
	} else if roles != nil && !fixedRoles[role] {
		if custom, found, err := roles.GetRole(role); err == nil && found {
			add(custom.Permissions...)
		}
	}
	for _, s := range pd.Scopes {
		add(scopePermissions[strings.TrimSpace(s)]...)
	}
	return perms, admin
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// writeDecision says whether pd may make this write, and if not, the
// permission it lacks.
func writeDecision(pd AuthPrincipal, roles *CustomRoleStore, path string) (allowed bool, need string) {
	rt, ok := matchWriteRoute(path)
	need = permAdmin
	if ok {
		need = rt.perm
	}
	perms, admin := principalPermissions(pd, roles)
	switch need {
	case permSelf, permQuery:
		return true, need
	case permPropose:
		if strings.TrimSpace(pd.Role) == RoleMCPAgent || admin {
			return true, need
		}
		for p := range perms {
			if !strings.HasSuffix(p, ".read") {
				return true, need
			}
		}
		return false, need
	case permAdmin:
		return admin, need
	}
	return admin || perms[need], need
}

// withWriteAuthorization refuses API writes the principal's permissions do
// not cover. Self-authenticating routes, and requests that fail
// authentication, pass through: the handler answers 401 or authenticates
// the caller its own way.
func withWriteAuthorization(next http.Handler, auth *Authenticator, roles *CustomRoleStore, auditProvider AuditProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if !isWriteMethod(r.Method) || !strings.HasPrefix(path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if rt, ok := matchWriteRoute(path); ok && rt.perm == permSelf {
			next.ServeHTTP(w, r)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		allowed, need := writeDecision(pd, roles, path)
		if allowed {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("write gate: denied %s %s for principal=%q role=%q (needs %s)", r.Method, path, pd.ID, pd.Role, need)
		emitAuditEventDetail(r, auditProvider, pd.ID, "api.write", "api", path, AuditOutcomeDenied,
			"method="+r.Method+" role="+truncateForLog(pd.Role)+" needs="+need)
		msg := "your role does not have the " + need + " permission this change needs"
		switch {
		case strings.TrimSpace(pd.Role) == RoleMCPAgent:
			msg = "the mcp-agent role may only propose actions (POST /api/v1/pending-actions)"
		case need == permAdmin:
			msg = "this change needs the pki-admin role"
		}
		writeForbidden(w, msg)
	})
}
