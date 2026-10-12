// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"sort"
	"strings"
)

// TM-08 / FG-3: a caller may hand out only what it holds. Before this, a
// custom role carrying user.manage passed the write gate and could then PATCH
// itself to pki-admin or PUT its own role to the whole vocabulary, because
// the permission that guards role management was also the one it granted.

// grantableRolePermissions is what a principal holding role would be able to
// do, or known=false for a role string no rule defines (typos, invented
// names). mcp-agent is included with its declared permissions, unlike in
// principalPermissions, so that handing it out needs those permissions too.
func grantableRolePermissions(role string, roles *CustomRoleStore) (perms map[string]bool, known bool) {
	role = strings.TrimSpace(role)
	if role == "" {
		return nil, false
	}
	perms = map[string]bool{}
	add := func(ps []string) {
		for _, p := range ps {
			perms[p] = true
		}
	}
	if fixed := fixedRolePermissions(role); fixed != nil {
		add(fixed)
		if role == "pki-operator" {
			add(operatorExtras)
		}
		return perms, true
	}
	if legacy, ok := legacyRolePermissions[role]; ok {
		add(legacy)
		return perms, true
	}
	if roles != nil && !fixedRoles[role] {
		if custom, found, err := roles.GetRole(role); err == nil && found {
			add(custom.Permissions)
			return perms, true
		}
	}
	return nil, false
}

// grantRefusal is why a role assignment or permission grant was refused.
type grantRefusal struct {
	status int // 400 unknown role, 403 above the caller
	msg    string
	detail string // audit change summary
}

// checkRoleGrant says whether caller may give someone role. nil means yes.
// pki-admin and the bootstrap token (admin) may grant any defined role; a
// delegate may grant only roles whose permissions it holds, and never an
// admin role, whose power is more than its permission list.
func checkRoleGrant(caller AuthPrincipal, roles *CustomRoleStore, role string) *grantRefusal {
	role = strings.TrimSpace(role)
	want, known := grantableRolePermissions(role, roles)
	if !known {
		return &grantRefusal{http.StatusBadRequest, "unknown role", "unknown role " + truncateForLog(role)}
	}
	held, admin := principalPermissions(caller, roles)
	if admin {
		return nil
	}
	if role == "pki-admin" || role == "bootstrap" {
		return &grantRefusal{http.StatusForbidden, "only pki-admin may grant the " + role + " role", "role=" + role + " needs admin"}
	}
	if missing := missingPermissions(held, want); len(missing) > 0 {
		return &grantRefusal{http.StatusForbidden, "you may grant only roles whose permissions you hold yourself", "role=" + role + " missing=" + strings.Join(missing, ",")}
	}
	return nil
}

// checkPermissionGrant is checkRoleGrant for a custom role's permission list.
func checkPermissionGrant(caller AuthPrincipal, roles *CustomRoleStore, perms []string) *grantRefusal {
	held, admin := principalPermissions(caller, roles)
	if admin {
		return nil
	}
	want := map[string]bool{}
	for _, p := range perms {
		want[p] = true
	}
	if missing := missingPermissions(held, want); len(missing) > 0 {
		return &grantRefusal{http.StatusForbidden, "you may grant only permissions you hold yourself", "missing=" + strings.Join(missing, ",")}
	}
	return nil
}

func missingPermissions(held, want map[string]bool) []string {
	var missing []string
	for p := range want {
		if !held[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	return missing
}

// checkTargetRole says whether caller may act on a user who currently holds
// role: it must be able to grant that role itself, or a delegate could demote,
// disable or delete a pki-admin. A role no rule defines is admin-only.
func checkTargetRole(caller AuthPrincipal, roles *CustomRoleStore, role string) *grantRefusal {
	if strings.TrimSpace(role) == "" {
		return nil
	}
	ref := checkRoleGrant(caller, roles, role)
	if ref == nil || ref.status != http.StatusBadRequest {
		return ref
	}
	if _, admin := principalPermissions(caller, roles); admin {
		return nil
	}
	return &grantRefusal{http.StatusForbidden, "you may change only users whose role you could grant", ref.detail}
}

// roleGrantRefusal checks a custom role definition against its author. The
// vocabulary is checked first so a typo stays a 400 rather than a 403.
func roleGrantRefusal(caller AuthPrincipal, roles *CustomRoleStore, role CustomRole) *grantRefusal {
	perms, err := validatePermissions(role.Permissions)
	if err != nil {
		return &grantRefusal{http.StatusBadRequest, err.Error(), "invalid permissions"}
	}
	return checkPermissionGrant(caller, roles, perms)
}

// refuseGrant answers a grantRefusal and records it in the audit trail.
func refuseGrant(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, caller AuthPrincipal, action, resourceType, resourceID string, ref *grantRefusal) {
	outcome := AuditOutcomeDenied
	if ref.status == http.StatusBadRequest {
		outcome = AuditOutcomeFailure
	}
	emitAuditEventDetail(r, auditProvider, caller.ID, action, resourceType, resourceID, outcome, ref.detail)
	if ref.status == http.StatusBadRequest {
		writeBadRequest(w, ref.msg)
		return
	}
	writeForbidden(w, ref.msg)
}

// requireReadPermission gates a read on one permission from the vocabulary,
// the read-side twin of the write gate: admin, or a role (or scope) that
// holds it. mcp-agent holds nothing here whatever its scopes.
func requireReadPermission(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, pd AuthPrincipal, roles *CustomRoleStore, perm, action, resourceType, resourceID string) bool {
	held, admin := principalPermissions(pd, roles)
	if admin || held[perm] {
		return true
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, action, resourceType, resourceID, AuditOutcomeDenied,
		"role="+truncateForLog(pd.Role)+" needs="+perm)
	writeForbidden(w, "your role does not have the "+perm+" permission")
	return false
}
