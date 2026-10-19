// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// W12-06: the admin surface W6-08 disclosed. Store refusals
// (vocabulary, reserved names, SoD) pass through verbatim — the
// refusal text is the documentation.

// NewCustomRoleStoreFromEnv opens the shared DB and returns nil when
// unavailable (endpoints then answer 503 — visible degradation).
func NewCustomRoleStoreFromEnv() *CustomRoleStore {
	state := newDBProviderState[*CustomRoleStore](
		"custom-roles",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *CustomRoleStore { s, _ := NewCustomRoleStore(db, false); return s },
		func(db *sql.DB) *CustomRoleStore { s, _ := NewCustomRoleStore(db, true); return s },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("custom-roles", state.openErr) // logs the outage itself
		return nil
	}
	// Schema comes from migration 000034; EnsureSchema-style self-heal for
	// deployments that point this store elsewhere.
	if _, err := state.store.db.Exec(`
CREATE TABLE IF NOT EXISTS custom_roles (
    name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '[]', tenant_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS role_sod_constraints (
    id TEXT PRIMARY KEY, permission_a TEXT NOT NULL, permission_b TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE (permission_a, permission_b));`); err != nil {
		_ = dbProviderUnavailable("custom-roles", err) // logs the outage itself
		return nil
	}
	return state.store
}

// roleMayManageRoles is the guarded path custom roles resolve on:
// compiled admin roles pass, and so does any custom role granted
// user.manage — RoleHasPermission spans fixed + custom by design.
func roleMayManageRoles(store *CustomRoleStore, role string) bool {
	if isAdminRole(role) {
		return true
	}
	if store == nil {
		return false
	}
	ok, err := store.RoleHasPermission(role, "user.manage")
	return err == nil && ok
}

type roleListEntry struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Builtin     bool     `json:"builtin"`
	TenantID    string   `json:"tenant_id,omitempty"`
}

// roleTenantRefusal reports whether pd may NOT write a role owned by roleTenant.
// Global roles ("") are super-admin-only; tenant roles belong to that tenant.
func roleTenantRefusal(pd AuthPrincipal, roleTenant string) bool {
	if pd.SuperAdmin {
		return false
	}
	return roleTenant == "" || roleTenant != pd.Tenant
}

// registerCustomRoleHandlers mounts the roles admin API.
func registerCustomRoleHandlers(mux *http.ServeMux, auth *Authenticator, store *CustomRoleStore, auditProvider AuditProvider) {
	gate := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			// Privilege-management surface: a rejected attempt is the
			// reconnaissance signal the append-only trail must keep.
			emitAuditEvent(r, auditProvider, "", "role.access", "role", "roles", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !roleMayManageRoles(store, pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "role.access", "role", "roles", AuditOutcomeDenied)
			writeForbidden(w, "your role is not authorized to manage roles")
			return AuthPrincipal{}, false
		}
		if store == nil {
			writeServiceUnavailable(w, "custom-role store unavailable")
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := gate(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			var custom []CustomRole
			var err error
			if pd.SuperAdmin && !pd.TenantScoped {
				custom, err = store.ListRoles()
			} else {
				custom, err = store.ListRolesForTenant(pd.Tenant)
			}
			if err != nil {
				writeServiceUnavailable(w, "role list failed")
				return
			}
			out := make([]roleListEntry, 0, len(custom)+len(fixedRoles))
			for name := range fixedRoles {
				out = append(out, roleListEntry{Name: name, Builtin: true})
			}
			for _, c := range custom {
				out = append(out, roleListEntry{Name: c.Name, Description: c.Description, Permissions: c.Permissions, TenantID: c.TenantID})
			}
			writeJSONData(w, out)
		case http.MethodPost:
			var role CustomRole
			if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			// Never trust the body's tenant_id: the owner is the caller's tenant.
			role.TenantID = ""
			if pd.TenantScoped {
				role.TenantID = pd.Tenant
			}
			if ref := roleGrantRefusal(pd, store, role); ref != nil {
				refuseGrant(w, r, auditProvider, pd, "role.create", "role", role.Name, ref)
				return
			}
			created, err := store.CreateRole(role)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "role.create", "role", role.Name, AuditOutcomeFailure)
				switch {
				case errors.Is(err, errCustomRoleExists):
					writeConflict(w, err.Error())
				case errors.Is(err, errCustomRolePersist):
					writeServiceUnavailable(w, "the role could not be saved")
				default:
					writeBadRequest(w, err.Error()) // store refusal text verbatim
				}
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "role.create", "role", created.Name, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data CustomRole `json:"data"`
			}{Data: created})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/roles/sod-constraints", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := gate(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			constraints, err := listSoDConstraints(r.Context(), store)
			if err != nil {
				writeServiceUnavailable(w, "constraint list failed")
				return
			}
			writeJSONData(w, constraints)
		case http.MethodPost:
			var req struct {
				PermissionA string `json:"permission_a"`
				PermissionB string `json:"permission_b"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			// A SoD constraint is applied to every tenant's roles.
			if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "role.sod_add", "role_sod", "-") {
				return
			}
			created, err := store.AddSoDConstraint(req.PermissionA, req.PermissionB)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "role.sod_add", "role_sod", req.PermissionA+"|"+req.PermissionB, AuditOutcomeFailure)
				writeBadRequest(w, err.Error()) // no-grandfathering refusal verbatim
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "role.sod_add", "role_sod", created.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data SoDConstraint `json:"data"`
			}{Data: created})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/roles/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/roles/sod-constraints") {
			http.NotFound(w, r)
			return
		}
		pd, ok := gate(w, r)
		if !ok {
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
		if name == "" || strings.Contains(name, "/") {
			writeBadRequest(w, "expected /roles/{name}")
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if existing, found, err := store.GetRole(name); err == nil && found {
				if roleTenantRefusal(pd, existing.TenantID) {
					action := "role.update"
					if r.Method == http.MethodDelete {
						action = "role.delete"
					}
					emitAuditEventDetail(r, auditProvider, pd.ID, action, "role", name, AuditOutcomeDenied, "cross-tenant")
					writeForbidden(w, "role belongs to another tenant")
					return
				}
				if ref := checkPermissionGrant(pd, store, existing.Permissions); ref != nil {
					refuseGrant(w, r, auditProvider, pd, "role.update", "role", name, ref)
					return
				}
			}
		}
		switch r.Method {
		case http.MethodPut:
			var role CustomRole
			if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			role.Name = name
			if ref := roleGrantRefusal(pd, store, role); ref != nil {
				refuseGrant(w, r, auditProvider, pd, "role.update", "role", name, ref)
				return
			}
			updated, err := store.UpdateRole(role)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "role.update", "role", name, AuditOutcomeFailure)
				if errors.Is(err, errCustomRolePersist) {
					writeServiceUnavailable(w, "the role could not be saved")
					return
				}
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "role.update", "role", name, AuditOutcomeSuccess)
			writeJSONData(w, updated)
		case http.MethodDelete:
			if err := store.DeleteRole(name); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "role.delete", "role", name, AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "role.delete", "role", name, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, http.MethodPut+", "+http.MethodDelete)
		}
	})
}

// listSoDConstraints returns persisted pairs plus the immutable
// built-in, marked builtin — the listing must show the whole law.
func listSoDConstraints(ctx context.Context, store *CustomRoleStore) ([]map[string]any, error) {
	out := []map[string]any{{
		"permission_a": builtinSoD[0], "permission_b": builtinSoD[1], "builtin": true,
	}}
	rows, err := store.db.QueryContext(ctx, `SELECT id, permission_a, permission_b FROM role_sod_constraints ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, a, b string
		if err := rows.Scan(&id, &a, &b); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "permission_a": a, "permission_b": b, "builtin": false})
	}
	return out, rows.Err()
}
