// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"kryptkeeper/internal/logging"
)

var (
	errCustomRoleExists  = errors.New("custom role already exists")
	errCustomRolePersist = errors.New("custom role could not be saved")
)

// SQLite extended result codes for a duplicate key (sqlite3.h:
// SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE).
const (
	pgUniqueViolation          = "23505"
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

// isUniqueViolation reports a duplicate-key refusal by driver error code, not
// message text: Postgres unique_violation (23505) via pgx, or the SQLite
// primary-key/unique extended codes via modernc.
func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == pgUniqueViolation
	}
	var lite *sqlite.Error
	if errors.As(err, &lite) {
		return lite.Code() == sqliteConstraintUnique || lite.Code() == sqliteConstraintPrimaryKey
	}
	return false
}

// W6-08 (PE-10/D-049/FR-P11): admin-defined roles composed from a CLOSED
// permission vocabulary, with separation-of-duties constraints enforced
// at role-definition time. Roles were a compile-time switch before this.

// The permission vocabulary. Closed on purpose: a typo must be refused
// at creation, never silently minted as a dead permission.
var permissionVocabulary = map[string]bool{
	"certificate.read":    true,
	"certificate.issue":   true,
	"certificate.renew":   true,
	"certificate.revoke":  true,
	"ca.manage":           true,
	"key.manage":          true,
	"action.propose":      true,
	"action.approve":      true,
	"report.read":         true,
	"audit.read":          true,
	"discovery.manage":    true,
	"notification.manage": true,
	"protocol.manage":     true,
	"dashboard.manage":    true,
	"tenant.manage":       true,
	"user.manage":         true,
}

// fixedRoles are the compiled roles a custom role may never shadow.
var fixedRoles = map[string]bool{
	"pki-admin":       true,
	"pki-operator":    true,
	"viewer":          true,
	"service-account": true,
	"auditor":         true,
	"approver":        true,
	RoleMCPAgent:      true,
	RoleRequester:     true,
	"bootstrap":       true,
}

// builtinSoD is the immutable constraint: the proposer must never be the
// approver, structurally (D-029/R-C1's law lifted from a special case to
// a rule). It is enforced even on an empty table and cannot be deleted.
var builtinSoD = [2]string{"action.propose", "action.approve"}

// CustomRole is one admin-defined role.
type CustomRole struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	// TenantID empty = GLOBAL role (super-admin-managed); otherwise owned by that tenant.
	TenantID string `json:"tenant_id"`
}

// SoDConstraint is one persisted pair.
type SoDConstraint struct {
	ID          string `json:"id"`
	PermissionA string `json:"permission_a"`
	PermissionB string `json:"permission_b"`
}

// CustomRoleStore owns the custom_roles + role_sod_constraints tables.
type CustomRoleStore struct {
	db       *sql.DB
	postgres bool
	now      func() time.Time
}

func NewCustomRoleStore(db *sql.DB, postgres bool) (*CustomRoleStore, error) {
	if db == nil {
		return nil, fmt.Errorf("custom role store requires a database")
	}
	return &CustomRoleStore{db: db, postgres: postgres, now: time.Now}, nil
}

func (s *CustomRoleStore) rebind(q string) string {
	if !s.postgres {
		return q
	}
	out := make([]byte, 0, len(q)+8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, fmt.Sprintf("$%d", n)...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// validatePermissions checks vocabulary membership and normalizes order.
func validatePermissions(perms []string) ([]string, error) {
	if len(perms) == 0 {
		return nil, fmt.Errorf("custom role: at least one permission is required")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		if !permissionVocabulary[p] {
			return nil, fmt.Errorf("custom role: %q is not in the permission vocabulary", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// checkSoD refuses a permission set violating any constraint — the
// built-in pair first, then every persisted pair.
func (s *CustomRoleStore) checkSoD(perms []string) error {
	has := map[string]bool{}
	for _, p := range perms {
		has[p] = true
	}
	if has[builtinSoD[0]] && has[builtinSoD[1]] {
		return fmt.Errorf("separation of duties: %s and %s may never coexist in one role (built-in: the proposer must not be the approver)", builtinSoD[0], builtinSoD[1])
	}
	rows, err := s.db.Query(`SELECT permission_a, permission_b FROM role_sod_constraints`)
	if err != nil {
		return fmt.Errorf("custom role: load sod constraints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			return err
		}
		if has[a] && has[b] {
			return fmt.Errorf("separation of duties: %s and %s may not coexist in one role (constraint on record)", a, b)
		}
	}
	return rows.Err()
}

// CreateRole defines a custom role. Fixed role names are reserved.
func (s *CustomRoleStore) CreateRole(role CustomRole) (CustomRole, error) {
	if role.Name == "" {
		return CustomRole{}, fmt.Errorf("custom role: name is required")
	}
	if fixedRoles[role.Name] {
		return CustomRole{}, fmt.Errorf("custom role: %q is a fixed role and cannot be redefined", role.Name)
	}
	perms, err := validatePermissions(role.Permissions)
	if err != nil {
		return CustomRole{}, err
	}
	if err := s.checkSoD(perms); err != nil {
		return CustomRole{}, err
	}
	role.Permissions = perms
	raw, err := json.Marshal(perms)
	if err != nil {
		return CustomRole{}, fmt.Errorf("custom role: marshal: %w", err)
	}
	now := s.now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec(s.rebind(`
		INSERT INTO custom_roles (name, description, permissions, tenant_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`),
		role.Name, role.Description, string(raw), role.TenantID, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return CustomRole{}, fmt.Errorf("%w: a role named %q is already defined", errCustomRoleExists, role.Name)
		}
		// Driver text names tables and constraints: log it, never return it.
		logging.Warnf("custom role persist failed: %v", err)
		return CustomRole{}, errCustomRolePersist
	}
	return role, nil
}

// UpdateRole replaces a custom role's permission set, under the same
// vocabulary + SoD rules.
func (s *CustomRoleStore) UpdateRole(role CustomRole) (CustomRole, error) {
	if fixedRoles[role.Name] {
		return CustomRole{}, fmt.Errorf("custom role: %q is a fixed role and cannot be redefined", role.Name)
	}
	perms, err := validatePermissions(role.Permissions)
	if err != nil {
		return CustomRole{}, err
	}
	if err := s.checkSoD(perms); err != nil {
		return CustomRole{}, err
	}
	role.Permissions = perms
	raw, _ := json.Marshal(perms) // validated slice of plain strings: cannot fail
	res, err := s.db.Exec(s.rebind(`
		UPDATE custom_roles SET description = ?, permissions = ?, updated_at = ? WHERE name = ?`),
		role.Description, string(raw), s.now().UTC().Format(time.RFC3339), role.Name)
	if err != nil {
		logging.Warnf("custom role persist failed: %v", err)
		return CustomRole{}, errCustomRolePersist
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return CustomRole{}, fmt.Errorf("custom role %q not found", role.Name)
	}
	return role, nil
}

// GetRole loads one custom role.
func (s *CustomRoleStore) GetRole(name string) (CustomRole, bool, error) {
	row := s.db.QueryRow(s.rebind(`SELECT name, description, permissions, tenant_id FROM custom_roles WHERE name = ?`), name)
	var role CustomRole
	var raw string
	if err := row.Scan(&role.Name, &role.Description, &raw, &role.TenantID); err != nil {
		if err == sql.ErrNoRows {
			return CustomRole{}, false, nil
		}
		return CustomRole{}, false, err
	}
	if err := json.Unmarshal([]byte(raw), &role.Permissions); err != nil {
		return CustomRole{}, false, fmt.Errorf("custom role %s: permissions parse: %w", name, err)
	}
	return role, true, nil
}

// ListRoles returns every custom role.
func (s *CustomRoleStore) ListRoles() ([]CustomRole, error) {
	return s.listRoles(`SELECT name, description, permissions, tenant_id FROM custom_roles ORDER BY name`)
}

// ListRolesForTenant returns the tenant's own roles plus global ones.
func (s *CustomRoleStore) ListRolesForTenant(tenant string) ([]CustomRole, error) {
	return s.listRoles(`SELECT name, description, permissions, tenant_id FROM custom_roles WHERE tenant_id = ? OR tenant_id = '' ORDER BY name`, tenant)
}

func (s *CustomRoleStore) listRoles(query string, args ...any) ([]CustomRole, error) {
	rows, err := s.db.Query(s.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomRole
	for rows.Next() {
		var role CustomRole
		var raw string
		if err := rows.Scan(&role.Name, &role.Description, &raw, &role.TenantID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &role.Permissions); err != nil {
			return nil, fmt.Errorf("custom role %s: permissions parse: %w", role.Name, err)
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

// DeleteRole removes a custom role. Fixed roles are untouchable.
func (s *CustomRoleStore) DeleteRole(name string) error {
	if fixedRoles[name] {
		return fmt.Errorf("custom role: %q is a fixed role", name)
	}
	res, err := s.db.Exec(s.rebind(`DELETE FROM custom_roles WHERE name = ?`), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("custom role %q not found", name)
	}
	return nil
}

// AddSoDConstraint persists a new pair. Existing roles violating the new
// constraint are refused: a constraint that grandfathers violations is
// theater.
func (s *CustomRoleStore) AddSoDConstraint(a, b string) (SoDConstraint, error) {
	if a == b || !permissionVocabulary[a] || !permissionVocabulary[b] {
		return SoDConstraint{}, fmt.Errorf("sod constraint: two distinct vocabulary permissions required")
	}
	roles, err := s.ListRoles()
	if err != nil {
		return SoDConstraint{}, err
	}
	for _, r := range roles {
		has := map[string]bool{}
		for _, p := range r.Permissions {
			has[p] = true
		}
		if has[a] && has[b] {
			return SoDConstraint{}, fmt.Errorf("sod constraint: existing role %q holds both %s and %s — fix the role first", r.Name, a, b)
		}
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return SoDConstraint{}, err
	}
	c := SoDConstraint{ID: "sod-" + hex.EncodeToString(buf), PermissionA: a, PermissionB: b}
	_, err = s.db.Exec(s.rebind(`
		INSERT INTO role_sod_constraints (id, permission_a, permission_b, created_at)
		VALUES (?, ?, ?, ?)`),
		c.ID, a, b, s.now().UTC().Format(time.RFC3339))
	if err != nil {
		return SoDConstraint{}, fmt.Errorf("sod constraint: persist: %w", err)
	}
	return c, nil
}

// fixedRolePermissions maps compiled roles onto the vocabulary so one
// resolver answers for both worlds.
func fixedRolePermissions(role string) []string {
	switch role {
	case "pki-admin", "bootstrap":
		out := make([]string, 0, len(permissionVocabulary))
		for p := range permissionVocabulary {
			out = append(out, p)
		}
		return out
	case "pki-operator":
		return []string{"certificate.read", "certificate.issue", "certificate.renew", "certificate.revoke", "action.approve", "report.read"}
	case "viewer":
		return []string{"certificate.read", "report.read"}
	case "auditor":
		return []string{"certificate.read", "report.read", "audit.read"}
	case "approver":
		return []string{"certificate.read", "action.approve", "report.read"}
	case RoleMCPAgent:
		return []string{"certificate.read", "action.propose"}
	case "service-account":
		return []string{"certificate.read", "certificate.issue", "certificate.renew"}
	}
	return nil
}

// RoleHasPermission answers for fixed AND custom roles through one API.
// Unknown roles hold nothing.
func (s *CustomRoleStore) RoleHasPermission(role, permission string) (bool, error) {
	if perms := fixedRolePermissions(role); perms != nil {
		for _, p := range perms {
			if p == permission {
				return true, nil
			}
		}
		return false, nil
	}
	custom, found, err := s.GetRole(role)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	for _, p := range custom.Permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}
