// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// W6-08: admin-defined roles beyond the fixed set, with enforceable
// separation of duties.

const customRolesTestSchema = `
CREATE TABLE IF NOT EXISTS custom_roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '[]',
    tenant_id   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_sod_constraints (
    id           TEXT PRIMARY KEY,
    permission_a TEXT NOT NULL,
    permission_b TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (permission_a, permission_b)
);`

func newCustomRoleStore(t *testing.T) (*CustomRoleStore, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(customRolesTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	s, err := NewCustomRoleStore(db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return s, db
}

func TestCustomRoleDefinedBeyondFixedSet(t *testing.T) {
	s, db := newCustomRoleStore(t)
	role, err := s.CreateRole(CustomRole{
		Name:        "cert-desk",
		Description: "issues and renews, nothing else",
		Permissions: []string{"certificate.issue", "certificate.renew", "certificate.read"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(role.Permissions) != 3 {
		t.Fatalf("permissions normalized wrong: %v", role.Permissions)
	}

	// Resolves through the shared API, and survives a store restart.
	s2, err := NewCustomRoleStore(db, false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ok, err := s2.RoleHasPermission("cert-desk", "certificate.issue")
	if err != nil || !ok {
		t.Fatalf("custom role must resolve its permission after restart: %v %v", ok, err)
	}
	ok, _ = s2.RoleHasPermission("cert-desk", "ca.manage")
	if ok {
		t.Fatal("custom role must not hold permissions it was not given")
	}
	// Fixed roles answer through the same resolver.
	if ok, _ := s2.RoleHasPermission("pki-admin", "ca.manage"); !ok {
		t.Fatal("pki-admin must resolve every vocabulary permission")
	}
	if ok, _ := s2.RoleHasPermission(RoleMCPAgent, "action.approve"); ok {
		t.Fatal("mcp-agent must never resolve action.approve")
	}
	if ok, _ := s2.RoleHasPermission("no-such-role", "certificate.read"); ok {
		t.Fatal("unknown roles hold nothing")
	}
}

func TestCustomRoleRefusals(t *testing.T) {
	s, _ := newCustomRoleStore(t)

	// Fixed names are reserved.
	if _, err := s.CreateRole(CustomRole{Name: "pki-admin", Permissions: []string{"report.read"}}); err == nil {
		t.Fatal("shadowing a fixed role must be refused")
	}
	// Vocabulary is closed.
	if _, err := s.CreateRole(CustomRole{Name: "typo-role", Permissions: []string{"certifcate.isue"}}); err == nil {
		t.Fatal("unknown permissions must be refused")
	}
	// Empty set is meaningless.
	if _, err := s.CreateRole(CustomRole{Name: "empty-role", Permissions: nil}); err == nil {
		t.Fatal("an empty permission set must be refused")
	}
}

func TestSeparationOfDutiesEnforced(t *testing.T) {
	s, _ := newCustomRoleStore(t)

	// Built-in, immutable: proposer != approver.
	_, err := s.CreateRole(CustomRole{
		Name:        "self-dealer",
		Permissions: []string{"action.propose", "action.approve"},
	})
	if err == nil || !strings.Contains(err.Error(), "proposer") {
		t.Fatalf("built-in SoD must refuse propose+approve, got %v", err)
	}

	// Admin-defined pair: issue x approve.
	if _, err := s.AddSoDConstraint("certificate.issue", "action.approve"); err != nil {
		t.Fatalf("add constraint: %v", err)
	}
	_, err = s.CreateRole(CustomRole{
		Name:        "issue-and-bless",
		Permissions: []string{"certificate.issue", "action.approve"},
	})
	if err == nil || !strings.Contains(err.Error(), "may not coexist") {
		t.Fatalf("persisted SoD must refuse, got %v", err)
	}

	// The pair separately is fine.
	if _, err := s.CreateRole(CustomRole{Name: "issuer", Permissions: []string{"certificate.issue"}}); err != nil {
		t.Fatalf("issuer alone: %v", err)
	}
	if _, err := s.CreateRole(CustomRole{Name: "blesser", Permissions: []string{"action.approve"}}); err != nil {
		t.Fatalf("approver alone: %v", err)
	}

	// A new constraint cannot grandfather an existing violation.
	if _, err := s.CreateRole(CustomRole{Name: "reader-manager", Permissions: []string{"certificate.read", "ca.manage"}}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.AddSoDConstraint("certificate.read", "ca.manage"); err == nil {
		t.Fatal("a constraint violated by an existing role must be refused")
	}

	// Updates re-run SoD too.
	if _, err := s.UpdateRole(CustomRole{Name: "issuer", Permissions: []string{"certificate.issue", "action.approve"}}); err == nil {
		t.Fatal("an update violating SoD must be refused")
	}
}

func TestCustomRoleStoreTenantList(t *testing.T) {
	s, _ := newCustomRoleStore(t)
	for _, r := range []CustomRole{
		{Name: "role-a", Permissions: []string{"certificate.read"}, TenantID: "a"},
		{Name: "role-b", Permissions: []string{"certificate.read"}, TenantID: "b"},
		{Name: "role-global", Permissions: []string{"certificate.read"}},
	} {
		if _, err := s.CreateRole(r); err != nil {
			t.Fatalf("create %s: %v", r.Name, err)
		}
	}
	got, err := s.ListRolesForTenant("a")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name] = true
	}
	if len(got) != 2 || !names["role-a"] || !names["role-global"] || names["role-b"] {
		t.Fatalf("ListRolesForTenant(a) = %v", names)
	}
}

// H-F17: duplicate detection keys off driver error codes, so message text
// that merely mentions a constraint must not match.
func TestIsUniqueViolationUsesDriverCodes(t *testing.T) {
	if !isUniqueViolation(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23505"})) {
		t.Error("pg 23505 must match, wrapped or not")
	}
	if isUniqueViolation(&pgconn.PgError{Code: "23503", Message: "duplicate key value"}) {
		t.Error("a different pg code must not match on message text")
	}
	if isUniqueViolation(errors.New("UNIQUE constraint failed: custom_roles.name")) {
		t.Error("plain text without a driver error must not match")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ddl := range []string{
		`CREATE TABLE pk (name TEXT PRIMARY KEY)`,
		`CREATE TABLE uq (name TEXT NOT NULL UNIQUE)`,
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	for _, tbl := range []string{"pk", "uq"} {
		if _, err := db.Exec(`INSERT INTO ` + tbl + ` VALUES ('a')`); err != nil {
			t.Fatal(err)
		}
		_, err := db.Exec(`INSERT INTO ` + tbl + ` VALUES ('a')`)
		if err == nil || !isUniqueViolation(err) {
			t.Errorf("%s: duplicate insert error %v not recognised", tbl, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO nosuch VALUES (1)`); isUniqueViolation(err) {
		t.Error("an unrelated sqlite error must not match")
	}
}
