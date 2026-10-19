// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// W12-06: the roles admin API — CRUD, verbatim refusals, custom-role
// gate resolution, and audit coverage.

func newRolesTestStore(t *testing.T) *CustomRoleStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
CREATE TABLE custom_roles (name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '',
 permissions TEXT NOT NULL DEFAULT '[]', tenant_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE role_sod_constraints (id TEXT PRIMARY KEY, permission_a TEXT NOT NULL,
 permission_b TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE (permission_a, permission_b));`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	s, err := NewCustomRoleStore(db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return s
}

type recordingAudit struct{ events []string }

func (r *recordingAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (r *recordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	r.events = append(r.events, e.Action+":"+string(e.Outcome))
	return nil
}

func rolesTestMux(t *testing.T, store *CustomRoleStore, audit AuditProvider) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerCustomRoleHandlers(mux, newReportsTestAuth(t), store, audit)
	return mux
}

func TestRolesCRUDAndVerbatimRefusals(t *testing.T) {
	store := newRolesTestStore(t)
	audit := &recordingAudit{}
	mux := rolesTestMux(t, store, audit)

	// Create.
	body, _ := json.Marshal(CustomRole{Name: "cert-reader", Description: "read-only certs",
		Permissions: []string{"certificate.read", "report.read"}})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/roles", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Vocabulary typo: the store's exact refusal comes through.
	bad, _ := json.Marshal(CustomRole{Name: "typo-role", Permissions: []string{"certificate.readd"}})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/roles", bad))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not in the permission vocabulary") {
		t.Fatalf("vocabulary refusal must surface verbatim: %d %s", rec.Code, rec.Body.String())
	}

	// SoD violation (built-in pair): verbatim refusal.
	sod, _ := json.Marshal(CustomRole{Name: "sod-role", Permissions: []string{"action.propose", "action.approve"}})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/roles", sod))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "separation of duties") {
		t.Fatalf("SoD refusal must surface verbatim: %d %s", rec.Code, rec.Body.String())
	}

	// List includes builtin + custom.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/roles", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "cert-reader") || !strings.Contains(rec.Body.String(), "pki-admin") {
		t.Fatalf("list must span custom + builtin: %d", rec.Code)
	}

	// Update + delete.
	upd, _ := json.Marshal(CustomRole{Permissions: []string{"certificate.read"}})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPut, "/api/v1/roles/cert-reader", upd))
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/roles/cert-reader", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}

	// Every mutation audited (successes and the two refusals).
	joined := strings.Join(audit.events, " ")
	for _, want := range []string{"role.create:success", "role.create:failure", "role.update:success", "role.delete:success"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing audit event %q in %v", want, audit.events)
		}
	}
}

func TestSoDConstraintEndpoints(t *testing.T) {
	store := newRolesTestStore(t)
	mux := rolesTestMux(t, store, &recordingAudit{})

	// Listing always shows the immutable built-in pair.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/roles/sod-constraints", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "action.propose") {
		t.Fatalf("built-in pair must be listed: %d %s", rec.Code, rec.Body.String())
	}

	// Add a pair.
	body, _ := json.Marshal(map[string]string{"permission_a": "ca.manage", "permission_b": "key.manage"})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/roles/sod-constraints", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("add constraint: %d %s", rec.Code, rec.Body.String())
	}

	// No grandfathering: a role violating the new pair refuses verbatim.
	role, _ := json.Marshal(CustomRole{Name: "violator", Permissions: []string{"ca.manage", "key.manage"}})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/roles", role))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "separation of duties") {
		t.Fatalf("new constraint must bind: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCustomRoleResolvesOnGuardedPath(t *testing.T) {
	store := newRolesTestStore(t)
	if _, err := store.CreateRole(CustomRole{Name: "role-admin", Permissions: []string{"user.manage"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.CreateRole(CustomRole{Name: "cert-reader", Permissions: []string{"certificate.read"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A custom role granted user.manage passes the guarded path.
	if !roleMayManageRoles(store, "role-admin") {
		t.Fatal("custom role with user.manage must pass the gate")
	}
	// One without it does not; compiled admin roles still pass.
	if roleMayManageRoles(store, "cert-reader") {
		t.Fatal("custom role without user.manage must be refused")
	}
	if !roleMayManageRoles(store, "pki-admin") {
		t.Fatal("compiled admin must pass")
	}
}

func TestRolesUnauthenticatedRefused(t *testing.T) {
	mux := rolesTestMux(t, newRolesTestStore(t), &recordingAudit{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// Review fix (security challenger #2): an authorization denial on the
// roles surface must leave an audit trail — a refused access attempt
// that records nothing is invisible to the append-only log.
func TestRolesUnauthorizedIsAudited(t *testing.T) {
	audit := &recordingAudit{}
	mux := rolesTestMux(t, newRolesTestStore(t), audit)
	rec := httptest.NewRecorder()
	// No Authorization header → gate() must deny AND audit.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if !strings.Contains(strings.Join(audit.events, " "), "role.access:denied") {
		t.Fatalf("a denied roles access must be audited, got %v", audit.events)
	}
}

// rolesTenantMux wires the roles API with MULTI_TENANCY on and two tenant admins.
func rolesTenantMux(t *testing.T, audit AuditProvider) (mux *http.ServeMux, acme, globex string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := NewAuthenticatorFromEnv()
	_, acme, err := auth.CreateAPIKey("acme-svc", "svc-acme", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, globex, err = auth.CreateAPIKey("globex-svc", "svc-globex", "pki-admin", []string{"*"}, "", "globex", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mux = http.NewServeMux()
	registerCustomRoleHandlers(mux, auth, newRolesTestStore(t), audit)
	return mux, acme, globex
}

const rolePayload = `{"name":"%s","permissions":["certificate.read"]}`

func TestRolesCrossTenantWriteForbidden(t *testing.T) {
	audit := &recordingAudit{}
	mux, acme, globex := rolesTenantMux(t, audit)
	if rec := doLeakJSON(mux, http.MethodPost, "/api/v1/roles", acme, "", fmt.Sprintf(rolePayload, "acme-role")); rec.Code != http.StatusCreated {
		t.Fatalf("acme create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doLeakJSON(mux, http.MethodPut, "/api/v1/roles/acme-role", globex, "", fmt.Sprintf(rolePayload, "acme-role")); rec.Code != http.StatusForbidden {
		t.Fatalf("globex PUT: want 403, got %d", rec.Code)
	}
	if rec := doLeakJSON(mux, http.MethodDelete, "/api/v1/roles/acme-role", globex, "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("globex DELETE: want 403, got %d", rec.Code)
	}
	if rec := doLeakJSON(mux, http.MethodGet, "/api/v1/roles", acme, "", ""); !strings.Contains(rec.Body.String(), "acme-role") {
		t.Fatalf("role must survive: %s", rec.Body.String())
	}
	found := false
	for _, e := range audit.events {
		if e == "role.update:denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing role.update:denied in %v", audit.events)
	}
	// The owner may still edit and delete it.
	if rec := doLeakJSON(mux, http.MethodDelete, "/api/v1/roles/acme-role", acme, "", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("owner DELETE: %d", rec.Code)
	}
}

func TestRolesGlobalSuperAdminOnly(t *testing.T) {
	mux, acme, _ := rolesTenantMux(t, &recordingAudit{})
	if rec := doLeakJSON(mux, http.MethodPost, "/api/v1/roles", "root-token", "", fmt.Sprintf(rolePayload, "shared-role")); rec.Code != http.StatusCreated {
		t.Fatalf("super-admin create global: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doLeakJSON(mux, http.MethodPut, "/api/v1/roles/shared-role", acme, "", fmt.Sprintf(rolePayload, "shared-role")); rec.Code != http.StatusForbidden {
		t.Fatalf("acme PUT global: want 403, got %d", rec.Code)
	}
	if rec := doLeakJSON(mux, http.MethodDelete, "/api/v1/roles/shared-role", acme, "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("acme DELETE global: want 403, got %d", rec.Code)
	}
	if rec := doLeakJSON(mux, http.MethodDelete, "/api/v1/roles/shared-role", "root-token", "", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("super-admin DELETE global: %d", rec.Code)
	}
}

func TestRolesListScopedToTenant(t *testing.T) {
	mux, acme, globex := rolesTenantMux(t, &recordingAudit{})
	doLeakJSON(mux, http.MethodPost, "/api/v1/roles", "root-token", "", fmt.Sprintf(rolePayload, "shared-role"))
	doLeakJSON(mux, http.MethodPost, "/api/v1/roles", acme, "", fmt.Sprintf(rolePayload, "acme-role"))
	doLeakJSON(mux, http.MethodPost, "/api/v1/roles", globex, "", fmt.Sprintf(rolePayload, "globex-role"))
	body := doLeakJSON(mux, http.MethodGet, "/api/v1/roles", acme, "", "").Body.String()
	for _, want := range []string{"acme-role", "shared-role", "pki-admin"} {
		if !strings.Contains(body, want) {
			t.Errorf("acme list missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "globex-role") {
		t.Errorf("acme list leaks globex role: %s", body)
	}
	if all := doLeakJSON(mux, http.MethodGet, "/api/v1/roles", "root-token", "", "").Body.String(); !strings.Contains(all, "globex-role") || !strings.Contains(all, "acme-role") {
		t.Errorf("super-admin must see all: %s", all)
	}
}

// CB-03: a duplicate role name is a 409 with a plain message, never the
// driver's UNIQUE-constraint text.
func TestRolesDuplicateNameIsConflictWithoutDriverText(t *testing.T) {
	mux := rolesTestMux(t, newRolesTestStore(t), &recordingAudit{})
	body, _ := json.Marshal(CustomRole{Name: "cert-reader", Permissions: []string{"certificate.read"}})
	for i, want := range []int{http.StatusCreated, http.StatusConflict} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/roles", body))
		if rec.Code != want {
			t.Fatalf("attempt %d: got %d want %d: %s", i, rec.Code, want, rec.Body.String())
		}
		if i == 1 {
			out := rec.Body.String()
			if !strings.Contains(out, "already defined") || strings.Contains(out, "UNIQUE") || strings.Contains(out, "custom_roles") {
				t.Fatalf("conflict body leaks driver text or lacks message: %s", out)
			}
		}
	}
}
