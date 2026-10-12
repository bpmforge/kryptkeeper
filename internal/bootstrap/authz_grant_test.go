// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// grantHarness serves the real users, roles, API-key, audit and proposal
// handlers behind the write gate, so each case runs the path a request takes.
type grantHarness struct {
	*writeGateHarness
	users *stubUserProvider
}

func newGrantHarness(t *testing.T) *grantHarness {
	t.Helper()
	mux := http.NewServeMux()
	h := &grantHarness{
		writeGateHarness: newWriteGateHarness(t, mux),
		users: &stubUserProvider{users: []UserRecord{
			{ID: "u-op", Email: "op@example.com", Role: "pki-operator", Status: "active"},
			{ID: "u-view", Email: "v@example.com", Role: "viewer", Status: "active"},
			{ID: "u-cr", Email: "c@example.com", Role: "cert-reader", Status: "active"},
		}},
	}
	h.auth.roleStore = h.roles
	registerUserHandlers(mux, h.auth, h.users, h.roles, h.audit)
	registerCustomRoleHandlers(mux, h.auth, h.roles, h.audit)
	registerAuthHandlers(mux, h.auth, h.audit)
	registerAuditHandlers(mux, h.auth, h.roles, h.audit)
	registerAuditTrustHandlers(mux, h.auth, h.roles, h.audit)
	registerPendingActionHandlers(mux, h.auth, nil, newTestPendingStore(t), h.audit, nil)
	// A custom role that may manage users and roles but is no admin: the
	// delegation TM-08 abused.
	for _, r := range []CustomRole{
		{Name: "delegate", Permissions: []string{"user.manage", "certificate.read"}},
		{Name: "cert-reader", Permissions: []string{"certificate.read"}},
	} {
		if _, err := h.roles.CreateRole(r); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *grantHarness) json(token, method, path string, body any) *httpResult {
	raw, _ := json.Marshal(body)
	rec := h.do(token, method, path, raw)
	return &httpResult{Code: rec.Code, Body: rec.Body.String()}
}

type httpResult struct {
	Code int
	Body string
}

func (h *grantHarness) lastAudit(t *testing.T, action string) AuditEntry {
	t.Helper()
	for i := len(h.audit.entries) - 1; i >= 0; i-- {
		if h.audit.entries[i].Action == action {
			return h.audit.entries[i]
		}
	}
	t.Fatalf("no %q audit event recorded", action)
	return AuditEntry{}
}

func TestUserRoleChangeCannotExceedCaller(t *testing.T) {
	h := newGrantHarness(t)
	delegate := h.key(t, "delegate")
	operator := h.key(t, "pki-operator")
	admin := h.key(t, "pki-admin")

	cases := []struct {
		name, tok, path, method string
		body                    map[string]string
		want                    int
	}{
		// TM-08: user.manage alone let a delegate make anyone pki-admin.
		{"delegate promotes self to admin", delegate, "/api/v1/users/p-delegate", "PATCH", map[string]string{"role": "pki-admin"}, 403},
		{"delegate promotes other to admin", delegate, "/api/v1/users/u-view", "PATCH", map[string]string{"role": "pki-admin"}, 403},
		{"delegate grants operator it does not hold", delegate, "/api/v1/users/u-view", "PATCH", map[string]string{"role": "pki-operator"}, 403},
		{"delegate invites admin", delegate, "/api/v1/users/invite", "POST", map[string]string{"email": "x@example.com", "role": "pki-admin"}, 403},
		{"delegate invites bootstrap", delegate, "/api/v1/users/invite", "POST", map[string]string{"email": "x@example.com", "role": "bootstrap"}, 403},
		{"delegate may grant a role it holds", delegate, "/api/v1/users/u-cr", "PATCH", map[string]string{"role": "cert-reader"}, 200},
		// The write gate already stops an operator (no user.manage); the
		// grant check must not be the only layer, and must not weaken it.
		{"operator promotes to admin", operator, "/api/v1/users/u-op", "PATCH", map[string]string{"role": "pki-admin"}, 403},
		{"unknown role on PATCH", admin, "/api/v1/users/u-view", "PATCH", map[string]string{"role": "pki-adm1n"}, 400},
		{"unknown role on invite", admin, "/api/v1/users/invite", "POST", map[string]string{"email": "y@example.com", "role": "superuser"}, 400},
		{"admin grants admin", admin, "/api/v1/users/u-view", "PATCH", map[string]string{"role": "pki-admin"}, 200},
		{"admin grants a custom role", admin, "/api/v1/users/u-op", "PATCH", map[string]string{"role": "delegate"}, 200},
		{"UI role name pki-auditor stays valid", admin, "/api/v1/users/u-op", "PATCH", map[string]string{"role": "pki-auditor"}, 200},
		{"bootstrap token grants admin", "test-token", "/api/v1/users/u-op", "PATCH", map[string]string{"role": "pki-admin"}, 200},
	}
	for _, c := range cases {
		if got := h.json(c.tok, c.method, c.path, c.body); got.Code != c.want {
			t.Errorf("%s: got %d, want %d (%s)", c.name, got.Code, c.want, got.Body)
		}
	}
	for _, u := range h.users.users {
		if u.ID == "u-view" && u.Role == "pki-operator" {
			t.Error("a refused grant still changed the user")
		}
	}
}

func TestRefusedGrantIsAudited(t *testing.T) {
	h := newGrantHarness(t)
	rec := h.json(h.key(t, "delegate"), "PATCH", "/api/v1/users/u-cr", map[string]string{"role": "pki-admin"})
	if rec.Code != 403 {
		t.Fatalf("got %d", rec.Code)
	}
	ev := h.lastAudit(t, "users.update")
	if ev.Outcome != "denied" || !strings.Contains(ev.ChangeSummary, "pki-admin") {
		t.Errorf("audit event %+v", ev)
	}
}

func TestCustomRoleCannotGrantMissingPermissions(t *testing.T) {
	h := newGrantHarness(t)
	delegate := h.key(t, "delegate")
	operator := h.key(t, "pki-operator")
	admin := h.key(t, "pki-admin")

	cases := []struct {
		name, tok, method, path string
		body                    CustomRole
		want                    int
	}{
		{"delegate widens its own role", delegate, "PUT", "/api/v1/roles/delegate", CustomRole{Permissions: []string{"user.manage", "ca.manage", "key.manage"}}, 403},
		{"delegate creates a role with more than it holds", delegate, "POST", "/api/v1/roles", CustomRole{Name: "big", Permissions: []string{"certificate.read", "tenant.manage"}}, 403},
		{"operator creates a role it could not exercise", operator, "POST", "/api/v1/roles", CustomRole{Name: "big2", Permissions: []string{"ca.manage"}}, 403},
		{"delegate creates a subset role", delegate, "POST", "/api/v1/roles", CustomRole{Name: "small", Permissions: []string{"certificate.read"}}, 201},
		{"typo permission stays a 400", delegate, "POST", "/api/v1/roles", CustomRole{Name: "typo", Permissions: []string{"certificate.rread"}}, 400},
		{"admin may grant anything in the vocabulary", admin, "POST", "/api/v1/roles", CustomRole{Name: "wide", Permissions: []string{"ca.manage", "key.manage", "audit.read"}}, 201},
	}
	for _, c := range cases {
		if got := h.json(c.tok, c.method, c.path, c.body); got.Code != c.want {
			t.Errorf("%s: got %d, want %d (%s)", c.name, got.Code, c.want, got.Body)
		}
	}
	if r, _, _ := h.roles.GetRole("delegate"); len(r.Permissions) != 2 {
		t.Errorf("refused PUT changed the role: %v", r.Permissions)
	}
}

func TestAPIKeyRoleCeiling(t *testing.T) {
	h := newGrantHarness(t)
	admin := h.key(t, "pki-admin")
	operator := h.key(t, "pki-operator")

	mint := func(tok, role string) int {
		return h.json(tok, "POST", "/api/v1/api-keys", map[string]string{"principal_id": "bot-1", "role": role}).Code
	}
	if got := mint(operator, "pki-admin"); got != 403 {
		t.Errorf("operator minting an admin key: got %d, want 403", got)
	}
	if got := mint(admin, "pki-admin-typo"); got != 400 {
		t.Errorf("unknown role on key create: got %d, want 400", got)
	}
	if got := mint(admin, RoleMCPAgent); got != 201 {
		t.Errorf("admin minting an mcp-agent key: got %d, want 201", got)
	}
	if got := mint(admin, "cert-reader"); got != 201 {
		t.Errorf("admin minting a custom-role key: got %d, want 201", got)
	}
	// The handler's own ceiling, independent of the admin-only route rule.
	opPD := AuthPrincipal{ID: "p", Role: "pki-operator"}
	for _, role := range []string{"pki-admin", "bootstrap", RoleMCPAgent, "delegate", "auditor"} {
		if ref := checkRoleGrant(opPD, h.roles, role); ref == nil || ref.status != 403 {
			t.Errorf("operator granting %s: %+v, want 403", role, ref)
		}
	}
	for _, role := range []string{"viewer", "service-account", "pki-operator", "approver"} {
		if ref := checkRoleGrant(opPD, h.roles, role); ref != nil {
			t.Errorf("operator granting %s refused: %+v", role, ref)
		}
	}
}

// The audit log names every actor, IP and change, so reading it is its own
// permission (LLM-001 / A01-004).
func TestAuditReadNeedsPermission(t *testing.T) {
	h := newGrantHarness(t)
	if _, err := h.roles.CreateRole(CustomRole{Name: "audit-reader", Permissions: []string{"audit.read"}}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		role string
		want int
	}{
		{"pki-admin", 200}, {"auditor", 200}, {"pki-auditor", 200}, {"audit-reader", 200},
		{RoleMCPAgent, 403}, {"service-account", 403}, {"viewer", 403}, {"pki-viewer", 403},
		{"pki-operator", 403}, {"approver", 403}, {"made-up-role", 403}, {"cert-reader", 403},
	}
	for _, path := range []string{"/api/v1/audit", "/api/v1/audit/transparency/inclusion?index=0"} {
		for _, c := range cases {
			got := h.json(h.key(t, c.role), "GET", path, nil).Code
			if (c.want == 200) != (got != 403) {
				t.Errorf("GET %s as %s: got %d, want %d", path, c.role, got, c.want)
			}
		}
		if got := h.json("test-token", "GET", path, nil).Code; got == 403 {
			t.Errorf("GET %s as bootstrap token refused", path)
		}
	}
	// mcp-agent stays refused whatever scopes its key carries.
	if got := h.json(h.key(t, RoleMCPAgent, "*", "audit:read"), "GET", "/api/v1/audit", nil).Code; got != 403 {
		t.Errorf("mcp-agent with scopes read the audit log: %d", got)
	}
	if got := h.json(h.key(t, "service-account", "audit:read"), "GET", "/api/v1/audit", nil).Code; got != 200 {
		t.Errorf("an explicit audit:read scope should grant it: %d", got)
	}
	if ev := h.lastAudit(t, "audit.list"); ev.Outcome == "" {
		t.Error("denied audit reads are not recorded")
	}
}

// A delegate must not be able to demote, disable or remove what it could not
// create: the target's current role counts, not only the new one.
func TestDelegateCannotActOnHigherTargets(t *testing.T) {
	h := newGrantHarness(t)
	h.users.users = append(h.users.users, UserRecord{ID: "u-admin", Email: "a@example.com", Role: "pki-admin", Status: "active"})
	admin := h.key(t, "pki-admin")
	delegate := h.key(t, "delegate")
	if _, err := h.roles.CreateRole(CustomRole{Name: "ca-role", Permissions: []string{"ca.manage"}}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, tok, method, path string
		body                    any
		want                    int
	}{
		{"delegate demotes pki-admin", delegate, "PATCH", "/api/v1/users/u-admin", map[string]string{"role": "viewer"}, 403},
		{"delegate disables pki-admin", delegate, "PATCH", "/api/v1/users/u-admin", map[string]string{"status": "disabled"}, 403},
		{"delegate deactivates pki-admin", delegate, "DELETE", "/api/v1/users/u-admin", nil, 403},
		{"delegate disables a lesser user", delegate, "PATCH", "/api/v1/users/u-cr", map[string]string{"status": "disabled"}, 200},
		{"admin demotes pki-admin", admin, "PATCH", "/api/v1/users/u-admin", map[string]string{"role": "viewer"}, 200},
		{"delegate rewrites a role holding ca.manage", delegate, "PUT", "/api/v1/roles/ca-role", CustomRole{Permissions: []string{"certificate.read"}}, 403},
		{"delegate removes a role holding ca.manage", delegate, "DELETE", "/api/v1/roles/ca-role", nil, 403},
		{"delegate removes a role it could create", delegate, "DELETE", "/api/v1/roles/cert-reader", nil, 204},
		{"admin removes a role holding ca.manage", admin, "DELETE", "/api/v1/roles/ca-role", nil, 204},
	}
	for _, c := range cases {
		if got := h.json(c.tok, c.method, c.path, c.body); got.Code != c.want {
			t.Errorf("%s: got %d, want %d (%s)", c.name, got.Code, c.want, got.Body)
		}
	}
}
