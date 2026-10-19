// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scimSecRig(t *testing.T, users *fileUserProvider, audit AuditProvider) *http.ServeMux {
	t.Helper()
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := newTestSCIMAuthenticator()
	auth.config.scimDefaultRole = "pki-viewer"
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, users, audit)
	return mux
}

// F7 / D-204: the SCIM bearer cannot mint privileged roles.
func TestSCIM_RoleCeiling(t *testing.T) {
	cases := []struct {
		role    string
		optIn   bool
		wantErr bool
	}{
		{"pki-viewer", false, false},
		{"pki-operator", false, false},
		{"pki-admin", false, true},
		{"PKI-Admin", false, true},
		{"super-admin", false, true},
		{"pki-admin", true, false},
		{"break-glass", false, true},
		{"break-glass", true, true},
		{"bootstrap", true, true},
		{"mcp-agent", true, true},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			if c.optIn {
				t.Setenv(scimAllowAdminRolesEnv, "true")
			}
			users := &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "u1@example.com", Role: "pki-viewer", Status: "active"}}}
			audit := &expiryAudit{}
			mux := scimSecRig(t, users, audit)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Users", `{"userName":"new@example.com","kryptkeeperRole":"`+c.role+`"}`))
			if c.wantErr != (rec.Code == http.StatusForbidden) || (!c.wantErr && rec.Code != http.StatusCreated) {
				t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
			}

			rec = httptest.NewRecorder()
			mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Users/u1", `{"Operations":[{"op":"replace","path":"kryptkeeperRole","value":"`+c.role+`"}]}`))
			got, _, _ := findSCIMUserByID(context.Background(), users, "u1")
			if c.wantErr && (rec.Code != http.StatusForbidden || got.Role != "pki-viewer") {
				t.Fatalf("patch: %d role=%s %s", rec.Code, got.Role, rec.Body.String())
			}
			if !c.wantErr && (rec.Code != http.StatusOK || !strings.EqualFold(got.Role, c.role)) {
				t.Fatalf("patch: %d role=%s %s", rec.Code, got.Role, rec.Body.String())
			}
			if c.wantErr && len(audit.all("scim.users.update", AuditOutcomeDenied)) != 1 {
				t.Fatalf("denial not audited: %+v", audit.entries)
			}
		})
	}
}

// A misconfigured default role cannot smuggle an admin in either.
func TestSCIM_DefaultRoleAdminRefused(t *testing.T) {
	users := &fileUserProvider{}
	auth := newTestSCIMAuthenticator()
	auth.config.scimDefaultRole = "pki-admin"
	m := http.NewServeMux()
	registerSCIMHandlers(m, auth, users, stubAuditProvider{})
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Users", `{"userName":"x@example.com"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("default admin role: %d %s", rec.Code, rec.Body.String())
	}
}

// A SCIM client creating a group named like a mapped admin group must not get
// the admin role without the opt-in; membership is still recorded.
func TestSCIM_GroupMapAdminRoleWithheld(t *testing.T) {
	auth := newTestSCIMAuthenticator() // maps kryptkeeper-admins -> pki-admin
	users := &fileUserProvider{users: []UserRecord{{ID: "user-1", Email: "a@example.com", Role: "pki-viewer", Status: "active"}}}
	store := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, users, func() scimGroupStore { return store }, stubAuditProvider{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Groups", `{"displayName":"kryptkeeper-admins","members":[{"value":"user-1"}]}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := findSCIMUserByID(context.Background(), users, "user-1"); got.Role != "pki-viewer" {
		t.Fatalf("role escalated to %s", got.Role)
	}
}

// Tenancy: the tenant-less SCIM bearer stays inside the default tenant.
func TestSCIM_OtherTenantUsersUntouchable(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	users := &fileUserProvider{users: []UserRecord{
		{ID: "u-def", Email: "d@example.com", Role: "pki-viewer", Status: "active"},
		{ID: "u-acme", Email: "a@example.com", Role: "pki-viewer", Status: "active", Tenant: "acme"},
	}}
	mux := scimSecRig(t, users, stubAuditProvider{})
	for _, c := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodDelete, ""},
		{http.MethodPatch, `{"Operations":[{"op":"replace","path":"active","value":false}]}`},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, scimAuthedRequest(c.method, "/scim/v2/Users/u-acme", c.body))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s other tenant: %d %s", c.method, rec.Code, rec.Body.String())
		}
	}
	if got, _, _ := findSCIMUserByID(context.Background(), users, "u-acme"); got.Status != "active" {
		t.Fatalf("other tenant's user was modified: %+v", got)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodGet, "/scim/v2/Users", ""))
	if strings.Contains(rec.Body.String(), "u-acme") || !strings.Contains(rec.Body.String(), "u-def") {
		t.Fatalf("list: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodDelete, "/scim/v2/Users/u-def", ""))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("default-tenant delete: %d", rec.Code)
	}
}

func seedPendingApproval(t *testing.T, s ApprovalStore, id, requester, team string) {
	t.Helper()
	if err := s.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: "t", CAID: "ca", Requester: requester, TeamID: team,
		Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

// W33-23 wiring: deprovisioning (PATCH active=false and DELETE) cancels the
// user's pending approvals and leaves others' alone.
func TestSCIM_DeprovisionCancelsPendingApprovals(t *testing.T) {
	for _, via := range []string{"patch", "delete"} {
		t.Run(via, func(t *testing.T) {
			users := &fileUserProvider{users: []UserRecord{
				{ID: "u1", Email: "u1@example.com", Role: "pki-viewer", Status: "active"},
				{ID: "u2", Email: "u2@example.com", Role: "pki-viewer", Status: "active"},
			}}
			audit := &expiryAudit{}
			mux := scimSecRig(t, users, audit)
			store, err := newApprovalStoreFromEnv()
			if err != nil || store == nil {
				t.Fatalf("store: %v", err)
			}
			seedPendingApproval(t, store, "a-u1", "u1", "T")
			seedPendingApproval(t, store, "a-u2", "u2", "T")
			rec := httptest.NewRecorder()
			if via == "patch" {
				mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Users/u1", `{"Operations":[{"op":"replace","path":"active","value":false}]}`))
			} else {
				mux.ServeHTTP(rec, scimAuthedRequest(http.MethodDelete, "/scim/v2/Users/u1", ""))
			}
			if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			if got, _ := store.Get(context.Background(), "a-u1"); got.Status != "rejected" {
				t.Fatalf("u1 approval status %q", got.Status)
			}
			if got, _ := store.Get(context.Background(), "a-u2"); got.Status != "pending" {
				t.Fatalf("u2 approval status %q", got.Status)
			}
			if len(audit.all("approval.cancel", AuditOutcomeSuccess)) != 1 {
				t.Fatalf("cancel audit: %+v", audit.entries)
			}
		})
	}
}

// Group member removal cancels approvals filed for that team only.
func TestSCIM_GroupMemberRemovalCancelsTeamApprovals(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := newTestSCIMAuthenticator()
	users := &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "u1@example.com", Role: "pki-viewer", Status: "active"}}}
	groupStore := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, users, func() scimGroupStore { return groupStore }, stubAuditProvider{})
	store, err := newApprovalStoreFromEnv()
	if err != nil || store == nil {
		t.Fatalf("store: %v", err)
	}
	seedPendingApproval(t, store, "a-team", "u1", "team-a")
	seedPendingApproval(t, store, "a-other", "u1", "team-b")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Groups", `{"displayName":"team-a","members":[{"value":"u1"}]}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	groups, _ := groupStore.List(context.Background())
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Groups/"+groups[0].ID, `{"Operations":[{"op":"remove","path":"members","value":[{"value":"u1"}]}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := store.Get(context.Background(), "a-team"); got.Status != "rejected" {
		t.Fatalf("team-a approval %q", got.Status)
	}
	if got, _ := store.Get(context.Background(), "a-other"); got.Status != "pending" {
		t.Fatalf("team-b approval %q", got.Status)
	}
}

// Removing someone who was never in the group must not cancel their
// approvals: RemoveMember succeeds for non-members.
func TestSCIM_GroupRemovalOfNonMemberCancelsNothing(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := newTestSCIMAuthenticator()
	users := &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "u1@example.com", Role: "pki-viewer", Status: "active"}}}
	groupStore := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, users, func() scimGroupStore { return groupStore }, stubAuditProvider{})
	store, err := newApprovalStoreFromEnv()
	if err != nil || store == nil {
		t.Fatalf("store: %v", err)
	}
	seedPendingApproval(t, store, "a-team", "u1", "team-a")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Groups", `{"displayName":"team-a"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	groups, _ := groupStore.List(context.Background())
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Groups/"+groups[0].ID, `{"Operations":[{"op":"remove","path":"members","value":[{"value":"u1"}]}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := store.Get(context.Background(), "a-team"); got.Status != "pending" {
		t.Fatalf("non-member removal cancelled approval: %q", got.Status)
	}
}
