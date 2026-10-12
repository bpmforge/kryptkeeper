// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const testSCIMBearerToken = "scim-shared-secret-token"

func newTestSCIMAuthenticator() *Authenticator {
	return &Authenticator{
		config: authValidatorConfig{
			mode:             "bootstrap",
			loginEnabled:     true,
			loginSigning:     "signing-secret",
			loginTTL:         5 * time.Minute,
			refreshTTL:       10 * time.Minute,
			loginPepper:      "pepper",
			scimBearerToken:  testSCIMBearerToken,
			scimDefaultRole:  "pki-viewer",
			scimGroupRoleMap: map[string]string{"kryptkeeper-admins": "pki-admin"},
			loginUser: loginCredential{
				Email:        "admin@example.com",
				PasswordHash: apiKeyVerifier("correct-password", "pepper"),
				Role:         "pki-admin",
				Subject:      "local-admin",
				Active:       true,
			},
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}
}

// TestSCIM_OrdinarySessionIsRejected is acceptance #5's discriminating test:
// SCIM is a trust boundary separate from using the product, so a normal,
// validly-authenticated operator session must NOT reach it.
func TestSCIM_OrdinarySessionIsRejected(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{}
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct-password"}`))
	loginRec := httptest.NewRecorder()
	mux.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("local login: expected 200, got %d (%s)", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginResp.Data.AccessToken == "" {
		t.Fatal("expected a non-empty access token from login")
	}

	scimReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	scimReq.Header.Set("Authorization", "Bearer "+loginResp.Data.AccessToken)
	scimRec := httptest.NewRecorder()
	mux.ServeHTTP(scimRec, scimReq)

	if scimRec.Code != http.StatusUnauthorized {
		t.Fatalf("an ordinary operator session must be rejected by SCIM, got %d (%s)", scimRec.Code, scimRec.Body.String())
	}
}

func TestSCIM_NoBearerTokenIsRejected(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, userProvider, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no bearer token, got %d", rec.Code)
	}
}

func scimAuthedRequest(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("Authorization", "Bearer "+testSCIMBearerToken)
	req.Header.Set("Content-Type", "application/scim+json")
	return req
}

func TestSCIM_CreateListGetUser(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, userProvider, stubAuditProvider{})

	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, scimAuthedRequest(http.MethodPost, "/scim/v2/Users", `{"userName":"bob@example.com","active":true}`))
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d (%s)", createRec.Code, createRec.Body.String())
	}
	var created scimUserResource
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" || created.UserName != "bob@example.com" {
		t.Fatalf("created resource = %+v", created)
	}
	if created.KryptkeeperRole != "pki-viewer" {
		t.Fatalf("expected default role pki-viewer, got %q", created.KryptkeeperRole)
	}

	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, scimAuthedRequest(http.MethodGet, "/scim/v2/Users", ""))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list users: expected 200, got %d", listRec.Code)
	}
	var list scimListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if list.TotalResults != 1 {
		t.Fatalf("expected 1 user, got %d", list.TotalResults)
	}

	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, scimAuthedRequest(http.MethodGet, "/scim/v2/Users/"+created.ID, ""))
	if getRec.Code != http.StatusOK {
		t.Fatalf("get user: expected 200, got %d (%s)", getRec.Code, getRec.Body.String())
	}
}

func TestSCIM_GetUnknownUser404(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, userProvider, stubAuditProvider{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodGet, "/scim/v2/Users/does-not-exist", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// TestSCIM_PatchActiveFalseDeprovisions_AuthzCheckFails is acceptance #4's
// core proof: deprovisioning via SCIM revokes access, demonstrated by a
// subsequent authz-check on that user's existing session failing.
func TestSCIM_PatchActiveFalseDeprovisions_AuthzCheckFails(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "carol@example.com", Role: "pki-operator", Status: "active"},
	}}
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, userProvider, stubAuditProvider{})

	now := time.Now()
	accessToken, _, _, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}

	preReq := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	preReq.Header.Set("Authorization", "Bearer "+accessToken)
	preRec := httptest.NewRecorder()
	mux.ServeHTTP(preRec, preReq)
	if preRec.Code != http.StatusOK {
		t.Fatalf("expected the session to authenticate before deprovisioning, got %d (%s)", preRec.Code, preRec.Body.String())
	}

	patchRec := httptest.NewRecorder()
	mux.ServeHTTP(patchRec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Users/user-1", `{"Operations":[{"op":"replace","path":"active","value":false}]}`))
	if patchRec.Code != http.StatusOK {
		t.Fatalf("PATCH active=false: expected 200, got %d (%s)", patchRec.Code, patchRec.Body.String())
	}
	var patched scimUserResource
	if err := json.Unmarshal(patchRec.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if patched.Active {
		t.Fatal("expected the patched resource to report active=false")
	}

	postReq := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	postReq.Header.Set("Authorization", "Bearer "+accessToken)
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after SCIM deprovisioning, got %d (%s)", postRec.Code, postRec.Body.String())
	}
}

func TestSCIM_DeleteUserDeprovisionsInsteadOfHardDelete(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "dave@example.com", Role: "pki-operator", Status: "active"},
	}}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, userProvider, stubAuditProvider{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodDelete, "/scim/v2/Users/user-1", ""))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE user: expected 204, got %d (%s)", rec.Code, rec.Body.String())
	}

	users, err := userProvider.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected the account to still exist (soft deprovision), got %d users", len(users))
	}
	if !isDeprovisionedStatus(users[0].Status) {
		t.Fatalf("expected status deactivated, got %q", users[0].Status)
	}
}

func TestSCIM_PatchRoleChange(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "erin@example.com", Role: "pki-viewer", Status: "active"},
	}}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, userProvider, stubAuditProvider{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Users/user-1", `{"Operations":[{"op":"replace","path":"role","value":"pki-operator"}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH role: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var patched scimUserResource
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if patched.KryptkeeperRole != "pki-operator" {
		t.Fatalf("expected role pki-operator after patch, got %q", patched.KryptkeeperRole)
	}
}

// --- Groups: IdP group membership -> Kryptkeeper role mapping ---

func openFreshSCIMTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "scim-groups-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestSCIMGroupStore(t *testing.T) scimGroupStore {
	t.Helper()
	store := &sqliteSCIMGroupStore{db: openFreshSCIMTestDB(t)}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	// Re-run to prove the schema is re-runnable (PLAYBOOK).
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema second run (idempotency): %v", err)
	}
	return store
}

func TestSCIMGroups_CreateWithMembersAppliesRoleMapping(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "frank@example.com", Role: "pki-viewer", Status: "active"},
	}}
	groupStore := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, userProvider, func() scimGroupStore { return groupStore }, stubAuditProvider{})

	body := `{"displayName":"kryptkeeper-admins","members":[{"value":"user-1"}]}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Groups", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}

	users, err := userProvider.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Role != "pki-admin" {
		t.Fatalf("expected user-1's role mapped to pki-admin via group membership, got %+v", users)
	}
}

func TestSCIMGroups_PatchAddMemberAppliesRoleMapping(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-2", Email: "grace@example.com", Role: "pki-viewer", Status: "active"},
	}}
	groupStore := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, userProvider, func() scimGroupStore { return groupStore }, stubAuditProvider{})

	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, scimAuthedRequest(http.MethodPost, "/scim/v2/Groups", `{"displayName":"kryptkeeper-admins"}`))
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d (%s)", createRec.Code, createRec.Body.String())
	}
	var created scimGroupResource
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	patchBody := `{"Operations":[{"op":"add","path":"members","value":[{"value":"user-2"}]}]}`
	patchRec := httptest.NewRecorder()
	mux.ServeHTTP(patchRec, scimAuthedRequest(http.MethodPatch, "/scim/v2/Groups/"+created.ID, patchBody))
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch add member: expected 200, got %d (%s)", patchRec.Code, patchRec.Body.String())
	}

	users, err := userProvider.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Role != "pki-admin" {
		t.Fatalf("expected user-2's role mapped to pki-admin after PATCH add, got %+v", users)
	}

	var group scimGroupResource
	if err := json.Unmarshal(patchRec.Body.Bytes(), &group); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if len(group.Members) != 1 || group.Members[0].Value != "user-2" {
		t.Fatalf("expected group to list user-2 as a member, got %+v", group.Members)
	}
}

func TestSCIMGroups_UnmappedGroupLeavesRoleUnchanged(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-3", Email: "heidi@example.com", Role: "pki-viewer", Status: "active"},
	}}
	groupStore := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, userProvider, func() scimGroupStore { return groupStore }, stubAuditProvider{})

	body := `{"displayName":"some-unmapped-group","members":[{"value":"user-3"}]}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(http.MethodPost, "/scim/v2/Groups", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}

	users, err := userProvider.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Role != "pki-viewer" {
		t.Fatalf("expected user-3's role unchanged for an unmapped group, got %+v", users)
	}
}
