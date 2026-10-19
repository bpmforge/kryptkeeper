// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type scimListBody struct {
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

func scimDo(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, scimAuthedRequest(method, path, body))
	return rec
}

func scimList(t *testing.T, mux *http.ServeMux, path string) (scimListBody, int) {
	t.Helper()
	rec := scimDo(t, mux, http.MethodGet, path, "")
	var out scimListBody
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list: %v (%s)", err, rec.Body.String())
		}
		// Empty results must marshal as [], never null.
		if !strings.Contains(rec.Body.String(), `"Resources":[`) {
			t.Fatalf("Resources must be a JSON array, got %s", rec.Body.String())
		}
	}
	return out, rec.Code
}

func scimUserByID(t *testing.T, p *fileUserProvider, id string) UserRecord {
	t.Helper()
	users, err := p.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.ID == id {
			return u
		}
	}
	t.Fatalf("user %q not found", id)
	return UserRecord{}
}

func TestSCIMPatchUserVariants(t *testing.T) {
	t.Setenv(scimAllowAdminRolesEnv, "true") // these cases exercise admin role assignment (D-204 opt-in)
	const schemaActive = "urn:ietf:params:scim:schemas:core:2.0:User:active"
	cases := []struct {
		name       string
		startState string
		body       string
		wantCode   int
		wantRole   string
		wantActive bool
	}{
		{"Okta no-path replace active=false", "active", `{"Operations":[{"op":"replace","value":{"active":false}}]}`, 200, "pki-operator", false},
		{"Entra Replace active=\"False\"", "active", `{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, 200, "pki-operator", false},
		{"Entra Replace active=\"True\" reactivates", "deactivated", `{"Operations":[{"op":"Replace","path":"active","value":"True"}]}`, 200, "pki-operator", true},
		{"Okta no-path replace active=true reactivates", "deactivated", `{"Operations":[{"op":"replace","value":{"active":true}}]}`, 200, "pki-operator", true},
		{"schema-qualified active path", "active", `{"Operations":[{"op":"replace","path":"` + schemaActive + `","value":false}]}`, 200, "pki-operator", false},
		{"mixed-case path ACTIVE", "active", `{"Operations":[{"op":"REPLACE","path":"ACTIVE","value":"false"}]}`, 200, "pki-operator", false},
		{"add kryptkeeperRole", "active", `{"Operations":[{"op":"add","path":"kryptkeeperRole","value":"pki-admin"}]}`, 200, "pki-admin", true},
		{"no-path object sets role", "active", `{"Operations":[{"op":"replace","value":{"kryptkeeperRole":"auditor"}}]}`, 200, "auditor", true},
		{"remove active is refused", "active", `{"Operations":[{"op":"remove","path":"active"}]}`, 400, "pki-operator", true},
		{"remove kryptkeeperRole is a no-op", "active", `{"Operations":[{"op":"remove","path":"kryptkeeperRole"}]}`, 200, "pki-operator", true},
		{"emails selector replace is a no-op", "active", `{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"x@y.z"}]}`, 200, "pki-operator", true},
		{"name.givenName replace is a no-op", "active", `{"Operations":[{"op":"Replace","path":"name.givenName","value":"Zed"}]}`, 200, "pki-operator", true},
		{"invalid op move", "active", `{"Operations":[{"op":"move","path":"active","value":false}]}`, 400, "pki-operator", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := newTestSCIMAuthenticator()
			users := &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "u1@example.com", Role: "pki-operator", Status: tc.startState}}}
			mux := http.NewServeMux()
			registerSCIMHandlers(mux, auth, users, stubAuditProvider{})

			rec := scimDo(t, mux, http.MethodPatch, "/scim/v2/Users/u1", tc.body)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			got := scimUserByID(t, users, "u1")
			if got.Role != tc.wantRole || !isDeprovisionedStatus(got.Status) == !tc.wantActive {
				t.Fatalf("record = %+v, want role %q active=%v", got, tc.wantRole, tc.wantActive)
			}
			if tc.wantCode == 200 {
				var res scimUserResource
				if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
					t.Fatal(err)
				}
				if res.Active != tc.wantActive {
					t.Fatalf("response active = %v, want %v", res.Active, tc.wantActive)
				}
			}
		})
	}
}

func scimGroupRig(t *testing.T) (*http.ServeMux, *fileUserProvider, string) {
	t.Helper()
	auth := newTestSCIMAuthenticator()
	auth.config.scimGroupRoleMap = map[string]string{"kryptkeeper-admins": "pki-admin"}
	users := &fileUserProvider{users: []UserRecord{
		{ID: "u1", Email: "u1@example.com", Role: "pki-viewer", Status: "active"},
		{ID: "u2", Email: "u2@example.com", Role: "pki-viewer", Status: "active"},
		{ID: "u3", Email: "u3@example.com", Role: "pki-viewer", Status: "active"},
	}}
	store := newTestSCIMGroupStore(t)
	mux := http.NewServeMux()
	registerSCIMGroupHandlers(mux, auth, users, func() scimGroupStore { return store }, stubAuditProvider{})
	rec := scimDo(t, mux, http.MethodPost, "/scim/v2/Groups", `{"displayName":"kryptkeeper-admins"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group = %d (%s)", rec.Code, rec.Body.String())
	}
	var g scimGroupResource
	_ = json.Unmarshal(rec.Body.Bytes(), &g)
	return mux, users, g.ID
}

func groupMembers(t *testing.T, mux *http.ServeMux, id string) map[string]bool {
	t.Helper()
	rec := scimDo(t, mux, http.MethodGet, "/scim/v2/Groups/"+id, "")
	var g scimGroupResource
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range g.Members {
		out[m.Value] = true
	}
	return out
}

func TestSCIMPatchGroupVariants(t *testing.T) {
	t.Setenv(scimAllowAdminRolesEnv, "true") // these cases exercise admin role assignment (D-204 opt-in)
	cases := []struct {
		name string
		ops  []string // each is the Operations JSON array body, applied in order
		want []string
		// roles asserted after the last op
		admins []string
	}{
		{"add members applies role map", []string{`[{"op":"add","path":"members","value":[{"value":"u1"},{"value":"u2"}]}]`}, []string{"u1", "u2"}, []string{"u1", "u2"}},
		{"Add with capitalised op", []string{`[{"op":"Add","path":"members","value":[{"value":"u1"}]}]`}, []string{"u1"}, []string{"u1"}},
		{"remove by value array", []string{
			`[{"op":"add","path":"members","value":[{"value":"u1"},{"value":"u2"}]}]`,
			`[{"op":"remove","path":"members","value":[{"value":"u1"}]}]`,
		}, []string{"u2"}, []string{"u1", "u2"}},
		{"remove by members[value eq] path", []string{
			`[{"op":"add","path":"members","value":[{"value":"u1"},{"value":"u2"}]}]`,
			`[{"op":"Remove","path":"members[value eq \"u2\"]"}]`,
		}, []string{"u1"}, []string{"u1", "u2"}},
		{"replace swaps the set and re-applies the role map", []string{
			`[{"op":"add","path":"members","value":[{"value":"u1"},{"value":"u2"}]}]`,
			`[{"op":"replace","path":"members","value":[{"value":"u2"},{"value":"u3"}]}]`,
		}, []string{"u2", "u3"}, []string{"u1", "u2", "u3"}},
		{"unknown path is ignored", []string{`[{"op":"add","path":"displayName","value":"x"}]`}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux, users, gid := scimGroupRig(t)
			for _, ops := range tc.ops {
				rec := scimDo(t, mux, http.MethodPatch, "/scim/v2/Groups/"+gid, `{"Operations":`+ops+`}`)
				if rec.Code != http.StatusOK {
					t.Fatalf("patch = %d (%s)", rec.Code, rec.Body.String())
				}
			}
			got := groupMembers(t, mux, gid)
			if len(got) != len(tc.want) {
				t.Fatalf("members = %v, want %v", got, tc.want)
			}
			for _, id := range tc.want {
				if !got[id] {
					t.Fatalf("members = %v, want %v", got, tc.want)
				}
			}
			// Removal never strips a role already granted (see scim.go); the
			// role map is applied when a member is (re)added.
			for _, id := range tc.admins {
				if r := scimUserByID(t, users, id).Role; r != "pki-admin" {
					t.Fatalf("user %s role = %q, want pki-admin from the group map", id, r)
				}
			}
		})
	}
}

func TestSCIMFilterUsers(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	users := &fileUserProvider{users: []UserRecord{
		{ID: "u1", Email: "alice@x.com", Role: "pki-viewer", Status: "active"},
		{ID: "u2", Email: "alan@x.com", Role: "pki-viewer", Status: "deactivated"},
		{ID: "u3", Email: "bob@x.com", Role: "pki-viewer", Status: "active"},
	}}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, users, stubAuditProvider{})

	cases := []struct {
		name   string
		filter string
		want   int
		code   int
	}{
		{"userName eq", `userName eq "alice@x.com"`, 1, 200},
		{"case-insensitive keywords", `USERNAME EQ "alice@x.com"`, 1, 200},
		{"case-insensitive value", `userName eq "ALICE@X.COM"`, 1, 200},
		{"sw", `userName sw "al"`, 2, 200},
		{"co", `userName co "ob@"`, 1, 200},
		{"emails.value eq", `emails.value eq "bob@x.com"`, 1, 200},
		{"emails selector", `emails[type eq "work"].value eq "bob@x.com"`, 1, 200},
		{"active eq true", `active eq true`, 2, 200},
		{"active eq false", `active eq false`, 1, 200},
		{"id eq", `id eq "u2"`, 1, 200},
		{"no match", `userName eq "nobody"`, 0, 200},
		{"and is refused", `a eq "b" and c eq "d"`, 0, 400},
		{"and with real attrs is refused", `userName eq "a" and active eq true`, 0, 400},
		{"unknown attribute", `nickName eq "x"`, 0, 400},
		{"unknown operator", `userName ne "x"`, 0, 400},
		{"unterminated quote", `userName eq "x`, 0, 400},
		{"unquoted string", `userName eq x`, 0, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, code := scimList(t, mux, "/scim/v2/Users?filter="+url.QueryEscape(tc.filter))
			if code != tc.code {
				t.Fatalf("status = %d, want %d", code, tc.code)
			}
			if code == 200 && (list.TotalResults != tc.want || len(list.Resources) != tc.want) {
				t.Fatalf("total=%d items=%d, want %d", list.TotalResults, len(list.Resources), tc.want)
			}
		})
	}
}

func TestSCIMFilterGroups(t *testing.T) {
	mux, _, _ := scimGroupRig(t)
	if rec := scimDo(t, mux, http.MethodPost, "/scim/v2/Groups", `{"displayName":"ops-team"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	cases := []struct {
		filter string
		want   int
		code   int
	}{
		{`displayName eq "ops-team"`, 1, 200},
		{`DISPLAYNAME sw "kryptkeeper"`, 1, 200},
		{`displayName eq "nobody"`, 0, 200},
		{`displayName eq "a" or displayName eq "b"`, 0, 400},
		{`userName eq "x"`, 0, 400},
	}
	for _, tc := range cases {
		list, code := scimList(t, mux, "/scim/v2/Groups?filter="+url.QueryEscape(tc.filter))
		if code != tc.code || (code == 200 && (list.TotalResults != tc.want || len(list.Resources) != tc.want)) {
			t.Fatalf("filter %q: status %d total %d items %d, want status %d count %d", tc.filter, code, list.TotalResults, len(list.Resources), tc.code, tc.want)
		}
	}
}

func TestSCIMPagination(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	recs := make([]UserRecord, 0, 7)
	for i := 1; i <= 7; i++ {
		recs = append(recs, UserRecord{ID: fmt.Sprintf("u%d", i), Email: fmt.Sprintf("user%d@x.com", i), Role: "pki-viewer", Status: "active"})
	}
	users := &fileUserProvider{users: recs}
	mux := http.NewServeMux()
	registerSCIMHandlers(mux, auth, users, stubAuditProvider{})

	cases := []struct {
		name                         string
		query                        string
		wantItems, wantTotal, wantSI int
	}{
		{"first page", "startIndex=1&count=3", 3, 7, 1},
		{"last partial page", "startIndex=7&count=3", 1, 7, 7},
		{"start past the end", "startIndex=100", 0, 7, 100},
		{"count=0 returns the total only", "count=0", 0, 7, 1},
		{"startIndex=0 is treated as 1", "startIndex=0&count=2", 2, 7, 1},
		{"negative count is 0", "count=-5", 0, 7, 1},
		{"defaults return everything", "", 7, 7, 1},
		{"count is capped", "count=100000", 7, 7, 1},
		{"filter plus page counts matches only", "filter=" + url.QueryEscape(`userName sw "user"`) + "&startIndex=2&count=2", 2, 7, 2},
		{"narrow filter plus page", "filter=" + url.QueryEscape(`userName eq "user3@x.com"`) + "&count=5", 1, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, code := scimList(t, mux, "/scim/v2/Users?"+tc.query)
			if code != 200 {
				t.Fatalf("status = %d", code)
			}
			if len(list.Resources) != tc.wantItems || list.ItemsPerPage != tc.wantItems || list.TotalResults != tc.wantTotal || list.StartIndex != tc.wantSI {
				t.Fatalf("items=%d itemsPerPage=%d total=%d startIndex=%d, want %d/%d/%d/%d",
					len(list.Resources), list.ItemsPerPage, list.TotalResults, list.StartIndex, tc.wantItems, tc.wantItems, tc.wantTotal, tc.wantSI)
			}
		})
	}

	// Pages are sorted by userName, so successive pages never overlap.
	first, _ := scimList(t, mux, "/scim/v2/Users?startIndex=1&count=3")
	second, _ := scimList(t, mux, "/scim/v2/Users?startIndex=4&count=3")
	var a, b scimUserResource
	_ = json.Unmarshal(first.Resources[2], &a)
	_ = json.Unmarshal(second.Resources[0], &b)
	if a.UserName != "user3@x.com" || b.UserName != "user4@x.com" {
		t.Fatalf("pages not contiguous in userName order: %q then %q", a.UserName, b.UserName)
	}
}

// TestSCIMGroupPagination pins totalResults/startIndex on the Groups list too.
func TestSCIMGroupPagination(t *testing.T) {
	mux, _, _ := scimGroupRig(t)
	for _, n := range []string{"b-team", "c-team"} {
		if rec := scimDo(t, mux, http.MethodPost, "/scim/v2/Groups", `{"displayName":"`+n+`"}`); rec.Code != http.StatusCreated {
			t.Fatal(rec.Body.String())
		}
	}
	list, _ := scimList(t, mux, "/scim/v2/Groups?startIndex=2&count=1")
	if list.TotalResults != 3 || len(list.Resources) != 1 || list.StartIndex != 2 || list.ItemsPerPage != 1 {
		t.Fatalf("group page = %+v", list)
	}
	list, _ = scimList(t, mux, "/scim/v2/Groups?startIndex=50")
	if list.TotalResults != 3 || len(list.Resources) != 0 {
		t.Fatalf("group page past end = %+v", list)
	}
}

// TestSCIMDeactivateEndsRefresh is the W6-10 regression: deprovisioning
// through SCIM must end access at the next refresh and on the next request.
func TestSCIMDeactivateEndsRefresh(t *testing.T) {
	auth := newTestSCIMAuthenticator()
	users := &fileUserProvider{users: []UserRecord{{ID: "user-1", Email: "carol@example.com", Role: "pki-operator", Status: "active"}}}
	auth.userProvider = users
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, users, stubAuditProvider{})

	now := time.Now()
	access, _, refresh, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatal(err)
	}
	authz := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := authz(); got != http.StatusOK {
		t.Fatalf("pre-deactivation authz-check = %d, want 200", got)
	}
	rec := scimDo(t, mux, http.MethodPatch, "/scim/v2/Users/user-1", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d (%s)", rec.Code, rec.Body.String())
	}
	if _, _, _, _, err := auth.Refresh(refresh, now.Add(time.Minute)); err != errInvalidRefreshToken {
		t.Fatalf("Refresh after deactivation: err = %v, want errInvalidRefreshToken", err)
	}
	if got := authz(); got != http.StatusUnauthorized {
		t.Fatalf("authz-check with the old access token after deactivation = %d, want 401", got)
	}
}
