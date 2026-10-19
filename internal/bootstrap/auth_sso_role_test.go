// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const ssoRoleMapJSON = `[{"claim_value":"kk-admins","role":"pki-admin"},{"claim_value":"kk-ops","role":"pki-operator"},{"claim_value":"kk-audit","role":"auditor"}]`

func ssoRoleMap(t *testing.T) []roleMapEntry {
	t.Helper()
	m, err := parseRoleMapJSON(ssoRoleMapJSON)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type ssoOIDCRig struct {
	mux   *http.ServeMux
	auth  *Authenticator
	users *fileUserProvider
	login oidcLoginStart
}

// newSSOOIDCRig wires a real OIDC callback whose ID token carries groups.
// storedRole is the role already on the provisioned record ("" = a SCIM user
// with no group).
func newSSOOIDCRig(t *testing.T, groups []any, storedRole, unmapped string) *ssoOIDCRig {
	t.Helper()
	priv := generateTestRSAKey(t)
	jwksJSON := buildTestJWKS(t, testOIDCKID, &priv.PublicKey)
	claims := validIDTokenClaims(time.Now())
	claims["groups"] = groups
	idp := newTestOIDCNonceEndpoint(t, priv, claims)
	auth := newTestOIDCLoginAuthenticator(t, idp.URL, jwksJSON)
	auth.config.roleClaim = "groups"
	auth.config.roleMap = ssoRoleMap(t)
	auth.config.unmappedRole = unmapped
	users := &fileUserProvider{users: []UserRecord{{ID: "user-1", Email: "alice@example.com", Role: storedRole, Status: "active"}}}
	auth.userProvider = users
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, users, stubAuditProvider{})
	return &ssoOIDCRig{mux: mux, auth: auth, users: users, login: startOIDCLogin(t, mux, idp)}
}

func (r *ssoOIDCRig) callback() *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, r.login.callbackRequest())
	return rec
}

func (r *ssoOIDCRig) storedRole(t *testing.T) string {
	t.Helper()
	us, _ := r.users.ListUsers(context.Background())
	return us[0].Role
}

func authzRole(t *testing.T, mux *http.ServeMux, c *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authz-check = %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Role
}

func TestOIDCLogin_UnmappedGroupDeniedByDefault(t *testing.T) {
	rig := newSSOOIDCRig(t, []any{"interns"}, "", "")
	rec := rig.callback()
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgSSONoRoleMapped) {
		t.Fatalf("unmapped SSO login = %d %s, want 403 %q", rec.Code, rec.Body.String(), msgSSONoRoleMapped)
	}
	if hasSessionCookie(rec) {
		t.Fatal("a denied login must not set a session cookie")
	}
}

func TestOIDCLogin_UnmappedGroupReadOnlyOptIn(t *testing.T) {
	rig := newSSOOIDCRig(t, []any{"interns"}, "", "read-only")
	rec := rig.callback()
	if rec.Code != http.StatusFound {
		t.Fatalf("opted-in unmapped login = %d (%s), want 302", rec.Code, rec.Body.String())
	}
	if got := authzRole(t, rig.mux, sessionCookieFrom(rec)); got != "viewer" {
		t.Fatalf("role = %q, want viewer", got)
	}
}

func TestOIDCLogin_MappedGroupWinsAndIsPersistedForRefresh(t *testing.T) {
	rig := newSSOOIDCRig(t, []any{"kk-ops"}, "", "")
	rec := rig.callback()
	if rec.Code != http.StatusFound {
		t.Fatalf("mapped login = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := authzRole(t, rig.mux, sessionCookieFrom(rec)); got != "pki-operator" {
		t.Fatalf("session role = %q, want pki-operator", got)
	}
	if got := rig.storedRole(t); got != "pki-operator" {
		t.Fatalf("stored role = %q: refresh re-reads the store, so the mapping must be persisted", got)
	}
	// Refresh re-reads the store: a refresh token for this user keeps the role.
	_, _, refresh, _, err := rig.auth.mintSessionForUser("user-1", "pki-operator", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, _, err := rig.auth.Refresh(refresh, time.Now())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := jwtRoleClaim(access); got != "pki-operator" {
		t.Fatalf("role after refresh = %q", got)
	}
}

func TestOIDCLogin_MappedGroupOverridesStoredRoleAndRespectsPrecedence(t *testing.T) {
	rig := newSSOOIDCRig(t, []any{"kk-audit", "kk-admins"}, "pki-viewer", "")
	rec := rig.callback()
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d", rec.Code)
	}
	// Map order is precedence: kk-admins is listed before kk-audit.
	if got := authzRole(t, rig.mux, sessionCookieFrom(rec)); got != "pki-admin" {
		t.Fatalf("role = %q, want pki-admin", got)
	}
}

func TestOIDCLogin_NoGroupKeepsProvisionedRole(t *testing.T) {
	rig := newSSOOIDCRig(t, []any{"interns"}, "pki-viewer", "")
	rec := rig.callback()
	if rec.Code != http.StatusFound {
		t.Fatalf("provisioned user with a role must still log in, got %d", rec.Code)
	}
	if got := authzRole(t, rig.mux, sessionCookieFrom(rec)); got != "pki-viewer" {
		t.Fatalf("role = %q, want the SCIM/operator-set pki-viewer", got)
	}
}

func newSSOSAMLRig(t *testing.T, groups []string, storedRole, unmapped string) (*http.ServeMux, *fileUserProvider, string) {
	t.Helper()
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()
	p := validSAMLAssertionParams("assertion-sso", "alice@example.com", "alice@example.com", now)
	p.Groups = groups
	doc := signResponseEnvelope(t, sigCtx, buildSAMLResponseXML(t, "response-sso", testSAMLACSURL, testSAMLIDPIssuer, buildSAMLAssertionXML(t, p)))
	auth := newTestSAMLAuthenticator(t, idpCert)
	auth.config.roleClaim = "groups"
	auth.config.roleMap = ssoRoleMap(t)
	auth.config.unmappedRole = unmapped
	users := &fileUserProvider{users: []UserRecord{{ID: "user-1", Email: "alice@example.com", Role: storedRole, Status: "active"}}}
	auth.userProvider = users
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, users, stubAuditProvider{})
	return mux, users, encodeSAMLResponse(t, doc)
}

func TestSAMLLogin_UnmappedGroupDeniedByDefault(t *testing.T) {
	mux, _, resp := newSSOSAMLRig(t, []string{"interns"}, "", "")
	rec := postSAMLResponse(t, mux, resp)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgSSONoRoleMapped) {
		t.Fatalf("unmapped SAML login = %d %s, want 403", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

func TestSAMLLogin_UnmappedGroupReadOnlyOptIn(t *testing.T) {
	mux, _, resp := newSSOSAMLRig(t, nil, "", "read-only")
	rec := postSAMLResponse(t, mux, resp)
	if rec.Code != http.StatusFound {
		t.Fatalf("opted-in SAML login = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := authzRole(t, mux, sessionCookieFrom(rec)); got != "viewer" {
		t.Fatalf("role = %q, want viewer", got)
	}
}

func TestSAMLLogin_MappedGroupPersisted(t *testing.T) {
	mux, users, resp := newSSOSAMLRig(t, []string{"kk-audit"}, "", "")
	rec := postSAMLResponse(t, mux, resp)
	if rec.Code != http.StatusFound {
		t.Fatalf("mapped SAML login = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := authzRole(t, mux, sessionCookieFrom(rec)); got != "auditor" {
		t.Fatalf("role = %q, want auditor", got)
	}
	us, _ := users.ListUsers(context.Background())
	if us[0].Role != "auditor" {
		t.Fatalf("stored role = %q, want auditor", us[0].Role)
	}
}

// The users.role CHECK of migration 000001 refused viewer/auditor/custom roles
// and ""; migration 000090 lifts it. This pins that on the real schema.
func TestDBUserProvider_AcceptsSSORoles(t *testing.T) {
	p := newFreshUserDBProvider(t)
	ctx := context.Background()
	for _, role := range []string{"", "viewer", "auditor", "approver", "custom-role"} {
		u, err := p.InviteUser(ctx, "u-"+role+"@example.com", role)
		if err != nil {
			t.Fatalf("InviteUser role %q: %v", role, err)
		}
		if _, err := p.UpdateUser(ctx, u.ID, "auditor", ""); err != nil {
			t.Fatalf("UpdateUser to auditor from %q: %v", role, err)
		}
	}
}

func previewRig(t *testing.T) (*http.ServeMux, *Authenticator) {
	t.Helper()
	auth := newLoginAuth("unused",
		UserRecord{ID: "admin-1", Email: "a@example.com", Role: "pki-admin", Status: "active"},
		UserRecord{ID: "viewer-1", Email: "v@example.com", Role: "viewer", Status: "active"},
	)
	auth.config.roleClaim = "groups"
	auth.config.roleMap = ssoRoleMap(t)
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})
	return mux, auth
}

func previewGET(t *testing.T, mux *http.ServeMux, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/role-map/preview"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestRoleMapPreview(t *testing.T) {
	mux, auth := previewRig(t)
	adminTok, _, _, _, err := auth.mintSessionForUser("admin-1", "pki-admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	viewerTok, _, _, _, err := auth.mintSessionForUser("viewer-1", "viewer", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	type data struct {
		Mapped, WouldLogin               bool
		Role, Matched, Policy, Effective string
		Groups                           []string
	}
	decode := func(rec *httptest.ResponseRecorder) data {
		var b struct {
			Data struct {
				Groups            []string `json:"groups"`
				Mapped            bool     `json:"mapped"`
				Role              string   `json:"role"`
				MatchedClaimValue string   `json:"matched_claim_value"`
				UnmappedPolicy    string   `json:"unmapped_policy"`
				EffectiveRole     string   `json:"effective_role"`
				WouldLogin        bool     `json:"would_login"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		d := b.Data
		return data{d.Mapped, d.WouldLogin, d.Role, d.MatchedClaimValue, d.UnmappedPolicy, d.EffectiveRole, d.Groups}
	}

	if rec := previewGET(t, mux, "", "?groups=kk-ops"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
	if rec := previewGET(t, mux, viewerTok, "?groups=kk-ops"); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin = %d, want 403", rec.Code)
	}

	rec := previewGET(t, mux, adminTok, "?groups=everyone,kk-ops")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin = %d (%s)", rec.Code, rec.Body.String())
	}
	if d := decode(rec); !d.Mapped || d.Role != "pki-operator" || d.Matched != "kk-ops" || d.Effective != "pki-operator" || !d.WouldLogin || d.Policy != "deny" {
		t.Fatalf("mapped preview = %+v", d)
	}

	if d := decode(previewGET(t, mux, adminTok, "?groups=")); d.Mapped || d.Role != "" || d.WouldLogin || len(d.Groups) != 0 {
		t.Fatalf("empty groups preview = %+v", d)
	}
	if d := decode(previewGET(t, mux, adminTok, "?groups=nope")); d.Mapped || d.WouldLogin || d.Effective != "" {
		t.Fatalf("unmapped preview must say the login would be denied, got %+v", d)
	}

	auth.config.unmappedRole = "read-only"
	if d := decode(previewGET(t, mux, adminTok, "?groups=nope")); d.Mapped || !d.WouldLogin || d.Effective != "viewer" || d.Policy != "read-only" {
		t.Fatalf("opt-in preview = %+v", d)
	}

	tooMany := "?groups=" + strings.Repeat("g,", roleMapPreviewMaxGroups+1)
	if rec := previewGET(t, mux, adminTok, tooMany); rec.Code != http.StatusBadRequest {
		t.Fatalf("51 groups = %d, want 400", rec.Code)
	}
	if rec := previewGET(t, mux, adminTok, "?groups="+strings.Repeat("x", roleMapPreviewMaxGroupLen+1)); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized group = %d, want 400", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/role-map/preview", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
}

// The role map is instance-global IdP policy: with multi-tenancy on only an
// unscoped super-admin may read it, never a tenant admin.
func TestRoleMapPreview_TenantAdminDeniedWhenMultiTenant(t *testing.T) {
	mux, auth := previewRig(t)
	adminTok, _, _, _, err := auth.mintSessionForUser("admin-1", "pki-admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := previewGET(t, mux, adminTok, "?groups=kk-ops"); rec.Code != http.StatusOK {
		t.Fatalf("single-tenant admin = %d, want 200", rec.Code)
	}
	t.Setenv("MULTI_TENANCY", "true")
	if rec := previewGET(t, mux, adminTok, "?groups=kk-ops"); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant admin with multi-tenancy on = %d, want 403", rec.Code)
	}
}

// Migration 000090 on Postgres: the CHECK is dropped by name, so prove on a
// live database that the empty role and non-legacy roles are now accepted.
func TestDBUserProvider_Postgres_AcceptsSSORoles(t *testing.T) {
	migratedPostgresForTest(t)
	p, ok := newDBUserProviderFromEnv().(*dbUserProvider)
	if !ok || !p.postgres {
		t.Fatalf("expected a postgres dbUserProvider, got %T", p)
	}
	ctx := context.Background()
	for _, role := range []string{"", "viewer", "auditor", "approver", "custom-role"} {
		u, err := p.InviteUser(ctx, "u-"+role+"@example.com", role)
		if err != nil {
			t.Fatalf("InviteUser role %q: %v", role, err)
		}
		if _, err := p.UpdateUser(ctx, u.ID, "auditor", ""); err != nil {
			t.Fatalf("UpdateUser to auditor from %q: %v", role, err)
		}
	}
}
