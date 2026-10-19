// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func jwtModeConfig(claim, mapJSON string, t *testing.T) authValidatorConfig {
	t.Helper()
	m, err := parseRoleMapJSON(mapJSON)
	if err != nil {
		t.Fatalf("parse map: %v", err)
	}
	return authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret, roleClaim: claim, roleMap: m}
}

func principalFor(t *testing.T, cfg authValidatorConfig, extra map[string]any) AuthPrincipal {
	t.Helper()
	p, err := tryPrincipalFor(t, cfg, extra)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return p
}

func tryPrincipalFor(t *testing.T, cfg authValidatorConfig, extra map[string]any) (AuthPrincipal, error) {
	t.Helper()
	claims := map[string]any{"sub": "svc-1", "exp": float64(time.Now().Add(time.Hour).Unix())}
	for k, v := range extra {
		claims[k] = v
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signHS256JWT(t, strongSecret, claims))
	return authenticatePrincipal(req, cfg, nil, time.Now())
}

func TestBearerRole_Mapping(t *testing.T) {
	const mapJSON = `[{"claim_value":"kk-issuers","role":"service-account"},{"claim_value":"kk-admins","role":"pki-admin"},{"claim_value":"kk-ops","role":"pki-operator"}]`
	cases := []struct {
		name  string
		claim string
		extra map[string]any
		want  string
	}{
		{"no claim at all", "groups", nil, ""},
		{"string claim match", "kk_role", map[string]any{"kk_role": "kk-issuers"}, "service-account"},
		{"string claim no match", "kk_role", map[string]any{"kk_role": "interns"}, ""},
		{"array claim match", "groups", map[string]any{"groups": []any{"everyone", "kk-ops"}}, "pki-operator"},
		{"array claim no match", "groups", map[string]any{"groups": []any{"everyone"}}, ""},
		{"precedence is map order, not claim order", "groups", map[string]any{"groups": []any{"kk-admins", "kk-issuers"}}, "service-account"},
		{"precedence second entry beats third", "groups", map[string]any{"groups": []any{"kk-ops", "kk-admins"}}, "pki-admin"},
		{"non-string claim ignored", "groups", map[string]any{"groups": float64(7)}, ""},
		{"array of non-strings ignored", "groups", map[string]any{"groups": []any{1, true}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tryPrincipalFor(t, jwtModeConfig(tc.claim, mapJSON, t), tc.extra)
			if tc.want == "" {
				if !errors.Is(err, errRoleUnmapped) {
					t.Fatalf("an unmapped token must be refused with errRoleUnmapped, got role %q err %v", p.Role, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if p.Role != tc.want {
				t.Fatalf("role = %q, want %q", p.Role, tc.want)
			}
			if tc.want == "pki-admin" && (len(p.Scopes) != 1 || p.Scopes[0] != "*") {
				t.Fatalf("pki-admin must carry the admin scope, got %v", p.Scopes)
			}
			if tc.want != "pki-admin" && len(p.Scopes) != 0 {
				t.Fatalf("non-admin must carry no scopes, got %v", p.Scopes)
			}
		})
	}
}

func TestBearerRole_DeniedWithoutMappingByDefault(t *testing.T) {
	cfg := authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret}
	_, err := tryPrincipalFor(t, cfg, map[string]any{"role": "pki-admin", "groups": []any{"kk-admins"}})
	if !errors.Is(err, errRoleUnmapped) {
		t.Fatalf("an unmapped bearer token must be refused whatever it claims, got err %v", err)
	}
}

func TestBearerRole_ReadOnlyOptIn(t *testing.T) {
	cfg := authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret, unmappedRole: "read-only"}
	if p := principalFor(t, cfg, map[string]any{"role": "pki-admin"}); p.Role != "viewer" || len(p.Scopes) != 0 {
		t.Fatalf("opted-in unmapped token must be a scope-less viewer, got %+v", p)
	}
	cfg = jwtModeConfig("groups", `[{"claim_value":"kk-ops","role":"pki-operator"}]`, t)
	cfg.unmappedRole = "read-only"
	if p := principalFor(t, cfg, map[string]any{"groups": []any{"kk-ops"}}); p.Role != "pki-operator" {
		t.Fatalf("a mapped group must still win over the fallback, got %q", p.Role)
	}
	if p := principalFor(t, cfg, map[string]any{"groups": []any{"other"}}); p.Role != "viewer" {
		t.Fatalf("unmatched group with opt-in must be viewer, got %q", p.Role)
	}
}

func TestBearerRole_UnknownUnmappedValueDeniesAndWarns(t *testing.T) {
	cfg := authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret, unmappedRole: "admin"}
	if _, err := tryPrincipalFor(t, cfg, nil); !errors.Is(err, errRoleUnmapped) {
		t.Fatalf("an unrecognised APP_AUTH_UNMAPPED_ROLE must deny, got %v", err)
	}
	auth := &Authenticator{config: cfg}
	report := &StartupReport{}
	auth.validateBearerRoleMap(report)
	if !hasMsg(report.Warnings, "APP_AUTH_UNMAPPED_ROLE must be") {
		t.Fatalf("expected a warning about the unrecognised value, got %+v", report)
	}
}

func TestBearerRole_RuntimeRefusesMCPAgentAndBootstrap(t *testing.T) {
	cfg := jwtModeConfig("groups", `[{"claim_value":"a","role":"mcp-agent"},{"claim_value":"b","role":"bootstrap"}]`, t)
	for _, g := range []string{"a", "b"} {
		if p, err := tryPrincipalFor(t, cfg, map[string]any{"groups": []any{g}}); !errors.Is(err, errRoleUnmapped) {
			t.Fatalf("group %q must not yield a privileged role, got %q (err %v)", g, p.Role, err)
		}
	}
}

func TestBearerRole_OIDCDeniesUnmappedAndMaps(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwks := buildTestJWKS(t, "k1", &priv.PublicKey)
	m, _ := parseRoleMapJSON(`[{"claim_value":"issuers","role":"service-account"}]`)
	cfg := authValidatorConfig{mode: "oidc", oidcIssuer: "https://idp.example", oidcAudience: "kk", oidcJWKSJSON: jwks, roleClaim: "groups", roleMap: m}
	do := func(extra map[string]any) (AuthPrincipal, error) {
		claims := map[string]any{"sub": "svc", "iss": "https://idp.example", "aud": "kk", "exp": float64(time.Now().Add(time.Hour).Unix())}
		for k, v := range extra {
			claims[k] = v
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+signTestRS256JWT(t, priv, "k1", claims))
		return authenticatePrincipal(req, cfg, nil, time.Now())
	}
	if _, err := do(nil); !errors.Is(err, errRoleUnmapped) {
		t.Fatalf("unmapped oidc token must be refused, got %v", err)
	}
	if p, err := do(map[string]any{"groups": []any{"issuers"}}); err != nil || p.Role != "service-account" {
		t.Fatalf("mapped oidc token = %+v, %v", p, err)
	}
	cfg.unmappedRole = "read-only"
	if p, err := do(nil); err != nil || p.Role != "viewer" || p.AuthType != "oidc" {
		t.Fatalf("opted-in unmapped oidc token = %+v, %v", p, err)
	}
}

func TestParseRoleMapJSON(t *testing.T) {
	if m, err := parseRoleMapJSON(""); err != nil || m != nil {
		t.Fatalf("empty must be (nil,nil), got %v %v", m, err)
	}
	m, err := parseRoleMapJSON(` [ {"claim_value":" a ","role":" viewer "} ] `)
	if err != nil || len(m) != 1 || m[0].ClaimValue != "a" || m[0].Role != "viewer" {
		t.Fatalf("got %v %v", m, err)
	}
	for _, bad := range []string{`{"a":"viewer"}`, `[{"claim_value":"a","roles":"viewer"}]`, `not json`, `[1]`} {
		if _, err := parseRoleMapJSON(bad); err == nil {
			t.Fatalf("%s must be rejected", bad)
		}
	}
}

func TestValidationReport_RoleMap(t *testing.T) {
	custom := func(name string) (bool, error) { return name == "cert-requester", nil }
	cases := []struct {
		name    string
		cfg     authValidatorConfig
		lookup  func(string) (bool, error)
		wantErr string
		noErr   bool
	}{
		{"valid fixed roles", jwtModeConfig("g", `[{"claim_value":"a","role":"service-account"},{"claim_value":"b","role":"pki-admin"}]`, t), nil, "", true},
		{"unknown role", jwtModeConfig("g", `[{"claim_value":"a","role":"superuser"}]`, t), nil, "unknown role", false},
		{"custom role exists", jwtModeConfig("g", `[{"claim_value":"a","role":"cert-requester"}]`, t), custom, "", true},
		{"custom role missing", jwtModeConfig("g", `[{"claim_value":"a","role":"ghost"}]`, t), custom, "unknown role", false},
		{"custom role needs a lookup", jwtModeConfig("g", `[{"claim_value":"a","role":"cert-requester"}]`, t), nil, "unknown role", false},
		{"mcp-agent refused", jwtModeConfig("g", `[{"claim_value":"a","role":"mcp-agent"}]`, t), nil, "may not be granted", false},
		{"bootstrap refused", jwtModeConfig("g", `[{"claim_value":"a","role":"bootstrap"}]`, t), nil, "may not be granted", false},
		{"map without claim", jwtModeConfig("", `[{"claim_value":"a","role":"viewer"}]`, t), nil, "APP_AUTH_ROLE_CLAIM is empty", false},
		{"empty entry", jwtModeConfig("g", `[{"claim_value":"","role":"viewer"}]`, t), nil, "non-empty", false},
		{"parse failure", authValidatorConfig{mode: "jwt", jwtHS256Secret: strongSecret, roleMapErr: "APP_AUTH_ROLE_MAP_JSON must be a JSON array"}, nil, "JSON array", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{config: tc.cfg}
			if tc.lookup != nil {
				a.SetCustomRoleLookup(tc.lookup)
			}
			r := a.ValidationReport()
			if tc.noErr {
				if len(r.Errors) != 0 {
					t.Fatalf("unexpected errors: %v", r.Errors)
				}
				return
			}
			if !hasMsg(r.Errors, tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, r.Errors)
			}
		})
	}
}

func TestValidationReport_RoleMapLookupFailureIsWarning(t *testing.T) {
	a := &Authenticator{config: jwtModeConfig("g", `[{"claim_value":"a","role":"cert-requester"}]`, t)}
	a.SetCustomRoleLookup(func(string) (bool, error) { return false, errors.New("db down") })
	r := a.ValidationReport()
	if len(r.Errors) != 0 || !hasMsg(r.Warnings, "could not verify custom role") {
		t.Fatalf("errors=%v warnings=%v", r.Errors, r.Warnings)
	}
}

func TestNewAuthenticatorFromEnv_RoleMap(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")
	t.Setenv("APP_JWT_HS256_SECRET", strongSecret)
	t.Setenv("APP_AUTH_ROLE_CLAIM", "kk_role")
	t.Setenv("APP_AUTH_ROLE_MAP_JSON", `[{"claim_value":"issuer","role":"service-account"}]`)
	a := NewAuthenticatorFromEnv()
	if a.config.roleClaim != "kk_role" || len(a.config.roleMap) != 1 || a.config.roleMapErr != "" {
		t.Fatalf("config = %+v", a.config)
	}
	t.Setenv("APP_AUTH_ROLE_MAP_JSON", `{bad`)
	b := NewAuthenticatorFromEnv()
	if b.config.roleMapErr == "" || len(b.ValidationReport().Errors) == 0 {
		t.Fatal("a malformed map must surface as a validation error")
	}
}

// W33-22: the requester role holds exactly certificate.read + certificate.issue,
// and the write gate lets it make exactly one write (POST /api/v1/certificates).
func TestRoleMap_RequesterRole_LeastPrivilege(t *testing.T) {
	pd := AuthPrincipal{ID: "team-a", Role: RoleRequester}

	perms, admin := principalPermissions(pd, nil)
	if admin {
		t.Fatal("requester must not be admin")
	}
	want := map[string]bool{"certificate.read": true, "certificate.issue": true}
	if len(perms) != len(want) {
		t.Fatalf("requester permissions = %v, want exactly %v", perms, want)
	}
	for p := range want {
		if !perms[p] {
			t.Fatalf("requester lacks %s: %v", p, perms)
		}
	}
	if !roleGrantableByMap(RoleRequester) {
		t.Fatal("requester must be grantable through the role map")
	}
	if !fixedRoles[RoleRequester] {
		t.Fatal("a custom role must not be able to shadow requester")
	}
	if _, known := grantableRolePermissions(RoleRequester, nil); !known {
		t.Fatal("requester must be a known grantable role")
	}

	allowed := []string{"/api/v1/certificates", "/api/v1/certificates/"}
	for _, p := range allowed {
		if ok, need := writeDecision(pd, nil, p); !ok {
			t.Errorf("requester must be allowed to POST %s (needs %s)", p, need)
		}
	}

	denied := []string{
		"/api/v1/approvals/abc/approve",
		"/api/v1/approvals/abc/reject",
		"/api/v1/pending-actions",
		"/api/v1/pending-actions/abc/approve",
		"/api/v1/certificates/abc/revoke",
		"/api/v1/certificates/abc/renew",
		"/api/v1/certificates/abc/ownership",
		"/api/v1/certificates/bulk-revoke",
		"/api/v1/certificates/bulk-reissue",
		"/api/v1/certificates/import",
		"/api/v1/certificates/bulk-import",
		"/api/v1/codesign/requests",
		"/api/v1/ssh/certificates",
		"/api/v1/spiffe/svid",
		"/api/v1/cas",
		"/api/v1/cas/ca-1/rotate",
		"/api/v1/templates",
		"/api/v1/templates/t-1",
		"/api/v1/keys",
		"/api/v1/keys/k-1/rotate",
		"/api/v1/ceremonies/c-1",
		"/api/v1/config/settings",
		"/api/v1/users",
		"/api/v1/users/u-1",
		"/api/v1/roles/custom",
		"/api/v1/tenants",
		"/api/v1/policies/p-1",
		"/api/v1/team-policies",
		"/api/v1/team-policies/team-a",
		"/api/v1/api-keys",
		"/api/v1/discovery/scan",
		"/api/v1/notifications/rules",
		"/api/v1/exceptions/e-1",
		"/api/v1/admin/anything",
		"/api/v1/not-a-known-route",
	}
	for _, p := range denied {
		if ok, need := writeDecision(pd, nil, p); ok {
			t.Errorf("requester must be denied %s (route needs %s)", p, need)
		}
	}

	// Scopes on the key must not widen what a requester can write.
	scoped := AuthPrincipal{ID: "team-a", Role: RoleRequester, Scopes: []string{"*", "ops:write"}}
	if ok, _ := writeDecision(scoped, nil, "/api/v1/discovery/scan"); ok {
		t.Error("a scoped requester key must stay confined to POST /api/v1/certificates")
	}
}
