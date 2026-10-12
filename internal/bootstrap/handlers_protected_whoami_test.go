// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProtectedWhoami_ReportsRoleAndCanApproveActions proves G-58's
// prerequisite: a caller's own token can see its resolved role AND a
// CanApproveActions boolean computed via the real canApproveActions
// function (not re-derived from Role by the caller), for both an
// approver-capable role and a non-approver role including RoleMCPAgent.
func TestProtectedWhoami_ReportsRoleAndCanApproveActions(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "whoami-test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/protected/whoami", registerProtectedWhoamiHandler(auth, stubAuditProvider{}))

	cases := []struct {
		name        string
		role        string
		wantApprove bool
		wantRole    string
	}{
		{"pki-admin can approve", "pki-admin", true, "pki-admin"},
		{"pki-operator can approve", "pki-operator", true, "pki-operator"},
		{"pki-auditor cannot approve", "pki-auditor", false, "pki-auditor"},
		{"mcp-agent structurally cannot approve", RoleMCPAgent, false, RoleMCPAgent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, token, err := auth.CreateAPIKey(tc.name+"-key", tc.name+"-principal", tc.role, []string{"*"}, "", "", time.Now())
			if err != nil {
				t.Fatalf("create api key: %v", err)
			}
			req := httptest.NewRequest("GET", "/api/v1/protected/whoami", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("status = %d, want 200. body: %s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Role              string `json:"role"`
				CanApproveActions bool   `json:"can_approve_actions"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Role != tc.wantRole {
				t.Errorf("role = %q, want %q", resp.Role, tc.wantRole)
			}
			if resp.CanApproveActions != tc.wantApprove {
				t.Errorf("can_approve_actions = %v, want %v", resp.CanApproveActions, tc.wantApprove)
			}
		})
	}
}
