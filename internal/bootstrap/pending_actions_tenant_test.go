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

// TestPendingActionsStayTenantIsolated is a W2-01 regression test: pending
// actions were already tenant-enforced before this ticket
// (handlers_pending_actions.go:107-116, filterPendingActionsByTenant) — this
// proves it stays that way, rather than adding new enforcement code.
func TestPendingActionsStayTenantIsolated(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")

	auth := NewAuthenticatorFromEnv()
	_, acmeToken, err := auth.CreateAPIKey("acme-approver", "acme-approver", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create acme api key: %v", err)
	}
	_, globexToken, err := auth.CreateAPIKey("globex-approver", "globex-approver", "pki-admin", []string{"*"}, "", "globex", time.Now())
	if err != nil {
		t.Fatalf("create globex api key: %v", err)
	}

	store := newTestPendingStore(t)
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, store, stubAuditProvider{}, nil)

	globexAction, err := store.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1"}`),
		ProposedBy: "mcp:agent", Tenant: "globex",
	})
	if err != nil {
		t.Fatalf("seed globex action: %v", err)
	}
	acmeAction, err := store.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp2"}`),
		ProposedBy: "mcp:agent", Tenant: "acme",
	})
	if err != nil {
		t.Fatalf("seed acme action: %v", err)
	}

	postAs := func(token, tenant, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Tenant", tenant)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// Cross-tenant approve/reject are hidden as not-found (existing convention
	// — see handlers_pending_actions.go:113-116 — distinct from the 403 used
	// elsewhere in W2-01; this test only proves it still holds).
	if rec := postAs(acmeToken, "acme", "/api/v1/pending-actions/"+globexAction.ID+"/approve"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant approve: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := postAs(acmeToken, "acme", "/api/v1/pending-actions/"+globexAction.ID+"/reject"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant reject: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	// Same-tenant reject succeeds (approve would also execute a real revoke
	// against reportCertProvider, which doesn't implement RevokeCertificate
	// meaningfully — reject alone is enough to prove the positive path).
	if rec := postAs(globexToken, "globex", "/api/v1/pending-actions/"+globexAction.ID+"/reject"); rec.Code != http.StatusOK {
		t.Fatalf("same-tenant reject: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// List is scoped: acme's approver sees only the acme action.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pending-actions", nil)
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []PendingAction `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].ID != acmeAction.ID {
		t.Fatalf("expected only the acme action visible, got %+v", resp.Data)
	}
}
