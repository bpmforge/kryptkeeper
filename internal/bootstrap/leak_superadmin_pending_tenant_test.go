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

// An unscoped super-admin's own tenant says nothing about where an action
// runs. Stamping it as DefaultTenant made the L-03 execution-time re-check
// refuse every legitimate super-admin action on a tenant's resources.
func TestSuperAdminPendingActionStampsTargetTenant(t *testing.T) {
	setupTenantWritePathTest(t)
	certs := NewFileCertificateProviderFromEnv()
	auth := NewAuthenticatorFromEnv()
	_, globexToken, _ := auth.CreateAPIKey("globex-v", "globex-v", "pki-admin", []string{"*"}, "", "globex", time.Now())
	_, acmeToken, _ := auth.CreateAPIKey("acme-v", "acme-v", "pki-admin", []string{"*"}, "", "acme", time.Now())
	store := newTestPendingStore(t)
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, certs, store, stubAuditProvider{}, nil)

	propose := func(body string) PendingAction {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pending-actions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer root-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("super-admin proposal want 201, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data PendingAction `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Data
	}

	action := propose(`{"action_type":"bulk_revoke","params":{"ca_id":"ca-globex"}}`)
	if action.Tenant != "globex" {
		t.Fatalf("action must be stamped with the target's tenant, got %q", action.Tenant)
	}
	if _, err := executePendingAction(context.Background(), certs, action); err != nil && strings.Contains(err.Error(), "not in the action's tenant") {
		t.Fatalf("legitimate super-admin action refused at execution: %v", err)
	}

	byCert := propose(`{"action_type":"revoke","params":{"fingerprint":"fp-acme-cert"}}`)
	if byCert.Tenant != "acme" {
		t.Fatalf("cert target resolves through its CA to acme, got %q", byCert.Tenant)
	}

	// The stamped tenant is what scopes the queue: the owning tenant sees it, others do not.
	listFor := func(token, tenant string) int {
		code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/pending-actions", token, tenant, "")
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, body)
		}
		var resp struct {
			Data []PendingAction `json:"data"`
		}
		_ = json.Unmarshal([]byte(body), &resp)
		return len(resp.Data)
	}
	if n := listFor(globexToken, "globex"); n != 1 {
		t.Fatalf("globex should see the action aimed at its CA, got %d", n)
	}
	if n := listFor(acmeToken, "acme"); n != 1 {
		t.Fatalf("acme should see only the action aimed at its cert, got %d", n)
	}

	// Unresolvable targets fall back to the proposer's tenant; execution stays fail-closed.
	if a := propose(`{"action_type":"revoke","params":{"fingerprint":"fp-missing"}}`); a.Tenant != DefaultTenant {
		t.Fatalf("unresolved target keeps proposer tenant, got %q", a.Tenant)
	}
}
