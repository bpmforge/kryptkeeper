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

func TestLeakL03_PendingActionTargetsMustBeInActionTenant(t *testing.T) {
	setupTenantWritePathTest(t)
	certs := NewFileCertificateProviderFromEnv()
	auth := NewAuthenticatorFromEnv()
	_, acmeToken, err := auth.CreateAPIKey("acme-prop", "acme-prop", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	store := newTestPendingStore(t)
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, certs, store, stubAuditProvider{}, nil)

	propose := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pending-actions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+acmeToken)
		req.Header.Set("X-Tenant", "acme")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	cases := map[string]string{
		"revoke":      `{"action_type":"revoke","params":{"fingerprint":"fp-globex-cert"}}`,
		"renew":       `{"action_type":"renew","params":{"fingerprint":"fp-globex-cert","csr_pem":"x"}}`,
		"bulk_revoke": `{"action_type":"bulk_revoke","params":{"ca_id":"ca-globex"}}`,
		"issue-ca":    `{"action_type":"issue","params":{"ca_id":"ca-globex","template_id":"tpl-acme","csr_pem":"x"}}`,
		"issue-tpl":   `{"action_type":"issue","params":{"ca_id":"ca-acme","template_id":"tpl-globex","csr_pem":"x"}}`,
	}
	for name, body := range cases {
		if rec := propose(body); rec.Code != http.StatusForbidden {
			t.Errorf("%s: cross-tenant proposal want 403, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := propose(`{"action_type":"revoke","params":{"fingerprint":"fp-acme-cert"}}`); rec.Code != http.StatusCreated {
		t.Fatalf("own-tenant proposal want 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Execution-time recheck: a crafted row that slipped past proposal.
	ctx := context.Background()
	for name, body := range map[string]string{
		"revoke":      `{"fingerprint":"fp-globex-cert"}`,
		"bulk_revoke": `{"ca_id":"ca-globex"}`,
		"issue":       `{"ca_id":"ca-globex","template_id":"tpl-globex","csr_pem":"x"}`,
	} {
		typ := name
		_, err := executePendingAction(ctx, certs, PendingAction{ActionType: typ, Params: json.RawMessage(body), Tenant: "acme"})
		if err == nil || !strings.Contains(err.Error(), "not in the action's tenant") {
			t.Errorf("%s exec: want tenant refusal, got %v", name, err)
		}
	}
}
