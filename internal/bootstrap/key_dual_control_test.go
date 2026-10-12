// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

// W9-10: destructive key ops behind the approval queue when dual control
// is on; refused as single-admin operations.

func newDualControlMux(t *testing.T, dualControlOn bool) (*http.ServeMux, keystore.Store, PendingActionStore) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	if dualControlOn {
		t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "true")
	} else {
		t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false")
	}
	auth := NewAuthenticatorFromEnv()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("dual-control-test-passphrase-32!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })

	// The same env-resolved store the handlers build internally — so the
	// test can inspect and decide what the handlers proposed.
	queue := NewPendingActionStoreFromEnv()
	if queue == nil {
		t.Fatal("pending action store unavailable")
	}
	if err := queue.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("queue schema: %v", err)
	}

	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProvider{}, "")
	registerPendingActionHandlers(mux, auth, NewFileCertificateProviderFromEnv(), queue, stubAuditProvider{}, nil, keys)
	return mux, keys, queue
}

func dualControlReq(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader = bytes.NewReader(nil)
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestDualControlOffKeepsDirectDelete(t *testing.T) {
	mux, keys, _ := newDualControlMux(t, false)
	if _, err := keys.GenerateKey("direct", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	rec := dualControlReq(t, mux, http.MethodDelete, "/api/v1/keys/direct", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("dual control off: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := keys.Signer("direct"); err == nil {
		t.Fatal("key must be gone with dual control off")
	}
}

func TestDualControlRefusesSingleAdminDestructiveOps(t *testing.T) {
	mux, keys, queue := newDualControlMux(t, true)
	if _, err := keys.GenerateKey("guarded", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Delete: proposed, not done.
	rec := dualControlReq(t, mux, http.MethodDelete, "/api/v1/keys/guarded", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("delete: expected 202 proposal, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := keys.Signer("guarded"); err != nil {
		t.Fatalf("key must still exist after a mere proposal: %v", err)
	}

	// Rotate: proposed, not done.
	rec = dualControlReq(t, mux, http.MethodPost, "/api/v1/keys/guarded/rotate", map[string]any{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("rotate: expected 202 proposal, got %d: %s", rec.Code, rec.Body.String())
	}

	// Export without a grant: proposed, and no key material returned.
	rec = dualControlReq(t, mux, http.MethodPost, "/api/v1/keys/guarded/export", map[string]any{
		"passphrase": "export-passphrase",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("export: expected 202 proposal, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE") || strings.Contains(rec.Body.String(), "BEGIN") {
		t.Fatal("export proposal response must not contain key material")
	}

	pending, err := queue.List(context.Background(), "pending")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("expected 3 proposals on the queue, got %d", len(pending))
	}

	// The proposer cannot approve their own proposal through the queue —
	// the second-approver requirement, end to end.
	rec = dualControlReq(t, mux, http.MethodPost, "/api/v1/pending-actions/"+pending[0].ID+"/approve", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval must be 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestApprovedKeyActionsExecute(t *testing.T) {
	_, keys, queue := newDualControlMux(t, true)
	ctx := context.Background()
	if _, err := keys.GenerateKey("doomed", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	dc := NewKeyDualControlFromEnv(queue)

	a, err := dc.Propose(ctx, keyActionDelete, "doomed", "admin-one")
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	// Second admin approves; the execution path is the same function the
	// approve handler dispatches to.
	result, err := executeKeyAction(ctx, keys, a)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if err := queue.Decide(ctx, a.ID, "approved", "admin-two", result); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if _, err := keys.Signer("doomed"); err == nil {
		t.Fatal("approved delete must actually delete")
	}

	// Rotate executes with the key's own algorithm.
	if _, err := keys.GenerateKey("spinner", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	a, err = dc.Propose(ctx, keyActionRotate, "spinner", "admin-one")
	if err != nil {
		t.Fatalf("propose rotate: %v", err)
	}
	if _, err := executeKeyAction(ctx, keys, a); err != nil {
		t.Fatalf("execute rotate: %v", err)
	}
	if _, err := keys.Signer("spinner"); err != nil {
		t.Fatalf("rotated key must exist: %v", err)
	}
}

func TestExportGrantFlow(t *testing.T) {
	mux, keys, queue := newDualControlMux(t, true)
	ctx := context.Background()
	if _, err := keys.GenerateKey("exportable", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Propose via the API (as principal "bootstrap"), approve as a second
	// admin directly on the queue; approval records a grant, never bytes.
	rec := dualControlReq(t, mux, http.MethodPost, "/api/v1/keys/exportable/export", map[string]any{
		"passphrase": "export-passphrase",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose: %d: %s", rec.Code, rec.Body.String())
	}
	var proposal struct {
		Data struct {
			ActionID string `json:"action_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &proposal); err != nil {
		t.Fatalf("parse: %v", err)
	}
	action, _, err := queue.Get(ctx, proposal.Data.ActionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	grant, err := executeKeyAction(ctx, keys, action)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if strings.Contains(string(grant), "PRIVATE") {
		t.Fatal("export approval must not contain key material")
	}
	if err := queue.Decide(ctx, action.ID, "approved", "admin-two", grant); err != nil {
		t.Fatalf("decide: %v", err)
	}

	// Redemption by the proposer with the approved grant succeeds ONCE.
	rec = dualControlReq(t, mux, http.MethodPost, "/api/v1/keys/exportable/export", map[string]any{
		"passphrase": "export-passphrase", "approved_action_id": action.ID,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN") {
		t.Fatal("redeemed export must return the encrypted PEM")
	}

	// Grants are single-use.
	rec = dualControlReq(t, mux, http.MethodPost, "/api/v1/keys/exportable/export", map[string]any{
		"passphrase": "export-passphrase", "approved_action_id": action.ID,
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("second redemption must be 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthorizeGrantRefusals(t *testing.T) {
	_, keys, queue := newDualControlMux(t, true)
	_ = keys
	ctx := context.Background()
	dc := NewKeyDualControlFromEnv(queue)
	auth := newReportsTestAuth(t)
	alice := AuthPrincipal{ID: "alice", Role: "pki-admin", AuthType: "local"}
	redeem := func(keyID string, pd AuthPrincipal, id string) error {
		return dc.AuthorizeGrant(ctx, auth, keyActionExport, keyID, "", pd, id)
	}

	a, err := dc.ProposeGrant(ctx, auth, keyActionExport, "k1", "", alice)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	// Pending, not approved.
	if err := redeem("k1", alice, a.ID); err == nil {
		t.Fatal("a pending grant must not authorize")
	}
	if err := queue.Decide(ctx, a.ID, "approved", "bob", json.RawMessage(`{"export_granted":true}`)); err != nil {
		t.Fatalf("decide: %v", err)
	}
	// Wrong key.
	if err := redeem("other-key", alice, a.ID); err == nil {
		t.Fatal("a grant for another key must not authorize")
	}
	// Wrong principal: the grant belongs to its proposer.
	if err := redeem("k1", AuthPrincipal{ID: "mallory", AuthType: "local"}, a.ID); err == nil {
		t.Fatal("a grant must only be redeemable by its proposer")
	}
	// Happy path, then single-use.
	if err := redeem("k1", alice, a.ID); err != nil {
		t.Fatalf("valid grant refused: %v", err)
	}
	if err := redeem("k1", alice, a.ID); err == nil {
		t.Fatal("grants must be single-use")
	}
	// Grants must be proposed with a binding.
	if _, err := dc.Propose(ctx, keyActionExport, "k1", "alice"); err == nil {
		t.Fatal("an unbound grant proposal must be refused")
	}
}
