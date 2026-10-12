// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/keystore"
)

// W17-08: exposing the leaf-escrow ceremony must not weaken it. The
// guarantees under test are the ones a route could quietly erode:
// opt-in default-off, dual control, and no material on the wire.

func custodyOpsMux(t *testing.T) (*http.ServeMux, keystore.Store) {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	store, err := keystore.NewSoftwareStore(t.TempDir(), []byte("custody-ops-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err := store.GenerateKey("leaf-web", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	mux := http.NewServeMux()
	registerKeyCustodyOpsHandlers(mux, newReportsTestAuth(t), store, stubAuditProvider{})
	return mux, store
}

func postCustody(t *testing.T, mux *http.ServeMux, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, path, raw))
	return rec
}

// Default posture: NO tenant opted in, so a deposit is refused. This is
// the W15-03 decision and the thing a wiring ticket could silently undo.
func TestLeafEscrowEndpointRefusedWhenTenantNotOptedIn(t *testing.T) {
	t.Setenv("KRYPTKEEPER_LEAF_ESCROW_TENANTS", "")
	mux, _ := custodyOpsMux(t)
	rec := postCustody(t, mux, "/api/v1/keys/leaf-escrow", map[string]string{
		"key_id":                 "leaf-web",
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "bravo-secret",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("custody must be off by default, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Opted in: deposit succeeds, and the bundle carries no plaintext key.
func TestLeafEscrowEndpointDepositAndRecoverRoundTrip(t *testing.T) {
	t.Setenv("KRYPTKEEPER_LEAF_ESCROW_TENANTS", "default")
	mux, store := custodyOpsMux(t)

	rec := postCustody(t, mux, "/api/v1/keys/leaf-escrow", map[string]string{
		"key_id":                 "leaf-web",
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "bravo-secret",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("opted-in deposit must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	bundle := rec.Body.Bytes()
	if bytes.Contains(bundle, []byte("PRIVATE KEY")) {
		t.Fatal("the escrow bundle must be ciphertext — it leaked a plaintext key block")
	}

	// Destroy the key, then recover it through the same ceremony.
	if err := store.Delete("leaf-web"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rec = postCustody(t, mux, "/api/v1/keys/leaf-escrow/recover", map[string]any{
		"bundle":                 json.RawMessage(bundle),
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "bravo-secret",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("recover must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := store.Signer("leaf-web"); err != nil {
		t.Fatalf("the key must be back in the store: %v", err)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("recovery response leaked key material")
	}
}

// Dual control must survive the route: one custodian is not enough, and
// two identical secrets are single control wearing a disguise.
func TestLeafEscrowEndpointEnforcesDualControl(t *testing.T) {
	t.Setenv("KRYPTKEEPER_LEAF_ESCROW_TENANTS", "default")
	mux, _ := custodyOpsMux(t)

	for name, body := range map[string]map[string]string{
		"single custodian": {"key_id": "leaf-web", "custodian_a_passphrase": "only-one"},
		"identical secrets": {"key_id": "leaf-web",
			"custodian_a_passphrase": "same-secret", "custodian_b_passphrase": "same-secret"},
	} {
		rec := postCustody(t, mux, "/api/v1/keys/leaf-escrow", body)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s must be refused, got 200", name)
		}
	}
}

func TestLeafEscrowEndpointRequiresAdmin(t *testing.T) {
	t.Setenv("KRYPTKEEPER_LEAF_ESCROW_TENANTS", "default")
	mux, _ := custodyOpsMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/keys/leaf-escrow", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
