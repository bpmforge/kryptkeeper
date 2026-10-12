// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

// W9-12: the escrow API — dual control enforced end-to-end through the
// HTTP surface, both custodians or nothing.

func newEscrowTestMux(t *testing.T) (*http.ServeMux, keystore.Store) {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("escrow-http-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProvider{}, "")
	registerKeyEscrowHandlers(mux, auth, keys, stubAuditProvider{})
	return mux, keys
}

func postEscrowJSON(t *testing.T, mux *http.ServeMux, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestEscrowEndpointRoundTrip(t *testing.T) {
	mux, keys := newEscrowTestMux(t)
	if _, err := keys.GenerateKey("api-ca", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}

	rec := postEscrowJSON(t, mux, "/api/v1/keys/escrow", map[string]any{
		"key_id":                 "api-ca",
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "bravo-secret",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("escrow: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var bundle keystore.EscrowBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("bundle parse: %v", err)
	}
	if bundle.KeyID != "api-ca" || len(bundle.Shares) != 2 {
		t.Fatalf("malformed bundle: %+v", bundle)
	}

	if err := keys.Delete("api-ca"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rec = postEscrowJSON(t, mux, "/api/v1/keys/escrow/recover", map[string]any{
		"bundle":                 json.RawMessage(rec.Body.Bytes()),
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "bravo-secret",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("recover: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := keys.Signer("api-ca"); err != nil {
		t.Fatalf("key not usable after API recovery: %v", err)
	}
}

func TestEscrowRecoverEndpointRefusesSingleCustodian(t *testing.T) {
	mux, keys := newEscrowTestMux(t)
	if _, err := keys.GenerateKey("solo", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	rec := postEscrowJSON(t, mux, "/api/v1/keys/escrow", map[string]any{
		"key_id":                 "solo",
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "bravo-secret",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("escrow: %d: %s", rec.Code, rec.Body.String())
	}
	bundleRaw := append([]byte(nil), rec.Body.Bytes()...)
	if err := keys.Delete("solo"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rec = postEscrowJSON(t, mux, "/api/v1/keys/escrow/recover", map[string]any{
		"bundle":                 json.RawMessage(bundleRaw),
		"custodian_a_passphrase": "alpha-secret",
		"custodian_b_passphrase": "wrong",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for single-custodian recovery, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "custodian B") {
		t.Fatalf("refusal must name the failing slot, got: %s", rec.Body.String())
	}
	if _, err := keys.Signer("solo"); err == nil {
		t.Fatal("key must not exist after refused recovery")
	}
}

func TestEscrowEndpointRefusesIdenticalPassphrases(t *testing.T) {
	mux, keys := newEscrowTestMux(t)
	if _, err := keys.GenerateKey("same", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	rec := postEscrowJSON(t, mux, "/api/v1/keys/escrow", map[string]any{
		"key_id":                 "same",
		"custodian_a_passphrase": "one-secret",
		"custodian_b_passphrase": "one-secret",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for identical passphrases, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEscrowEndpointRequiresAuth(t *testing.T) {
	mux, _ := newEscrowTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/escrow", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}
}
