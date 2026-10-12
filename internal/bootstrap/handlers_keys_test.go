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

// W9-05: the keys API enforces the generation policy — the exact surface
// that previously passed any algorithm straight through (G-42).

func newKeysTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	return newKeysTestMuxWithBackend(t, "")
}

// newKeysTestMuxWithBackend lets W19-19's PQC-on-HSM tests inject a backend
// label ("pkcs11") without any package-level state -- keyBackend is a plain
// constructor argument all the way down to registerKeyHandlers.
func newKeysTestMuxWithBackend(t *testing.T, keyBackend string) *http.ServeMux {
	t.Helper()
	t.Setenv("KRYPTKEEPER_KEY_DUAL_CONTROL", "false") // D-122: default is ON; these tests cover the direct path
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("keys-policy-test-passphrase-32b!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, auth, keys, stubAuditProvider{}, keyBackend)
	return mux
}

func postKeyGenerate(t *testing.T, mux *http.ServeMux, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestKeyGenerateRefusesBelowFloorWithCitedRule(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "weak-ca-key", "algorithm": "RSA-2048", "purpose": "ca",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 policy refusal, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "min_rsa_bits") {
		t.Fatalf("refusal must cite the rule, got: %s", rec.Body.String())
	}
}

func TestKeyGenerateAllowsPolicyCompliantRequest(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "good-key", "algorithm": "ECDSA-P256",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKeyGenerateRefusesUnknownAlgorithmAtThePolicy(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "des-key", "algorithm": "DES",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allowed_algorithms") {
		t.Fatalf("refusal must cite the rule, got: %s", rec.Body.String())
	}
}

// TestKeyGenerateRefusesPQCOnHSMBackendWithADRReference covers W19-19: the
// UAT (W19-08) observed a bare 503 with no explanation and, worse, no way to
// tell it apart from a real backend outage. The refusal must be a 422 that
// names the ADR and creates no token object.
func TestKeyGenerateRefusesPQCOnHSMBackendWithADRReference(t *testing.T) {
	mux := newKeysTestMuxWithBackend(t, "pkcs11")

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "pqc-key", "algorithm": string(keystore.MLDSA65),
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md") {
		t.Fatalf("refusal must cite the ADR, got: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "software-keystore-only") {
		t.Fatalf("refusal must say PQC keys are software-keystore-only, got: %s", rec.Body.String())
	}

	// No token object: the key must not exist in the underlying store.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/keys/pqc-key", nil)
	getReq.Header.Set("Authorization", "Bearer test-token")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("expected the refused key to not exist, got %d: %s", getRec.Code, getRec.Body.String())
	}
}

// TestKeyGenerateAllowsPQCOnSoftwareBackend proves the refusal is
// backend-scoped, not algorithm-scoped: PQC on the software backend
// (the default/empty activeKeyBackend) still succeeds.
func TestKeyGenerateAllowsPQCOnSoftwareBackend(t *testing.T) {
	mux := newKeysTestMux(t)

	rec := postKeyGenerate(t, mux, map[string]string{
		"id": "pqc-software-key", "algorithm": string(keystore.MLDSA65),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}
