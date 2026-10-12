// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// testJWK is a fixed, syntactically-valid EC JWK used by the direct
// verifyExternalAccountBinding unit tests below. Its coordinates don't need
// to be a real on-curve point: verifyExternalAccountBinding only computes
// its RFC 7638 thumbprint from the JSON fields, it never reconstructs a
// crypto.PublicKey from them.
func testJWK(x string) *JSONWebKey {
	return &JSONWebKey{Kty: "EC", Crv: "P-256", X: x, Y: "dummy-y-value"}
}

func buildEAB(t *testing.T, kid string, macKey []byte, url string, jwk *JSONWebKey) *ExternalAccountBinding {
	t.Helper()
	protectedJSON, _ := json.Marshal(eabProtectedHeader{Alg: "HS256", KID: kid, URL: url})
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(jwkJSON)

	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protectedB64 + "." + payloadB64))

	return &ExternalAccountBinding{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
}

func TestVerifyExternalAccountBinding_Valid(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	if err := store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("save eab key: %v", err)
	}
	jwk := testJWK("account-key-x")
	thumbprint, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	eab := buildEAB(t, "kid-1", macKey, "https://hub.example.com/acme/new-account", jwk)

	if err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint); err != nil {
		t.Fatalf("expected valid EAB to verify, got: %v", err)
	}
}

func TestVerifyExternalAccountBinding_BadMAC(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "kid-1", []byte("wrong-key-entirely"), "https://hub.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected verification failure for wrong MAC key")
	}
}

func TestVerifyExternalAccountBinding_UnknownKID(t *testing.T) {
	store := NewMemStore()
	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "no-such-kid", []byte("whatever"), "https://hub.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestVerifyExternalAccountBinding_DisabledKey(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, Disabled: true, CreatedAt: time.Now().UTC()})

	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "kid-1", macKey, "https://hub.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected error for disabled key")
	}
}

func TestVerifyExternalAccountBinding_WrongURL(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	jwk := testJWK("account-key-x")
	thumbprint, _ := jwkThumbprint(jwk)
	eab := buildEAB(t, "kid-1", macKey, "https://attacker.example.com/acme/new-account", jwk)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", thumbprint)
	if err == nil {
		t.Fatal("expected error for url mismatch (replay to a different endpoint)")
	}
}

func TestVerifyExternalAccountBinding_WrongAlg(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	protectedJSON, _ := json.Marshal(eabProtectedHeader{Alg: "none", KID: "kid-1", URL: "https://hub.example.com/acme/new-account"})
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	eab := &ExternalAccountBinding{Protected: protectedB64, Payload: payloadB64, Signature: base64.RawURLEncoding.EncodeToString([]byte("x"))}

	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", "irrelevant-thumbprint")
	if err == nil {
		t.Fatal("expected error for unsupported alg")
	}
}

func TestVerifyExternalAccountBinding_Missing(t *testing.T) {
	store := NewMemStore()
	if err := verifyExternalAccountBinding(store, nil, "https://hub.example.com/acme/new-account", "irrelevant-thumbprint"); err == nil {
		t.Fatal("expected error for missing EAB")
	}
}

// TestVerifyExternalAccountBinding_PayloadKeyMismatch proves the G-44
// anti-replay fix: an externalAccountBinding value that is otherwise
// perfectly valid (right kid, right url, right MAC) must still be rejected
// if its payload JWK isn't the key of the account actually presenting it.
func TestVerifyExternalAccountBinding_PayloadKeyMismatch(t *testing.T) {
	store := NewMemStore()
	macKey := []byte("super-secret-mac-key-material")
	store.SaveEABKey(&EABKey{KID: "kid-1", MACKey: macKey, CreatedAt: time.Now().UTC()})

	victimJWK := testJWK("victim-key-x")
	attackerJWK := testJWK("attacker-key-x")
	attackerThumbprint, _ := jwkThumbprint(attackerJWK)

	// eab is validly HMAC-signed and bound (in payload) to victimJWK, but the
	// caller presenting it (per its outer account JWS) is attackerJWK.
	eab := buildEAB(t, "kid-1", macKey, "https://hub.example.com/acme/new-account", victimJWK)
	err := verifyExternalAccountBinding(store, eab, "https://hub.example.com/acme/new-account", attackerThumbprint)
	if err == nil {
		t.Fatal("expected error: eab payload is bound to a different account key")
	}
}

func TestEABConfigFromEnv(t *testing.T) {
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	macKeyB64 := base64.RawURLEncoding.EncodeToString([]byte("some-mac-key"))
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"kid-1":"`+macKeyB64+`"}`)

	cfg, err := eabConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.required {
		t.Error("expected required=true")
	}
	if len(cfg.seedKeys) != 1 || cfg.seedKeys[0].KID != "kid-1" {
		t.Fatalf("expected 1 seed key kid-1, got %+v", cfg.seedKeys)
	}
}

func TestEABConfigFromEnv_InvalidJSON(t *testing.T) {
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `not-json`)
	if _, err := eabConfigFromEnv(); err == nil {
		t.Fatal("expected error for invalid APP_ACME_EAB_KEYS_JSON")
	}
}

func TestACMENewAccountEABRequired(t *testing.T) {
	macKey := []byte("super-secret-mac-key-material-32")
	macKeyB64 := base64.RawURLEncoding.EncodeToString(macKey)
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"kid-1":"`+macKeyB64+`"}`)

	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMETestClient(t)

	// Without EAB: rejected.
	payload, _ := json.Marshal(map[string]any{"contact": []string{"mailto:a@example.com"}, "termsOfServiceAgreed": true})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without EAB, got %d", resp.StatusCode)
	}

	// With a valid EAB bound to this account's own key: accepted, and the
	// binding is recorded.
	eab := buildEAB(t, "kid-1", macKey, srv.baseURL+"/acme/new-account", client.jwk)
	payload2, _ := json.Marshal(map[string]any{
		"contact":                []string{"mailto:a@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eab,
	})
	resp2 := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 201 with valid EAB, got %d: %s", resp2.StatusCode, b)
	}

	var acct Account
	if err := json.NewDecoder(resp2.Body).Decode(&acct); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	mem, ok := srv.store.(*MemStore)
	if !ok {
		t.Fatal("expected MemStore")
	}
	if kid := mem.accountEAB[acct.ID]; kid != "kid-1" {
		t.Fatalf("expected account bound to kid-1, got %q", kid)
	}
}

// TestACMENewAccountEABReplayRejected proves acceptance criterion 2's
// closed replay gap end-to-end: an externalAccountBinding value captured
// for one account's key cannot be replayed by a different account key.
func TestACMENewAccountEABReplayRejected(t *testing.T) {
	macKey := []byte("super-secret-mac-key-material-32")
	macKeyB64 := base64.RawURLEncoding.EncodeToString(macKey)
	t.Setenv("APP_ACME_EAB_REQUIRED", "true")
	t.Setenv("APP_ACME_EAB_KEYS_JSON", `{"kid-1":"`+macKeyB64+`"}`)

	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	victim := newACMETestClient(t)
	eab := buildEAB(t, "kid-1", macKey, srv.baseURL+"/acme/new-account", victim.jwk) // bound to victim's key

	attacker := newACMETestClient(t) // a different keypair entirely
	payload, _ := json.Marshal(map[string]any{
		"contact":                []string{"mailto:attacker@example.com"},
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eab, // replayed, still bound to victim.jwk
	})
	resp := attacker.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected replayed EAB (bound to a different account key) to be rejected, got %d", resp.StatusCode)
	}
}

func TestACMENewAccountEABOptionalByDefault(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMETestClient(t)
	payload, _ := json.Marshal(map[string]any{"contact": []string{"mailto:a@example.com"}, "termsOfServiceAgreed": true})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when EAB is not required, got %d", resp.StatusCode)
	}
}
