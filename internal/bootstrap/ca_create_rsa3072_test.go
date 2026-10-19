// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

func TestParseAlgorithmAcceptsRSA3072Spellings(t *testing.T) {
	for _, in := range []string{"RSA-3072", "rsa3072", "RSA_3072"} {
		got, err := parseAlgorithm(in)
		if err != nil || got != keystore.RSA3072 {
			t.Errorf("parseAlgorithm(%q) = %q, %v", in, got, err)
		}
	}
}

func TestCASupportedAlgorithmSetIsNine(t *testing.T) {
	want := []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096", "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
	if !slices.Equal(caSupportedAlgorithms, want) {
		t.Fatalf("caSupportedAlgorithms = %v", caSupportedAlgorithms)
	}
	for _, a := range want {
		if _, err := parseAlgorithm(a); err != nil {
			t.Errorf("parseAlgorithm(%q): %v", a, err)
		}
	}
}

func TestCreateCAHandlerRSA3072HierarchyVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-3072 generation is slow")
	}
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	engine := newSoftwareEngine(t)
	mux := http.NewServeMux()
	registerCAHandlers(mux, auth, NewEngineCAProvider(engine), NewTenantStoreFromEnv(), stubAuditProviderForCA{})

	post := func(body string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cas", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	idOf := func(raw string) string {
		var r struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		return r.Data.ID
	}

	code, body := post(`{"type":"root","algorithm":"RSA-3072","subject_cn":"R3072 Root"}`)
	if code != http.StatusCreated {
		t.Fatalf("root: %d %s", code, body)
	}
	rootID := idOf(body)
	code, body = post(`{"type":"intermediate","algorithm":"RSA-3072","subject_cn":"R3072 Issuing","parent_ca_id":"` + rootID + `"}`)
	if code != http.StatusCreated {
		t.Fatalf("intermediate: %d %s", code, body)
	}

	root, err := engine.GetCA(rootID)
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := root.Certificate.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() != 3072 {
		t.Fatalf("root key = %T", root.Certificate.PublicKey)
	}

	// Full root+issuing+leaf chain, x509.Verify and openssl verify.
	r, i := verifyHierarchy(t, keystore.RSA3072)
	if pub, ok := i.Certificate.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() != 3072 || r.Certificate == nil {
		t.Fatalf("issuing key = %T", i.Certificate.PublicKey)
	}

	code, body = post(`{"type":"root","algorithm":"DSA","subject_cn":"x"}`)
	if code != http.StatusBadRequest || !strings.Contains(body, `"RSA-3072"`) {
		t.Fatalf("400 body must list RSA-3072: %d %s", code, body)
	}
}
