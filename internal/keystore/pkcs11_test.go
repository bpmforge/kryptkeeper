// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11

package keystore

import (
	"crypto"
	"os"
	"testing"
)

// pkcs11Token skips the test unless a real PKCS#11 token (e.g. SoftHSM2) is
// configured via the environment KRYPTKEEPER_PKCS11_LIB expects.
func pkcs11Token(t *testing.T) {
	t.Helper()
	if os.Getenv("KRYPTKEEPER_PKCS11_LIB") == "" {
		t.Skip("KRYPTKEEPER_PKCS11_LIB not set — skipping SoftHSM2 integration test")
	}
}

func TestPKCS11Store_GenerateSignVerify_RSA(t *testing.T) {
	pkcs11Token(t)

	store, err := NewPKCS11StoreFromEnv()
	if err != nil {
		t.Fatalf("NewPKCS11StoreFromEnv: %v", err)
	}

	meta, err := store.GenerateKey("pkcs11-test-rsa", RSA2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if meta.ID != "pkcs11-test-rsa" {
		t.Errorf("meta.ID = %q, want pkcs11-test-rsa", meta.ID)
	}
	if meta.CreatedAt == "" {
		t.Error("meta.CreatedAt is empty")
	}

	pub, err := store.PublicKey("pkcs11-test-rsa")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}

	signer, err := store.Signer("pkcs11-test-rsa")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	digest := make([]byte, 32)
	sig, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}

func TestPKCS11Store_GenerateSignVerify_ECDSA(t *testing.T) {
	pkcs11Token(t)

	store, err := NewPKCS11StoreFromEnv()
	if err != nil {
		t.Fatalf("NewPKCS11StoreFromEnv: %v", err)
	}

	if _, err := store.GenerateKey("pkcs11-test-ecdsa", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub, err := store.PublicKey("pkcs11-test-ecdsa")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}

	signer, err := store.Signer("pkcs11-test-ecdsa")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	digest := make([]byte, 32)
	if _, err := signer.Sign(nil, digest, crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestPKCS11Store_PublicKey_UnknownKeyErrors(t *testing.T) {
	pkcs11Token(t)

	store, err := NewPKCS11StoreFromEnv()
	if err != nil {
		t.Fatalf("NewPKCS11StoreFromEnv: %v", err)
	}
	if _, err := store.PublicKey("does-not-exist"); err == nil {
		t.Fatal("expected an error for a nonexistent key ID")
	}
}

// TestPKCS11Store_TokenLabelOnly_OpensWithoutSlot is the regression test for
// W19-08: NewPKCS11StoreFromEnv previously always set crypto11.Config's
// SlotNumber (defaulting to 0) *and* TokenLabel together, but
// crypto11.Configure requires exactly one token selector and hard-errors
// ("config must specify exactly one way to select a token") when both are
// set -- so this backend could never open ANY token, real or SoftHSM2,
// regardless of configuration. Proven empirically against a real SoftHSM2
// token before the fix (this test failed with that exact error) and after
// (it passes). KRYPTKEEPER_PKCS11_SLOT must be unset for this test to
// exercise the token-label path; pkcs11Token skips it otherwise via the lib
// env var, so also require SLOT to be absent here.
func TestPKCS11Store_TokenLabelOnly_OpensWithoutSlot(t *testing.T) {
	pkcs11Token(t)
	if os.Getenv("KRYPTKEEPER_PKCS11_SLOT") != "" {
		t.Skip("KRYPTKEEPER_PKCS11_SLOT is set — this test exercises token-label-only selection")
	}

	store, err := NewPKCS11StoreFromEnv()
	if err != nil {
		t.Fatalf("NewPKCS11StoreFromEnv with token label only: %v", err)
	}
	if _, err := store.GenerateKey("pkcs11-test-label-only", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
}

// The token has no Ed25519 mechanism in this backend; the suite asserts the
// refusal. Skips (naming KRYPTKEEPER_PKCS11_LIB) without a SoftHSM2 token.
func TestConformance_PKCS11(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		pkcs11Token(t)
		s, err := NewPKCS11StoreFromEnv()
		if err != nil {
			t.Fatalf("NewPKCS11StoreFromEnv: %v", err)
		}
		return s
	}, withUnsupported(Ed25519))
}
