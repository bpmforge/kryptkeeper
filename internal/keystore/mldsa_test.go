// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/rand"
	"testing"
)

func TestGenerateAndSignMLDSA44(t *testing.T) {
	store := newTestStore(t)
	meta, err := store.GenerateKey("mldsa44-test", MLDSA44)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-44: %v", err)
	}
	if meta.Algorithm != MLDSA44 {
		t.Errorf("expected ML-DSA-44, got %s", meta.Algorithm)
	}

	signer, err := store.Signer("mldsa44-test")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer.Public() == nil {
		t.Fatal("Public() returned nil")
	}

	msg := []byte("test message for ML-DSA-44 signing")
	sig, err := signer.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestGenerateAndSignMLDSA65(t *testing.T) {
	store := newTestStore(t)
	meta, err := store.GenerateKey("mldsa65-test", MLDSA65)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-65: %v", err)
	}
	if meta.Algorithm != MLDSA65 {
		t.Errorf("expected ML-DSA-65, got %s", meta.Algorithm)
	}

	signer, err := store.Signer("mldsa65-test")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	msg := []byte("test message for ML-DSA-65 signing")
	sig, err := signer.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestGenerateAndSignMLDSA87(t *testing.T) {
	store := newTestStore(t)
	meta, err := store.GenerateKey("mldsa87-test", MLDSA87)
	if err != nil {
		t.Fatalf("GenerateKey ML-DSA-87: %v", err)
	}
	if meta.Algorithm != MLDSA87 {
		t.Errorf("expected ML-DSA-87, got %s", meta.Algorithm)
	}

	signer, err := store.Signer("mldsa87-test")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	msg := []byte("test message for ML-DSA-87 signing")
	sig, err := signer.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestMLDSARoundTripEncryptDecrypt(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("mldsa-rt", MLDSA65); err != nil {
		t.Fatalf("generate: %v", err)
	}

	pub1, err := store.PublicKey("mldsa-rt")
	if err != nil {
		t.Fatalf("public key from original store: %v", err)
	}

	// New store instance — forces disk reload.
	store2, err := NewSoftwareStore(store.dir, store.passphrase)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	pub2, err := store2.PublicKey("mldsa-rt")
	if err != nil {
		t.Fatalf("public key after reload: %v", err)
	}

	// Both public keys should marshal to the same bytes.
	m1, ok1 := pub1.(MLDSAPublicKey)
	m2, ok2 := pub2.(MLDSAPublicKey)
	if !ok1 || !ok2 {
		t.Fatal("public keys are not MLDSAPublicKey")
	}

	b1, _ := m1.MarshalBinary()
	b2, _ := m2.MarshalBinary()
	if len(b1) != len(b2) {
		t.Fatalf("public key size mismatch: %d vs %d", len(b1), len(b2))
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			t.Fatal("public keys differ after round-trip")
		}
	}
}

func TestMLDSADetectAlgorithm(t *testing.T) {
	store := newTestStore(t)
	for _, algo := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		if _, err := store.GenerateKey(string(algo), algo); err != nil {
			t.Fatalf("generate %s: %v", algo, err)
		}
		meta, err := store.Metadata(string(algo))
		if err != nil {
			t.Fatalf("metadata %s: %v", algo, err)
		}
		if meta.Algorithm != algo {
			t.Errorf("detectAlgorithm %s: got %s", algo, meta.Algorithm)
		}
	}
}

func TestMLDSADuplicateKeyRejected(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("dup-mldsa", MLDSA65); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if _, err := store.GenerateKey("dup-mldsa", MLDSA65); err != ErrKeyExists {
		t.Fatalf("expected ErrKeyExists, got %v", err)
	}
}

func TestMLDSADeleteKey(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("del-mldsa", MLDSA65); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := store.Delete("del-mldsa"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Signer("del-mldsa"); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestMLDSAWrongPassphraseFailsDecryption(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("mldsa-wrongpass", MLDSA65); err != nil {
		t.Fatalf("generate: %v", err)
	}

	badStore, err := NewSoftwareStore(store.dir, []byte("wrong-passphrase-definitely!!"))
	if err != nil {
		t.Fatalf("create bad store: %v", err)
	}
	if _, err := badStore.Signer("mldsa-wrongpass"); err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestMLDSAListKeys(t *testing.T) {
	store := newTestStore(t)
	store.GenerateKey("k1", MLDSA44)
	store.GenerateKey("k2", MLDSA65)
	store.GenerateKey("k3", ECDSAP256)

	keys, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestIsMLDSA(t *testing.T) {
	cases := []struct {
		algo Algorithm
		want bool
	}{
		{MLDSA44, true},
		{MLDSA65, true},
		{MLDSA87, true},
		{ECDSAP256, false},
		{RSA2048, false},
		{Ed25519, false},
	}
	for _, tc := range cases {
		if got := IsMLDSA(tc.algo); got != tc.want {
			t.Errorf("IsMLDSA(%s) = %v, want %v", tc.algo, got, tc.want)
		}
	}
}
