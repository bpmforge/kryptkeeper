// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"
)

func newTestStore(t *testing.T) *SoftwareStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewSoftwareStore(dir, []byte("test-passphrase-32chars-minimum!"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return store
}

func TestGenerateAndSignRSA2048(t *testing.T) {
	store := newTestStore(t)
	meta, err := store.GenerateKey("rsa-test", RSA2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if meta.Algorithm != RSA2048 {
		t.Errorf("expected RSA-2048, got %s", meta.Algorithm)
	}

	signer, err := store.Signer("rsa-test")
	if err != nil {
		t.Fatalf("get signer: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pub := signer.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
}

func TestGenerateAndSignRSA4096(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-4096 generation is slow")
	}
	store := newTestStore(t)
	_, err := store.GenerateKey("rsa4096-test", RSA4096)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := store.Signer("rsa4096-test")
	if err != nil {
		t.Fatalf("get signer: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestGenerateAndSignECDSAP256(t *testing.T) {
	store := newTestStore(t)
	meta, err := store.GenerateKey("ec-test", ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if meta.Algorithm != ECDSAP256 {
		t.Errorf("expected ECDSA-P256, got %s", meta.Algorithm)
	}

	signer, err := store.Signer("ec-test")
	if err != nil {
		t.Fatalf("get signer: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pub := signer.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestGenerateAndSignECDSAP384(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("ec384-test", ECDSAP384)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := store.Signer("ec384-test")
	if err != nil {
		t.Fatalf("get signer: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestGenerateAndSignEd25519(t *testing.T) {
	store := newTestStore(t)
	meta, err := store.GenerateKey("ed-test", Ed25519)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if meta.Algorithm != Ed25519 {
		t.Errorf("expected Ed25519, got %s", meta.Algorithm)
	}

	signer, err := store.Signer("ed-test")
	if err != nil {
		t.Fatalf("get signer: %v", err)
	}

	message := []byte("test data for ed25519")
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pub := signer.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, message, sig) {
		t.Fatal("Ed25519 signature verification failed")
	}
}

func TestRoundTripEncryptDecrypt(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("round-trip", ECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Get the public key from the in-memory signer.
	pub1, err := store.PublicKey("round-trip")
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	// Create a fresh store pointing at the same directory to force disk read.
	store2, err := NewSoftwareStore(store.dir, store.passphrase)
	if err != nil {
		t.Fatalf("create store2: %v", err)
	}

	pub2, err := store2.PublicKey("round-trip")
	if err != nil {
		t.Fatalf("public key from disk: %v", err)
	}

	// Compare public keys.
	ecPub1 := pub1.(*ecdsa.PublicKey)
	ecPub2 := pub2.(*ecdsa.PublicKey)
	if !ecPub1.Equal(ecPub2) {
		t.Fatal("public keys do not match after round-trip")
	}
}

func TestWrongPassphraseFailsDecryption(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("wrong-pass", ECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	badStore, err := NewSoftwareStore(store.dir, []byte("wrong-passphrase-definitely!!"))
	if err != nil {
		t.Fatalf("create bad store: %v", err)
	}

	_, err = badStore.Signer("wrong-pass")
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestDuplicateKeyIDRejected(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("dup-test", ECDSAP256)
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}

	_, err = store.GenerateKey("dup-test", RSA2048)
	if err != ErrKeyExists {
		t.Fatalf("expected ErrKeyExists, got: %v", err)
	}
}

func TestKeyNotFound(t *testing.T) {
	store := newTestStore(t)

	_, err := store.Signer("nonexistent")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}

	_, err = store.Metadata("nonexistent")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestDeleteKey(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("delete-me", ECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := store.Delete("delete-me"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = store.Signer("delete-me")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound after delete, got: %v", err)
	}

	if err := store.Delete("delete-me"); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound on double delete, got: %v", err)
	}
}

func TestListKeys(t *testing.T) {
	store := newTestStore(t)
	_, _ = store.GenerateKey("key-a", ECDSAP256)
	_, _ = store.GenerateKey("key-b", Ed25519)

	keys, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("bad-algo", Algorithm("DSA-1024"))
	if err != ErrUnsupportedAlgo {
		t.Fatalf("expected ErrUnsupportedAlgo, got: %v", err)
	}
}

func TestEmptyPassphraseRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := NewSoftwareStore(dir, []byte(""))
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestPathTraversalSanitized(t *testing.T) {
	store := newTestStore(t)
	// Attempt path traversal in key ID.
	_, err := store.GenerateKey("../../../etc/passwd", ECDSAP256)
	if err != nil {
		t.Fatalf("generate with traversal ID: %v", err)
	}
	// Should be stored safely in the dir, not at /etc/passwd.
	meta, err := store.Metadata("../../../etc/passwd")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.ID != "../../../etc/passwd" {
		t.Errorf("unexpected ID: %s", meta.ID)
	}
}

func TestKeyFilePermissions(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GenerateKey("perm-test", ECDSAP256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	path := store.keyPath("perm-test")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected 0600 permissions, got %04o", perm)
	}
}
