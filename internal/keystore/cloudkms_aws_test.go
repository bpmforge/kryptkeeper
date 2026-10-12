// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"os"
	"testing"
)

// awsEndpoint returns the configured LocalStack endpoint, or skips the test.
func awsEndpoint(t *testing.T) string {
	t.Helper()
	ep := os.Getenv("AWS_ENDPOINT_URL")
	if ep == "" {
		t.Skip("AWS_ENDPOINT_URL not set — skipping LocalStack integration test")
	}
	return ep
}

func TestCloudKMSStore_AWS_GenerateAndSign(t *testing.T) {
	awsEndpoint(t)

	store, err := NewCloudKMSStore("aws")
	if err != nil {
		t.Fatalf("NewCloudKMSStore: %v", err)
	}

	meta, err := store.GenerateKey("test-key-1", ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if meta.ID != "test-key-1" {
		t.Errorf("meta.ID = %q, want %q", meta.ID, "test-key-1")
	}

	pub, err := store.PublicKey("test-key-1")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}

	signer, err := store.Signer("test-key-1")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer.Public() == nil {
		t.Fatal("signer.Public() is nil")
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}

func TestCloudKMSStore_AWS_DuplicateKey(t *testing.T) {
	awsEndpoint(t)

	store, err := NewCloudKMSStore("aws")
	if err != nil {
		t.Fatalf("NewCloudKMSStore: %v", err)
	}

	if _, err := store.GenerateKey("dup-key", ECDSAP256); err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}
	if _, err := store.GenerateKey("dup-key", ECDSAP256); err != ErrKeyExists {
		t.Fatalf("expected ErrKeyExists, got %v", err)
	}
}

func TestCloudKMSStore_AWS_RSA2048(t *testing.T) {
	awsEndpoint(t)

	store, err := NewCloudKMSStore("aws")
	if err != nil {
		t.Fatalf("NewCloudKMSStore: %v", err)
	}

	if _, err := store.GenerateKey("rsa-key", RSA2048); err != nil {
		t.Fatalf("GenerateKey RSA2048: %v", err)
	}

	signer, err := store.Signer("rsa-key")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	digest := make([]byte, 32)
	if _, err := signer.Sign(nil, digest, crypto.SHA256); err != nil {
		t.Fatalf("Sign RSA: %v", err)
	}
}

func TestCloudKMSStore_AWS_DeleteKey(t *testing.T) {
	awsEndpoint(t)

	store, err := NewCloudKMSStore("aws")
	if err != nil {
		t.Fatalf("NewCloudKMSStore: %v", err)
	}

	if _, err := store.GenerateKey("del-key", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.Delete("del-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete("del-key"); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestAwsKeySpec_UnsupportedAlgorithm(t *testing.T) {
	_, err := awsKeySpec(Ed25519)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
