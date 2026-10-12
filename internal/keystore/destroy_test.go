// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

// W9-07: destruction wipes what it claims to wipe, and cloud deletion
// destroys upstream BEFORE dropping the reference.

func TestZeroizeSignerWipesECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if key.D.Sign() == 0 {
		t.Fatal("test setup: D already zero")
	}
	if !ZeroizeSigner(key) {
		t.Fatal("ecdsa key not recognized")
	}
	if key.D.Sign() != 0 {
		t.Fatal("ecdsa D not wiped")
	}
}

func TestZeroizeSignerWipesRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if !ZeroizeSigner(key) {
		t.Fatal("rsa key not recognized")
	}
	if key.D.Sign() != 0 {
		t.Fatal("rsa D not wiped")
	}
	for i, prime := range key.Primes {
		if prime.Sign() != 0 {
			t.Fatalf("rsa prime %d not wiped", i)
		}
	}
}

func TestZeroizeSignerWipesEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if !ZeroizeSigner(priv) {
		t.Fatal("ed25519 key not recognized")
	}
	for i, b := range priv {
		if b != 0 {
			t.Fatalf("ed25519 byte %d not wiped", i)
		}
	}
}

type unknownSigner struct{ ecdsa.PrivateKey }

func TestZeroizeSignerLeavesUnknownTypesAlone(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapped := &unknownSigner{*key}
	if ZeroizeSigner(wrapped) {
		t.Fatal("unknown wrapper type must not claim a wipe")
	}
}

// The software store's Delete wipes the CACHED decrypted signer — the exact
// material os.Remove alone left live in memory.
func TestSoftwareDeleteZeroizesCachedSigner(t *testing.T) {
	store, err := NewSoftwareStore(t.TempDir(), []byte("destroy-test-passphrase-32bytes!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	if _, err := store.GenerateKey("doomed", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := store.Signer("doomed") // decrypts + caches
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ecdsaKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected signer type %T", signer)
	}
	before := new(big.Int).Set(ecdsaKey.D)
	if before.Sign() == 0 {
		t.Fatal("test setup: D already zero")
	}

	if err := store.Delete("doomed"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ecdsaKey.D.Sign() != 0 {
		t.Fatal("cached signer material survived Delete un-wiped")
	}
}

func TestSoftwareEvictSignerZeroizes(t *testing.T) {
	store, err := NewSoftwareStore(t.TempDir(), []byte("destroy-test-passphrase-32bytes!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	if _, err := store.GenerateKey("evicted", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, _ := store.Signer("evicted")
	ecdsaKey := signer.(*ecdsa.PrivateKey)

	store.EvictSigner("evicted")
	if ecdsaKey.D.Sign() != 0 {
		t.Fatal("evicted signer material not wiped")
	}
}

// Cloud delete destroys upstream FIRST; a provider refusal retains the
// reference — never lose the pointer to a live cloud key.
func TestCloudKMSDeleteDestroysUpstreamFirst(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fabricateEntry(t, store, "cloud-doomed", "arn:aws:kms:us-east-1:1:key/doomed")

	var destroyedURI string
	store.destroyKey = func(_ context.Context, cfg CloudKMSConfig) error {
		destroyedURI = cfg.KeyURI
		return nil
	}
	if err := store.Delete("cloud-doomed"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if destroyedURI != "arn:aws:kms:us-east-1:1:key/doomed" {
		t.Fatalf("provider destruction not invoked with the key URI: %q", destroyedURI)
	}
	if _, err := store.Metadata("cloud-doomed"); err == nil {
		t.Fatal("reference survived a successful destroy+delete")
	}
}

func TestCloudKMSDeleteRetainsReferenceWhenDestroyRefused(t *testing.T) {
	db := newCloudKMSTestDB(t)
	store, err := NewCloudKMSStoreWithDB("aws", db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fabricateEntry(t, store, "cloud-sticky", "arn:aws:kms:us-east-1:1:key/sticky")
	store.destroyKey = func(context.Context, CloudKMSConfig) error {
		return errors.New("kms says no")
	}

	if err := store.Delete("cloud-sticky"); err == nil {
		t.Fatal("delete must fail when the provider refuses destruction")
	}
	// The reference survives in memory AND on the row.
	if _, err := store.Metadata("cloud-sticky"); err != nil {
		t.Fatalf("reference lost despite refused destruction: %v", err)
	}
	reloaded, _ := NewCloudKMSStoreWithDB("aws", db, false)
	if _, err := reloaded.Metadata("cloud-sticky"); err != nil {
		t.Fatal("reference row lost despite refused destruction")
	}
}
