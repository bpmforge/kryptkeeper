// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import "testing"

// Metadata runs on every issuance; once the signer is cached it must not pay
// for another Argon2id derivation (64 MiB). A wrong passphrase makes any
// re-decrypt fail, so success proves the cache was used.
func TestMetadataUsesCachedSignerWithoutRedecrypt(t *testing.T) {
	store := newTestStore(t)
	algos := []Algorithm{ECDSAP256, ECDSAP384, RSA2048, Ed25519}
	for _, algo := range algos {
		id := "cached-" + string(algo)
		if _, err := store.GenerateKey(id, algo); err != nil {
			t.Fatalf("generate %s: %v", algo, err)
		}
		if _, err := store.Signer(id); err != nil {
			t.Fatalf("signer %s: %v", algo, err)
		}
	}
	store.passphrase = []byte("wrong-passphrase-wrong-passphrase")
	for _, algo := range algos {
		meta, err := store.Metadata("cached-" + string(algo))
		if err != nil {
			t.Fatalf("metadata %s re-decrypted instead of using cache: %v", algo, err)
		}
		if meta.Algorithm != algo {
			t.Errorf("got %s want %s", meta.Algorithm, algo)
		}
	}
}
