// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package vault_test drives the real VaultStore against a Vault dev server
// (run.sh starts it in a container and enables the transit engine). Skipped
// unless KK_LIVE_VAULT=1.
package vault_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestVaultStoreAgainstDevServer(t *testing.T) {
	if os.Getenv("KK_LIVE_VAULT") != "1" {
		t.Skip("set KK_LIVE_VAULT=1 (see run.sh) to run against a Vault dev server")
	}
	store, err := keystore.NewVaultStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("kryptkeeper vault uat")
	suffix := time.Now().UnixNano() % 1_000_000_000

	for _, algo := range []keystore.Algorithm{keystore.ECDSAP256, keystore.ECDSAP384, keystore.RSA2048, keystore.Ed25519} {
		t.Run(string(algo), func(t *testing.T) {
			id := fmt.Sprintf("uat-%s-%d", algo, suffix)
			if _, err := store.GenerateKey(id, algo); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if _, err := store.GenerateKey(id, algo); !errors.Is(err, keystore.ErrKeyExists) {
				t.Fatalf("duplicate GenerateKey = %v, want ErrKeyExists", err)
			}
			signer, err := store.Signer(id)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			pub, err := store.PublicKey(id)
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}

			var sum []byte
			h := crypto.SHA256
			switch algo {
			case keystore.ECDSAP384:
				s := sha512.Sum384(msg)
				sum, h = s[:], crypto.SHA384
			default:
				s := sha256.Sum256(msg)
				sum = s[:]
			}

			switch pk := pub.(type) {
			case *ecdsa.PublicKey:
				sig, err := signer.Sign(nil, sum, h)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if !ecdsa.VerifyASN1(pk, sum, sig) {
					t.Fatal("ECDSA signature did not verify")
				}
				sum[0] ^= 1
				if ecdsa.VerifyASN1(pk, sum, sig) {
					t.Fatal("signature verified over a tampered digest")
				}
			case *rsa.PublicKey:
				sig, err := signer.Sign(nil, sum, h)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if err := rsa.VerifyPKCS1v15(pk, h, sum, sig); err != nil {
					t.Fatalf("RSA signature did not verify: %v", err)
				}
				sum[0] ^= 1
				if rsa.VerifyPKCS1v15(pk, h, sum, sig) == nil {
					t.Fatal("signature verified over a tampered digest")
				}
			case ed25519.PublicKey:
				// Ed25519 signs the message itself, not a digest.
				sig, err := signer.Sign(nil, msg, crypto.Hash(0))
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if !ed25519.Verify(pk, msg, sig) {
					t.Fatal("Ed25519 signature did not verify")
				}
				if ed25519.Verify(pk, append([]byte("x"), msg...), sig) {
					t.Fatal("signature verified over a different message")
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}

			if err := store.Delete(id); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := store.PublicKey(id); !errors.Is(err, keystore.ErrKeyNotFound) {
				t.Fatalf("PublicKey after Delete = %v, want ErrKeyNotFound", err)
			}
		})
	}
}
