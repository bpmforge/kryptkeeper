// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package kmsazure_test drives the real CloudKMSStore Azure Key Vault path
// against the Lowkey Vault emulator (run.sh). The HTTP calls, JWK parsing and
// signature handling are the real code; only the vault is an emulator.
// Skipped unless KK_LIVE_KMS_AZURE=1.
package kmsazure_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"os"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

func TestAzureKMSStoreAgainstEmulator(t *testing.T) {
	if os.Getenv("KK_LIVE_KMS_AZURE") != "1" {
		t.Skip("set KK_LIVE_KMS_AZURE=1 (see run.sh) to run against Lowkey Vault")
	}
	if !strings.HasPrefix(os.Getenv("AZURE_KEYVAULT_URL"), "https://localhost") {
		t.Fatal("AZURE_KEYVAULT_URL must be the local emulator; refusing to touch a real vault")
	}
	store, err := keystore.NewCloudKMSStore("azure")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("kryptkeeper azure kms uat")
	sum256 := sha256.Sum256(msg)
	sum384 := sha512.Sum384(msg)

	cases := []struct {
		algo   keystore.Algorithm
		hash   crypto.Hash
		digest []byte
	}{
		{keystore.ECDSAP256, crypto.SHA256, sum256[:]},
		{keystore.ECDSAP384, crypto.SHA384, sum384[:]},
		{keystore.RSA2048, crypto.SHA256, sum256[:]},
	}
	for _, tc := range cases {
		t.Run(string(tc.algo), func(t *testing.T) {
			id := "uat-" + strings.ToLower(strings.ReplaceAll(string(tc.algo), "_", "-"))
			if _, err := store.GenerateKey(id, tc.algo); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signer, err := store.Signer(id)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			sig, err := signer.Sign(nil, tc.digest, tc.hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			tampered := append([]byte(nil), tc.digest...)
			tampered[0] ^= 1
			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				// crypto.Signer's contract for ECDSA is an ASN.1 DER signature.
				if !ecdsa.VerifyASN1(pub, tc.digest, sig) {
					t.Fatalf("ECDSA signature (%d bytes) is not a valid ASN.1 signature over the digest", len(sig))
				}
				if ecdsa.VerifyASN1(pub, tampered, sig) {
					t.Fatal("signature verified over a tampered digest")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pub, tc.hash, tc.digest, sig); err != nil {
					t.Fatalf("RSA signature did not verify: %v", err)
				}
				if rsa.VerifyPKCS1v15(pub, tc.hash, tampered, sig) == nil {
					t.Fatal("signature verified over a tampered digest")
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}
			if err := store.Delete(id); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := store.Signer(id); err == nil {
				t.Fatal("signer still resolvable after Delete")
			}
		})
	}
}
