// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package kmsgcp_test drives the real CloudKMSStore GCP path against the
// in-repo Cloud KMS wire-format emulator (run.sh builds and starts it and
// points KRYPTKEEPER_GCP_KMS_ENDPOINT at it). Skipped unless KK_LIVE_KMS_GCP=1.
package kmsgcp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestGCPKMSStoreAgainstEmulator(t *testing.T) {
	if os.Getenv("KK_LIVE_KMS_GCP") != "1" {
		t.Skip("set KK_LIVE_KMS_GCP=1 (see run.sh) to run against the Cloud KMS emulator")
	}
	if ep := os.Getenv("KRYPTKEEPER_GCP_KMS_ENDPOINT"); !strings.HasPrefix(ep, "http://127.0.0.1:") {
		t.Fatalf("KRYPTKEEPER_GCP_KMS_ENDPOINT=%q must be the loopback emulator; refusing to reach real GCP", ep)
	}
	store, err := keystore.NewCloudKMSStore("gcp")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("kryptkeeper gcp kms uat")
	suffix := time.Now().UnixNano() % 1_000_000_000

	for _, algo := range []keystore.Algorithm{keystore.ECDSAP256, keystore.ECDSAP384, keystore.RSA2048} {
		t.Run(string(algo), func(t *testing.T) {
			id := fmt.Sprintf("uat-%s-%d", strings.ToLower(string(algo)), suffix)
			if _, err := store.GenerateKey(id, algo); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signer, err := store.Signer(id)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			h := crypto.SHA256
			var d []byte
			if algo == keystore.ECDSAP384 {
				s := sha512.Sum384(msg)
				d, h = s[:], crypto.SHA384
			} else {
				s := sha256.Sum256(msg)
				d = s[:]
			}
			sig, err := signer.Sign(nil, d, h)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pub, d, sig) {
					t.Fatal("ECDSA signature did not verify against the returned public key")
				}
				d[0] ^= 1
				if ecdsa.VerifyASN1(pub, d, sig) {
					t.Fatal("signature verified over a tampered digest")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pub, h, d, sig); err != nil {
					t.Fatalf("RSA signature did not verify: %v", err)
				}
				d[0] ^= 1
				if rsa.VerifyPKCS1v15(pub, h, d, sig) == nil {
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
