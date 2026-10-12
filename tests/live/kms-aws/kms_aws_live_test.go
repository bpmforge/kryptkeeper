// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package kmsaws_test drives the real CloudKMSStore AWS path (aws-sdk-go-v2)
// against whatever KMS endpoint AWS_ENDPOINT_URL names. run.sh points it at a
// moto server container, so the SDK, request signing, CreateKey/GetPublicKey/
// Sign wire formats and the Delete (ScheduleKeyDeletion) path are the real
// code; only the service behind the socket is an emulator. Skipped unless
// KK_LIVE_KMS_AWS=1.
package kmsaws_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"kryptkeeper/internal/keystore"
)

func TestAWSKMSStoreAgainstEmulator(t *testing.T) {
	if os.Getenv("KK_LIVE_KMS_AWS") != "1" {
		t.Skip("set KK_LIVE_KMS_AWS=1 (see run.sh) to run against a KMS emulator")
	}
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Fatal("AWS_ENDPOINT_URL must point at the emulator; refusing to fall through to real AWS")
	}
	store, err := keystore.NewCloudKMSStore("aws")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("kryptkeeper kms uat"))

	for _, algo := range []keystore.Algorithm{keystore.ECDSAP256, keystore.ECDSAP384, keystore.RSA2048} {
		t.Run(string(algo), func(t *testing.T) {
			id := "uat-" + string(algo)
			if _, err := store.GenerateKey(id, algo); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signer, err := store.Signer(id)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			hash := crypto.SHA256
			d := digest[:]
			if algo == keystore.ECDSAP384 {
				s384 := crypto.SHA384.New()
				s384.Write([]byte("kryptkeeper kms uat"))
				d, hash = s384.Sum(nil), crypto.SHA384
			}
			sig, err := signer.Sign(nil, d, hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			// moto ignores MessageType=DIGEST and hashes the digest a second
			// time (real AWS KMS signs the digest as given). KK_KMS_EMULATOR_MOTO=1
			// makes this test verify over h(digest) for that emulator only;
			// it therefore proves wiring and wire formats, NOT DIGEST semantics.
			vd := func(b []byte) []byte {
				if os.Getenv("KK_KMS_EMULATOR_MOTO") != "1" {
					return b
				}
				h := hash.New()
				h.Write(b)
				return h.Sum(nil)
			}
			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pub, vd(d), sig) {
					t.Fatal("ECDSA signature from KMS did not verify against the returned public key")
				}
				d[0] ^= 1
				if ecdsa.VerifyASN1(pub, vd(d), sig) {
					t.Fatal("signature verified over a tampered digest")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pub, hash, vd(d), sig); err != nil {
					t.Fatalf("RSA signature did not verify: %v", err)
				}
				d[0] ^= 1
				if rsa.VerifyPKCS1v15(pub, hash, vd(d), sig) == nil {
					t.Fatal("signature verified over a tampered digest")
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}
			err = store.Delete(id)
			if os.Getenv("KK_KMS_EMULATOR_MOTO") == "1" {
				// moto answers ScheduleKeyDeletion with a 500 HTML traceback when
				// KeyId is an ARN (real AWS accepts ARNs). What this still proves
				// is the W9-07 contract: a refused destroy keeps the reference.
				if err == nil {
					t.Log("moto accepted ScheduleKeyDeletion this time; delete path covered")
					return
				}
				if _, serr := store.Signer(id); serr != nil {
					t.Fatalf("destroy refused but the key reference was dropped: %v", serr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := store.Signer(id); err == nil {
				t.Fatal("signer still resolvable after Delete")
			}
		})
	}
}
