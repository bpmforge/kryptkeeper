// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11

package keystore

import (
	"crypto"
	"crypto/rsa"
	"testing"
)

func TestPKCS11Store_GenerateSignVerify_RSA3072(t *testing.T) {
	pkcs11Token(t)

	store, err := NewPKCS11StoreFromEnv()
	if err != nil {
		t.Fatalf("NewPKCS11StoreFromEnv: %v", err)
	}
	if _, err := store.GenerateKey("pkcs11-test-rsa3072", RSA3072); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := store.PublicKey("pkcs11-test-rsa3072")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok || rsaPub.N.BitLen() != 3072 {
		t.Fatalf("public key = %T", pub)
	}
	signer, err := store.Signer("pkcs11-test-rsa3072")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	digest := make([]byte, 32)
	sig, err := signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	meta, err := store.Metadata("pkcs11-test-rsa3072")
	if err != nil || meta.Algorithm != RSA3072 {
		t.Fatalf("Metadata = %v, %v", meta.Algorithm, err)
	}
}
