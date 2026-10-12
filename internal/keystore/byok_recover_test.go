// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"testing"
)

// W17-12: plaintext recovery is the one sanctioned exception to "the
// Store exposes no plaintext export", so its dual-control gate and its
// exactness are what these pin.

func TestRecoverEscrowedKeyMaterialRoundTrips(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("byok-root", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, _ := store.Signer("byok-root")
	originalPub := signer.Public().(*ecdsa.PublicKey)

	bundle, err := EscrowKey(store, "byok-root", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}

	material, err := RecoverEscrowedKeyMaterial(bundle, passA, passB)
	if err != nil {
		t.Fatalf("recover material: %v", err)
	}
	defer zeroizeBytes(material)

	// It must be the REAL key: parse the DER and compare public halves.
	key, err := x509.ParsePKCS8PrivateKey(material)
	if err != nil {
		t.Fatalf("recovered material must be PKCS#8 DER: %v", err)
	}
	recovered, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected key type %T", key)
	}
	if recovered.PublicKey.X.Cmp(originalPub.X) != 0 || recovered.PublicKey.Y.Cmp(originalPub.Y) != 0 {
		t.Fatal("recovered material is not the escrowed key")
	}
}

// Dual control gates the plaintext path exactly as it gates every other
// recovery path — this is the guarantee that makes the exception
// acceptable.
func TestRecoverEscrowedKeyMaterialRequiresDualControl(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("byok-root2", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	bundle, err := EscrowKey(store, "byok-root2", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}

	if _, err := RecoverEscrowedKeyMaterial(bundle, passA, nil); err == nil {
		t.Fatal("a single custodian must not recover plaintext")
	}
	if _, err := RecoverEscrowedKeyMaterial(bundle, passA, passA); err == nil {
		t.Fatal("two identical secrets are single control and must be refused")
	}
	// A wrong second secret must fail, and must not disclose WHICH was wrong.
	_, err = RecoverEscrowedKeyMaterial(bundle, passA, []byte("wrong-custodian-b"))
	if err == nil {
		t.Fatal("a wrong custodian secret must not recover plaintext")
	}
	if bytes.Contains([]byte(err.Error()), []byte("custodian-b")) {
		t.Fatalf("the error must not echo a custodian secret: %v", err)
	}
}

func TestRecoverEscrowedKeyMaterialRejectsMalformedBundle(t *testing.T) {
	if _, err := RecoverEscrowedKeyMaterial([]byte(`{"schema_version":1}`), passA, passB); err == nil {
		t.Fatal("a bundle with no key id or shares must be refused")
	}
	if _, err := RecoverEscrowedKeyMaterial([]byte(`not json`), passA, passB); err == nil {
		t.Fatal("non-JSON must be refused")
	}
}

// The explicit dual-control precheck is NOT redundant with share
// decryption. A CRAFTED bundle whose two shares are both sealed under
// the SAME custodian secret would reconstruct fine from one secret —
// single control wearing a two-share disguise. The precheck is what
// refuses it before any share is opened.
func TestRecoverRefusesCraftedSingleSecretBundle(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("crafted", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Build a legitimate bundle, then re-seal BOTH shares under passA.
	legit, err := EscrowKey(store, "crafted", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}
	bundle, err := parseEscrowBundle(legit)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	shareA, err := openShare(bundle.KeyID, bundle.Shares[0], passA)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	shareB, err := openShare(bundle.KeyID, bundle.Shares[1], passB)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	resealedA, err := sealShare(bundle.KeyID, custodianSlotA, shareA, passA)
	if err != nil {
		t.Fatalf("reseal A: %v", err)
	}
	resealedB, err := sealShare(bundle.KeyID, custodianSlotB, shareB, passA) // same secret
	if err != nil {
		t.Fatalf("reseal B: %v", err)
	}
	bundle.Shares = []escrowShare{resealedA, resealedB}
	crafted, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Both shares now open under passA alone. Without the precheck this
	// would hand back the plaintext root to a single custodian.
	if _, err := RecoverEscrowedKeyMaterial(crafted, passA, passA); err == nil {
		t.Fatal("a crafted single-secret bundle must be refused — that is single control")
	}
}
