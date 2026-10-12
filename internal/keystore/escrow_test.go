// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

// W9-12: escrow under dual control — both custodians or nothing.

func newEscrowTestStore(t *testing.T) *SoftwareStore {
	t.Helper()
	store, err := NewSoftwareStore(t.TempDir(), []byte("escrow-test-passphrase-32-bytes!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

var (
	passA = []byte("custodian-alpha-passphrase")
	passB = []byte("custodian-bravo-passphrase")
)

// TestEscrowRecoveryDrill is the EXECUTED recovery drill required by the
// ticket: escrow → destroy → dual-control recover → sign and verify
// against the pre-escrow public key. Documented in
// docs/board/specs/W9-12.md.
func TestEscrowRecoveryDrill(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("drill-ca", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := store.Signer("drill-ca")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	originalPub := signer.Public().(*ecdsa.PublicKey)

	bundle, err := EscrowKey(store, "drill-ca", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}

	if err := store.Delete("drill-ca"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Signer("drill-ca"); err == nil {
		t.Fatal("key still present after destruction — drill precondition broken")
	}

	id, err := RecoverEscrowedKey(store, bundle, passA, passB)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if id != "drill-ca" {
		t.Fatalf("recovered under wrong id %q", id)
	}

	recovered, err := store.Signer("drill-ca")
	if err != nil {
		t.Fatalf("recovered signer: %v", err)
	}
	digest := sha256.Sum256([]byte("post-recovery signing drill"))
	sig, err := recovered.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(originalPub, digest[:], sig) {
		t.Fatal("recovered key signature does not verify against the pre-escrow public key")
	}
}

func TestEscrowRefusesIdenticalCustodianPassphrases(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("k", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := EscrowKey(store, "k", passA, passA); err == nil {
		t.Fatal("identical custodian passphrases must be refused")
	}
	if _, err := EscrowKey(store, "k", nil, passB); err == nil {
		t.Fatal("empty custodian passphrase must be refused")
	}
}

func TestEscrowRecoveryRequiresBothCustodians(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("dual", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	bundle, err := EscrowKey(store, "dual", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}
	if err := store.Delete("dual"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Wrong B: fails, names slot B, key stays absent.
	_, err = RecoverEscrowedKey(store, bundle, passA, []byte("not-bravo"))
	if err == nil {
		t.Fatal("recovery with one wrong passphrase must fail")
	}
	if !strings.Contains(err.Error(), "custodian B") {
		t.Fatalf("refusal must name the failing slot, got: %v", err)
	}
	if _, serr := store.Signer("dual"); serr == nil {
		t.Fatal("key must not exist after failed recovery")
	}

	// Wrong A: names slot A.
	_, err = RecoverEscrowedKey(store, bundle, []byte("not-alpha"), passB)
	if err == nil || !strings.Contains(err.Error(), "custodian A") {
		t.Fatalf("expected custodian A refusal, got: %v", err)
	}

	// Swapped passphrases are NOT equivalent to having both: each share is
	// bound to its slot.
	if _, err := RecoverEscrowedKey(store, bundle, passB, passA); err == nil {
		t.Fatal("swapped custodian passphrases must not recover")
	}
}

func TestEscrowTamperedBundleFailsClosed(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("tamper", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	bundle, err := EscrowKey(store, "tamper", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}
	if err := store.Delete("tamper"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Re-pointing the bundle at a different key id breaks the AAD binding.
	var parsed EscrowBundle
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsed.KeyID = "some-other-key"
	retargeted, _ := json.Marshal(parsed)
	if _, err := RecoverEscrowedKey(store, retargeted, passA, passB); err == nil {
		t.Fatal("bundle re-targeted at another key id must fail the AAD check")
	}

	// A flipped ciphertext byte fails GCM authentication.
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	ct := []byte(parsed.Shares[0].Ciphertext)
	if ct[0] == 'f' {
		ct[0] = '0'
	} else {
		ct[0] = 'f'
	}
	parsed.Shares[0].Ciphertext = string(ct)
	corrupted, _ := json.Marshal(parsed)
	if _, err := RecoverEscrowedKey(store, corrupted, passA, passB); err == nil {
		t.Fatal("corrupted share ciphertext must fail recovery")
	}
}
