// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// W9-12 (D-051/FR-P13): key escrow under dual control. The key is exported
// through the store's own backup envelope under a random inner secret; the
// secret is 2-of-2 XOR-split, one share per custodian. One share alone is a
// one-time pad — recovery without both passphrases is mathematically
// impossible, not merely policy-refused.

const escrowSchemaVersion = 1

const (
	custodianSlotA = "A"
	custodianSlotB = "B"
)

// escrowShare is one custodian's encrypted share of the inner secret.
type escrowShare struct {
	Slot       string `json:"slot"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// EscrowBundle is the JSON artifact escrow produces and recovery consumes.
// Everything in it is ciphertext under dual custody.
type EscrowBundle struct {
	SchemaVersion int           `json:"schema_version"`
	KeyID         string        `json:"key_id"`
	CreatedAt     string        `json:"created_at"`
	WrappedKeyPEM string        `json:"wrapped_key_pem"`
	Shares        []escrowShare `json:"shares"`
}

// shareAAD binds a share ciphertext to its bundle and slot so envelopes
// cannot be swapped between bundles or between custodians.
func shareAAD(keyID, slot string) []byte {
	return []byte("kryptkeeper-escrow-v1|" + keyID + "|" + slot)
}

func sealShare(keyID, slot string, share, passphrase []byte) (escrowShare, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return escrowShare{}, fmt.Errorf("escrow salt: %w", err)
	}
	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return escrowShare{}, fmt.Errorf("escrow cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return escrowShare{}, fmt.Errorf("escrow gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return escrowShare{}, fmt.Errorf("escrow nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, share, shareAAD(keyID, slot))
	return escrowShare{
		Slot:       slot,
		Salt:       hex.EncodeToString(salt),
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}, nil
}

func openShare(keyID string, es escrowShare, passphrase []byte) ([]byte, error) {
	salt, err := hexDecode(es.Salt, saltLen)
	if err != nil {
		return nil, fmt.Errorf("escrow share %s salt: %w", es.Slot, err)
	}
	nonce, err := hexDecode(es.Nonce, nonceLen)
	if err != nil {
		return nil, fmt.Errorf("escrow share %s nonce: %w", es.Slot, err)
	}
	ct, err := hex.DecodeString(es.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("escrow share %s ciphertext: %w", es.Slot, err)
	}
	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("escrow cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("escrow gcm: %w", err)
	}
	share, err := gcm.Open(nil, nonce, ct, shareAAD(keyID, es.Slot))
	if err != nil {
		// The slot name is for the operator mid-drill; never key material.
		return nil, fmt.Errorf("custodian %s passphrase failed: %w", es.Slot, ErrDecryptionFailed)
	}
	return share, nil
}

// EscrowKey exports key id from store under a random inner secret and
// splits that secret between two custodians. Identical passphrases are
// refused — two copies of one secret is single control.
func EscrowKey(store Store, id string, custodianA, custodianB []byte) ([]byte, error) {
	if len(custodianA) == 0 || len(custodianB) == 0 {
		return nil, fmt.Errorf("escrow requires both custodian passphrases")
	}
	if subtle.ConstantTimeCompare(custodianA, custodianB) == 1 {
		return nil, fmt.Errorf("escrow custodian passphrases must differ — dual control requires two secrets")
	}

	inner := make([]byte, argon2KeyLen)
	if _, err := io.ReadFull(rand.Reader, inner); err != nil {
		return nil, fmt.Errorf("escrow inner secret: %w", err)
	}
	innerPass := []byte(hex.EncodeToString(inner))
	defer zeroizeBytes(inner)
	defer zeroizeBytes(innerPass)

	wrapped, err := store.ExportEncryptedKey(id, innerPass)
	if err != nil {
		return nil, fmt.Errorf("escrow export: %w", err)
	}

	shareA := make([]byte, len(inner))
	if _, err := io.ReadFull(rand.Reader, shareA); err != nil {
		return nil, fmt.Errorf("escrow share: %w", err)
	}
	shareB := make([]byte, len(inner))
	for i := range inner {
		shareB[i] = inner[i] ^ shareA[i]
	}
	defer zeroizeBytes(shareA)
	defer zeroizeBytes(shareB)

	sealedA, err := sealShare(id, custodianSlotA, shareA, custodianA)
	if err != nil {
		return nil, err
	}
	sealedB, err := sealShare(id, custodianSlotB, shareB, custodianB)
	if err != nil {
		return nil, err
	}

	bundle := EscrowBundle{
		SchemaVersion: escrowSchemaVersion,
		KeyID:         id,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		WrappedKeyPEM: string(wrapped),
		Shares:        []escrowShare{sealedA, sealedB},
	}
	return json.Marshal(bundle)
}

// RecoverEscrowedKey rebuilds the inner secret from both custodian shares
// and imports the wrapped key back into store under its original ID. It
// returns the recovered key's ID.
func RecoverEscrowedKey(store Store, bundleJSON, custodianA, custodianB []byte) (string, error) {
	bundle, err := parseEscrowBundle(bundleJSON)
	if err != nil {
		return "", err
	}

	innerPass, err := recoverInnerPassphrase(bundle, custodianA, custodianB)
	if err != nil {
		return "", err
	}
	defer zeroizeBytes(innerPass)

	if err := store.ImportEncryptedKey(bundle.KeyID, []byte(bundle.WrappedKeyPEM), innerPass); err != nil {
		return "", fmt.Errorf("escrow recover import: %w", err)
	}
	return bundle.KeyID, nil
}

// parseEscrowBundle validates the bundle envelope shared by every
// recovery path.
func parseEscrowBundle(bundleJSON []byte) (EscrowBundle, error) {
	var bundle EscrowBundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return bundle, fmt.Errorf("escrow bundle parse: %w", err)
	}
	if bundle.SchemaVersion != escrowSchemaVersion {
		return bundle, fmt.Errorf("escrow bundle schema %d not supported", bundle.SchemaVersion)
	}
	if bundle.KeyID == "" || len(bundle.Shares) != 2 {
		return bundle, fmt.Errorf("escrow bundle malformed: key id and exactly two shares required")
	}
	return bundle, nil
}

// recoverInnerPassphrase XORs both custodian shares back into the inner
// secret. ONE implementation of this primitive, shared by every recovery
// path — two would be two chances to get dual control wrong.
//
// The caller owns the returned passphrase and MUST zeroize it.
func recoverInnerPassphrase(bundle EscrowBundle, custodianA, custodianB []byte) ([]byte, error) {
	byCustodian := map[string][]byte{custodianSlotA: custodianA, custodianSlotB: custodianB}
	inner := make([]byte, argon2KeyLen)
	seen := map[string]bool{}
	for _, es := range bundle.Shares {
		pass, ok := byCustodian[es.Slot]
		if !ok || seen[es.Slot] {
			zeroizeBytes(inner)
			return nil, fmt.Errorf("escrow bundle malformed: unexpected share slot %q", es.Slot)
		}
		seen[es.Slot] = true
		share, err := openShare(bundle.KeyID, es, pass)
		if err != nil {
			zeroizeBytes(inner)
			return nil, err
		}
		if len(share) != len(inner) {
			zeroizeBytes(share)
			zeroizeBytes(inner)
			return nil, fmt.Errorf("escrow share %s has wrong length", es.Slot)
		}
		for i := range inner {
			inner[i] ^= share[i]
		}
		zeroizeBytes(share)
	}
	innerPass := []byte(hex.EncodeToString(inner))
	zeroizeBytes(inner)
	return innerPass, nil
}
