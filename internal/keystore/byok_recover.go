// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// W17-12: recover escrowed key material to PLAINTEXT IN MEMORY.
//
// READ THIS BEFORE USING IT.
//
// The Store deliberately exposes no plaintext export — that is a custody
// decision, not an oversight, and every other recovery path imports the
// key back INTO a store rather than handing it out. This function is the
// single sanctioned exception, added under an explicit custody approval
// (Brad, 2026-08-20) for exactly one purpose: cloud-KMS import demands
// the raw PKCS#8 DER so it can be wrapped in the KMS's own
// RSA_AES_KEY_WRAP format, and no wrapping can happen without the
// plaintext existing transiently.
//
// The guarantees that make it acceptable:
//   - dual control: both custodian shares are required, exactly as every
//     other recovery path requires them (the SAME primitive, not a copy)
//   - the plaintext exists only in the returned slice; nothing is
//     written to disk, logged, or returned in an API response
//   - the CALLER MUST ZEROIZE the result. ExportEscrowedKeyToKMS does so
//     on every exit path including error paths.
//
// Do not add a second caller without re-examining the custody question.

// RecoverEscrowedKeyMaterial rebuilds the escrowed private key as raw
// PKCS#8 DER under dual control. The caller MUST zeroize the result.
func RecoverEscrowedKeyMaterial(bundleJSON, custodianA, custodianB []byte) ([]byte, error) {
	// Dual control is enforced here too, not only inside the share
	// reconstruction: a caller that supplied one secret twice must be
	// refused before any cryptographic work begins.
	if err := requireDualControl(custodianA, custodianB); err != nil {
		return nil, fmt.Errorf("escrow recover: %w", err)
	}
	bundle, err := parseEscrowBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	innerPass, err := recoverInnerPassphrase(bundle, custodianA, custodianB)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(innerPass)

	block, _ := pem.Decode([]byte(bundle.WrappedKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("escrow bundle malformed: wrapped key is not PEM")
	}
	return decryptBackupBlockToDER(block, innerPass)
}

// decryptBackupBlockToDER opens a backup envelope and returns the raw
// plaintext bytes, without parsing them into a key object.
//
// decryptBackupBlock (software.go) does the same unwrap and then parses;
// this stops one step earlier because cloud-KMS import wants the DER
// itself. The unwrap is duplicated deliberately rather than reusing that
// function, because returning bytes and returning a crypto.PrivateKey are
// different security surfaces and collapsing them would make the
// plaintext-bytes path reachable from every existing caller.
func decryptBackupBlockToDER(pemBlock *pem.Block, passphrase []byte) ([]byte, error) {
	saltHex, ok := pemBlock.Headers["Salt"]
	if !ok {
		return nil, fmt.Errorf("missing Salt header in backup PEM")
	}
	nonceHex, ok := pemBlock.Headers["Nonce"]
	if !ok {
		return nil, fmt.Errorf("missing Nonce header in backup PEM")
	}
	salt, err := hexDecode(saltHex, saltLen)
	if err != nil {
		return nil, fmt.Errorf("decode backup salt: %w", err)
	}
	nonce, err := hexDecode(nonceHex, nonceLen)
	if err != nil {
		return nil, fmt.Errorf("decode backup nonce: %w", err)
	}

	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroizeBytes(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("recover cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("recover gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, pemBlock.Bytes, nil)
	if err != nil {
		// A wrong custodian secret lands here. Return the sentinel rather
		// than a detailed error: which of the two secrets was wrong is
		// not something a caller should learn.
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
