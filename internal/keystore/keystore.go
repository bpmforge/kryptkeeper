// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"errors"
)

// Algorithm represents a supported key algorithm.
type Algorithm string

const (
	RSA2048   Algorithm = "RSA-2048"
	RSA3072   Algorithm = "RSA-3072"
	RSA4096   Algorithm = "RSA-4096"
	ECDSAP256 Algorithm = "ECDSA-P256"
	ECDSAP384 Algorithm = "ECDSA-P384"
	Ed25519   Algorithm = "Ed25519"

	// Post-quantum algorithms (NIST FIPS 204 / ML-DSA via Cloudflare CIRCL).
	MLDSA44 Algorithm = "ML-DSA-44"
	MLDSA65 Algorithm = "ML-DSA-65"
	MLDSA87 Algorithm = "ML-DSA-87"

	// Hybrid algorithms — classical primary key + ML-DSA secondary key.
	// Primary ECDSA signature works with all current TLS stacks.
	// Secondary ML-DSA signature is stored in X.509 alt-signature extensions.
	HybridECDSAP256MLDSA65 Algorithm = "Hybrid-ECDSA-P256-ML-DSA-65"
	HybridECDSAP384MLDSA87 Algorithm = "Hybrid-ECDSA-P384-ML-DSA-87"
)

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrUnsupportedAlgo  = errors.New("unsupported algorithm")
	ErrDecryptionFailed = errors.New("key decryption failed")
	ErrKeyExists        = errors.New("key already exists")
)

// KeyMetadata holds non-secret information about a stored key.
type KeyMetadata struct {
	ID        string    `json:"id"`
	Algorithm Algorithm `json:"algorithm"`
	CreatedAt string    `json:"created_at"`
	// State is empty for a live key and "pending_deletion" for a cloud-KMS key
	// inside its provider recovery window (W23-23). DeletionScheduledAt is
	// when the provider purges it for good (RFC3339); both are omitted for
	// live keys.
	State               string `json:"state,omitempty"`
	DeletionScheduledAt string `json:"deletion_scheduled_at,omitempty"`
}

// HybridKeyLoader is an optional extension to Store for backends that support
// hybrid key pairs. Callers should type-assert Store to HybridKeyLoader before use.
type HybridKeyLoader interface {
	LoadHybridKeyPair(id string) (HybridKeyPair, error)
}

// BackendLabeler is implemented by stores that front several backends and so
// know which one a create in flight targets (env vocabulary: software, pkcs11,
// vault, cloudkms).
type BackendLabeler interface{ CurrentBackendLabel() string }

// KeyRotateResult is returned by RotateKey.
type KeyRotateResult struct {
	New        KeyMetadata `json:"new"`
	PreviousID string      `json:"previous_id"` // retired key ID (old version still on disk)
}

// Store is the interface for key storage backends.
// All implementations must ensure private keys are never exposed in plaintext
// outside the Store boundary. The crypto.Signer returned by Signer() holds
// the decrypted key in memory for the lifetime of the process.
type Store interface {
	// GenerateKey creates a new key pair and persists the encrypted private key.
	GenerateKey(id string, algo Algorithm) (KeyMetadata, error)

	// Signer returns a crypto.Signer for the given key ID.
	// The private key is decrypted and held in memory.
	Signer(id string) (crypto.Signer, error)

	// PublicKey returns the public key for the given key ID.
	PublicKey(id string) (crypto.PublicKey, error)

	// Metadata returns metadata for a stored key.
	Metadata(id string) (KeyMetadata, error)

	// List returns metadata for all stored keys.
	List() ([]KeyMetadata, error)

	// Delete removes a key from the store. Returns ErrKeyNotFound if not present.
	Delete(id string) error

	// RotateKey generates a new key pair for the given ID, persists it, and
	// retires the old key. The old key file is kept as {id}-retired-{timestamp}.key.enc
	// for disaster recovery. Returns metadata for the new key.
	RotateKey(id string, algo Algorithm) (KeyRotateResult, error)

	// ExportEncryptedKey wraps the key in an AES-256-GCM envelope encrypted with
	// backupPassphrase (separate from the store passphrase) and returns the PEM bytes.
	// Every export must be audited by the caller.
	ExportEncryptedKey(id string, backupPassphrase []byte) ([]byte, error)

	// ImportEncryptedKey decrypts an export envelope and stores the key under id.
	// Returns ErrKeyExists if a key with that id already exists.
	ImportEncryptedKey(id string, data []byte, backupPassphrase []byte) error
}

var (
	ErrKeyBackupFailed = errors.New("key backup/export failed")
)

// rsaAlgorithmForBits buckets an RSA modulus size into the closest Algorithm
// constant: <=2048 RSA-2048, <=3072 RSA-3072, otherwise RSA-4096.
func rsaAlgorithmForBits(bits int) Algorithm {
	switch {
	case bits <= 2048:
		return RSA2048
	case bits <= 3072:
		return RSA3072
	default:
		return RSA4096
	}
}
