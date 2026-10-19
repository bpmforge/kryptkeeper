// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11

// Package keystore — PKCS#11 / HSM backend.
//
// Build with: go build -tags pkcs11
// Requires: go get github.com/ThalesGroup/crypto11
//           SoftHSM2 or a real PKCS#11 HSM at runtime
//
// Environment variables:
//
//	KRYPTKEEPER_PKCS11_LIB          path to PKCS#11 shared library
//	                                (e.g. /opt/homebrew/lib/softhsm/libsofthsm2.so)
//	KRYPTKEEPER_PKCS11_TOKEN_LABEL  HSM token label (required unless
//	                                KRYPTKEEPER_PKCS11_SLOT is set instead)
//	KRYPTKEEPER_PKCS11_PIN          HSM user PIN (required)
//	KRYPTKEEPER_PKCS11_SLOT         slot index (optional; overrides
//	                                token-label selection when set --
//	                                crypto11.Configure accepts exactly one
//	                                token selector, never both)

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ThalesGroup/crypto11"
)

// PKCS11Store implements Store using a PKCS#11 HSM.
// Private key bytes never leave the HSM — Sign() is dispatched into the token.
type PKCS11Store struct {
	ctx *crypto11.Context
}

var _ Store = (*PKCS11Store)(nil)

// NewPKCS11StoreFromEnv reads HSM configuration from environment variables
// and returns a PKCS11Store, or an error if the token cannot be opened.
func NewPKCS11StoreFromEnv() (Store, error) {
	lib := strings.TrimSpace(os.Getenv("KRYPTKEEPER_PKCS11_LIB"))
	tokenLabel := strings.TrimSpace(os.Getenv("KRYPTKEEPER_PKCS11_TOKEN_LABEL"))
	pin := strings.TrimSpace(os.Getenv("KRYPTKEEPER_PKCS11_PIN"))

	if lib == "" {
		return nil, fmt.Errorf("KRYPTKEEPER_PKCS11_LIB is required")
	}
	if tokenLabel == "" {
		return nil, fmt.Errorf("KRYPTKEEPER_PKCS11_TOKEN_LABEL is required")
	}
	if pin == "" {
		return nil, fmt.Errorf("KRYPTKEEPER_PKCS11_PIN is required")
	}

	// crypto11.Configure requires EXACTLY ONE of SlotNumber/TokenLabel/
	// TokenSerial to be set -- passing both is a hard error ("config must
	// specify exactly one way to select a token"), verified against the
	// vendored source ($GOMODCACHE/github.com/!thales!group/crypto11@v1.6.1/
	// crypto11.go Configure()). TokenLabel is required above, so SlotNumber
	// must stay nil unless the operator explicitly opts into slot-based
	// selection: this backend previously always set SlotNumber to a
	// default of 0 alongside TokenLabel, so Configure() unconditionally
	// failed and no PKCS#11 token could ever be opened (found and proven
	// empirically against SoftHSM2 in W19-08 -- softhsm2-util reassigns an
	// initialized token to a fresh slot ID, never slot 0, so even the
	// default value was also the wrong slot).
	var slotNumber *int
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_PKCS11_SLOT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("KRYPTKEEPER_PKCS11_SLOT must be an integer: %w", err)
		}
		slotNumber = &n
	}

	cfg := &crypto11.Config{
		Path: lib,
		Pin:  pin,
	}
	if slotNumber != nil {
		cfg.SlotNumber = slotNumber
	} else {
		cfg.TokenLabel = tokenLabel
	}

	ctx, err := crypto11.Configure(cfg)
	if err != nil {
		return nil, fmt.Errorf("open PKCS#11 token %q via %s: %w", tokenLabel, lib, err)
	}

	return &PKCS11Store{ctx: ctx}, nil
}

// GenerateKey creates an RSA or ECDSA key inside the HSM.
// The private key bytes never leave the token.
func (s *PKCS11Store) GenerateKey(id string, algo Algorithm) (KeyMetadata, error) {
	label := []byte(id)

	switch algo {
	case RSA2048:
		if _, err := s.ctx.GenerateRSAKeyPairWithLabel(label, label, 2048); err != nil {
			return KeyMetadata{}, fmt.Errorf("pkcs11 generate RSA-2048 key %q: %w", id, err)
		}
	case RSA3072:
		if _, err := s.ctx.GenerateRSAKeyPairWithLabel(label, label, 3072); err != nil {
			return KeyMetadata{}, fmt.Errorf("pkcs11 generate RSA-3072 key %q: %w", id, err)
		}
	case RSA4096:
		if _, err := s.ctx.GenerateRSAKeyPairWithLabel(label, label, 4096); err != nil {
			return KeyMetadata{}, fmt.Errorf("pkcs11 generate RSA-4096 key %q: %w", id, err)
		}
	case ECDSAP256:
		if _, err := s.ctx.GenerateECDSAKeyPairWithLabel(label, label, elliptic.P256()); err != nil {
			return KeyMetadata{}, fmt.Errorf("pkcs11 generate ECDSA-P256 key %q: %w", id, err)
		}
	case ECDSAP384:
		if _, err := s.ctx.GenerateECDSAKeyPairWithLabel(label, label, elliptic.P384()); err != nil {
			return KeyMetadata{}, fmt.Errorf("pkcs11 generate ECDSA-P384 key %q: %w", id, err)
		}
	default:
		return KeyMetadata{}, fmt.Errorf("%w: pkcs11 store does not support %q; supported: RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384", ErrUnsupportedAlgo, algo)
	}

	return KeyMetadata{
		ID:        id,
		Algorithm: algo,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// PublicKey returns the public key for the given key ID, derived from the
// HSM-backed signer. Private key bytes never leave the token.
func (s *PKCS11Store) PublicKey(id string) (crypto.PublicKey, error) {
	signer, err := s.Signer(id)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// Signer returns a crypto.Signer backed by the HSM key.
// Sign operations run inside the token — private key bytes never leave the HSM.
func (s *PKCS11Store) Signer(id string) (crypto.Signer, error) {
	label := []byte(id)
	signer, err := s.ctx.FindKeyPair(nil, label)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 find key %q: %w", id, err)
	}
	if signer == nil {
		return nil, ErrKeyNotFound
	}
	return signer, nil
}

// Metadata returns key metadata inferred from the HSM key's public key type.
func (s *PKCS11Store) Metadata(id string) (KeyMetadata, error) {
	signer, err := s.Signer(id)
	if err != nil {
		return KeyMetadata{}, err
	}

	algo := inferAlgorithmFromPublicKey(signer.Public())
	return KeyMetadata{ID: id, Algorithm: algo}, nil
}

// Delete removes a key from the HSM.
func (s *PKCS11Store) Delete(id string) error {
	label := []byte(id)
	signer, err := s.ctx.FindKeyPair(nil, label)
	if err != nil {
		return fmt.Errorf("pkcs11 find key %q for deletion: %w", id, err)
	}
	if signer == nil {
		return ErrKeyNotFound
	}
	if err := signer.Delete(); err != nil {
		return fmt.Errorf("pkcs11 delete key %q: %w", id, err)
	}
	return nil
}

// List returns metadata for all key pairs visible in the current token.
// Note: PKCS#11 labels are opaque bytes; callers should treat IDs as best-effort.
func (s *PKCS11Store) List() ([]KeyMetadata, error) {
	pairs, err := s.ctx.FindKeyPairs(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 list keys: %w", err)
	}
	out := make([]KeyMetadata, 0, len(pairs))
	for i, p := range pairs {
		out = append(out, KeyMetadata{
			ID:        fmt.Sprintf("pkcs11-key-%d", i),
			Algorithm: inferAlgorithmFromPublicKey(p.Public()),
		})
	}
	return out, nil
}

// inferAlgorithmFromPublicKey maps a crypto.PublicKey to the closest Algorithm constant.
func inferAlgorithmFromPublicKey(pub crypto.PublicKey) Algorithm {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsaAlgorithmForBits(k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return ECDSAP384
		default:
			return ECDSAP256
		}
	default:
		return ECDSAP256
	}
}

// RotateKey is not directly supported via PKCS#11 — HSM manages key versioning.
func (s *PKCS11Store) RotateKey(_ string, _ Algorithm) (KeyRotateResult, error) {
	return KeyRotateResult{}, fmt.Errorf("pkcs11: key rotation must be performed through the HSM management interface")
}

// ExportEncryptedKey is not supported via PKCS#11 — keys are non-extractable by design.
func (s *PKCS11Store) ExportEncryptedKey(_ string, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("pkcs11: private key export is not permitted from HSM-backed keys")
}

// ImportEncryptedKey is not supported via PKCS#11 — use HSM key import tooling.
func (s *PKCS11Store) ImportEncryptedKey(_ string, _ []byte, _ []byte) error {
	return fmt.Errorf("pkcs11: key import must be performed through the HSM management interface")
}
