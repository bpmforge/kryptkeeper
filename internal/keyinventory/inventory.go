// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package keyinventory unifies cloud KMS keys across AWS, Azure, and
// GCP into one algorithm-aware, rotation-status inventory (W15-01).
// This is the crypto-agility "one inventory of keys and algorithms"
// surface — and the biggest PQC blind spot, since cloud KMS keys are
// the longest-lived crypto an org holds and no cert-side assessment
// sees them. Read-only, metadata only: no key material is ever
// fetched.
package keyinventory

import (
	"context"
	"strings"
)

// Key is one cloud KMS key's metadata.
type Key struct {
	Provider        string `json:"provider"` // aws-kms | azure-kv | gcp-kms
	Location        string `json:"location"` // region / vault / keyring path
	KeyID           string `json:"key_id"`
	Algorithm       string `json:"algorithm"`
	Usage           string `json:"usage,omitempty"`
	State           string `json:"state,omitempty"`
	RotationEnabled bool   `json:"rotation_enabled"`
	CreatedAt       string `json:"created_at,omitempty"`
	PQCReadiness    string `json:"pqc_readiness"` // vulnerable | quantum_safe | unknown
}

// KeyInventory aggregates keys across providers.
type KeyInventory struct {
	Keys   []Key    `json:"keys"`
	Errors []string `json:"errors,omitempty"`
}

// KeySource lists a single provider's keys.
type KeySource interface {
	Provider() string
	ListKeys(ctx context.Context) ([]Key, error)
}

// Collect runs every source; per-provider failures are recorded and
// never sink the others (read-only, a dead provider is not fatal).
func Collect(ctx context.Context, sources ...KeySource) KeyInventory {
	inv := KeyInventory{}
	for _, s := range sources {
		keys, err := s.ListKeys(ctx)
		if err != nil {
			inv.Errors = append(inv.Errors, s.Provider()+": "+err.Error())
			continue
		}
		inv.Keys = append(inv.Keys, keys...)
	}
	return inv
}

// scoreKeyPQC classifies an algorithm for post-quantum readiness. This
// is the PQC denominator for keys, extending the cert-side story to
// the KMS surface. Classical RSA/ECC/symmetric are harvest-now-
// decrypt-later exposed; the NIST PQC families are quantum-safe.
func scoreKeyPQC(algorithm string) string {
	a := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(a, "ML-DSA"), strings.Contains(a, "MLDSA"),
		strings.Contains(a, "ML-KEM"), strings.Contains(a, "MLKEM"),
		strings.Contains(a, "SLH-DSA"), strings.Contains(a, "DILITHIUM"),
		strings.Contains(a, "KYBER"), strings.Contains(a, "FALCON"),
		strings.Contains(a, "SPHINCS"):
		return "quantum_safe"
	case strings.Contains(a, "RSA"), strings.Contains(a, "ECC"),
		strings.Contains(a, "EC_"), strings.HasPrefix(a, "EC-"), strings.Contains(a, "ECDSA"),
		strings.Contains(a, "P256"), strings.Contains(a, "P-256"),
		strings.Contains(a, "P384"), strings.Contains(a, "P-384"),
		strings.Contains(a, "P521"), strings.Contains(a, "P-521"),
		strings.Contains(a, "SECP"), strings.Contains(a, "AES"),
		strings.Contains(a, "SYMMETRIC"), strings.Contains(a, "HMAC"):
		return "vulnerable"
	case a == "":
		return "unknown"
	default:
		return "unknown"
	}
}
