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
	"fmt"
	"strings"
	"time"
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
	// KeyType is "" for cloud KMS keys, "host" or "user" for SSH keys (W24-33).
	KeyType string `json:"key_type,omitempty"`
	// Stale is true when the key is past its rotation window (SSH user keys).
	Stale bool `json:"stale,omitempty"`
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

// DefaultProviderTimeout bounds each provider so one hung source cannot hold
// the whole inventory request.
const DefaultProviderTimeout = 3 * time.Second

// Collect runs every source concurrently with DefaultProviderTimeout;
// per-provider failures are recorded and never sink the others (read-only,
// a dead provider is not fatal).
func Collect(ctx context.Context, sources ...KeySource) KeyInventory {
	return CollectWithTimeout(ctx, DefaultProviderTimeout, sources...)
}

type collectResult struct {
	keys []Key
	err  error
}

// CollectWithTimeout runs each source in its own goroutine under a
// per-provider deadline. A source that ignores its context is abandoned at
// the deadline (its result channel is buffered, so it cannot leak a blocked
// send). Output order follows source order.
func CollectWithTimeout(ctx context.Context, perProvider time.Duration, sources ...KeySource) KeyInventory {
	chans := make([]chan collectResult, len(sources))
	for i, s := range sources {
		ch := make(chan collectResult, 1)
		chans[i] = ch
		sctx, cancel := context.WithTimeout(ctx, perProvider)
		go func(s KeySource) {
			defer cancel()
			keys, err := s.ListKeys(sctx)
			ch <- collectResult{keys, err}
		}(s)
	}
	inv := KeyInventory{}
	deadline := time.Now().Add(perProvider)
	record := func(s KeySource, r collectResult) {
		if r.err != nil {
			inv.Errors = append(inv.Errors, s.Provider()+": "+r.err.Error())
			return
		}
		inv.Keys = append(inv.Keys, r.keys...)
	}
	for i, s := range sources {
		select { // a finished source always wins over an expired deadline
		case r := <-chans[i]:
			record(s, r)
			continue
		default:
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case r := <-chans[i]:
			record(s, r)
		case <-timer.C:
			inv.Errors = append(inv.Errors, fmt.Sprintf("%s: timed out after %s", s.Provider(), perProvider))
		case <-ctx.Done():
			inv.Errors = append(inv.Errors, s.Provider()+": "+ctx.Err().Error())
		}
		timer.Stop()
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
