// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// W9-05 (G-42/D-083): the key-generation policy. Before this, the keys API
// passed any algorithm straight through — an operator could mint an
// RSA-2048 CA key with no floor anywhere. Refusals cite the rule by name:
// a policy error is for a human deciding what to request instead.

// Purposes a key can be generated for. The purpose axis is the
// per-CA/role hook: rules are keyed by purpose, and a future role→purpose
// mapping (W6-08 RBAC) plugs in without changing this type.
const (
	PurposeGeneral = "general"
	PurposeCA      = "ca"
)

// rsaBits maps the RSA algorithm constants to their modulus size; non-RSA
// algorithms are not subject to the RSA floor.
func rsaBits(algo Algorithm) (int, bool) {
	switch algo {
	case RSA2048:
		return 2048, true
	case RSA4096:
		return 4096, true
	default:
		return 0, false
	}
}

// supportedAlgorithms is the full set the platform defines.
var supportedAlgorithms = map[Algorithm]bool{
	RSA2048: true, RSA4096: true,
	ECDSAP256: true, ECDSAP384: true, Ed25519: true,
	MLDSA44: true, MLDSA65: true, MLDSA87: true,
	HybridECDSAP256MLDSA65: true, HybridECDSAP384MLDSA87: true,
}

// PurposeRules are the per-purpose strength floors.
type PurposeRules struct {
	MinRSABits int
}

// KeygenPolicy is the data-driven generation policy.
type KeygenPolicy struct {
	// Allowed is the algorithm allow-list; nil/empty means every supported
	// algorithm.
	Allowed map[Algorithm]bool
	// Rules are keyed by purpose; a missing purpose uses the "general"
	// entry.
	Rules map[string]PurposeRules
}

// DefaultKeygenPolicy: all supported algorithms; RSA floor 3072 in general
// (RSA-2048 is below modern guidance) and 4096 for CA keys.
func DefaultKeygenPolicy() KeygenPolicy {
	return KeygenPolicy{
		Rules: map[string]PurposeRules{
			PurposeGeneral: {MinRSABits: 3072},
			PurposeCA:      {MinRSABits: 4096},
		},
	}
}

// KeygenPolicyFromEnv applies overrides:
// KRYPTKEEPER_KEYGEN_ALLOWED_ALGOS (CSV of Algorithm names; empty = all),
// KRYPTKEEPER_KEYGEN_MIN_RSA_BITS, KRYPTKEEPER_KEYGEN_CA_MIN_RSA_BITS.
// A misparsed value falls back to the default WITH a log line — never
// silently.
func KeygenPolicyFromEnv() KeygenPolicy {
	policy := DefaultKeygenPolicy()

	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_KEYGEN_ALLOWED_ALGOS")); raw != "" {
		allowed := map[Algorithm]bool{}
		for _, name := range strings.Split(raw, ",") {
			algo := Algorithm(strings.TrimSpace(name))
			if algo == "" {
				continue
			}
			if !supportedAlgorithms[algo] {
				log.Printf("keygen policy: KRYPTKEEPER_KEYGEN_ALLOWED_ALGOS names unknown algorithm %q; ignoring that entry", algo)
				continue
			}
			allowed[algo] = true
		}
		if len(allowed) > 0 {
			policy.Allowed = allowed
		} else {
			log.Print("keygen policy: KRYPTKEEPER_KEYGEN_ALLOWED_ALGOS parsed to an empty set; keeping the default allow-all")
		}
	}

	parseFloor := func(env, purpose string) {
		raw := strings.TrimSpace(os.Getenv(env))
		if raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			log.Printf("keygen policy: invalid %s=%q; keeping the default floor", env, raw)
			return
		}
		rules := policy.Rules[purpose]
		rules.MinRSABits = n
		policy.Rules[purpose] = rules
	}
	parseFloor("KRYPTKEEPER_KEYGEN_MIN_RSA_BITS", PurposeGeneral)
	parseFloor("KRYPTKEEPER_KEYGEN_CA_MIN_RSA_BITS", PurposeCA)

	return policy
}

// Check refuses a generation request that violates policy, citing the rule.
// Unknown algorithms are refused HERE, before any backend sees them — one
// consistent refusal surface.
func (p KeygenPolicy) Check(algo Algorithm, purpose string) error {
	if purpose == "" {
		purpose = PurposeGeneral
	}
	if !supportedAlgorithms[algo] {
		return fmt.Errorf("keygen policy: %q is not a supported algorithm (rule: allowed_algorithms)", algo)
	}
	if len(p.Allowed) > 0 && !p.Allowed[algo] {
		return fmt.Errorf("keygen policy: %s is not in the configured allow-list (rule: allowed_algorithms)", algo)
	}
	rules, ok := p.Rules[purpose]
	if !ok {
		rules = p.Rules[PurposeGeneral]
	}
	if bits, isRSA := rsaBits(algo); isRSA && rules.MinRSABits > 0 && bits < rules.MinRSABits {
		return fmt.Errorf("keygen policy: %s (%d bits) is below the %d-bit RSA floor for purpose %q (rule: min_rsa_bits)",
			algo, bits, rules.MinRSABits, purpose)
	}
	return nil
}
