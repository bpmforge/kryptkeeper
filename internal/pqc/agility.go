// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// W16-03: crypto-agility orchestration. PQC is the current algorithm
// transition; this generalizes the wave machinery to ANY transition —
// RSA-2048's 2030 disallowance, future NIST retirements — so the same
// derive/track motion survives the next event, not just this one. The
// org that owns the transition ENGINE owns every transition.

// DeprecationPolicy defines an algorithm/key-size transition and its
// deadline. A certificate MATCHES when its public-key algorithm is
// being retired (case-insensitive substring) AND/OR its key size is at
// or below MaxKeyBits. Both apply when both are set.
type DeprecationPolicy struct {
	Name       string    `json:"name"`
	Algorithms []string  `json:"algorithms"`   // e.g. ["RSA"], ["ECDSA"]
	MaxKeyBits int       `json:"max_key_bits"` // 0 = ignore key size
	Deadline   time.Time `json:"deadline"`
}

// Matches reports whether a certificate is subject to this policy.
func (p DeprecationPolicy) Matches(cert CertRecord) bool {
	algoMatch := len(p.Algorithms) == 0
	alg := strings.ToUpper(cert.Algorithm)
	for _, a := range p.Algorithms {
		if strings.Contains(alg, strings.ToUpper(a)) {
			algoMatch = true
			break
		}
	}
	if !algoMatch {
		return false
	}
	// A cert with an unknown key size (0) cannot be excluded by a size
	// bound — fall back to the algorithm match alone.
	if p.MaxKeyBits > 0 && cert.KeySize > 0 && cert.KeySize > p.MaxKeyBits {
		return false
	}
	return true
}

// AgilityItem is one matched certificate slotted into a wave tier.
type AgilityItem struct {
	Fingerprint string    `json:"fingerprint"`
	CommonName  string    `json:"common_name"`
	WaveTier    string    `json:"wave_tier"` // Test | Internal | Customer-Facing
	Reason      string    `json:"reason"`
	Deadline    time.Time `json:"deadline"`
}

// AgilityRoadmap is the derived transition plan for one policy.
type AgilityRoadmap struct {
	Policy       string                   `json:"policy"`
	GeneratedAt  time.Time                `json:"generated_at"`
	TotalMatched int                      `json:"total_matched"`
	ByWave       map[string][]AgilityItem `json:"by_wave"`
	Deadline     time.Time                `json:"deadline"`
}

// deriveWaveTier assigns a migration tier from the certificate's name,
// mirroring the PQC-wave heuristic (Test → Internal → Customer-Facing).
func deriveWaveTier(cert CertRecord) string {
	cn := strings.ToLower(cert.CommonName)
	switch {
	case strings.Contains(cn, "test"), strings.Contains(cn, "dev"),
		strings.Contains(cn, "staging"), strings.Contains(cn, "qa"):
		return "Test"
	case looksPublic(cn):
		return "Customer-Facing"
	default:
		return "Internal"
	}
}

// looksPublic reports whether the CN looks like an external FQDN (a
// dotted name that isn't an obvious internal TLD).
func looksPublic(cn string) bool {
	if !strings.Contains(cn, ".") {
		return false
	}
	for _, internal := range []string{".internal", ".local", ".corp", ".lan", ".intranet"} {
		if strings.HasSuffix(cn, internal) {
			return false
		}
	}
	return true
}

// DeriveAgilityRoadmap derives migration waves for a deprecation
// policy, grouping matched certs into tiers the SAME way PQC waves
// derive. Non-matching certs (already compliant) are ignored.
func DeriveAgilityRoadmap(certs []CertRecord, policy DeprecationPolicy, now time.Time) AgilityRoadmap {
	rm := AgilityRoadmap{
		Policy:      policy.Name,
		GeneratedAt: now.UTC(),
		ByWave:      map[string][]AgilityItem{},
		Deadline:    policy.Deadline,
	}
	for _, cert := range certs {
		if !policy.Matches(cert) {
			continue
		}
		tier := deriveWaveTier(cert)
		rm.ByWave[tier] = append(rm.ByWave[tier], AgilityItem{
			Fingerprint: cert.Fingerprint,
			CommonName:  cert.CommonName,
			WaveTier:    tier,
			Reason:      policy.Name + ": " + cert.Algorithm + keySizeSuffix(cert.KeySize),
			Deadline:    policy.Deadline,
		})
		rm.TotalMatched++
	}
	for tier := range rm.ByWave {
		items := rm.ByWave[tier]
		sort.Slice(items, func(i, j int) bool { return items[i].Fingerprint < items[j].Fingerprint })
	}
	return rm
}

func keySizeSuffix(bits int) string {
	if bits <= 0 {
		return ""
	}
	return " (" + strconv.Itoa(bits) + "-bit)"
}

// AgilityProgress reports migration progress against a policy deadline.
type AgilityProgress struct {
	Policy           string    `json:"policy"`
	TotalInventory   int       `json:"total_inventory"`
	MatchedRemaining int       `json:"matched_remaining"`
	PercentMigrated  int       `json:"percent_migrated"`
	Deadline         time.Time `json:"deadline"`
	Overdue          bool      `json:"overdue"`
}

// Progress computes how far a deprecation transition has advanced. A
// cert still MATCHING the policy is not yet migrated.
func Progress(certs []CertRecord, policy DeprecationPolicy, now time.Time) AgilityProgress {
	matched := 0
	for _, c := range certs {
		if policy.Matches(c) {
			matched++
		}
	}
	total := len(certs)
	percent := 100
	if total > 0 {
		percent = (total - matched) * 100 / total
	}
	return AgilityProgress{
		Policy:           policy.Name,
		TotalInventory:   total,
		MatchedRemaining: matched,
		PercentMigrated:  percent,
		Deadline:         policy.Deadline,
		Overdue:          matched > 0 && !policy.Deadline.IsZero() && now.After(policy.Deadline),
	}
}
