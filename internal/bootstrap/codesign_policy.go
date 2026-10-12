// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"strings"
	"time"
)

// W17-02: code-signing policy enforcement.
//
// Folded in from the deleted internal/codesign package, which was never
// reachable from any binary. That package also carried its own inventory
// and its own risk model — both redundant with the live
// handlers_codesign.go path and, worse, DIVERGENT: two different answers
// to "how risky is this signing cert" is a defect, not a feature. Only
// the genuinely unique capability survives, and it evaluates against the
// live inventory so the product keeps exactly one risk model.
//
// Signing keys outlive the software they sign, so a compromised or
// over-permissive code-signing cert is a supply-chain problem rather than
// an availability one — which is why the constraints below are worth
// enforcing continuously rather than at issuance only.

// CodeSigningPolicy constrains which code-signing certificates are
// acceptable. A zero-value field means "no constraint" — an unconfigured
// policy must never manufacture violations.
// Key-size minimums are per-family on purpose: a single "min bits" cannot
// compare RSA (2048/3072/4096) with EC (256/384/521) — 256 would wave
// through every RSA key while 2048 would reject every EC one. The deleted
// package had exactly that flaw. PQC algorithms (ML-DSA) carry no
// comparable bit-length and are exempt from the size check; the algorithm
// allowlist is the control that applies to them.
type CodeSigningPolicy struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
	MinRSAKeySizeBits int      `json:"min_rsa_key_size_bits,omitempty"`
	MinECKeySizeBits  int      `json:"min_ec_key_size_bits,omitempty"`
	MaxValidityDays   int      `json:"max_validity_days,omitempty"`
}

// minKeySizeFor returns the applicable minimum for a certificate's
// algorithm family, and whether a size check applies at all.
func minKeySizeFor(algorithm string, policy CodeSigningPolicy) (int, bool) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.HasPrefix(a, "RSA"):
		return policy.MinRSAKeySizeBits, policy.MinRSAKeySizeBits > 0
	case strings.HasPrefix(a, "EC"): // ECDSA, EC, ECDH
		return policy.MinECKeySizeBits, policy.MinECKeySizeBits > 0
	default:
		return 0, false // ML-DSA and friends: no comparable bit length
	}
}

// CodeSigningFinding is one certificate's violations under a policy.
type CodeSigningFinding struct {
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	CommonName        string   `json:"common_name"`
	Violations        []string `json:"violations"`
}

// CodeSigningPolicySummary is the evaluation of a whole inventory.
type CodeSigningPolicySummary struct {
	PolicyID  string               `json:"policy_id"`
	Evaluated int                  `json:"evaluated"`
	Compliant int                  `json:"compliant"`
	Violating int                  `json:"violating"`
	Findings  []CodeSigningFinding `json:"findings"`
}

// evaluateCodeSigningPolicy returns the violations for one certificate.
func evaluateCodeSigningPolicy(cert CodeSigningCert, policy CodeSigningPolicy) []string {
	var violations []string

	if len(policy.AllowedAlgorithms) > 0 {
		allowed := false
		for _, a := range policy.AllowedAlgorithms {
			if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(cert.PublicKeyAlgorithm)) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, fmt.Sprintf("key algorithm %q is not in the policy allowlist", cert.PublicKeyAlgorithm))
		}
	}

	if minBits, applies := minKeySizeFor(cert.PublicKeyAlgorithm, policy); applies && cert.KeySizeBits > 0 && cert.KeySizeBits < minBits {
		violations = append(violations, fmt.Sprintf("%s key size %d bits is below the policy minimum of %d", cert.PublicKeyAlgorithm, cert.KeySizeBits, minBits))
	}

	if policy.MaxValidityDays > 0 {
		from, ferr := time.Parse(time.RFC3339, cert.ValidFrom)
		until, uerr := time.Parse(time.RFC3339, cert.ValidUntil)
		switch {
		case ferr != nil || uerr != nil:
			// Unknown is not compliant: a window we cannot verify must be
			// reported, never silently passed.
			violations = append(violations, "validity window could not be parsed, so the policy maximum could not be verified")
		default:
			if days := int(until.Sub(from).Hours() / 24); days > policy.MaxValidityDays {
				violations = append(violations, fmt.Sprintf("validity of %d days exceeds the policy maximum of %d", days, policy.MaxValidityDays))
			}
		}
	}

	return violations
}

// summarizeCodeSigningPolicy evaluates a whole inventory against a policy.
func summarizeCodeSigningPolicy(certs []CodeSigningCert, policy CodeSigningPolicy) CodeSigningPolicySummary {
	summary := CodeSigningPolicySummary{PolicyID: policy.ID, Findings: []CodeSigningFinding{}}
	for _, cert := range certs {
		summary.Evaluated++
		violations := evaluateCodeSigningPolicy(cert, policy)
		if len(violations) == 0 {
			summary.Compliant++
			continue
		}
		summary.Violating++
		summary.Findings = append(summary.Findings, CodeSigningFinding{
			FingerprintSHA256: cert.FingerprintSHA256,
			CommonName:        cert.CommonName,
			Violations:        violations,
		})
	}
	return summary
}
