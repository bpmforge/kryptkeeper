// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"time"
)

// W16-05: DORA (in force Jan 2025) and NIS2 (transposition Oct 2024)
// control mappings for the EU enforcement wave. Cert/key controls map
// to their articles alongside PCI/SOC2/NIST, using the same
// ComplianceControl shape and the same live posture signals — so the
// evidence pack, PDF, and scheduled delivery render them unchanged.

// doraNIS2Controls builds the DORA and/or NIS2 controls for a
// framework selector ("dora", "nis2", or "all"). Any other value
// yields none.
func doraNIS2Controls(certs []CertificateItem, cas []CAListItem, framework string, now time.Time) []ComplianceControl {
	total := len(certs)
	count := func(fn func(CertificateItem) bool) int {
		n := 0
		for _, c := range certs {
			if fn(c) {
				n++
			}
		}
		return n
	}
	statusOf := func(passing, warning bool) string {
		switch {
		case passing:
			return "pass"
		case warning:
			return "warn"
		default:
			return "fail"
		}
	}
	pct := func(n, d int) string {
		if d == 0 {
			return "N/A (no certs)"
		}
		return fmt.Sprintf("%d/%d (%.0f%%)", n, d, float64(n)*100/float64(d))
	}
	hasFlag := func(c CertificateItem, flags ...string) bool {
		for _, f := range c.RiskFlags {
			for _, want := range flags {
				if f == want {
					return true
				}
			}
		}
		return false
	}

	weakCrypto := count(func(c CertificateItem) bool {
		return hasFlag(c, "WEAK_RSA_KEY", "WEAK_EC_KEY", "WEAK_SIGNATURE")
	})
	withOwner := count(func(c CertificateItem) bool { return c.OwnerEmail != "" || c.OwnerTeam != "" })
	tracked := count(func(c CertificateItem) bool {
		if c.ValidUntil == "" {
			return false
		}
		_, err := time.Parse(time.RFC3339, c.ValidUntil)
		return err == nil
	})
	pqcVulnerable := count(func(c CertificateItem) bool { return c.PQCVulnerable })

	var out []ComplianceControl

	if framework == "all" || framework == "dora" {
		out = append(out,
			ComplianceControl{
				ID: "DORA-Art9", Framework: "EU DORA",
				Title:    "ICT protection & prevention — cryptographic controls (Art. 9)",
				Status:   statusOf(weakCrypto == 0, weakCrypto <= total/20),
				Evidence: fmt.Sprintf("Certificates with weak key or signature algorithms: %d of %d.", weakCrypto, total),
				Remediation: func() string {
					if weakCrypto > 0 {
						return fmt.Sprintf("Replace %d certificate(s) using weak cryptography.", weakCrypto)
					}
					return ""
				}(),
			},
			ComplianceControl{
				ID: "DORA-Art10", Framework: "EU DORA",
				Title:    "ICT-related incident detection — certificate expiry monitoring (Art. 10)",
				Status:   statusOf(total == 0 || tracked == total, tracked >= total-total/20),
				Evidence: fmt.Sprintf("Certificates with tracked expiry: %s.", pct(tracked, total)),
			},
			ComplianceControl{
				ID: "DORA-Art6", Framework: "EU DORA",
				Title:    "ICT risk management framework — inventory governance & ownership (Art. 6)",
				Status:   statusOf(total == 0 || withOwner == total, withOwner >= total/2),
				Evidence: fmt.Sprintf("Certificates with an assigned owner: %s. CAs under management: %d.", pct(withOwner, total), len(cas)),
			},
		)
	}

	if framework == "all" || framework == "nis2" {
		out = append(out,
			ComplianceControl{
				ID: "NIS2-Art21-2h", Framework: "EU NIS2",
				Title:    "Cryptography & encryption policy (Art. 21(2)(h))",
				Status:   statusOf(weakCrypto == 0 && pqcVulnerable == 0, weakCrypto == 0),
				Evidence: fmt.Sprintf("Weak-crypto certs: %d. PQC-vulnerable: %s.", weakCrypto, pct(pqcVulnerable, total)),
				Remediation: func() string {
					if pqcVulnerable > 0 {
						return fmt.Sprintf("Plan post-quantum migration for %d vulnerable certificate(s).", pqcVulnerable)
					}
					return ""
				}(),
			},
			ComplianceControl{
				ID: "NIS2-Art21-2i", Framework: "EU NIS2",
				Title:    "Asset management — certificate inventory & ownership (Art. 21(2)(i))",
				Status:   statusOf(total == 0 || withOwner == total, withOwner >= total/2),
				Evidence: fmt.Sprintf("Inventoried certificates: %d. With owner: %s.", total, pct(withOwner, total)),
			},
			ComplianceControl{
				ID: "NIS2-Art23", Framework: "EU NIS2",
				Title:    "Incident-reporting readiness — inventory completeness (Art. 23)",
				Status:   statusOf(total == 0 || tracked == total, total > 0),
				Evidence: fmt.Sprintf("A certificate that is not inventoried cannot be reported on. Tracked: %s.", pct(tracked, total)),
			},
		)
	}

	return out
}
