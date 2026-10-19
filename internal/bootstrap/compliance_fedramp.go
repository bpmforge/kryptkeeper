// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"time"
)

// W28-09: FedRAMP Moderate certificate and key control mappings. Same
// ComplianceControl shape and live posture signals as DORA/NIS2. This is a
// mapping of controls to evidence, never an assessment, so the wording must
// not claim compliance, certification or authorization.

const fedrampFrameworkLabel = "FedRAMP Moderate (control mapping only; not an assessment)"

const fedrampMappingNotice = "This is a mapping of FedRAMP Moderate certificate and key controls to live Kryptkeeper evidence. It is not an assessor attestation and does not establish FedRAMP authorization."

// knownComplianceFrameworks is the only framework allow-list; the report
// handler derives its 400 for unknown values from it.
var knownComplianceFrameworks = []string{"all", "soc2", "pci", "nist", "dora", "nis2", "fedramp"}

// validComplianceFramework matches exactly on the already lower-cased value.
// Callers default an empty selector to "all" before calling, so "" is invalid.
func validComplianceFramework(fw string) bool {
	for _, k := range knownComplianceFrameworks {
		if fw == k {
			return true
		}
	}
	return false
}

// fedrampControlOrder is the stable emission order of fedrampControls.
var fedrampControlOrder = []string{"FEDRAMP-SC-12", "FEDRAMP-SC-13", "FEDRAMP-SC-17", "FEDRAMP-IA-5", "FEDRAMP-IA-5-2", "FEDRAMP-CM-8"}

// fedrampControlRules carries the pass/warn/fail rule text per control for
// the control-to-artifact index (W28-10).
var fedrampControlRules = map[string]string{
	"FEDRAMP-SC-12":  "pass: no certificate valid beyond 397 days; warn: at most 10% of certificates; fail: otherwise",
	"FEDRAMP-SC-13":  "pass: no weak key or signature algorithm; warn: at most 5% of certificates; fail: otherwise",
	"FEDRAMP-SC-17":  "pass: no untrusted-chain and no self-signed leaf certificates; warn: no untrusted chain but some self-signed; fail: any untrusted chain",
	"FEDRAMP-IA-5":   "pass: no expired, no expiring within 30 days, no unknown expiry; warn: none expired; fail: any expired",
	"FEDRAMP-IA-5-2": "pass: every certificate has an OCSP or CRL endpoint; warn: at most 10% lack both; fail: otherwise",
	"FEDRAMP-CM-8":   "pass: every certificate has an owner and a tracked expiry; warn: at least half have an owner; fail: otherwise",
}

func fedrampHasFlag(c CertificateItem, flags ...string) bool {
	for _, f := range c.RiskFlags {
		for _, want := range flags {
			if f == want {
				return true
			}
		}
	}
	return false
}

// fedrampControls returns the FedRAMP controls for framework "fedramp" or
// "all"; any other value yields nil. certs are already filtered to active
// certificates by the caller.
func fedrampControls(certs []CertificateItem, cas []CAListItem, framework string, now time.Time) []ComplianceControl {
	if framework != "all" && framework != "fedramp" {
		return nil
	}
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
	remediate := func(status, text string) string {
		if status == "pass" {
			return ""
		}
		return text
	}

	longValidity := count(func(c CertificateItem) bool { return fedrampHasFlag(c, "VALIDITY_EXCEEDS_397_DAYS") })
	weak := count(func(c CertificateItem) bool {
		return fedrampHasFlag(c, "WEAK_RSA_KEY", "WEAK_EC_KEY", "WEAK_SIGNATURE")
	})
	sunset := count(func(c CertificateItem) bool { return fedrampHasFlag(c, "NIST_SUNSET_RSA2048", "NIST_SUNSET_ECC224") })
	untrusted := count(func(c CertificateItem) bool { return fedrampHasFlag(c, "UNTRUSTED_CHAIN") })
	selfSigned := count(func(c CertificateItem) bool { return fedrampHasFlag(c, "SELF_SIGNED") })
	activeCAs := 0
	for _, ca := range cas {
		if caEffectiveStatus(ca, now) == "active" {
			activeCAs++
		}
	}
	t := tallyExpiry(certs, now)
	noRevocation := count(func(c CertificateItem) bool {
		return fedrampHasFlag(c, "NO_OCSP_URL") && fedrampHasFlag(c, "NO_CRL_DP")
	})
	withOwner := count(func(c CertificateItem) bool { return c.OwnerEmail != "" || c.OwnerTeam != "" })
	tracked := count(func(c CertificateItem) bool {
		if c.ValidUntil == "" {
			return false
		}
		_, err := time.Parse(time.RFC3339, c.ValidUntil)
		return err == nil
	})

	sc12 := statusOf(longValidity == 0, longValidity <= total/10)
	sc13 := statusOf(weak == 0, weak <= total/20)
	sc17 := statusOf(untrusted == 0 && selfSigned == 0, untrusted == 0)
	ia5 := statusOf(t.expired == 0 && t.expiring30 == 0 && t.unknown == 0, t.expired == 0)
	ia52 := statusOf(noRevocation == 0, noRevocation <= total/10)
	cm8 := statusOf(total == 0 || (withOwner == total && tracked == total), withOwner >= total/2)

	byID := map[string]ComplianceControl{
		"FEDRAMP-SC-12": {
			ID: "FEDRAMP-SC-12", Title: "Cryptographic key establishment and management", Status: sc12,
			Evidence:    fmt.Sprintf("Certificates with validity beyond 397 days: %d of %d.", longValidity, total),
			Remediation: remediate(sc12, fmt.Sprintf("Reissue %d certificate(s) with a validity of 397 days or less and rotate their keys at renewal.", longValidity)),
		},
		"FEDRAMP-SC-13": {
			ID: "FEDRAMP-SC-13", Title: "Cryptographic protection", Status: sc13,
			Evidence:    fmt.Sprintf("Weak key or signature algorithms: %d of %d. Past NIST sunset: %d.", weak, total, sunset),
			Remediation: remediate(sc13, fmt.Sprintf("Replace %d certificate(s) using weak cryptography with FIPS-approved algorithms (RSA-3072+, ECDSA P-256+).", weak)),
		},
		"FEDRAMP-SC-17": {
			ID: "FEDRAMP-SC-17", Title: "Public key infrastructure certificates", Status: sc17,
			Evidence:    fmt.Sprintf("Untrusted chain: %d. Self-signed leaf: %d. Active CAs: %d of %d.", untrusted, selfSigned, activeCAs, len(cas)),
			Remediation: remediate(sc17, "Reissue certificates with an untrusted chain from a trusted CA; replace self-signed leaf certificates."),
		},
		"FEDRAMP-IA-5": {
			ID: "FEDRAMP-IA-5", Title: "Authenticator management (certificate lifecycle)", Status: ia5,
			Evidence:    fmt.Sprintf("Expired: %d. Expiring <30d: %d. Unknown expiry: %d.", t.expired, t.expiring30, t.unknown),
			Remediation: remediate(ia5, "Renew or revoke expired certificates; correct records with missing expiry."),
		},
		"FEDRAMP-IA-5-2": {
			ID: "FEDRAMP-IA-5-2", Title: "PKI-based authentication: revocation checking", Status: ia52,
			Evidence:    fmt.Sprintf("Certificates with no revocation endpoint (OCSP or CRL): %d of %d.", noRevocation, total),
			Remediation: remediate(ia52, "Issue certificates that carry an OCSP responder URL or CRL distribution point."),
		},
		"FEDRAMP-CM-8": {
			ID: "FEDRAMP-CM-8", Title: "System component inventory", Status: cm8,
			Evidence:    fmt.Sprintf("Inventoried: %d. With owner: %d. With tracked expiry: %d.", total, withOwner, tracked),
			Remediation: remediate(cm8, "Assign an owner to every certificate and re-scan to fill missing expiry dates."),
		},
	}

	out := make([]ComplianceControl, 0, len(fedrampControlOrder))
	for _, id := range fedrampControlOrder {
		c := byID[id]
		c.Framework = fedrampFrameworkLabel
		out = append(out, c)
	}
	return out
}
