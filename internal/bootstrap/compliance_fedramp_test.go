// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// W28-09: FedRAMP Moderate control mappings.

func fedrampHealthy(n int) []CertificateItem {
	future := time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	out := make([]CertificateItem, n)
	for i := range out {
		out[i] = CertificateItem{FingerprintSHA256: fmt.Sprintf("h%d", i), OwnerTeam: "web", ValidUntil: future}
	}
	return out
}

func TestFedrampControlsFrameworkSelection(t *testing.T) {
	now := time.Now()
	for _, fw := range []string{"fedramp", "all"} {
		got := fedrampControls(fedrampHealthy(2), nil, fw, now)
		if len(got) != len(fedrampControlOrder) {
			t.Fatalf("%s: want %d controls, got %d", fw, len(fedrampControlOrder), len(got))
		}
		for i, c := range got {
			if c.ID != fedrampControlOrder[i] {
				t.Fatalf("%s: position %d want %s got %s", fw, i, fedrampControlOrder[i], c.ID)
			}
			if c.Framework != fedrampFrameworkLabel {
				t.Fatalf("%s: framework label %q", c.ID, c.Framework)
			}
		}
	}
	for _, fw := range []string{"pci", "dora", "", "bogus"} {
		if got := fedrampControls(fedrampHealthy(2), nil, fw, now); got != nil {
			t.Fatalf("%q must yield nil, got %d controls", fw, len(got))
		}
	}
}

func TestFedrampControlsRequiredIDsPresent(t *testing.T) {
	ids := controlIDs(fedrampControls(nil, nil, "fedramp", time.Now()))
	for _, id := range []string{"FEDRAMP-SC-12", "FEDRAMP-SC-13", "FEDRAMP-SC-17", "FEDRAMP-IA-5"} {
		if _, ok := ids[id]; !ok {
			t.Fatalf("missing required control %s", id)
		}
	}
}

func TestFedrampControlsEveryControlHasRuleAndRemediation(t *testing.T) {
	now := time.Now()
	bad := []CertificateItem{{
		FingerprintSHA256: "bad",
		ValidUntil:        now.Add(-24 * time.Hour).Format(time.RFC3339),
		RiskFlags: []string{"WEAK_RSA_KEY", "VALIDITY_EXCEEDS_397_DAYS", "UNTRUSTED_CHAIN", "SELF_SIGNED",
			"NO_OCSP_URL", "NO_CRL_DP", "NIST_SUNSET_RSA2048"},
	}}
	for _, c := range fedrampControls(bad, nil, "fedramp", now) {
		if c.Status == "pass" {
			t.Fatalf("%s should not pass on a bad estate", c.ID)
		}
		if c.Remediation == "" || c.Evidence == "" {
			t.Fatalf("%s needs remediation and evidence: %+v", c.ID, c)
		}
		rule := fedrampControlRules[c.ID]
		for _, want := range []string{"pass:", "warn:", "fail:"} {
			if !strings.Contains(rule, want) {
				t.Fatalf("%s rule %q lacks %q", c.ID, rule, want)
			}
		}
	}
}

func TestFedrampControlsPassOnCleanEstate(t *testing.T) {
	now := time.Now()
	for name, certs := range map[string][]CertificateItem{"healthy": fedrampHealthy(3), "empty": nil} {
		for _, c := range fedrampControls(certs, nil, "fedramp", now) {
			if c.Status != "pass" || c.Remediation != "" {
				t.Fatalf("%s: %s want pass with no remediation, got %q / %q", name, c.ID, c.Status, c.Remediation)
			}
		}
	}
}

func TestFedrampStatusThresholds(t *testing.T) {
	now := time.Now()
	status := func(certs []CertificateItem, id string) string {
		return controlIDs(fedrampControls(certs, nil, "fedramp", now))[id].Status
	}
	flagged := func(n int, flag string) []CertificateItem {
		certs := fedrampHealthy(100)
		for i := 0; i < n; i++ {
			certs[i].RiskFlags = []string{flag}
		}
		return certs
	}
	if got := status(flagged(1, "WEAK_RSA_KEY"), "FEDRAMP-SC-13"); got != "warn" {
		t.Fatalf("1 weak in 100: want warn, got %s", got)
	}
	if got := status(flagged(6, "WEAK_RSA_KEY"), "FEDRAMP-SC-13"); got != "fail" {
		t.Fatalf("6 weak in 100: want fail, got %s", got)
	}
	if got := status(flagged(1, "UNTRUSTED_CHAIN"), "FEDRAMP-SC-17"); got != "fail" {
		t.Fatalf("untrusted chain: want fail, got %s", got)
	}
	if got := status(flagged(1, "SELF_SIGNED"), "FEDRAMP-SC-17"); got != "warn" {
		t.Fatalf("self-signed only: want warn, got %s", got)
	}
}

func TestValidComplianceFramework(t *testing.T) {
	for _, fw := range knownComplianceFrameworks {
		if !validComplianceFramework(fw) {
			t.Fatalf("%q should be valid", fw)
		}
	}
	for _, fw := range []string{"FEDRAMP", "iso27001", "", "pci "} {
		if validComplianceFramework(fw) {
			t.Fatalf("%q should be invalid", fw)
		}
	}
}

func TestFedrampLabelIsMappingOnly(t *testing.T) {
	if !strings.Contains(fedrampFrameworkLabel, "mapping only") {
		t.Fatalf("label must say mapping only: %q", fedrampFrameworkLabel)
	}
	if !strings.Contains(fedrampMappingNotice, "not an assessor attestation") {
		t.Fatalf("notice must disclaim attestation: %q", fedrampMappingNotice)
	}
}
