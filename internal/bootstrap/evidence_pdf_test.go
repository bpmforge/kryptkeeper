// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"testing"
	"time"
)

func sampleEvidence() ComplianceEvidenceReport {
	return ComplianceEvidenceReport{
		GeneratedAt: "2026-06-17T00:00:00Z",
		Framework:   "pci",
		Summary:     ComplianceSummary{Pass: 2, Warn: 1, Fail: 1},
		Controls: []ComplianceControl{
			{ID: "4.2.1.1", Framework: "pci", Title: "Inventory of certificates", Status: "pass", Evidence: "142 certs inventoried with owners."},
			{ID: "4.2.1", Framework: "pci", Title: "Strong cryptography", Status: "warn", Evidence: "3 RSA-2048 certs remain.", Remediation: "Migrate to RSA-3072+ or ECDSA P-256."},
			{ID: "3.6.1", Framework: "pci", Title: "Key lifecycle", Status: "fail", Evidence: "1 CA key has no rotation date.", Remediation: "Set a rotation schedule."},
		},
	}
}

func TestRenderComplianceEvidencePDF_ProducesValidPDF(t *testing.T) {
	at := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	b, err := renderComplianceEvidencePDF(sampleEvidence(), 142, at)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty PDF")
	}
	if !bytes.HasPrefix(b, []byte("%PDF-")) {
		t.Fatalf("not a PDF (magic): %q", b[:min(8, len(b))])
	}
	if !bytes.Contains(b, []byte("%%EOF")) {
		t.Error("PDF missing EOF marker")
	}
}

func TestRenderComplianceEvidencePDF_ScalesWithControls(t *testing.T) {
	at := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	small, _ := renderComplianceEvidencePDF(sampleEvidence(), 142, at)

	big := sampleEvidence()
	for i := 0; i < 40; i++ {
		big.Controls = append(big.Controls, ComplianceControl{
			ID: "X", Status: "pass", Evidence: "more evidence to render",
		})
	}
	large, _ := renderComplianceEvidencePDF(big, 142, at)
	// A pack with many more controls produces a larger document.
	if len(large) <= len(small) {
		t.Fatalf("expected larger PDF for more controls: small=%d large=%d", len(small), len(large))
	}
}

func TestFrameworkDisplayName(t *testing.T) {
	cases := map[string]string{
		"pci":  "PCI DSS 4.0.1",
		"soc2": "SOC 2",
		"nist": "NIST SP 800-57",
		"all":  "All Frameworks",
		"":     "All Frameworks",
	}
	for in, want := range cases {
		if got := frameworkDisplayName(in); got != want {
			t.Errorf("frameworkDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}
