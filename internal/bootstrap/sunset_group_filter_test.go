// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"testing"
	"time"
)

// The Algorithm Sunset page drills into a group with ?sunset_group=<id>. The
// list must hold exactly the certificates the report counted: same match func,
// same active-only rule.
func TestSunsetGroupFilterMatchesReportGroups(t *testing.T) {
	revokedAt := time.Now().UTC().Format(time.RFC3339)
	certs := []CertificateItem{
		{FingerprintSHA256: "weak-sig", RiskFlags: []string{"WEAK_SIGNATURE"}},
		{FingerprintSHA256: "weak-sig-pqc", RiskFlags: []string{"WEAK_SIGNATURE"}, PQCVulnerable: true},
		{FingerprintSHA256: "weak-sig-revoked", RiskFlags: []string{"WEAK_SIGNATURE"}, RevokedAt: &revokedAt},
		{FingerprintSHA256: "weak-sig-renewed", RiskFlags: []string{"WEAK_SIGNATURE"}, RenewalStatus: string(RenewalStatusRenewed)},
		{FingerprintSHA256: "clean"},
	}
	report := computeAlgorithmSunset(certs)
	if len(report.Groups) == 0 {
		t.Fatal("fixture produced no sunset groups")
	}
	for _, g := range report.Groups {
		if g.ID == "" {
			t.Fatalf("group %q has no id", g.Algorithm)
		}
		f := newCertFilter(CertificateListQuery{SunsetGroup: g.ID})
		var got int
		for i := range certs {
			if f.matches(&certs[i]) {
				got++
			}
		}
		if got != g.Count || got == 0 {
			t.Errorf("group %s: filter matched %d, report counted %d", g.ID, got, g.Count)
		}
		if n := len(filterFileCertificates(certs, CertificateListQuery{SunsetGroup: g.ID})); n != g.Count {
			t.Errorf("group %s: file provider matched %d, report counted %d", g.ID, n, g.Count)
		}
	}
	if (newCertFilter(CertificateListQuery{SunsetGroup: "weak_signature"})).matchesAll() {
		t.Error("a sunset_group filter must not take the whole-inventory fast path")
	}
}

func TestSunsetGroupFilterRejectsUnknownID(t *testing.T) {
	mux := trustTestMux(t, stubDiscoveryProvider{})
	if rec := getAuthed(mux, "/api/v1/certificates?sunset_group=Classical+algorithms"); rec.Code != http.StatusBadRequest {
		t.Errorf("label as id = %d, want 400", rec.Code)
	}
	if rec := getAuthed(mux, "/api/v1/certificates?sunset_group=pqc_vulnerable"); rec.Code == http.StatusBadRequest {
		t.Errorf("valid id rejected: %d %s", rec.Code, rec.Body.String())
	}
}
