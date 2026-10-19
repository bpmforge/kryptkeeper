// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/pqc"
)

func TestPQCMigrationHandler_RoadmapFromInventory(t *testing.T) {
	auth := newReportsTestAuth(t)
	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		{
			FingerprintSHA256: "ca", CommonName: "Root CA", PublicKeyAlgorithm: "RSA",
			KeyUsage: []string{"certSign", "crlSign"}, PQCReadiness: "vulnerable",
			ValidFrom: now.Format(time.RFC3339), ValidUntil: now.Add(3650 * 24 * time.Hour).Format(time.RFC3339),
		},
		{
			FingerprintSHA256: "cs", CommonName: "release-signing", PublicKeyAlgorithm: "RSA",
			ExtendedKeyUsage: []string{"codeSigning"}, PQCReadiness: "vulnerable",
			ValidFrom: now.Format(time.RFC3339), ValidUntil: now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		},
		{
			FingerprintSHA256: "safe", CommonName: "pqc.example", PublicKeyAlgorithm: "ML-DSA-65",
			PQCReadiness: "quantum_safe",
			ValidFrom:    now.Format(time.RFC3339), ValidUntil: now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
		},
	}}

	mux := http.NewServeMux()
	registerPQCMigrationHandler(mux, auth, certs, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/pqc-migration", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data pqc.MigrationRoadmap `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	d := resp.Data
	if d.TotalCerts != 3 {
		t.Fatalf("total certs: got %d", d.TotalCerts)
	}
	if d.QuantumSafe != 1 {
		t.Errorf("quantum-safe: got %d", d.QuantumSafe)
	}
	// CA + code-signing are the two vulnerable items, both critical, sorted first.
	if len(d.Items) != 2 {
		t.Fatalf("expected 2 roadmap items, got %d", len(d.Items))
	}
	if d.Items[0].Priority != "critical" || d.Items[1].Priority != "critical" {
		t.Errorf("expected both critical, got %s / %s", d.Items[0].Priority, d.Items[1].Priority)
	}
}

func TestPQCMigrationHandler_TimelineInPayload(t *testing.T) {
	auth := newReportsTestAuth(t)
	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "a", PQCReadiness: "vulnerable", ValidFrom: now.Format(time.RFC3339), ValidUntil: now.Add(30 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "b", PQCReadiness: "vulnerable", ValidFrom: now.Format(time.RFC3339), ValidUntil: time.Date(2035, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)},
	}}
	mux := http.NewServeMux()
	registerPQCMigrationHandler(mux, auth, certs, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/pqc-migration", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var resp struct {
		Data struct {
			Timeline *pqc.Timeline `json:"timeline"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tl := resp.Data.Timeline
	if tl == nil || tl.Quarters == nil {
		t.Fatalf("timeline missing from payload: %s", rec.Body.String())
	}
	if tl.ExpireAfter2030 != 1 {
		t.Errorf("expire_after_2030 = %d, want 1", tl.ExpireAfter2030)
	}
	if tl.ExpireBefore2030+tl.ExpireAfter2030 != 2 {
		t.Errorf("split does not cover inventory: %+v", tl)
	}
}

func TestPQCMigrationHandler_RequiresAuth(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerPQCMigrationHandler(mux, auth, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/pqc-migration", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestIsCACert(t *testing.T) {
	if !isCACert(CertificateItem{KeyUsage: []string{"certSign"}}) {
		t.Error("expected CA detection for certSign")
	}
	if isCACert(CertificateItem{KeyUsage: []string{"digitalSignature"}}) {
		t.Error("non-CA should not be detected as CA")
	}
}
