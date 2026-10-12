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
)

func TestCodeSigningInventoryFiltersByEKU(t *testing.T) {
	auth := newReportsTestAuth(t)
	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		{
			FingerprintSHA256: "cs-1",
			CommonName:        "release-signing",
			ExtendedKeyUsage:  []string{"codeSigning"},
			ValidUntil:        now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
			Grade:             "A",
		},
		{
			FingerprintSHA256: "cs-expired",
			CommonName:        "old-signing",
			ExtendedKeyUsage:  []string{"codeSigning"},
			ValidUntil:        now.Add(-5 * 24 * time.Hour).Format(time.RFC3339),
		},
		{
			FingerprintSHA256: "tls-1",
			CommonName:        "web.example.com",
			ExtendedKeyUsage:  []string{"serverAuth"},
			ValidUntil:        now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
		},
	}}

	mux := http.NewServeMux()
	registerCodeSigningHandler(mux, auth, certs, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/code-signing", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data CodeSigningInventory `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Total != 2 {
		t.Fatalf("expected 2 code-signing certs, got %d", resp.Data.Total)
	}
	if resp.Data.Expired != 1 {
		t.Fatalf("expected 1 expired, got %d", resp.Data.Expired)
	}
	// TLS cert must be excluded.
	for _, c := range resp.Data.Certs {
		if c.FingerprintSHA256 == "tls-1" {
			t.Fatal("serverAuth cert leaked into code-signing inventory")
		}
	}
}

func TestCodeSigningInventoryRequiresAuth(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerCodeSigningHandler(mux, auth, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/code-signing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
