// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateSPIFFEID(t *testing.T) {
	td := "example.org"
	if _, err := validateSPIFFEID("spiffe://example.org/ns/prod/sa/web", td); err != nil {
		t.Errorf("valid ID rejected: %v", err)
	}
	bad := map[string]string{
		"wrong scheme":       "https://example.org/x",
		"wrong trust domain": "spiffe://other.org/x",
		"no path":            "spiffe://example.org",
		"dotdot":             "spiffe://example.org/../etc",
	}
	for name, id := range bad {
		if _, err := validateSPIFFEID(id, td); err == nil {
			t.Errorf("%s: expected rejection for %q", name, id)
		}
	}
}

// spiffeTestSetup wires a real CA engine + trust domain and returns the mux.
func spiffeTestSetup(t *testing.T) *http.ServeMux {
	t.Helper()
	_, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	SetSPIFFEEngine(engine)
	t.Cleanup(func() { SetSPIFFEEngine(nil) })
	t.Setenv("SPIFFE_TRUST_DOMAIN", "example.org")
	t.Setenv("SPIFFE_SIGNING_CA_ID", caID)

	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerSPIFFEHandlers(mux, auth, &reportCAProvider{}, stubAuditProvider{})
	return mux
}

func TestSPIFFE_MintSVIDCarriesURISAN(t *testing.T) {
	mux := spiffeTestSetup(t)

	body, _ := json.Marshal(map[string]string{"spiffe_id": "spiffe://example.org/ns/prod/sa/checkout"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/svid", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			SPIFFEID  string `json:"spiffe_id"`
			SVIDPEM   string `json:"svid_pem"`
			KeyPEM    string `json:"key_pem"`
			BundlePEM string `json:"bundle_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(resp.Data.KeyPEM, "PRIVATE KEY") {
		t.Error("missing private key PEM")
	}
	if !strings.Contains(resp.Data.BundlePEM, "BEGIN CERTIFICATE") {
		t.Error("missing trust bundle PEM")
	}
	// The issued SVID must carry the SPIFFE ID as a URI SAN.
	block, _ := pem.Decode([]byte(resp.Data.SVIDPEM))
	if block == nil {
		t.Fatal("svid_pem is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse svid: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.org/ns/prod/sa/checkout" {
		t.Fatalf("SVID URI SAN wrong: %v", cert.URIs)
	}
	// SVID should support client + server auth.
	hasClient := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
	}
	if !hasClient {
		t.Error("SVID missing clientAuth EKU")
	}
}

func TestSPIFFE_RejectsForeignTrustDomain(t *testing.T) {
	mux := spiffeTestSetup(t)
	body, _ := json.Marshal(map[string]string{"spiffe_id": "spiffe://evil.example/x"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/svid", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign trust domain, got %d", rec.Code)
	}
}

func TestSPIFFE_BundleEndpoint(t *testing.T) {
	mux := spiffeTestSetup(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/spiffe/bundle", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("bundle is not PEM")
	}
}

func TestSPIFFE_DisabledWithoutConfig(t *testing.T) {
	SetSPIFFEEngine(nil)
	t.Setenv("SPIFFE_TRUST_DOMAIN", "")
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerSPIFFEHandlers(mux, auth, &reportCAProvider{}, stubAuditProvider{})

	body, _ := json.Marshal(map[string]string{"spiffe_id": "spiffe://example.org/x"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/svid", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when SPIFFE unconfigured, got %d", rec.Code)
	}
}

func TestSPIFFE_Status(t *testing.T) {
	mux := spiffeTestSetup(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/spiffe/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Data struct {
			Enabled        bool   `json:"enabled"`
			TrustDomain    string `json:"trust_domain"`
			SVIDTTLSeconds int    `json:"svid_ttl_seconds"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Data.Enabled || resp.Data.TrustDomain != "example.org" {
		t.Errorf("unexpected status: %+v", resp.Data)
	}
}
