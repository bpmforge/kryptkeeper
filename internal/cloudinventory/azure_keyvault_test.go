// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAzureKVListCertificates(t *testing.T) {
	exp := time.Now().Add(90 * 24 * time.Hour).Unix()
	page := azureCertListResponse{
		Value: []azureCertItem{
			{
				ID: "https://myvault.vault.azure.net/certificates/web-tls/abc123",
				Attributes: struct {
					Enabled   bool  `json:"enabled"`
					Created   int64 `json:"created"`
					Updated   int64 `json:"updated"`
					Expires   int64 `json:"exp"`
					NotBefore int64 `json:"nbf"`
				}{Enabled: true, Expires: exp},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()

	c := &AzureKVConnector{
		client:     srv.Client(),
		vaultURL:   srv.URL,
		token:      "test-token",
		apiVersion: "7.4",
	}

	certs, err := c.ListCertificates(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName != "web-tls" {
		t.Errorf("unexpected common name %q", certs[0].CommonName)
	}
	if certs[0].Status != "enabled" {
		t.Errorf("unexpected status %q", certs[0].Status)
	}
	if certs[0].NotAfter.IsZero() {
		t.Error("expected non-zero NotAfter")
	}
}

func TestAzureCertName(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"https://vault.azure.net/certificates/my-cert/version", "my-cert"},
		{"https://vault.azure.net/certificates/tls-cert", "tls-cert"},
		{"bare-name", "bare-name"},
	}
	for _, tc := range cases {
		if got := azureCertName(tc.id); got != tc.want {
			t.Errorf("azureCertName(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestAzureVaultRegion(t *testing.T) {
	got := azureVaultRegion("https://myvault.vault.azure.net")
	if got != "myvault.vault.azure.net" {
		t.Errorf("unexpected region %q", got)
	}
}

func TestAzureVaultRegionInvalidURL(t *testing.T) {
	got := azureVaultRegion("://invalid-url")
	if got == "" {
		t.Error("expected non-empty fallback for invalid URL")
	}
}

func TestAzureGetTokenMissingCreds(t *testing.T) {
	_, err := azureGetToken(t.Context(), "", "", "")
	if err == nil {
		t.Error("expected error for missing credentials")
	}
}

func TestNewAzureKVConnectorMissingVaultURL(t *testing.T) {
	t.Setenv("AZURE_KEYVAULT_URL", "")
	_, err := NewAzureKVConnector(t.Context())
	if err == nil {
		t.Error("expected error when AZURE_KEYVAULT_URL is missing")
	}
}

func TestAzureListPageNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	defer srv.Close()

	c := &AzureKVConnector{
		client:     srv.Client(),
		vaultURL:   srv.URL,
		token:      "bad-token",
		apiVersion: "7.4",
	}

	_, err := c.ListCertificates(t.Context())
	if err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestAzureKVPagination(t *testing.T) {
	exp := time.Now().Add(90 * 24 * time.Hour).Unix()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			json.NewEncoder(w).Encode(azureCertListResponse{
				Value: []azureCertItem{
					{ID: "https://vault.azure.net/certificates/cert-p2/v1", Attributes: struct {
						Enabled   bool  `json:"enabled"`
						Created   int64 `json:"created"`
						Updated   int64 `json:"updated"`
						Expires   int64 `json:"exp"`
						NotBefore int64 `json:"nbf"`
					}{Enabled: true, Expires: exp}},
				},
			})
		} else {
			json.NewEncoder(w).Encode(azureCertListResponse{
				Value: []azureCertItem{
					{ID: "https://vault.azure.net/certificates/cert-p1/v1", Attributes: struct {
						Enabled   bool  `json:"enabled"`
						Created   int64 `json:"created"`
						Updated   int64 `json:"updated"`
						Expires   int64 `json:"exp"`
						NotBefore int64 `json:"nbf"`
					}{Enabled: true, Expires: exp}},
				},
				NextLink: srvURL + "/certificates?api-version=7.4&page=2",
			})
		}
	}))
	srvURL = srv.URL
	defer srv.Close()

	c := &AzureKVConnector{
		client:     srv.Client(),
		vaultURL:   srv.URL,
		token:      "test-token",
		apiVersion: "7.4",
	}

	certs, err := c.ListCertificates(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs from 2 pages, got %d", len(certs))
	}
}
