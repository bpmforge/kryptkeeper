// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGCPListCertificates(t *testing.T) {
	page := gcpCertListResponse{
		Certificates: []gcpCert{
			{
				Name:       "projects/my-project/locations/global/certificates/web-cert",
				ExpireTime: "2026-12-31T00:00:00Z",
				CreateTime: "2025-01-01T00:00:00Z",
				Managed: struct {
					Domains                  []string `json:"domains"`
					State                    string   `json:"state"`
					AuthorizationAttemptInfo []struct {
						Domain string `json:"domain"`
						State  string `json:"state"`
					} `json:"authorizationAttemptInfo"`
				}{
					Domains: []string{"web.example.com", "www.example.com"},
					State:   "ACTIVE",
				},
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

	c := &GCPCertManagerConnector{
		client:    srv.Client(),
		projectID: "my-project",
		region:    "global",
		token:     "test-token",
		apiBase:   srv.URL,
	}

	certs, err := c.ListCertificates(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName != "web.example.com" {
		t.Errorf("unexpected common name %q", certs[0].CommonName)
	}
	if certs[0].Status != "active" {
		t.Errorf("unexpected status %q", certs[0].Status)
	}
	if certs[0].NotAfter.IsZero() {
		t.Error("expected non-zero NotAfter")
	}
}

func TestGCPListCertificatesErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	c := &GCPCertManagerConnector{
		client:    srv.Client(),
		projectID: "my-project",
		region:    "global",
		token:     "test-token",
		apiBase:   srv.URL,
	}

	_, err := c.ListCertificates(t.Context())
	if err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestGCPGetTokenFromEnv(t *testing.T) {
	t.Setenv("GOOGLE_ACCESS_TOKEN", "env-token-value")
	token, err := gcpGetToken(t.Context())
	if err != nil {
		t.Fatalf("gcpGetToken: %v", err)
	}
	if token != "env-token-value" {
		t.Errorf("expected env-token-value, got %q", token)
	}
}

func TestNewGCPCertManagerConnectorMissingProjectID(t *testing.T) {
	t.Setenv("GCP_PROJECT_ID", "")
	_, err := NewGCPCertManagerConnector(t.Context())
	if err == nil {
		t.Error("expected error when GCP_PROJECT_ID is missing")
	}
}

func TestGCPCertDNSNames(t *testing.T) {
	cert := gcpCert{
		Managed: struct {
			Domains                  []string `json:"domains"`
			State                    string   `json:"state"`
			AuthorizationAttemptInfo []struct {
				Domain string `json:"domain"`
				State  string `json:"state"`
			} `json:"authorizationAttemptInfo"`
		}{Domains: []string{"a.example.com", "b.example.com"}},
		SanDnsnames: []string{"b.example.com", "c.example.com"}, // b is duplicate
	}
	names := gcpCertDNSNames(cert)
	if len(names) != 3 { // a, b, c — b deduplicated
		t.Errorf("expected 3 unique names, got %d: %v", len(names), names)
	}
}

func TestGCPCertDNSNamesEmpty(t *testing.T) {
	cert := gcpCert{}
	names := gcpCertDNSNames(cert)
	if names != nil {
		t.Errorf("expected nil for empty cert, got %v", names)
	}
}

func TestGCPCertCommonName(t *testing.T) {
	cases := []struct {
		cert gcpCert
		want string
	}{
		{
			gcpCert{Managed: struct {
				Domains                  []string `json:"domains"`
				State                    string   `json:"state"`
				AuthorizationAttemptInfo []struct {
					Domain string `json:"domain"`
					State  string `json:"state"`
				} `json:"authorizationAttemptInfo"`
			}{Domains: []string{"api.example.com"}}},
			"api.example.com",
		},
		{
			gcpCert{
				Name:        "projects/p/locations/global/certificates/my-cert",
				SanDnsnames: []string{"san.example.com"},
			},
			"san.example.com",
		},
		{
			gcpCert{Name: "projects/p/locations/global/certificates/fallback-name"},
			"fallback-name",
		},
	}
	for _, tc := range cases {
		if got := gcpCertCommonName(tc.cert); got != tc.want {
			t.Errorf("gcpCertCommonName got %q, want %q", got, tc.want)
		}
	}
}
