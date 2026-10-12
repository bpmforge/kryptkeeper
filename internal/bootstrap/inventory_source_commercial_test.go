// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// W13-05: the four commercial sources against recorded fixtures —
// auth shapes, listing+detail paths, paging, and status mapping.

func commercialCreds(t *testing.T, payload string) OutboundCredentialStore {
	t.Helper()
	return &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-c", CredentialType: CredentialTypeAPIToken},
		payload: []byte(payload),
	}
}

func TestSectigoSourcePagingAndStatus(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("login") != "api-user" || r.Header.Get("password") != "api-pass" || r.Header.Get("customerUri") != "acme" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/ssl/v1/collect/"):
			_, _ = fmt.Fprintf(w, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/ssl/v1/collect/"), "/x509CO"))
		case r.URL.Path == "/api/ssl/v1":
			if strings.Contains(r.URL.RawQuery, "position=0") {
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{"sslId": 1, "commonName": "a.example.com", "status": "Issued"},
					{"sslId": 2, "commonName": "b.example.com", "status": "Revoked"},
					{"sslId": 3, "commonName": "c.example.com", "status": "Requested"}, // skipped
				})
			} else {
				_ = json.NewEncoder(w).Encode([]map[string]any{})
			}
		}
	}))
	t.Cleanup(srv.Close)

	src, err := newSectigoSource(context.Background(),
		fmt.Sprintf(`{"base_url":%q,"customer_uri":"acme"}`, srv.URL),
		"cred-c", commercialCreds(t, `{"login":"api-user","password":"api-pass"}`))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	// point at the fixture's client-free default; replace transport
	src.(*sectigoSource).client = srv.Client()
	certs, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected issued+revoked (requested skipped), got %d", len(certs))
	}
	if certs[0].UpstreamStatus != "active" || certs[1].UpstreamStatus != "revoked" {
		t.Fatalf("status mapping: %+v", certs)
	}
	if !strings.Contains(certs[0].PEM, "BEGIN CERTIFICATE") {
		t.Fatalf("collect must return PEM: %q", certs[0].PEM)
	}
}

func TestEntrustSourceListsAndDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer entrust-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/cvs/api/v1/certificates":
			_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{
				{"trackingId": 10, "status": "ACTIVE"},
				{"trackingId": 11, "status": "PENDING"}, // skipped
			}})
		case "/cvs/api/v1/certificates/10":
			_ = json.NewEncoder(w).Encode(map[string]any{"certificate": "-----BEGIN CERTIFICATE-----\nMTA=\n-----END CERTIFICATE-----"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	src, err := newEntrustSource(context.Background(),
		fmt.Sprintf(`{"base_url":%q}`, srv.URL),
		"cred-c", commercialCreds(t, `{"api_key":"entrust-key"}`))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	src.(*entrustSource).client = srv.Client()
	certs, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(certs) != 1 || certs[0].UpstreamStatus != "active" || !strings.Contains(certs[0].PEM, "BEGIN CERTIFICATE") {
		t.Fatalf("entrust results: %+v", certs)
	}
}

func TestAWSPCASourceSignsAndInventoriesAuthorities(t *testing.T) {
	var authHeaders, targets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		target := r.Header.Get("X-Amz-Target")
		targets = append(targets, target)
		switch target {
		case "ACMPrivateCA.ListCertificateAuthorities":
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateAuthorities": []map[string]any{
				{"Arn": "arn:aws:acm-pca:us-east-1:123:certificate-authority/ca-1", "Status": "ACTIVE"},
				{"Arn": "arn:aws:acm-pca:us-east-1:123:certificate-authority/ca-2", "Status": "DISABLED"},
			}})
		case "ACMPrivateCA.GetCertificateAuthorityCertificate":
			_ = json.NewEncoder(w).Encode(map[string]any{"Certificate": "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----"})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	src, err := newAWSPCASource(context.Background(),
		fmt.Sprintf(`{"region":"us-east-1","endpoint":%q}`, srv.URL),
		"cred-c", commercialCreds(t, `{"access_key_id":"AKIATEST","secret_access_key":"sekrit"}`))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	src.(*awsPCASource).client = srv.Client()
	certs, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(certs) != 2 || certs[0].UpstreamStatus != "active" || certs[1].UpstreamStatus != "revoked" {
		t.Fatalf("pca results: %+v", certs)
	}
	// SigV4: credential scope names acm-pca, and the JSON-RPC pair is right.
	if !strings.Contains(authHeaders[0], "AWS4-HMAC-SHA256") || !strings.Contains(authHeaders[0], "acm-pca") {
		t.Fatalf("request must be SigV4-signed for acm-pca: %q", authHeaders[0])
	}
	if targets[0] != "ACMPrivateCA.ListCertificateAuthorities" {
		t.Fatalf("targets: %v", targets)
	}
}

func TestGCPCASSourcePagingAndRevocation(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.Path, "/projects/proj/locations/us-central1/caPools/pool-1/certificates") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		page++
		if page == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificates": []map[string]any{
					{"pemCertificate": "-----BEGIN CERTIFICATE-----\nR0NQ\n-----END CERTIFICATE-----"},
				},
				"nextPageToken": "tok2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{
				{"pemCertificate": "-----BEGIN CERTIFICATE-----\nUkVW\n-----END CERTIFICATE-----",
					"revocationDetails": map[string]any{"revocationState": "REVOKED"}},
			},
		})
	}))
	t.Cleanup(srv.Close)

	src, err := newGCPCASSource(context.Background(),
		fmt.Sprintf(`{"base_url":%q,"project":"proj","location":"us-central1","ca_pool":"pool-1"}`, srv.URL),
		"cred-c", commercialCreds(t, "gcp-token"))
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	src.(*gcpCASSource).client = srv.Client()
	certs, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(certs) != 2 || certs[0].UpstreamStatus != "active" || certs[1].UpstreamStatus != "revoked" {
		t.Fatalf("cas results (paging + revocation): %+v", certs)
	}
}

func TestCommercialSourceTypesRegistered(t *testing.T) {
	for _, typ := range []string{"sectigo", "entrust", "aws_pca", "gcp_cas"} {
		if !validInventorySourceTypes[typ] {
			t.Fatalf("type %q not registered", typ)
		}
	}
}
