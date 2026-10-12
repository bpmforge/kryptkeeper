// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// S-43 criterion 1 ("any surface"): the command palette renders the CA
// status string from this handler verbatim, so an expired-but-stored-
// active CA must project "expired" here too.

type searchStubCAProvider struct {
	CAProvider
	items []CAListItem
}

func (p *searchStubCAProvider) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: p.items, Total: len(p.items)}, nil
}

func expiredStoredActiveCA(id string) CAListItem {
	item := CAListItem{
		ID: id, Name: "Expired Root", DisplayName: "Expired Root",
		Type: "root", Status: "active",
	}
	item.Certificate = &struct {
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		SubjectDN         string `json:"subject_dn"`
		ValidFrom         string `json:"valid_from"`
		ValidUntil        string `json:"valid_until"`
		PublicKeyAlg      string `json:"public_key_algorithm"`
		KeySizeBits       int    `json:"key_size_bits"`
	}{
		FingerprintSHA256: "fp-" + id,
		SubjectDN:         "CN=Expired Root",
		ValidFrom:         "2020-01-01T00:00:00Z",
		ValidUntil:        "2021-01-01T00:00:00Z", // long lapsed
		PublicKeyAlg:      "ECDSA",
		KeySizeBits:       256,
	}
	return item
}

func TestSearchProjectsExpiredCAStatus(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "search-token")
	auth := NewAuthenticatorFromEnv()

	caProv := &searchStubCAProvider{items: []CAListItem{expiredStoredActiveCA("ca-lapsed")}}
	mux := http.NewServeMux()
	registerSearchHandlers(mux, auth, NewFileCertificateProviderFromEnv(), caProv, NewFileTemplateProviderFromEnv(), nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=expired", nil)
	req.Header.Set("Authorization", "Bearer search-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("search: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			Kind        string `json:"kind"`
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var found bool
	for _, r := range resp.Data {
		if r.Kind == "ca" && r.ID == "ca-lapsed" {
			found = true
			if !strings.Contains(r.Description, "Status: expired") {
				t.Fatalf("expired CA must present as expired in search, got %q", r.Description)
			}
			if strings.Contains(r.Description, "Status: active") {
				t.Fatalf("expired CA must not advertise active in search: %q", r.Description)
			}
		}
	}
	if !found {
		t.Fatalf("expired CA missing from search results: %s", rec.Body.String())
	}
}

type searchEndpointStub struct{ stubDiscoveryProvider }

func (searchEndpointStub) ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{Endpoints: []DiscoveryEndpoint{{
		ID: "ep-test-1", Hostname: "edge.internal", Port: 443, Protocol: "tls",
	}}, Total: 1}, nil
}

// The search handler had no endpoint producer at all — Discovery's "Open
// full search" link could never return the endpoint the user came from,
// and the UI's "endpoint" badge tone was a dead key.
func TestSearchFindsDiscoveredEndpoints(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerSearchHandlers(mux, auth, NewFileCertificateProviderFromEnv(), stubCAProvider{}, NewFileTemplateProviderFromEnv(), searchEndpointStub{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=edge", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []searchResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, r := range resp.Data {
		if r.Kind == "endpoint" {
			found = true
			if !strings.HasPrefix(r.URL, "/discovery/endpoints/") {
				t.Errorf("endpoint URL must deep-link the Discovery detail route, got %q", r.URL)
			}
		}
	}
	if !found {
		t.Fatalf("expected an endpoint result for %q, got %+v", "edge", resp.Data)
	}
}
