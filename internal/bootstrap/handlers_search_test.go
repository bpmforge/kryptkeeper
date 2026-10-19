// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
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

// perfCertProvider pages over an in-memory inventory so ForEachCertificate
// walks it exactly as it would a real provider.
type perfCertProvider struct {
	CertificateProvider
	items []CertificateItem
}

func (p *perfCertProvider) ListCertificates(_ context.Context, q CertificateListQuery) (CertificateListResult, error) {
	lo := q.Offset
	if lo > len(p.items) {
		lo = len(p.items)
	}
	hi := len(p.items)
	if q.Limit > 0 && lo+q.Limit < hi {
		hi = lo + q.Limit
	}
	return CertificateListResult{Items: p.items[lo:hi], Total: len(p.items), Limit: q.Limit}, nil
}

func searchTestCert(n int, caID string) CertificateItem {
	sum := sha256.Sum256([]byte(fmt.Sprintf("cert-%d", n)))
	return CertificateItem{
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		CommonName:        fmt.Sprintf("host-%d.example.test", n),
		SubjectAltNames:   []string{fmt.Sprintf("san-%d.example.test", n)},
		OwnerEmail:        fmt.Sprintf("owner-%d@example.test", n),
		CAID:              caID,
		ValidFrom:         "2026-01-01T00:00:00Z",
	}
}

func newSearchMux(t *testing.T, certs CertificateProvider, audit AuditProvider) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "search-token")
	mux := http.NewServeMux()
	registerSearchHandlers(mux, NewAuthenticatorFromEnv(), certs, stubCAProvider{}, NewFileTemplateProviderFromEnv(), nil, audit)
	return mux
}

func searchDo(t *testing.T, mux *http.ServeMux, q string) []searchResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q="+url.QueryEscape(q), nil)
	req.Header.Set("Authorization", "Bearer search-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("search %q: %d %s", q, rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []searchResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data
}

func TestCertMatchesSearchFields(t *testing.T) {
	c := CertificateItem{
		FingerprintSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		CommonName:        "Web.Example.com",
		SubjectDN:         "CN=Web.Example.com,O=Acme Corp",
		SubjectAltNames:   []string{"alt.example.org"},
		URISANs:           []string{"spiffe://trust.example/svc/payments"},
		OwnerEmail:        "Alice@Example.com",
		OwnerTeam:         "Platform",
	}
	cases := []struct {
		q    string
		want bool
	}{
		{"web.example", true}, {"WEB.EXAMPLE", true}, {"alt.example.org", true},
		{"spiffe://trust.example/svc", true}, {"o=acme", true}, {"alice@example", true},
		{"platform", true}, {c.FingerprintSHA256, true}, {"abcdef01", true},
		{"ab:cd:ef:01:23", true}, {"abcdef0", false}, {"nothing-like-this", false},
	}
	for _, tc := range cases {
		if got := certMatchesSearch(c, strings.ToLower(tc.q)); got != tc.want {
			t.Errorf("certMatchesSearch(%q) = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestSearchFindsCertByCNSANFingerprintOwner(t *testing.T) {
	prov := &perfCertProvider{}
	for i := 0; i < 5; i++ {
		prov.items = append(prov.items, searchTestCert(i, "ca-a"))
	}
	mux := newSearchMux(t, prov, stubAuditProvider{})
	target := prov.items[3]
	for name, q := range map[string]string{
		"cn": "host-3.example", "san": "san-3.example", "fingerprint": target.FingerprintSHA256[:16], "owner": "owner-3@example",
	} {
		n := 0
		for _, r := range searchDo(t, mux, q) {
			if r.Kind == "certificate" {
				n++
				if r.ID != target.FingerprintSHA256 {
					t.Errorf("%s: wrong cert %s", name, r.ID)
				}
			}
		}
		if n != 1 {
			t.Errorf("%s: expected exactly 1 certificate result, got %d", name, n)
		}
	}
}

func TestSearchP95Under1sOn10kCerts(t *testing.T) {
	prov := &perfCertProvider{}
	for i := 0; i < 10000; i++ {
		prov.items = append(prov.items, searchTestCert(i, "ca-a"))
	}
	t.Setenv("SEARCH_AUDIT_SAMPLE_RATE", "0")
	mux := newSearchMux(t, prov, stubAuditProvider{})
	var durs []time.Duration
	for i := 0; i < 25; i++ {
		n := 400*i + 7 + i%3 // spread targets, including the tail of the inventory
		target := prov.items[n]
		for _, q := range []string{
			fmt.Sprintf("host-%d.example.test", n), fmt.Sprintf("san-%d.example.test", n),
			target.FingerprintSHA256, fmt.Sprintf("owner-%d@example.test", n),
		} {
			start := time.Now()
			got := searchDo(t, mux, q)
			durs = append(durs, time.Since(start))
			found := false
			for _, r := range got {
				found = found || r.ID == target.FingerprintSHA256
			}
			if !found {
				t.Fatalf("query %q did not find cert %d", q, n)
			}
		}
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	p95 := durs[94]
	t.Logf("p95=%v max=%v", p95, durs[99])
	if p95 >= time.Second {
		t.Fatalf("search p95 %v >= 1s on 10,000 certs", p95)
	}
}

func TestSearchAuditSampled(t *testing.T) {
	prov := &perfCertProvider{items: []CertificateItem{searchTestCert(1, "ca-a")}}
	run := func(rate string) *recordingAuditProvider {
		t.Setenv("SEARCH_AUDIT_SAMPLE_RATE", rate)
		rec := &recordingAuditProvider{}
		mux := newSearchMux(t, prov, rec)
		for i := 0; i < 20; i++ {
			searchDo(t, mux, "owner-1@example.test")
		}
		return rec
	}
	if n := run("0").count("search.query"); n != 0 {
		t.Fatalf("rate 0: %d rows", n)
	}
	if n := run("1").count("search.query"); n != 20 {
		t.Fatalf("rate 1: %d rows", n)
	}
	orig := searchSampleFloat
	t.Cleanup(func() { searchSampleFloat = orig })
	flip := false
	searchSampleFloat = func() float64 {
		flip = !flip
		if flip {
			return 0.2
		}
		return 0.7
	}
	rec := run("0.5")
	if n := rec.count("search.query"); n != 10 {
		t.Fatalf("rate 0.5 alternating: %d rows, want 10", n)
	}
	for _, e := range rec.entries {
		if !strings.Contains(e.ChangeSummary, "query_len") || strings.Contains(e.ChangeSummary, "owner-1") {
			t.Fatalf("bad audit detail: %q", e.ChangeSummary)
		}
	}
}

func TestSearchAuditRateParsing(t *testing.T) {
	for in, want := range map[string]float64{"": 0.1, "abc": 0.1, "-1": 0.1, "2": 0.1, "0.25": 0.25, "0": 0} {
		t.Setenv("SEARCH_AUDIT_SAMPLE_RATE", in)
		if got := searchAuditSampleRate(); got != want {
			t.Errorf("rate %q = %v, want %v", in, got, want)
		}
	}
}

type searchTenantStub struct {
	TenantStore
	byCA map[string]string
}

func (s searchTenantStub) CATenant(_ context.Context, caID string) (string, error) {
	t, ok := s.byCA[caID]
	if !ok {
		return "", fmt.Errorf("unknown ca %s", caID)
	}
	return t, nil
}

func TestSearchTenantScopedMatchesNothingForeign(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	prev := activeTenantStore
	setActiveTenantStore(searchTenantStub{byCA: map[string]string{"ca-a": "acme", "ca-b": "globex"}})
	t.Cleanup(func() { setActiveTenantStore(prev) })

	a, b, orphan := searchTestCert(1, "ca-a"), searchTestCert(2, "ca-b"), searchTestCert(3, "ca-gone")
	for _, c := range []*CertificateItem{&a, &b, &orphan} {
		c.SubjectAltNames = append(c.SubjectAltNames, "shared.example.test")
		c.OwnerTeam = "platform"
	}
	prov := &perfCertProvider{items: []CertificateItem{a, b, orphan}}
	ctx := context.Background()
	acme := AuthPrincipal{Tenant: "acme", TenantScoped: true}

	for _, q := range []string{"shared.example.test", "platform", b.FingerprintSHA256, a.FingerprintSHA256} {
		got, err := searchCertificates(ctx, acme, prov, q, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range got {
			if c.CAID != "ca-a" {
				t.Fatalf("query %q leaked %s (CA %s) to acme", q, c.CommonName, c.CAID)
			}
		}
		wantN := 1
		if q == b.FingerprintSHA256 {
			wantN = 0
		}
		if len(got) != wantN {
			t.Fatalf("query %q: %d results, want %d", q, len(got), wantN)
		}
	}
	all, err := searchCertificates(ctx, AuthPrincipal{SuperAdmin: true}, prov, "platform", 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("unscoped super-admin should see all 3, got %d (%v)", len(all), err)
	}
}
