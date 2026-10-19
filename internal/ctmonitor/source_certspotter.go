// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// W24-20: second CT source, Cert Spotter (SSLMate) issuances API.
//
// Why not a raw RFC 6962 log: get-entries is positional (start/end indexes),
// so a log cannot be queried by domain; finding one domain's certificates
// would mean tailing every entry of every log (hundreds of millions). That is
// not a "second source for when crt.sh is down". Cert Spotter indexes the same
// logs by domain.
//
// Request shape verified against https://sslmate.com/help/reference/ct_search_api_v1
// (2026-10-15): GET /v1/issuances?domain=&include_subdomains=true&after=<id>,
// repeatable expand=, Bearer or Basic auth, JSON array ordered by discovery
// time, paginate with the last id until an empty array. issuer.name is an
// expandable field; the issuer is also read from the certificate itself as a
// fallback.

const (
	certSpotterMaxPages = 10
	certSpotterBase     = "https://api.certspotter.com"
)

type certSpotterSource struct {
	base   string
	apiKey string
	client *http.Client
}

// NewCertSpotterSource returns the Cert Spotter source. base "" =
// https://api.certspotter.com; apiKey "" = unauthenticated (hourly-limited).
func NewCertSpotterSource(base, apiKey string) CTSource {
	if base == "" {
		base = certSpotterBase
	}
	return &certSpotterSource{base: base, apiKey: apiKey, client: &http.Client{Timeout: 30 * time.Second}}
}

func (s *certSpotterSource) Name() string { return "certspotter" }

type certSpotterIssuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Issuer    struct {
		Name         string `json:"name"`
		FriendlyName string `json:"friendly_name"`
	} `json:"issuer"`
	CertDER string `json:"cert_der"`
}

func (s *certSpotterSource) Search(ctx context.Context, domain string) ([]CTEntry, error) {
	var out []CTEntry
	after := ""
	for page := 0; page < certSpotterMaxPages; page++ {
		items, err := s.fetchPage(ctx, domain, after)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return out, nil
		}
		for _, it := range items {
			e, err := certSpotterEntry(it)
			if err != nil {
				return nil, fmt.Errorf("certspotter issuance %s: %w", it.ID, err)
			}
			out = append(out, e)
		}
		after = items[len(items)-1].ID
	}
	return out, nil
}

func (s *certSpotterSource) fetchPage(ctx context.Context, domain, after string) ([]certSpotterIssuance, error) {
	q := url.Values{}
	q.Set("domain", domain)
	q.Set("include_subdomains", "true")
	q["expand"] = []string{"dns_names", "issuer", "issuer.name", "cert_der"}
	if after != "" {
		q.Set("after", after)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/v1/issuances?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter query for %s: %w", domain, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("certspotter rate limited")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("certspotter query for %s: HTTP %d", domain, resp.StatusCode)
	}
	var items []certSpotterIssuance
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("certspotter response for %s: %w", domain, err)
	}
	return items, nil
}

// certSpotterEntry takes the serial from the certificate itself, normalized
// like crt.sh's so the same certificate de-duplicates across sources.
func certSpotterEntry(it certSpotterIssuance) (CTEntry, error) {
	der, err := base64.StdEncoding.DecodeString(it.CertDER)
	if err != nil || len(der) == 0 {
		return CTEntry{}, errors.New("missing or invalid cert_der")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CTEntry{}, fmt.Errorf("parse cert_der: %w", err)
	}
	e := CTEntry{
		EntryID:    it.ID,
		CommonName: cert.Subject.CommonName,
		DNSNames:   it.DNSNames,
		Issuer:     firstNonEmpty(it.Issuer.Name, it.Issuer.FriendlyName, cert.Issuer.String()),
		Serial:     NormalizeSerial(cert.SerialNumber.Text(16)),
		NotBefore:  cert.NotBefore.UTC(),
		NotAfter:   cert.NotAfter.UTC(),
	}
	if len(e.DNSNames) == 0 {
		e.DNSNames = cert.DNSNames
	}
	// Prefer the API's dates when present (RFC 3339); the cert is the fallback.
	if t, err := time.Parse(time.RFC3339, it.NotAfter); err == nil {
		e.NotAfter = t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, it.NotBefore); err == nil {
		e.NotBefore = t.UTC()
	}
	return e, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
