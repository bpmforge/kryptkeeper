// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestNamePolicyValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *NamePolicy
		ok   bool
	}{
		{"nil", nil, true},
		{"empty", &NamePolicy{}, true},
		{"suffixes", &NamePolicy{AllowedDNSSuffixes: []string{".corp.example", "example.com"}}, true},
		{"bare dot suffix", &NamePolicy{AllowedDNSSuffixes: []string{"."}}, false},
		{"blank suffix", &NamePolicy{AllowedDNSSuffixes: []string{"  "}}, false},
		{"wildcard in suffix", &NamePolicy{AllowedDNSSuffixes: []string{"*.example.com"}}, false},
		{"suffix with slash", &NamePolicy{AllowedDNSSuffixes: []string{"example.com/x"}}, false},
		{"exact name", &NamePolicy{AllowedDNSNames: []string{"exact.example"}}, true},
		{"exact name leading dot", &NamePolicy{AllowedDNSNames: []string{".exact.example"}}, false},
		{"uri prefix with uris", &NamePolicy{AllowURISANs: true, AllowedURIPrefixes: []string{"spiffe://prod.example/"}}, true},
		{"uri prefix without allow", &NamePolicy{AllowedURIPrefixes: []string{"spiffe://prod.example/"}}, false},
		{"uri prefix not a uri", &NamePolicy{AllowURISANs: true, AllowedURIPrefixes: []string{"prod.example"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.p.Validate(); (err == nil) != tc.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestDNSNameMatchesSuffixes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		suffixes []string
		want     bool
	}{
		{"a.corp.example", []string{".corp.example"}, true},
		{"corp.example", []string{".corp.example"}, false}, // leading dot: strictly below
		{"evilcorp.example", []string{".corp.example"}, false},
		{"corp.example", []string{"corp.example"}, true}, // no dot: the name itself
		{"a.b.corp.example", []string{"corp.example"}, true},
		{"notcorp.example", []string{"corp.example"}, false},
		{"A.CORP.Example.", []string{".corp.example"}, true}, // case + trailing dot
		{"corp.example.evil.com", []string{".corp.example"}, false},
		{"*.corp.example", []string{".corp.example"}, true},
		{"*.example", []string{".corp.example"}, false},
		{"*.corp.example", []string{"corp.example"}, true},
		{"x.other", []string{".corp.example", "example.com"}, false},
	} {
		if got := DNSNameMatchesSuffixes(tc.name, tc.suffixes); got != tc.want {
			t.Errorf("DNSNameMatchesSuffixes(%q, %v) = %v, want %v", tc.name, tc.suffixes, got, tc.want)
		}
	}
}

func nameCSR(t *testing.T, cn string, dns []string, ips []net.IP, uris []string) *x509.CertificateRequest {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var us []*url.URL
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		us = append(us, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: dns, IPAddresses: ips, URIs: us,
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// SUP-A04-3: the engine refuses names outside the template's name policy and
// lets a template without one issue as before.
func TestIssueCertificate_NamePolicy(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("NP Root", pkix.Name{CommonName: "NP Root CA"}, "ECDSA-P256", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	suffixOnly := &NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}, AllowedDNSNames: []string{"exact.example"}}
	spiffe := &NamePolicy{AllowURISANs: true, AllowedURIPrefixes: []string{"spiffe://prod.example/"}}
	cnBound := &NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}, CNMustBeSAN: true}
	ip := []net.IP{net.ParseIP("10.0.0.1")}

	for _, tc := range []struct {
		name string
		np   *NamePolicy
		csr  *x509.CertificateRequest
		ok   bool
	}{
		{"no name policy, any names", nil, nameCSR(t, "x", []string{"anything.evil"}, ip, []string{"spiffe://x/y"}), true},
		{"suffix match", suffixOnly, nameCSR(t, "", []string{"a.corp.example"}, nil, nil), true},
		{"exact match", suffixOnly, nameCSR(t, "", []string{"exact.example"}, nil, nil), true},
		{"SAN outside suffixes", suffixOnly, nameCSR(t, "", []string{"a.corp.example", "www.evil.example"}, nil, nil), false},
		{"lookalike suffix", suffixOnly, nameCSR(t, "", []string{"evilcorp.example"}, nil, nil), false},
		{"IP SAN not allowed", suffixOnly, nameCSR(t, "", []string{"a.corp.example"}, ip, nil), false},
		{"IP SAN allowed", &NamePolicy{AllowIPSANs: true}, nameCSR(t, "", nil, ip, nil), true},
		{"URI SAN not allowed", suffixOnly, nameCSR(t, "", []string{"a.corp.example"}, nil, []string{"spiffe://prod.example/a"}), false},
		{"URI under prefix", spiffe, nameCSR(t, "", nil, nil, []string{"spiffe://prod.example/ns/a"}), true},
		{"URI outside prefix", spiffe, nameCSR(t, "", nil, nil, []string{"spiffe://evil.example/ns/a"}), false},
		{"CN is a SAN", cnBound, nameCSR(t, "a.corp.example", []string{"a.corp.example"}, nil, nil), true},
		{"CN not in SANs", cnBound, nameCSR(t, "victim.bank.example", []string{"a.corp.example"}, nil, nil), false},
		// RC1-C-01: default flags (CNMustBeSAN=false) must not let a CN bypass the DNS restriction.
		{"default flags: CN-only outside suffixes", suffixOnly, nameCSR(t, "victim.bank.example", nil, nil, nil), false},
		{"default flags: CN outside suffixes beside valid SAN", suffixOnly, nameCSR(t, "victim.bank.example", []string{"a.corp.example"}, nil, nil), false},
		{"default flags: CN-only inside suffixes", suffixOnly, nameCSR(t, "a.corp.example", nil, nil, nil), true},
		{"default flags: non-DNS CN refused when DNS restricted", suffixOnly, nameCSR(t, "Alice Smith", nil, nil, nil), false},
		{"no DNS restriction: free-text CN still fine", &NamePolicy{AllowIPSANs: true}, nameCSR(t, "Alice Smith", nil, nil, nil), true},
		{"CN with no SANs at all", cnBound, nameCSR(t, "victim.bank.example", nil, nil, nil), false},
		{"empty CN needs no SAN", cnBound, nameCSR(t, "", []string{"a.corp.example"}, nil, nil), true},
		{"free-text CN outside DNS restriction is refused (RC1-C-01)", suffixOnly, nameCSR(t, "free-text", []string{"a.corp.example"}, nil, nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := IssuanceRequest{CSR: tc.csr, Validity: 24 * time.Hour}
			if tc.np != nil {
				req.Policy = &TemplatePolicy{ID: "tpl", Names: tc.np}
			}
			_, err := engine.IssueCertificate(root.ID, req)
			if tc.ok && err != nil {
				t.Fatalf("expected issuance, got %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrPolicyViolation) {
				t.Fatalf("expected ErrPolicyViolation, got %v", err)
			}
		})
	}
}

// The check judges the names that will be signed: names a protocol supplies
// (CallerNamesOnly) and the Subject override are covered, not only the CSR.
func TestIssueCertificate_NamePolicyCoversCallerNamesAndSubject(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("NP2 Root", pkix.Name{CommonName: "NP2 Root CA"}, "ECDSA-P256", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pol := &TemplatePolicy{ID: "tpl", Names: &NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}, CNMustBeSAN: true}}
	csr := nameCSR(t, "", nil, nil, nil) // the CSR itself names nothing

	_, err = engine.IssueCertificate(root.ID, IssuanceRequest{CSR: csr, Policy: pol, CallerNamesOnly: true,
		DNSNames: []string{"host.evil.example"}})
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("caller-supplied DNS name outside suffixes: got %v", err)
	}
	_, err = engine.IssueCertificate(root.ID, IssuanceRequest{CSR: csr, Policy: pol, CallerNamesOnly: true,
		DNSNames: []string{"host.corp.example"}, Subject: &pkix.Name{CommonName: "other.corp.example"}})
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("Subject override CN outside SANs: got %v", err)
	}
	if _, err = engine.IssueCertificate(root.ID, IssuanceRequest{CSR: csr, Policy: pol, CallerNamesOnly: true,
		DNSNames: []string{"host.corp.example"}, Subject: &pkix.Name{CommonName: "host.corp.example"}}); err != nil {
		t.Fatalf("compliant caller names refused: %v", err)
	}
}
