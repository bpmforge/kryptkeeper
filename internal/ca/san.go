// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import "crypto/x509"

// SubjectAltNameStrings collects every SAN kind (DNS, IP, URI, email) off a
// certificate as strings, DNS first then IP then URI then email,
// deduplicated, never nil.
//
// Shared between internal/bootstrap (the dashboard/API issuance and renewal
// path) and internal/acme (the ACME issuance path): both persist a
// certificate's SANs as a flat []string for later re-derivation of a
// renewal CSR, and both used to build that list from cert.DNSNames alone,
// silently dropping IP/URI/email SANs from every renewal (W18-14, verified
// live 2026-09-10 with an IP SAN). acme must not import bootstrap, and
// bootstrap already imports ca, so this lives here as the one shared
// implementation rather than being duplicated in each caller.
func SubjectAltNameStrings(cert *x509.Certificate) []string {
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses))
	seen := make(map[string]struct{}, cap(sans))
	add := func(s string) {
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		sans = append(sans, s)
	}
	for _, dns := range cert.DNSNames {
		add(dns)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	for _, u := range cert.URIs {
		if u != nil {
			add(u.String())
		}
	}
	for _, email := range cert.EmailAddresses {
		add(email)
	}
	return sans
}
