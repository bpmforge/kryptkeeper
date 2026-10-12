// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// name_policy.go — which names a template may put in a certificate
// (SUP-A04-3). TemplatePolicy used to bound algorithms, key size, validity and
// EKUs only, so any template let a requester name any host. The check runs on
// the names about to be signed (issueLeafCertificate), not on the CSR, so it
// covers classical/PQC/hybrid CSRs and protocol-supplied names alike.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// NamePolicy restricts the SANs and CN of certificates issued under a
// template. A template without one is unrestricted (existing behaviour). When
// present, IP and URI SANs are refused unless explicitly allowed; DNS names
// are restricted only when AllowedDNSSuffixes or AllowedDNSNames is non-empty.
type NamePolicy struct {
	// AllowedDNSSuffixes: ".x" matches any name below x (not x itself); "x"
	// (no leading dot) matches x and anything below it.
	AllowedDNSSuffixes []string `json:"allowed_dns_suffixes,omitempty"`
	// AllowedDNSNames matches exactly (case-insensitive, trailing dot ignored).
	AllowedDNSNames []string `json:"allowed_dns_names,omitempty"`
	AllowIPSANs     bool     `json:"allow_ip_sans,omitempty"`
	AllowURISANs    bool     `json:"allow_uri_sans,omitempty"`
	// AllowedURIPrefixes, when non-empty, limits URI SANs to those starting
	// with one of these (e.g. "spiffe://prod.example/"). Requires AllowURISANs.
	AllowedURIPrefixes []string `json:"allowed_uri_prefixes,omitempty"`
	// CNMustBeSAN requires a non-empty subject CN to equal one of the SANs,
	// so the CN cannot name something the SAN checks never saw. Even when
	// false, a CN outside the SANs must satisfy the DNS restriction whenever
	// one is configured (RC1-C-01).
	CNMustBeSAN bool `json:"cn_must_be_san,omitempty"`
}

// Validate rejects a malformed policy at template create/update time.
func (p *NamePolicy) Validate() error {
	if p == nil {
		return nil
	}
	for _, s := range p.AllowedDNSSuffixes {
		n := normalizeDNSName(s)
		if strings.Trim(n, ".") == "" || strings.ContainsAny(n, " /*@:") {
			return fmt.Errorf("name_policy: invalid allowed_dns_suffixes entry %q", s)
		}
	}
	for _, s := range p.AllowedDNSNames {
		n := normalizeDNSName(s)
		if n == "" || strings.ContainsAny(n, " /@:") || strings.HasPrefix(n, ".") {
			return fmt.Errorf("name_policy: invalid allowed_dns_names entry %q", s)
		}
	}
	for _, s := range p.AllowedURIPrefixes {
		if !strings.Contains(s, "://") || strings.TrimSpace(s) != s {
			return fmt.Errorf("name_policy: invalid allowed_uri_prefixes entry %q (want scheme://...)", s)
		}
	}
	if len(p.AllowedURIPrefixes) > 0 && !p.AllowURISANs {
		return errors.New("name_policy: allowed_uri_prefixes requires allow_uri_sans")
	}
	return nil
}

func normalizeDNSName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// DNSNameMatchesSuffixes reports whether name falls under one of the suffixes
// (".x" = strictly below x; "x" = x or below). A wildcard "*.y" is judged as
// the shallowest name it can stand for, so "*.corp.example" passes
// ".corp.example" but "*.example" does not.
func DNSNameMatchesSuffixes(name string, suffixes []string) bool {
	n := normalizeDNSName(name)
	if strings.HasPrefix(n, "*.") {
		n = "w" + n[1:]
	}
	for _, s := range suffixes {
		sfx := normalizeDNSName(s)
		if strings.HasPrefix(sfx, ".") {
			if strings.HasSuffix(n, sfx) && len(n) > len(sfx) {
				return true
			}
			continue
		}
		if n == sfx || strings.HasSuffix(n, "."+sfx) {
			return true
		}
	}
	return false
}

func (p *NamePolicy) dnsAllowed(name string) bool {
	if len(p.AllowedDNSSuffixes) == 0 && len(p.AllowedDNSNames) == 0 {
		return true
	}
	n := normalizeDNSName(name)
	for _, e := range p.AllowedDNSNames {
		if normalizeDNSName(e) == n {
			return true
		}
	}
	return DNSNameMatchesSuffixes(name, p.AllowedDNSSuffixes)
}

// Check returns the first way the names breach the policy, or nil.
func (p *NamePolicy) Check(dns []string, ips []net.IP, uris []*url.URL, cn string) *PolicyViolation {
	if p == nil {
		return nil
	}
	for _, d := range dns {
		if !p.dnsAllowed(d) {
			return &PolicyViolation{Field: "dns_names", Message: fmt.Sprintf("DNS name %q is not permitted by the template's name policy", d)}
		}
	}
	if len(ips) > 0 && !p.AllowIPSANs {
		return &PolicyViolation{Field: "ip_addresses", Message: "IP address SANs are not permitted by the template's name policy"}
	}
	if len(uris) > 0 && !p.AllowURISANs {
		return &PolicyViolation{Field: "uris", Message: "URI SANs are not permitted by the template's name policy"}
	}
	for _, u := range uris {
		if len(p.AllowedURIPrefixes) == 0 {
			break
		}
		ok := false
		for _, pre := range p.AllowedURIPrefixes {
			if strings.HasPrefix(u.String(), pre) {
				ok = true
				break
			}
		}
		if !ok {
			return &PolicyViolation{Field: "uris", Message: fmt.Sprintf("URI SAN %q is not under an allowed prefix", u.String())}
		}
	}
	if strings.TrimSpace(cn) != "" {
		inSANs := cnAmongSANs(cn, dns, ips, uris)
		if p.CNMustBeSAN && !inSANs {
			return &PolicyViolation{Field: "common_name", Message: fmt.Sprintf("subject CN %q is not among the certificate's SANs", cn)}
		}
		// RC1-C-01: a CN-only CSR (no SANs) skipped every DNS check under the
		// default CNMustBeSAN=false, and clients that still match on CN would
		// accept it. When the template restricts DNS names, a CN that is not
		// one of the (already checked) SANs is held to the same restriction,
		// so a non-DNS-shaped CN such as "Alice Smith" is refused there.
		if !inSANs && p.hasDNSRestriction() && !p.dnsAllowed(cn) {
			return &PolicyViolation{Field: "common_name", Message: fmt.Sprintf("subject CN %q is not permitted by the template's DNS name policy", cn)}
		}
	}
	return nil
}

func (p *NamePolicy) hasDNSRestriction() bool {
	return len(p.AllowedDNSSuffixes) > 0 || len(p.AllowedDNSNames) > 0
}

func cnAmongSANs(cn string, dns []string, ips []net.IP, uris []*url.URL) bool {
	cn = strings.TrimSpace(cn)
	for _, d := range dns {
		if normalizeDNSName(d) == normalizeDNSName(cn) {
			return true
		}
	}
	for _, ip := range ips {
		if ip.String() == cn {
			return true
		}
	}
	for _, u := range uris {
		if u.String() == cn {
			return true
		}
	}
	return false
}

// checkNamePolicy is the engine hook: tmpl carries the names that will be signed.
func checkNamePolicy(pol *TemplatePolicy, tmpl *x509.Certificate) error {
	if pol == nil || pol.Names == nil {
		return nil
	}
	if v := pol.Names.Check(tmpl.DNSNames, tmpl.IPAddresses, tmpl.URIs, tmpl.Subject.CommonName); v != nil {
		return fmt.Errorf("%w: %s (template %s)", ErrPolicyViolation, *v, pol.ID)
	}
	return nil
}
