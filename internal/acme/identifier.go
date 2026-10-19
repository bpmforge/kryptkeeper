// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"kryptkeeper/internal/ca"
)

// normalizeDNSIdentifier lower-cases v and validates it as a certifiable DNS
// name. The CA signs exactly what this accepts, so it is deliberately
// narrower than DNS itself: no IP literals, ports, trailing dots,
// underscores, or localhost. Single-label names (an intranet host such as
// "fileserver") are allowed: this is an internal CA and http-01/dns-01 still
// prove control; only a wildcard needs two labels under it, so "*.corp"
// cannot cover a whole internal namespace. One leading "*." wildcard label
// is allowed (RFC 8555 §7.1.3); the returned base has it stripped.
func normalizeDNSIdentifier(v string) (value, base string, wildcard bool, err error) {
	value = strings.ToLower(v)
	if value == "" || len(value) > 253 {
		return "", "", false, errors.New("identifier must be 1-253 characters")
	}
	base = value
	if rest, ok := strings.CutPrefix(value, "*."); ok {
		base, wildcard = rest, true
	}
	if _, perr := netip.ParseAddr(base); perr == nil {
		return "", "", false, errors.New("IP addresses are not accepted as identifiers")
	}
	if base == "localhost" || strings.HasSuffix(base, ".localhost") {
		return "", "", false, errors.New("localhost names are not accepted (RFC 6761)")
	}
	labels := strings.Split(base, ".")
	if wildcard && len(labels) < 2 {
		return "", "", false, errors.New("a wildcard needs at least two labels under it")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", "", false, errors.New("labels must be 1-63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", "", false, errors.New("labels must not start or end with a hyphen")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", "", false, errors.New("labels may contain only a-z, 0-9 and hyphen")
			}
		}
	}
	// An all-numeric final label is how non-canonical IPv4 forms ("127.1")
	// look; no public or private TLD is numeric.
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" {
		return "", "", false, errors.New("final label must not be numeric")
	}
	return value, base, wildcard, nil
}

// validateAllowEntry checks one provisioner allow-list entry: lowercase, with
// an optional "*." prefix, the remainder a certifiable DNS name.
func validateAllowEntry(e string) (string, error) {
	if e != strings.ToLower(strings.TrimSpace(e)) {
		return "", errors.New("must be lowercase with no surrounding space")
	}
	rest := strings.TrimPrefix(e, "*.")
	if _, _, wild, err := normalizeDNSIdentifier(rest); err != nil {
		return "", err
	} else if wild {
		return "", errors.New("only one leading *. is allowed")
	}
	return e, nil
}

// errBadCSR is the finalize-time CSR rejection; its text is returned to the
// client as the badCSR problem detail.
type errBadCSR string

func (e errBadCSR) Error() string { return string(e) }

// checkFinalizeCSR enforces RFC 8555 §7.4: the names the CSR asks for must be
// exactly the validated order identifiers, and nothing the order did not
// validate (IP, URI, email SANs) may ride along. A CSR signed by the
// account key is refused because it would make the account key the
// certificate key (RFC 8555 §11.1).
func checkFinalizeCSR(csr *x509.CertificateRequest, identifiers []string, accountKey crypto.PublicKey) error {
	if err := csr.CheckSignature(); err != nil {
		return errBadCSR("CSR signature invalid")
	}
	if err := ca.CheckPublicKeyStrength(csr.PublicKey); err != nil {
		return errBadCSR("key too weak: " + err.Error())
	}
	if len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return errBadCSR("CSR must not contain IP, URI or email subject alternative names")
	}
	if accountKey != nil {
		a, aerr := x509.MarshalPKIXPublicKey(accountKey)
		c, cerr := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if aerr == nil && cerr == nil && bytes.Equal(a, c) {
			return errBadCSR("CSR must not reuse the account key")
		}
	}
	want := make(map[string]bool, len(identifiers))
	for _, id := range identifiers {
		want[strings.ToLower(id)] = true
	}
	got := make(map[string]bool)
	for _, n := range csr.DNSNames {
		got[strings.ToLower(n)] = true
	}
	if csr.Subject.CommonName != "" {
		got[strings.ToLower(csr.Subject.CommonName)] = true
	}
	if len(got) != len(want) {
		return errBadCSR(fmt.Sprintf("CSR names do not match the order identifiers (%d requested, %d ordered)", len(got), len(want)))
	}
	for n := range got {
		if !want[n] {
			return errBadCSR("CSR contains a name that is not an order identifier")
		}
	}
	return nil
}

// sortedIdentifierValues returns the order's identifier values, sorted so the
// certificate CN (first entry) is deterministic.
func sortedIdentifierValues(idents []Identifier) []string {
	out := make([]string, 0, len(idents))
	for _, id := range idents {
		out = append(out, id.Value)
	}
	sort.Strings(out)
	return out
}
