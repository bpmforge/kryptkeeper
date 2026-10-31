// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// name_constraints.go — refuse, before signing, a certificate that its
// issuing CA's name constraints (RFC 5280 §4.2.1.10) would make invalid.
// Without this the CA signs it and the failure surfaces at the relying
// party, long after the requester has gone. crypto/x509 enforces DNS, IP,
// email and URI constraints only at verification time and does not handle
// directoryName at all (it leaves the extension in UnhandledCriticalExtensions),
// so the directoryName subtrees are parsed here.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var oidExtNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

// dirNameConstraints are the directoryName subtrees of one CA certificate.
// onlyKnown is false when the extension also holds a GeneralName form this
// package does not evaluate (otherName, x400Address, ediPartyName,
// registeredID).
type dirNameConstraints struct {
	permitted, excluded []pkix.RDNSequence
	onlyKnown           bool
}

// parseDirNameConstraints reads the directoryName subtrees from caCert's
// NameConstraints extension. ok is false when there is no such extension.
func parseDirNameConstraints(caCert *x509.Certificate) (dirNameConstraints, bool, error) {
	var raw []byte
	for _, e := range caCert.Extensions {
		if e.Id.Equal(oidExtNameConstraints) {
			raw = e.Value
			break
		}
	}
	if raw == nil {
		return dirNameConstraints{}, false, nil
	}
	out := dirNameConstraints{onlyKnown: true}
	var top asn1.RawValue
	if rest, err := asn1.Unmarshal(raw, &top); err != nil || len(rest) != 0 || top.Tag != asn1.TagSequence {
		return out, true, fmt.Errorf("invalid NameConstraints extension")
	}
	body := top.Bytes
	for len(body) > 0 {
		var subtrees asn1.RawValue
		var err error
		if body, err = asn1.Unmarshal(body, &subtrees); err != nil || subtrees.Class != asn1.ClassContextSpecific {
			return out, true, fmt.Errorf("invalid NameConstraints extension")
		}
		var dst *[]pkix.RDNSequence
		switch subtrees.Tag {
		case 0:
			dst = &out.permitted
		case 1:
			dst = &out.excluded
		default:
			return out, true, fmt.Errorf("invalid NameConstraints extension")
		}
		inner := subtrees.Bytes
		for len(inner) > 0 {
			var subtree asn1.RawValue
			if inner, err = asn1.Unmarshal(inner, &subtree); err != nil || subtree.Tag != asn1.TagSequence {
				return out, true, fmt.Errorf("invalid GeneralSubtree")
			}
			var base asn1.RawValue
			if _, err := asn1.Unmarshal(subtree.Bytes, &base); err != nil || base.Class != asn1.ClassContextSpecific {
				return out, true, fmt.Errorf("invalid GeneralSubtree base")
			}
			switch base.Tag {
			case 1, 2, 6, 7: // rfc822Name, dNSName, URI, iPAddress: crypto/x509 parsed these.
			case 4: // directoryName [4] EXPLICIT Name
				seq, err := parseRDNSequence(base.Bytes)
				if err != nil {
					return out, true, fmt.Errorf("invalid directoryName constraint: %w", err)
				}
				*dst = append(*dst, seq)
			default:
				out.onlyKnown = false
			}
		}
	}
	return out, true, nil
}

// nameConstraintViolation explains why a certificate falls outside an
// issuing CA's name constraints.
func nameConstraintViolation(caCert *x509.Certificate, detail, observed string) error {
	return &PolicyViolationError{
		Policy:   "issuing CA name constraints",
		Rule:     "name_constraints",
		Detail:   fmt.Sprintf("%s; the CA %q does not permit it (RFC 5280 name constraints), so the certificate would fail validation", detail, FormatRDNSequence(subjectSeq(caCert))),
		Observed: observed,
	}
}

func subjectSeq(c *x509.Certificate) pkix.RDNSequence {
	seq, err := parseRDNSequence(c.RawSubject)
	if err != nil {
		return c.Subject.ToRDNSequence()
	}
	return seq
}

// checkIssuerNameConstraints returns a PolicyViolationError when leaf (the
// template about to be signed) breaks a name constraint of any CA in chain.
// The subject is judged in its encoded form, so it must be the final one.
func checkIssuerNameConstraints(chain []*x509.Certificate, leaf *x509.Certificate) error {
	subject := leaf.Subject.ToRDNSequence()
	for _, c := range chain {
		if c == nil {
			continue
		}
		if err := checkOneCANameConstraints(c, subject, leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses, leaf.URIs); err != nil {
			return err
		}
	}
	return nil
}

func checkOneCANameConstraints(c *x509.Certificate, subject pkix.RDNSequence, dns []string, ips []net.IP, emails []string, uris []*url.URL) error {
	dn, has, err := parseDirNameConstraints(c)
	if err != nil {
		return nameConstraintViolation(c, "its NameConstraints extension cannot be read: "+err.Error(), "")
	}
	if !has {
		return nil
	}
	// RFC 5280: directoryName constraints apply to a non-empty subject.
	if len(subject) > 0 {
		if len(dn.permitted) > 0 && !dnUnderAny(subject, dn.permitted) {
			return nameConstraintViolation(c, fmt.Sprintf("subject %q is not under a permitted directoryName (%s)", FormatRDNSequence(subject), formatDNList(dn.permitted)), FormatRDNSequence(subject))
		}
		if dnUnderAny(subject, dn.excluded) {
			return nameConstraintViolation(c, fmt.Sprintf("subject %q is under an excluded directoryName", FormatRDNSequence(subject)), FormatRDNSequence(subject))
		}
	}
	for _, d := range dns {
		if len(c.PermittedDNSDomains) > 0 && !dnsUnderAnyConstraint(d, c.PermittedDNSDomains) {
			return nameConstraintViolation(c, fmt.Sprintf("DNS name %q is not under a permitted DNS subtree %v", d, c.PermittedDNSDomains), d)
		}
		if dnsUnderAnyConstraint(d, c.ExcludedDNSDomains) {
			return nameConstraintViolation(c, fmt.Sprintf("DNS name %q is under an excluded DNS subtree", d), d)
		}
	}
	for _, ip := range ips {
		if len(c.PermittedIPRanges) > 0 && !ipInAny(ip, c.PermittedIPRanges) {
			return nameConstraintViolation(c, fmt.Sprintf("IP address %s is not in a permitted range", ip), ip.String())
		}
		if ipInAny(ip, c.ExcludedIPRanges) {
			return nameConstraintViolation(c, fmt.Sprintf("IP address %s is in an excluded range", ip), ip.String())
		}
	}
	for _, e := range emails {
		if len(c.PermittedEmailAddresses) > 0 && !emailUnderAny(e, c.PermittedEmailAddresses) {
			return nameConstraintViolation(c, fmt.Sprintf("email address %q is not permitted", e), e)
		}
		if emailUnderAny(e, c.ExcludedEmailAddresses) {
			return nameConstraintViolation(c, fmt.Sprintf("email address %q is excluded", e), e)
		}
	}
	for _, u := range uris {
		host := u.Hostname()
		if len(c.PermittedURIDomains) > 0 && !dnsUnderAnyConstraint(host, c.PermittedURIDomains) {
			return nameConstraintViolation(c, fmt.Sprintf("URI %q is not under a permitted URI domain", u.String()), u.String())
		}
		if host != "" && dnsUnderAnyConstraint(host, c.ExcludedURIDomains) {
			return nameConstraintViolation(c, fmt.Sprintf("URI %q is under an excluded URI domain", u.String()), u.String())
		}
	}
	return nil
}

func formatDNList(list []pkix.RDNSequence) string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = FormatRDNSequence(s)
	}
	return strings.Join(out, "; ")
}

// dnUnderAny reports whether subject has one of bases as a prefix: same RDNs,
// in order, from the top of the tree (RFC 5280 §7.1 matching).
func dnUnderAny(subject pkix.RDNSequence, bases []pkix.RDNSequence) bool {
	for _, b := range bases {
		if dnHasPrefix(subject, b) {
			return true
		}
	}
	return false
}

func dnHasPrefix(subject, base pkix.RDNSequence) bool {
	if len(base) > len(subject) {
		return false
	}
	for i := range base {
		if !rdnEqualFold(subject[i], base[i]) {
			return false
		}
	}
	return true
}

// rdnEqualFold compares two RDNs as sets of attributes, values matched
// case-insensitively with whitespace runs collapsed (caseIgnoreMatch, which
// is what DC, O, OU, L, ST and C use).
func rdnEqualFold(a, b pkix.RelativeDistinguishedNameSET) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if x.Type.Equal(y.Type) && attrValueEqualFold(x.Value, y.Value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func attrValueEqualFold(a, b any) bool {
	as, aok := rdnValueString(a)
	bs, bok := rdnValueString(b)
	if !aok || !bok {
		return false
	}
	return strings.EqualFold(strings.Join(strings.Fields(as), " "), strings.Join(strings.Fields(bs), " "))
}

func dnsUnderAnyConstraint(name string, constraints []string) bool {
	for _, c := range constraints {
		if c == "" || DNSNameMatchesSuffixes(name, []string{c}) {
			return true
		}
	}
	return false
}

func ipInAny(ip net.IP, ranges []*net.IPNet) bool {
	for _, r := range ranges {
		// An IPv4 address only matches an IPv4 range and vice versa.
		if (ip.To4() != nil) != (len(r.IP) == net.IPv4len) {
			continue
		}
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// emailUnderAny follows RFC 5280: "a@b" is one mailbox, "b" is every mailbox
// at host b, ".b" every mailbox at a host below b.
func emailUnderAny(addr string, constraints []string) bool {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return false
	}
	local, host := addr[:at], normalizeDNSName(addr[at+1:])
	for _, c := range constraints {
		if i := strings.LastIndex(c, "@"); i >= 0 {
			if local == c[:i] && host == normalizeDNSName(c[i+1:]) {
				return true
			}
			continue
		}
		cc := normalizeDNSName(c)
		if strings.HasPrefix(cc, ".") {
			if strings.HasSuffix(host, cc) && len(host) > len(cc) {
				return true
			}
		} else if host == cc {
			return true
		}
	}
	return false
}

// withoutDirNameUnhandled returns c, or a copy with the NameConstraints
// extension removed from UnhandledCriticalExtensions when the only part
// crypto/x509 could not handle is directoryName. crypto/x509 still enforces
// the DNS, IP, email and URI parts from the parsed fields; the caller must
// check the directoryName part on the verified chain with
// chainSatisfiesDirNames. Any other unhandled form leaves c as it is, so
// verification still fails on it.
func withoutDirNameUnhandled(c *x509.Certificate) *x509.Certificate {
	idx := -1
	for i, id := range c.UnhandledCriticalExtensions {
		if id.Equal(oidExtNameConstraints) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return c
	}
	dn, has, err := parseDirNameConstraints(c)
	if err != nil || !has || !dn.onlyKnown {
		return c
	}
	cp := *c
	cp.UnhandledCriticalExtensions = append(append([]asn1.ObjectIdentifier(nil), c.UnhandledCriticalExtensions[:idx]...), c.UnhandledCriticalExtensions[idx+1:]...)
	return &cp
}

// chainSatisfiesDirNames applies every directoryName constraint in chain
// (leaf first) to the certificates below it, skipping self-issued
// intermediates as RFC 5280 §6.1.4(b) does.
func chainSatisfiesDirNames(chain []*x509.Certificate) bool {
	for i := 1; i < len(chain); i++ {
		dn, has, err := parseDirNameConstraints(chain[i])
		if err != nil {
			return false
		}
		if !has || (len(dn.permitted) == 0 && len(dn.excluded) == 0) {
			continue
		}
		for j := 0; j < i; j++ {
			below := chain[j]
			if j > 0 && string(below.RawIssuer) == string(below.RawSubject) {
				continue
			}
			subject, err := parseRDNSequence(below.RawSubject)
			if err != nil {
				return false
			}
			if len(subject) == 0 {
				continue
			}
			if len(dn.permitted) > 0 && !dnUnderAny(subject, dn.permitted) {
				return false
			}
			if dnUnderAny(subject, dn.excluded) {
				return false
			}
		}
	}
	return true
}
