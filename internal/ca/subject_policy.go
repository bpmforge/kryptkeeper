// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// subject_policy.go — fixed subject components on a template. ACME clients
// (win-acme, acme.sh, Posh-ACME, certbot) cannot ask for anything beyond the
// CN, so a CA with directoryName name constraints (e.g. permitted
// DC=foo,DC=bar) refuses every certificate they get. A template can name
// RDNs that are appended after the CN on every certificate issued under it,
// whatever the request carried: the EJBCA "non-modifiable default" model.

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"crypto/x509/pkix"
)

// SubjectRDN is one fixed subject component, e.g. {Type: "DC", Value: "foo"}.
type SubjectRDN struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SubjectPolicy fixes subject components for certificates issued under a
// template. FixedRDNs are written in the order a DN is read (RFC 4514, most
// specific first): [DC=foo, DC=bar] issues "CN=web,DC=foo,DC=bar", encoded
// in the certificate as DC=bar, DC=foo, CN=web so a directoryName constraint
// of DC=bar,DC=foo is a prefix of it (RFC 5280 §4.2.1.10).
//
// When FixedRDNs is non-empty the issued subject is exactly the CN plus these
// RDNs; any other subject attributes in the request are dropped, so a
// requester cannot put itself outside the CA's constraints.
type SubjectPolicy struct {
	FixedRDNs []SubjectRDN `json:"fixed_rdns,omitempty"`
}

const maxFixedRDNs = 10

var (
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidCN              = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// subjectRDNTypes are the attribute types a template may fix. CN is not one:
// it always comes from the validated request.
var subjectRDNTypes = map[string]asn1.ObjectIdentifier{
	"DC": oidDomainComponent,
	"O":  {2, 5, 4, 10},
	"OU": {2, 5, 4, 11},
	"L":  {2, 5, 4, 7},
	"ST": {2, 5, 4, 8},
	"C":  {2, 5, 4, 6},
}

// rdnLabels names the attribute types this package prints; the stdlib prints
// DC as a dotted OID with a hex value, which no operator can read.
var rdnLabels = map[string]string{
	"0.9.2342.19200300.100.1.25": "DC",
	"2.5.4.3":                    "CN",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.6":                    "C",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.9":                    "STREET",
	"2.5.4.17":                   "POSTALCODE",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.1":  "UID",
}

// Validate rejects a malformed policy at template create/update time.
func (p *SubjectPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if len(p.FixedRDNs) > maxFixedRDNs {
		return fmt.Errorf("subject_policy: at most %d fixed_rdns", maxFixedRDNs)
	}
	for i, r := range p.FixedRDNs {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		if _, ok := subjectRDNTypes[typ]; !ok {
			return fmt.Errorf("subject_policy: fixed_rdns[%d]: type %q is not one of DC, O, OU, L, ST, C", i, r.Type)
		}
		if err := validateRDNValue(typ, r.Value); err != nil {
			return fmt.Errorf("subject_policy: fixed_rdns[%d] (%s): %w", i, typ, err)
		}
	}
	return nil
}

func validateRDNValue(typ, v string) error {
	if v == "" || strings.TrimSpace(v) != v {
		return errors.New("value must be non-empty with no leading or trailing spaces")
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return errors.New("value must not contain control characters")
		}
	}
	switch typ {
	case "DC":
		// One DNS label (RFC 4519 §2.4); "foo.bar" is two DC entries.
		if len(v) > 63 {
			return errors.New("a DC value is one DNS label of at most 63 characters")
		}
		for _, c := range v {
			if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				return errors.New("a DC value is one DNS label (letters, digits, hyphen); use one entry per label")
			}
		}
	case "C":
		if len(v) != 2 || strings.ToUpper(v) != v || !isASCIILetters(v) {
			return errors.New("C must be a two-letter upper-case country code")
		}
	default:
		if len([]rune(v)) > 64 {
			return errors.New("value must be at most 64 characters")
		}
	}
	return nil
}

func isASCIILetters(s string) bool {
	for _, c := range s {
		if c < 'A' || c > 'z' || (c > 'Z' && c < 'a') {
			return false
		}
	}
	return true
}

// Active reports whether the policy changes anything.
func (p *SubjectPolicy) Active() bool { return p != nil && len(p.FixedRDNs) > 0 }

// Subject builds the issued subject: the fixed RDNs in encoding order, then
// cn when non-empty. It returns nil when the policy fixes nothing, so callers
// keep the subject they already resolved. Validate must have passed.
func (p *SubjectPolicy) Subject(cn string) *pkix.Name {
	if !p.Active() {
		return nil
	}
	// Everything goes in ExtraNames so the encoding order is exactly ours;
	// CommonName is also set for code that reads it, and ToRDNSequence skips
	// it because the CN OID is already in ExtraNames.
	n := &pkix.Name{CommonName: cn}
	for i := len(p.FixedRDNs) - 1; i >= 0; i-- {
		r := p.FixedRDNs[i]
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: subjectRDNTypes[typ], Value: rdnEncodedValue(typ, r.Value)})
	}
	if cn != "" {
		n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oidCN, Value: cn})
	}
	return n
}

// rdnEncodedValue picks the string type the attribute's schema requires.
// encoding/asn1 would write DC as a PrintableString; RFC 4519 says IA5String.
func rdnEncodedValue(typ, v string) any {
	if typ == "DC" {
		return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(v)}
	}
	return v
}

// subjectForPolicy returns the subject a template's fixed RDNs impose on a
// request whose CN is cn, or nil when the template fixes none.
func subjectForPolicy(pol *TemplatePolicy, cn string) *pkix.Name {
	if pol == nil {
		return nil
	}
	return pol.Subject.Subject(cn)
}

// rdnValueString returns an attribute value as text, including the
// asn1.RawValue form Subject uses for DC.
func rdnValueString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case asn1.RawValue:
		return string(t.Bytes), true
	}
	return "", false
}

// FormatRDNSequence prints a DN the way operators write it (most specific
// first) with DC and the other common types named rather than as OIDs.
func FormatRDNSequence(seq pkix.RDNSequence) string {
	parts := make([]string, 0, len(seq))
	for i := len(seq) - 1; i >= 0; i-- {
		atvs := make([]string, 0, len(seq[i]))
		for _, atv := range seq[i] {
			label, ok := rdnLabels[atv.Type.String()]
			if !ok {
				label = atv.Type.String()
			}
			val, ok := rdnValueString(atv.Value)
			if !ok {
				val = fmt.Sprintf("%v", atv.Value)
			}
			atvs = append(atvs, label+"="+escapeRDNValue(val))
		}
		parts = append(parts, strings.Join(atvs, "+"))
	}
	return strings.Join(parts, ",")
}

func escapeRDNValue(v string) string {
	var b strings.Builder
	for i, c := range v {
		switch {
		case strings.ContainsRune(`,+"\<>;=`, c),
			i == 0 && (c == ' ' || c == '#'),
			i == len(v)-1 && c == ' ':
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// parseRDNSequence decodes a certificate's raw subject.
func parseRDNSequence(raw []byte) (pkix.RDNSequence, error) {
	var seq pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after subject")
	}
	return seq, nil
}

// sameRDNSequence reports whether two DNs have the same RDNs in the same
// order with byte-identical values. String type (PrintableString vs
// UTF8String) is ignored: upstream CAs re-encode freely and that does not
// change what the name says.
func sameRDNSequence(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if !a[i][j].Type.Equal(b[i][j].Type) {
				return false
			}
			av, aok := rdnValueString(a[i][j].Value)
			bv, bok := rdnValueString(b[i][j].Value)
			if !aok || !bok || av != bv {
				return false
			}
		}
	}
	return true
}
