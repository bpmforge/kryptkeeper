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
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestSubjectPolicyValidate(t *testing.T) {
	ok := []*SubjectPolicy{
		nil,
		{},
		fixedDC("foo", "bar"),
		{FixedRDNs: []SubjectRDN{{Type: "o", Value: "Example Ltd"}, {Type: "C", Value: "GB"}, {Type: "OU", Value: "Web"}, {Type: "L", Value: "Leeds"}, {Type: "ST", Value: "West Yorkshire"}}},
	}
	for i, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string]*SubjectPolicy{
		"CN is never fixed":   {FixedRDNs: []SubjectRDN{{Type: "CN", Value: "x"}}},
		"unknown type":        {FixedRDNs: []SubjectRDN{{Type: "SERIALNUMBER", Value: "1"}}},
		"empty value":         {FixedRDNs: []SubjectRDN{{Type: "DC", Value: ""}}},
		"padded value":        {FixedRDNs: []SubjectRDN{{Type: "O", Value: " x"}}},
		"dotted DC":           fixedDC("foo.bar"),
		"DC underscore":       fixedDC("foo_bar"),
		"long DC":             fixedDC(strings.Repeat("a", 64)),
		"lower-case country":  {FixedRDNs: []SubjectRDN{{Type: "C", Value: "gb"}}},
		"three-letter C":      {FixedRDNs: []SubjectRDN{{Type: "C", Value: "GBR"}}},
		"control char":        {FixedRDNs: []SubjectRDN{{Type: "O", Value: "a\nb"}}},
		"too long O":          {FixedRDNs: []SubjectRDN{{Type: "O", Value: strings.Repeat("a", 65)}}},
		"too many components": fixedDC("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"),
	}
	for name, p := range bad {
		if err := p.Validate(); err == nil || !strings.HasPrefix(err.Error(), "subject_policy:") {
			t.Errorf("%s: want subject_policy error, got %v", name, err)
		}
	}
}

func TestSubjectPolicyEncodingOrderAndTypes(t *testing.T) {
	p := &SubjectPolicy{FixedRDNs: []SubjectRDN{{Type: "OU", Value: "Web"}, {Type: "DC", Value: "foo"}, {Type: "dc", Value: "bar"}}}
	n := p.Subject("webserver")
	seq := n.ToRDNSequence()
	if len(seq) != 4 {
		t.Fatalf("want 4 RDNs, got %d", len(seq))
	}
	// Encoding order is top of the tree first; the CN is last.
	if !seq[0][0].Type.Equal(oidDomainComponent) || !seq[3][0].Type.Equal(oidCN) {
		t.Fatalf("encoding order: %v", seq)
	}
	if FormatRDNSequence(seq) != "CN=webserver,OU=Web,DC=foo,DC=bar" {
		t.Fatalf("format: %q", FormatRDNSequence(seq))
	}
	if n.CommonName != "webserver" {
		t.Fatal("CommonName must stay readable")
	}
	if (*SubjectPolicy)(nil).Subject("x") != nil || (&SubjectPolicy{}).Subject("x") != nil {
		t.Fatal("an empty policy changes nothing")
	}
}

func TestFixedRDNsReplaceRequestedSubjectAndEncodeDCAsIA5(t *testing.T) {
	e := newTestEngine(t)
	root, err := e.CreateRootCA("R", pkix.Name{CommonName: "R"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "web.example.test", Organization: []string{"Requester Chose This"}},
		DNSNames: []string{"web.example.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	issued, err := e.IssueCertificate(root.ID, IssuanceRequest{CSR: csr, Validity: time.Hour,
		Policy: &TemplatePolicy{ID: "t", Subject: fixedDC("example", "test")}})
	if err != nil {
		t.Fatal(err)
	}
	seq, err := parseRDNSequence(issued.Certificate.RawSubject)
	if err != nil {
		t.Fatal(err)
	}
	if FormatRDNSequence(seq) != "CN=web.example.test,DC=example,DC=test" {
		t.Fatalf("requested O must be dropped, got %q", FormatRDNSequence(seq))
	}
	// RFC 4519: domainComponent is an IA5String.
	var rdn []struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(issued.Certificate.RawSubject, &outer); err != nil {
		t.Fatal(err)
	}
	rest := outer.Bytes
	for len(rest) > 0 {
		var set asn1.RawValue
		rest, _ = asn1.Unmarshal(rest, &set)
		var atv struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(set.Bytes, &atv); err != nil {
			t.Fatal(err)
		}
		rdn = append(rdn, atv)
	}
	if rdn[0].Value.Tag != asn1.TagIA5String {
		t.Fatalf("DC encoded with tag %d, want IA5String", rdn[0].Value.Tag)
	}
	if issued.Certificate.Subject.CommonName != "web.example.test" {
		t.Fatal("parsed CN")
	}
}

func TestSameRDNSequenceIgnoresStringType(t *testing.T) {
	a := pkix.RDNSequence{{{Type: oidDomainComponent, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("foo")}}}}
	b := pkix.RDNSequence{{{Type: oidDomainComponent, Value: "foo"}}}
	if !sameRDNSequence(a, b) {
		t.Fatal("same text, different string type")
	}
	if sameRDNSequence(a, pkix.RDNSequence{{{Type: oidDomainComponent, Value: "Foo"}}}) {
		t.Fatal("upstream must return the exact value")
	}
}
