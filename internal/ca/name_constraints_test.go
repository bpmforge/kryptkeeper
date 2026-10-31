// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// dcSeq builds an RDNSequence in encoding order from DN-reading-order labels:
// dcSeq("foo", "bar") is DC=foo,DC=bar.
func dcSeq(labels ...string) pkix.RDNSequence {
	var seq pkix.RDNSequence
	for i := len(labels) - 1; i >= 0; i-- {
		seq = append(seq, pkix.RelativeDistinguishedNameSET{{
			Type:  oidDomainComponent,
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(labels[i])},
		}})
	}
	return seq
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// nameConstraintsExt encodes a critical NameConstraints extension with
// directoryName and dNSName permitted subtrees, which crypto/x509 cannot
// write itself.
func nameConstraintsExt(t *testing.T, permittedDNs []pkix.RDNSequence, permittedDNS []string, excludedDNs []pkix.RDNSequence) pkix.Extension {
	t.Helper()
	subtrees := func(dns []pkix.RDNSequence, hosts []string) []byte {
		var body []byte
		for _, dn := range dns {
			base := mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: mustMarshal(t, dn)})
			body = append(body, mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: base})...)
		}
		for _, h := range hosts {
			base := mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(h)})
			body = append(body, mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: base})...)
		}
		return body
	}
	var top []byte
	if p := subtrees(permittedDNs, permittedDNS); len(p) > 0 {
		top = append(top, mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: p})...)
	}
	if x := subtrees(excludedDNs, nil); len(x) > 0 {
		top = append(top, mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: x})...)
	}
	return pkix.Extension{
		Id:       oidExtNameConstraints,
		Critical: true,
		Value:    mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: top}),
	}
}

type testRoot struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestRoot(t *testing.T, cn string) testRoot {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testRoot{cert: cert, key: key}
}

// constrainedIssuingCA builds the setup from the field: an offline root held
// outside Kryptkeeper signs a Kryptkeeper intermediate with name constraints.
func constrainedIssuingCA(t *testing.T, ext pkix.Extension) (*Engine, *CA, testRoot) {
	t.Helper()
	e := newTestEngine(t)
	root := newTestRoot(t, "Offline Root")
	imported, err := e.ImportCA("Offline Root", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := e.CreateIntermediateCSR("Issuing", pkix.Name{CommonName: "Constrained Issuing"}, keystore.ECDSAP256, imported.ID)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := e.GetCSR(pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, csr.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := e.CompleteIntermediateCA(pending.ID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return e, issuing, root
}

func fixedDC(labels ...string) *SubjectPolicy {
	p := &SubjectPolicy{}
	for _, l := range labels {
		p.FixedRDNs = append(p.FixedRDNs, SubjectRDN{Type: "DC", Value: l})
	}
	return p
}

func TestDirectoryNameConstraintRefusesCNOnlyAndAcceptsFixedRDNs(t *testing.T) {
	ext := nameConstraintsExt(t, []pkix.RDNSequence{dcSeq("foo", "bar")}, []string{"foo.bar"}, nil)
	e, issuing, root := constrainedIssuingCA(t, ext)
	csr := newCSR(t, "webserver.foo.bar")

	// What every ACME client sends today: CN only. Signing it would produce a
	// certificate the relying party rejects, so it is refused up front.
	_, err := e.IssueCertificate(issuing.ID, IssuanceRequest{CSR: csr, DNSNames: []string{"webserver.foo.bar"}, CallerNamesOnly: true,
		Subject: &pkix.Name{CommonName: "webserver.foo.bar"}, Validity: 24 * time.Hour})
	var pv *PolicyViolationError
	if !errors.As(err, &pv) || pv.Rule != "name_constraints" || !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("CN-only subject under a DN-constrained CA must be refused: %v", err)
	}
	if !strings.Contains(err.Error(), "DC=foo,DC=bar") {
		t.Fatalf("refusal should name the permitted subtree: %v", err)
	}

	// The template's fixed RDNs put it under the subtree.
	pol := &TemplatePolicy{ID: "tpl-acme", Subject: fixedDC("foo", "bar")}
	issued, err := e.IssueCertificate(issuing.ID, IssuanceRequest{CSR: csr, DNSNames: []string{"webserver.foo.bar"}, CallerNamesOnly: true,
		Subject: &pkix.Name{CommonName: "webserver.foo.bar"}, Validity: 24 * time.Hour, Policy: pol, TemplateID: pol.ID})
	if err != nil {
		t.Fatalf("issue with fixed RDNs: %v", err)
	}
	got, err := parseRDNSequence(issued.Certificate.RawSubject)
	if err != nil {
		t.Fatal(err)
	}
	if s := FormatRDNSequence(got); s != "CN=webserver.foo.bar,DC=foo,DC=bar" {
		t.Fatalf("issued subject %q", s)
	}

	// The chain is valid once the directoryName part, which crypto/x509
	// cannot evaluate, is checked here.
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	inter := x509.NewCertPool()
	inter.AddCert(withoutDirNameUnhandled(issuing.Certificate))
	chains, err := issued.Certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 || !chainSatisfiesDirNames(chains[0]) {
		t.Fatalf("issued chain should verify: %v", err)
	}

	// The DNS part of the same extension still applies.
	_, err = e.IssueCertificate(issuing.ID, IssuanceRequest{CSR: newCSR(t, "web.other.test"), DNSNames: []string{"web.other.test"}, CallerNamesOnly: true,
		Subject: &pkix.Name{CommonName: "web.other.test"}, Validity: 24 * time.Hour, Policy: pol})
	if !errors.As(err, &pv) || !strings.Contains(err.Error(), "web.other.test") {
		t.Fatalf("DNS name outside the permitted subtree must be refused: %v", err)
	}
}

func TestDirectoryNameExcludedSubtree(t *testing.T) {
	ext := nameConstraintsExt(t, nil, nil, []pkix.RDNSequence{dcSeq("lab", "bar")})
	e, issuing, _ := constrainedIssuingCA(t, ext)
	csr := newCSR(t, "web.example.test")
	req := func(p *SubjectPolicy) IssuanceRequest {
		return IssuanceRequest{CSR: csr, DNSNames: []string{"web.example.test"}, CallerNamesOnly: true, Validity: time.Hour,
			Subject: &pkix.Name{CommonName: "web.example.test"}, Policy: &TemplatePolicy{ID: "t", Subject: p}}
	}
	if _, err := e.IssueCertificate(issuing.ID, req(fixedDC("lab", "bar"))); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("subject under an excluded subtree must be refused: %v", err)
	}
	if _, err := e.IssueCertificate(issuing.ID, req(fixedDC("prod", "bar"))); err != nil {
		t.Fatalf("subject outside the excluded subtree: %v", err)
	}
	// An empty permitted list leaves CN-only alone.
	if _, err := e.IssueCertificate(issuing.ID, req(nil)); err != nil {
		t.Fatalf("CN-only with only an excluded subtree: %v", err)
	}
}

func TestUnconstrainedCAUnaffected(t *testing.T) {
	e := newTestEngine(t)
	root, err := e.CreateRootCA("R", pkix.Name{CommonName: "R"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.IssueCertificate(root.ID, IssuanceRequest{CSR: newCSR(t, "a.example.test"), Validity: time.Hour}); err != nil {
		t.Fatal(err)
	}
}

func TestDirNameMatchingIsCaseAndSpaceInsensitive(t *testing.T) {
	subject := pkix.RDNSequence{
		{{Type: oidDomainComponent, Value: "BAR"}},
		{{Type: oidDomainComponent, Value: "Foo"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Web  Servers"}},
		{{Type: oidCN, Value: "x"}},
	}
	base := dcSeq("foo", "bar")
	if !dnHasPrefix(subject, base) {
		t.Fatal("DC values match case-insensitively")
	}
	ou := append(dcSeq("foo", "bar"), pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "web servers"}})
	if !dnHasPrefix(subject, ou) {
		t.Fatal("whitespace runs collapse")
	}
	if dnHasPrefix(subject, dcSeq("baz", "bar")) || dnHasPrefix(dcSeq("bar"), base) {
		t.Fatal("non-prefix matched")
	}
}

func TestUnknownGeneralNameFormStaysUnhandled(t *testing.T) {
	// registeredID [8]: neither crypto/x509 nor this package evaluates it, so
	// the CA must stay unverifiable rather than be waved through.
	base := mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{0x2a, 0x03}})
	subtree := mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: base})
	permitted := mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: subtree})
	ext := pkix.Extension{Id: oidExtNameConstraints, Critical: true,
		Value: mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: permitted})}
	root := newTestRoot(t, "R")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "I"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, ExtraExtensions: []pkix.Extension{ext}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	if len(c.UnhandledCriticalExtensions) == 0 {
		t.Fatal("expected crypto/x509 to leave the extension unhandled")
	}
	if withoutDirNameUnhandled(c) != c {
		t.Fatal("an unknown GeneralName form must not be stripped")
	}
}

func TestExternalCAWithDirectoryNameConstraints(t *testing.T) {
	e := newTestEngine(t)
	root := newTestRoot(t, "Upstream Root")
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Upstream Constrained Issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions: []pkix.Extension{nameConstraintsExt(t, []pkix.RDNSequence{dcSeq("foo", "bar")}, nil, nil)},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root.cert, &interKey.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(interDER)
	// The upstream (an EJBCA-style end entity profile) appends DC=foo,DC=bar.
	up := &upstreamCA{t: t, root: root.cert, inter: interCert, interKey: interKey}
	addDCs := func(tmpl *x509.Certificate, csr *x509.CertificateRequest) crypto.PublicKey {
		tmpl.Subject = *fixedDC("foo", "bar").Subject(csr.Subject.CommonName)
		return nil
	}
	up.tamper = addDCs
	e.SetExternalIssuer(up)
	c, err := e.CreateExternalCA("Upstream", "conn-1", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	cn := pkix.Name{CommonName: "web.foo.bar"}
	pol := &TemplatePolicy{ID: "t", Subject: fixedDC("foo", "bar")}
	issued, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "web.foo.bar"), DNSNames: []string{"web.foo.bar"}, CallerNamesOnly: true,
		Subject: &cn, Policy: pol, Validity: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("composed DN from a DN-constrained upstream must be accepted: %v", err)
	}
	if got, _ := parseRDNSequence(issued.Certificate.RawSubject); FormatRDNSequence(got) != "CN=web.foo.bar,DC=foo,DC=bar" {
		t.Fatalf("subject %q", FormatRDNSequence(got))
	}

	// Without the template's RDNs the hub expects CN only and refuses the
	// upstream's longer subject.
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "web.foo.bar"), DNSNames: []string{"web.foo.bar"}, CallerNamesOnly: true,
		Subject: &cn, Validity: 90 * 24 * time.Hour}); !errors.Is(err, ErrExternalCAResponseRejected) {
		t.Fatalf("subject beyond the bound identity must be rejected: %v", err)
	}

	// An upstream that signs outside its own constraints is caught here,
	// although crypto/x509 alone cannot see it.
	up.tamper = func(tmpl *x509.Certificate, csr *x509.CertificateRequest) crypto.PublicKey {
		tmpl.Subject = *fixedDC("evil", "bar").Subject(csr.Subject.CommonName)
		return nil
	}
	pol2 := &TemplatePolicy{ID: "t2", Subject: fixedDC("evil", "bar")}
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "web.foo.bar"), DNSNames: []string{"web.foo.bar"}, CallerNamesOnly: true,
		Subject: &cn, Policy: pol2, Validity: 90 * 24 * time.Hour}); !errors.Is(err, ErrExternalCAResponseRejected) {
		t.Fatalf("leaf outside the upstream's directoryName subtree must be rejected: %v", err)
	}
}
