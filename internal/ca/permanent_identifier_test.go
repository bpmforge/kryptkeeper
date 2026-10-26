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
	"net"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestIssuePermanentIdentifierSAN(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("PI Root", pkix.Name{CommonName: "PI Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)

	issue := func(ids []PermanentIdentifier, dns []string) *x509.Certificate {
		t.Helper()
		out, err := engine.IssueCertificate(root.ID, IssuanceRequest{
			CSR: csr, Validity: time.Hour, CallerNamesOnly: true,
			DNSNames: dns, PermanentIdentifiers: ids,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return out.Certificate
	}

	assigner := asn1.ObjectIdentifier{1, 2, 3, 4}
	cert := issue([]PermanentIdentifier{{Value: "C02ABC123", Assigner: assigner}}, []string{"host.example.test"})
	ids, foreign, err := SANPermanentIdentifiers(cert.Extensions)
	if err != nil || len(ids) != 1 || foreign != 1 {
		t.Fatalf("ids=%v foreign=%d err=%v", ids, foreign, err)
	}
	if ids[0].Value != "C02ABC123" || !ids[0].Assigner.Equal(assigner) {
		t.Fatalf("round trip lost data: %+v", ids[0])
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "host.example.test" {
		t.Fatalf("the DNS name must survive the SAN override, got %v", cert.DNSNames)
	}

	// No assigner, no other names: the SAN carries the otherName alone.
	cert = issue([]PermanentIdentifier{{Value: "SER1"}}, nil)
	ids, foreign, err = SANPermanentIdentifiers(cert.Extensions)
	if err != nil || len(ids) != 1 || foreign != 0 || ids[0].Assigner != nil {
		t.Fatalf("ids=%v foreign=%d err=%v", ids, foreign, err)
	}
	if err := cert.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatal(err)
	}
}

func TestMarshalSANKeepsIPs(t *testing.T) {
	ext, err := marshalSANExtension(nil, []net.IP{net.ParseIP("10.1.2.3")}, nil, []PermanentIdentifier{{Value: "X"}})
	if err != nil {
		t.Fatal(err)
	}
	ids, foreign, err := SANPermanentIdentifiers([]pkix.Extension{ext})
	if err != nil || len(ids) != 1 || foreign != 1 {
		t.Fatalf("ids=%v foreign=%d err=%v", ids, foreign, err)
	}
	if _, err := marshalSANExtension(nil, nil, nil, []PermanentIdentifier{{}}); err == nil {
		t.Fatal("an empty permanent identifier must not be encoded")
	}
	if _, _, err := SANPermanentIdentifiers([]pkix.Extension{{Id: oidSubjectAltName, Value: []byte{0x01}}}); err == nil {
		t.Fatal("malformed SAN must be an error")
	}
}
