// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func TestIssueCertificate_Backdate(t *testing.T) {
	engine, caID := identityRoot(t)
	root, err := engine.GetCA(caID)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(backdate time.Duration) (*x509.Certificate, error) {
		issued, err := engine.IssueCertificate(caID, IssuanceRequest{
			CSR: identityCSR(t), Validity: time.Hour, Backdate: backdate,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return nil, err
		}
		return issued.Certificate, nil
	}

	// Certificate times have one-second resolution: move past the root's
	// second so a backdated leaf is distinguishable from an undated one.
	time.Sleep(1100 * time.Millisecond)
	before := time.Now().UTC().Truncate(time.Second)
	plain, err := issue(0)
	if err != nil {
		t.Fatal(err)
	}
	if plain.NotBefore.Before(before) || !plain.NotBefore.After(root.Certificate.NotBefore) {
		t.Fatalf("zero backdate moved NotBefore to %v (issue time >= %v)", plain.NotBefore, before)
	}

	// The root was created moments ago, so a 5-minute backdate is clamped
	// to the root's own NotBefore: a leaf never predates its issuer.
	clamped, err := issue(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Measured after issuance: NotAfter is issue time + validity, and a
	// slow runner can issue seconds after any earlier timestamp.
	after := time.Now().UTC()
	if !clamped.NotBefore.Equal(root.Certificate.NotBefore) {
		t.Fatalf("NotBefore %v, want clamped to the root's %v", clamped.NotBefore, root.Certificate.NotBefore)
	}
	if clamped.NotAfter.After(after.Add(time.Hour)) {
		t.Fatalf("backdating must not extend NotAfter: %v", clamped.NotAfter)
	}

	if _, err := issue(-time.Minute); err == nil {
		t.Fatal("a negative backdate must be refused")
	}
}

func TestIssueCertificate_ExtraExtensions(t *testing.T) {
	engine, caID := identityRoot(t)
	issue := func(ext pkix.Extension) (*x509.Certificate, error) {
		issued, err := engine.IssueCertificate(caID, IssuanceRequest{
			CSR: identityCSR(t), Validity: time.Hour, ExtraExtensions: []pkix.Extension{ext},
			DNSNames: []string{"ws01.corp.example"}, CallerNamesOnly: true,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return nil, err
		}
		return issued.Certificate, nil
	}

	template := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}, Value: []byte{0x30, 0x00}}
	c, err := issue(template)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range c.Extensions {
		found = found || (e.Id.Equal(template.Id) && string(e.Value) == string(template.Value))
	}
	if !found {
		t.Fatal("extra extension missing from the certificate")
	}

	// A SAN or AIA supplied this way would replace what the engine derived
	// from validated input.
	sanOverride, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("evil.example")}})
	for name, ext := range map[string]pkix.Extension{
		"SAN": {Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanOverride},
		"EKU": {Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00}},
		"AIA": {Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x00}},
	} {
		if c, err := issue(ext); err == nil {
			t.Fatalf("%s override accepted; DNS SANs now %v", name, c.DNSNames)
		}
	}
}
