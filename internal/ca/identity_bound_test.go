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
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// A protocol that authenticates the requester (W20-08 WSTEP) must be able to
// issue for the authenticated identity regardless of what the CSR asks for:
// the CSR proves key possession only.
func identityCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Administrator", Organization: []string{"Attacker"}},
		DNSNames: []string{"dc01.victim.example"},
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

func identityRoot(t *testing.T) (*Engine, string) {
	t.Helper()
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Identity Test Root", pkix.Name{CommonName: "Identity Test Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	return engine, root.ID
}

func TestIssueCertificate_SubjectOverridesCSR(t *testing.T) {
	engine, caID := identityRoot(t)
	want := pkix.Name{CommonName: "ws01.corp.example"}
	issued, err := engine.IssueCertificate(caID, IssuanceRequest{
		CSR: identityCSR(t), Subject: &want, CallerNamesOnly: true,
		DNSNames:    []string{"ws01.corp.example"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c := issued.Certificate
	if c.Subject.CommonName != "ws01.corp.example" || len(c.Subject.Organization) != 0 {
		t.Fatalf("subject taken from CSR instead of the caller: %v", c.Subject)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "ws01.corp.example" {
		t.Fatalf("DNS SANs = %v, want only the caller's", c.DNSNames)
	}
}

// With no caller SANs, CallerNamesOnly must yield NO SANs rather than falling
// back to the CSR's (a user principal gets no DNS SAN).
func TestIssueCertificate_CallerNamesOnlyDropsCSRSANs(t *testing.T) {
	engine, caID := identityRoot(t)
	issued, err := engine.IssueCertificate(caID, IssuanceRequest{
		CSR: identityCSR(t), Subject: &pkix.Name{CommonName: "alice"}, CallerNamesOnly: true,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if n := len(issued.Certificate.DNSNames) + len(issued.Certificate.IPAddresses) + len(issued.Certificate.URIs); n != 0 {
		t.Fatalf("expected no SANs, got DNS=%v IP=%v URI=%v", issued.Certificate.DNSNames, issued.Certificate.IPAddresses, issued.Certificate.URIs)
	}
}

// Without the new fields, behaviour is unchanged: CSR subject and SANs flow
// through (every existing protocol relies on this).
func TestIssueCertificate_DefaultStillUsesCSR(t *testing.T) {
	engine, caID := identityRoot(t)
	issued, err := engine.IssueCertificate(caID, IssuanceRequest{
		CSR: identityCSR(t), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.Certificate.Subject.CommonName != "Administrator" || len(issued.Certificate.DNSNames) != 1 {
		t.Fatalf("default path changed: subject=%v dns=%v", issued.Certificate.Subject, issued.Certificate.DNSNames)
	}
}
