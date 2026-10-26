// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// upstreamCA is a stand-in for a customer's CA: a root, an intermediate that
// signs leaves, and knobs that make it misbehave.
type upstreamCA struct {
	t          *testing.T
	root       *x509.Certificate
	inter      *x509.Certificate
	interKey   crypto.Signer
	tamper     func(tmpl *x509.Certificate, csr *x509.CertificateRequest) crypto.PublicKey
	gotCSR     string
	gotCAID    string
	gotConn    string
	failWith   error
	omitChain  bool
	extraChain []*x509.Certificate
}

func newUpstreamCA(t *testing.T) *upstreamCA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Upstream Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Upstream Issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return &upstreamCA{t: t, root: root, inter: inter, interKey: interKey}
}

func (u *upstreamCA) rootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: u.root.Raw})
}

func (u *upstreamCA) IssueExternal(_ context.Context, caID, connectorID, csrPEM, _ string) (string, error) {
	u.gotCSR, u.gotCAID, u.gotConn = csrPEM, caID, connectorID
	if u.failWith != nil {
		return "", u.failWith
	}
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		u.t.Fatalf("upstream got an unparseable CSR: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, URIs: csr.URIs,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	pub := csr.PublicKey
	if u.tamper != nil {
		if p := u.tamper(tmpl, csr); p != nil {
			pub = p
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, u.inter, pub, u.interKey)
	if err != nil {
		u.t.Fatal(err)
	}
	var out bytes.Buffer
	_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if !u.omitChain {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: u.inter.Raw})
	}
	for _, c := range u.extraChain {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return out.String(), nil
}

func newCSR(t *testing.T, names ...string) *x509.CertificateRequest {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return csr
}

func externalEngine(t *testing.T) (*Engine, *upstreamCA, *CA) {
	t.Helper()
	e := newTestEngine(t)
	up := newUpstreamCA(t)
	e.SetExternalIssuer(up)
	c, err := e.CreateExternalCA("Customer Vault", "conn-1", up.rootPEM())
	if err != nil {
		t.Fatal(err)
	}
	return e, up, c
}

func TestExternalCAIssuesThroughConnectorAndReturnsVerifiedChain(t *testing.T) {
	e, up, c := externalEngine(t)
	if c.Type != CATypeExternal || c.KeyID != "" || c.ConnectorID != "conn-1" {
		t.Fatalf("external CA row wrong: %+v", c)
	}
	csr := newCSR(t, "app.example.com")
	issued, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour, TemplateID: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if up.gotCAID != c.ID || up.gotConn != "conn-1" || !strings.Contains(up.gotCSR, "CERTIFICATE REQUEST") {
		t.Fatalf("connector call wrong: ca=%s conn=%s", up.gotCAID, up.gotConn)
	}
	if issued.Certificate.Issuer.CommonName != "Upstream Issuing" {
		t.Fatalf("issuer %s", issued.Certificate.Issuer.CommonName)
	}
	chain, _ := parseBundle(issued.ChainPEM)
	if len(chain) != 1 || !chain[0].Equal(up.inter) {
		t.Fatalf("chain should be the intermediate only (root dropped), got %d certs", len(chain))
	}
	if issued.Fingerprint == "" || issued.SerialNumber == nil {
		t.Fatal("fingerprint/serial missing")
	}
}

func TestExternalCARejectsTamperedResponses(t *testing.T) {
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := []struct {
		name   string
		tamper func(*x509.Certificate, *x509.CertificateRequest) crypto.PublicKey
		want   string
	}{
		{"swapped key", func(*x509.Certificate, *x509.CertificateRequest) crypto.PublicKey { return &otherKey.PublicKey }, "public key does not match"},
		{"extra SAN", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.DNSNames = append(c.DNSNames, "evil.example.com")
			return nil
		}, `DNS name "evil.example.com" was not requested`},
		{"extra IP", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
			return nil
		}, "IP address 10.0.0.1 was not requested"},
		{"is a CA", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.IsCA = true
			c.KeyUsage |= x509.KeyUsageCertSign
			return nil
		}, "is a CA certificate"},
		{"cert sign usage", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.KeyUsage |= x509.KeyUsageCertSign
			return nil
		}, "may sign certificates"},
		{"code signing EKU", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
			return nil
		}, "codeSigning was not requested"},
		{"too long", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.NotAfter = time.Now().Add(400 * 24 * time.Hour)
			return nil
		}, "beyond the policy"},
		{"email SAN", func(c *x509.Certificate, _ *x509.CertificateRequest) crypto.PublicKey {
			c.EmailAddresses = []string{"a@example.com"}
			return nil
		}, "email addresses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, up, c := externalEngine(t)
			up.tamper = tc.tamper
			var observed *ExternalRejection
			e.SetExternalRejectionObserver(func(caID, connID string, r *ExternalRejection) {
				if caID == c.ID && connID == "conn-1" {
					observed = r
				}
			})
			_, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "app.example.com"), Validity: 90 * 24 * time.Hour})
			var rej *ExternalRejection
			if !errors.As(err, &rej) || !errors.Is(err, ErrExternalCAResponseRejected) {
				t.Fatalf("want ExternalRejection, got %v", err)
			}
			if !strings.Contains(rej.Reason, tc.want) {
				t.Fatalf("reason %q does not contain %q", rej.Reason, tc.want)
			}
			if rej.Fingerprint == "" {
				t.Fatal("rejection must carry the fingerprint for the audit record")
			}
			if observed != rej {
				t.Fatal("observer must hear every rejection")
			}
		})
	}
}

func TestExternalCARejectsCertificateFromAnotherCA(t *testing.T) {
	e, up, c := externalEngine(t)
	stranger := newUpstreamCA(t)
	// The upstream answers with a leaf from a CA the operator never trusted.
	up.inter, up.interKey = stranger.inter, stranger.interKey
	_, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "app.example.com"), Validity: 90 * 24 * time.Hour})
	var rej *ExternalRejection
	if !errors.As(err, &rej) || !strings.Contains(rej.Reason, "does not chain") {
		t.Fatalf("want chain rejection, got %v", err)
	}
}

func TestExternalCAMissingIntermediateIsRejectedUnlessTrusted(t *testing.T) {
	e, up, c := externalEngine(t)
	up.omitChain = true
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "a.example.com"), Validity: 90 * 24 * time.Hour}); !errors.Is(err, ErrExternalCAResponseRejected) {
		t.Fatalf("leaf without its intermediate must not verify against a root-only trust bundle: %v", err)
	}
	// Trusting the issuing intermediate directly is a valid operator choice.
	c2, err := e.CreateExternalCA("pinned issuing", "conn-1", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.inter.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.IssueCertificate(c2.ID, IssuanceRequest{CSR: newCSR(t, "a.example.com"), Validity: 90 * 24 * time.Hour}); err != nil {
		t.Fatalf("issuing-CA anchor: %v", err)
	}
}

func TestExternalCARefusals(t *testing.T) {
	e, up, c := externalEngine(t)
	csr := newCSR(t, "a.example.com")

	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{PQCCSR: &PQCCertificateRequest{}}); !errors.Is(err, ErrExternalCAUnsupportedKey) {
		t.Fatalf("PQC CSR: %v", err)
	}
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{HybridCSR: &HybridCertificateRequest{}}); !errors.Is(err, ErrExternalCAUnsupportedKey) {
		t.Fatalf("hybrid CSR: %v", err)
	}
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: csr, IsCA: true}); !errors.Is(err, ErrExternalCAInvalid) {
		t.Fatalf("IsCA request: %v", err)
	}
	if up.gotCSR != "" {
		t.Fatal("refused requests must never reach the upstream")
	}

	up.failWith = errors.New("upstream says no")
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: csr}); err == nil || !strings.Contains(err.Error(), "upstream says no") {
		t.Fatalf("connector error must surface: %v", err)
	}

	bare := newTestEngine(t)
	c3, err := bare.CreateExternalCA("no bridge", "conn-1", up.rootPEM())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.IssueCertificate(c3.ID, IssuanceRequest{CSR: csr}); !errors.Is(err, ErrExternalCANotConfigured) {
		t.Fatalf("no issuer attached: %v", err)
	}

	if err := e.UpdateCAStatus(c.ID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: csr}); !errors.Is(err, ErrCANotActive) {
		t.Fatalf("suspended external CA: %v", err)
	}
}

func TestExternalCABindsCallerIdentity(t *testing.T) {
	e, _, c := externalEngine(t)
	csr := newCSR(t, "a.example.com", "b.example.com")
	// The front door authorised only a.example.com; the upstream signs the
	// CSR as sent, so the extra name must be caught here.
	_, err := e.IssueCertificate(c.ID, IssuanceRequest{CSR: csr, DNSNames: []string{"a.example.com"}, Validity: 90 * 24 * time.Hour})
	if !errors.Is(err, ErrExternalCAResponseRejected) {
		t.Fatalf("names beyond the authorised set must be rejected: %v", err)
	}
	bound := pkix.Name{CommonName: "HOST$"}
	_, err = e.IssueCertificate(c.ID, IssuanceRequest{CSR: newCSR(t, "a.example.com"), Subject: &bound, Validity: 90 * 24 * time.Hour})
	if !errors.Is(err, ErrExternalCAResponseRejected) {
		t.Fatalf("subject differing from the bound identity must be rejected: %v", err)
	}
}

func TestCreateExternalCAValidatesTrustBundle(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.CreateExternalCA("x", "conn", nil); !errors.Is(err, ErrExternalCAInvalid) {
		t.Fatalf("empty bundle: %v", err)
	}
	if _, err := e.CreateExternalCA("", "conn", newUpstreamCA(t).rootPEM()); !errors.Is(err, ErrExternalCAInvalid) {
		t.Fatalf("missing name: %v", err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
	if _, err := e.CreateExternalCA("x", "conn", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); !errors.Is(err, ErrExternalCAInvalid) {
		t.Fatalf("non-CA certificate in bundle: %v", err)
	}
}
