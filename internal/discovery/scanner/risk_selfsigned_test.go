// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

type riskCertOpts struct {
	cn       string
	isCA     bool
	dnsNames []string
	ips      []net.IP
}

// selfSignedCert mirrors `openssl req -x509`: subject == issuer, signed by its
// own key. isCA reproduces openssl's default basicConstraints CA:TRUE.
func selfSignedCert(t *testing.T, o riskCertOpts) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: o.cn},
		DNSNames:              o.dnsNames,
		IPAddresses:           o.ips,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
	}
	if o.isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// signedBy issues a leaf for cn from parent, so subject != issuer.
func signedBy(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestSelfSignedLeafFlaggedRegardlessOfCAFlag(t *testing.T) {
	for _, isCA := range []bool{false, true} {
		c := selfSignedCert(t, riskCertOpts{cn: "lab.example.com", isCA: isCA, dnsNames: []string{"lab.example.com"}})
		_, flags := computeCertRisk(c, "lab.example.com", true)
		if !hasFlag(flags, "SELF_SIGNED") {
			t.Errorf("isCA=%v: served self-signed leaf must be SELF_SIGNED, got %v", isCA, flags)
		}
	}
}

func TestSelfSignedRootHigherInChainNotFlagged(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Real Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(der)
	leaf := signedBy(t, root, rootKey, "svc.example.com")

	_, rootFlags := computeCertRisk(root, "svc.example.com", false)
	if hasFlag(rootFlags, "SELF_SIGNED") {
		t.Errorf("root further up the chain must not be flagged, got %v", rootFlags)
	}
	_, leafFlags := computeCertRisk(leaf, "svc.example.com", true)
	if hasFlag(leafFlags, "SELF_SIGNED") {
		t.Errorf("CA-issued leaf must not be flagged, got %v", leafFlags)
	}
}

// Matching names is not enough: a cert that merely claims issuer == subject
// but is not signed by its own key is not self-signed.
func TestSelfSignedRequiresOwnSignatureToVerify(t *testing.T) {
	realKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "same-name"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &realKey.PublicKey, realKey)
	parent, _ := x509.ParseCertificate(caDER)
	// Same subject DN as its issuer, but a different key: cross-signed lookalike.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "same-name"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, parent, &otherKey.PublicKey, realKey)
	c, _ := x509.ParseCertificate(der)
	if _, flags := computeCertRisk(c, "same-name", true); hasFlag(flags, "SELF_SIGNED") {
		t.Errorf("subject==issuer without a self-verifying signature must not be flagged, got %v", flags)
	}
}

func TestHostnameMismatchOnIPTargets(t *testing.T) {
	dnsOnly := selfSignedCert(t, riskCertOpts{cn: "web.example.com", dnsNames: []string{"web.example.com"}})
	if _, f := computeCertRisk(dnsOnly, "192.0.2.10", true); hasFlag(f, "HOSTNAME_MISMATCH") {
		t.Errorf("DNS-only cert scanned by IP must not be HOSTNAME_MISMATCH, got %v", f)
	}
	if _, f := computeCertRisk(dnsOnly, "web.example.com", true); hasFlag(f, "HOSTNAME_MISMATCH") {
		t.Errorf("matching DNS name must not mismatch, got %v", f)
	}
	if _, f := computeCertRisk(dnsOnly, "other.example.com", true); !hasFlag(f, "HOSTNAME_MISMATCH") {
		t.Errorf("wrong DNS name must mismatch, got %v", f)
	}

	ipCert := selfSignedCert(t, riskCertOpts{cn: "ip", ips: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")}})
	if _, f := computeCertRisk(ipCert, "192.0.2.10", true); hasFlag(f, "HOSTNAME_MISMATCH") {
		t.Errorf("matching IP SAN must not mismatch, got %v", f)
	}
	if _, f := computeCertRisk(ipCert, "2001:db8::1", true); hasFlag(f, "HOSTNAME_MISMATCH") {
		t.Errorf("matching IPv6 SAN must not mismatch, got %v", f)
	}
	if _, f := computeCertRisk(ipCert, "192.0.2.99", true); !hasFlag(f, "HOSTNAME_MISMATCH") {
		t.Errorf("IP SANs present and none match must mismatch, got %v", f)
	}
}
