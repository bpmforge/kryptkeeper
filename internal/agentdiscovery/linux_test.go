// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kryptkeeper/internal/agentdiscovery"
)

// writeCertPEM writes a self-signed cert to a temp file and returns the path.
func writeCertPEM(t *testing.T, dir, filename string, cn string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return path
}

func TestWalkLinuxCerts_FindsCertsInDir(t *testing.T) {
	dir := t.TempDir()
	writeCertPEM(t, dir, "a.crt", "CN=a.example.com", time.Now().Add(90*24*time.Hour))
	writeCertPEM(t, dir, "b.pem", "CN=b.example.com", time.Now().Add(180*24*time.Hour))

	certs, err := agentdiscovery.WalkLinuxCerts([]string{dir})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
}

func TestWalkLinuxCerts_SkipsNonCertFiles(t *testing.T) {
	dir := t.TempDir()
	writeCertPEM(t, dir, "good.crt", "CN=good.example.com", time.Now().Add(90*24*time.Hour))
	// Write a non-cert file
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"key":"value"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "README.txt"), []byte("readme"), 0o644)

	certs, err := agentdiscovery.WalkLinuxCerts([]string{dir})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (non-cert files skipped), got %d", len(certs))
	}
}

func TestWalkLinuxCerts_DeduplicatesSameCert(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Write the same certificate content to both directories.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "dedup.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	_ = os.WriteFile(filepath.Join(dir1, "cert.crt"), pemBlock, 0o644)
	_ = os.WriteFile(filepath.Join(dir2, "cert.crt"), pemBlock, 0o644)

	certs, err := agentdiscovery.WalkLinuxCerts([]string{dir1, dir2})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert after deduplication, got %d", len(certs))
	}
}

func TestWalkLinuxCerts_SkipsMissingPaths(t *testing.T) {
	certs, err := agentdiscovery.WalkLinuxCerts([]string{"/nonexistent/path/xyz"})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for missing path, got %d", len(certs))
	}
}

func TestWalkLinuxCerts_MultipleCertsInOneFile(t *testing.T) {
	dir := t.TempDir()

	// Write two certs into a single PEM file (bundle).
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cert1.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cert2.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(180 * 24 * time.Hour),
	}
	der1, _ := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, &key1.PublicKey, key1)
	der2, _ := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key2.PublicKey, key2)

	bundlePath := filepath.Join(dir, "bundle.pem")
	f, _ := os.Create(bundlePath)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der1})
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der2})
	f.Close()

	certs, err := agentdiscovery.WalkLinuxCerts([]string{dir})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs from bundle, got %d", len(certs))
	}
}

func TestWalkLinuxCerts_AutoRenewableForSoonExpiring(t *testing.T) {
	dir := t.TempDir()
	// Expiring in 30 days — within the 90-day auto-renewable window.
	writeCertPEM(t, dir, "expiring.crt", "CN=expiring.example.com", time.Now().Add(30*24*time.Hour))

	certs, err := agentdiscovery.WalkLinuxCerts([]string{dir})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if !certs[0].AutoRenewable {
		t.Error("expected AutoRenewable=true for cert expiring in 30 days")
	}
}

func TestWalkLinuxCerts_FingerprintPopulated(t *testing.T) {
	dir := t.TempDir()
	writeCertPEM(t, dir, "cert.crt", "CN=fp.example.com", time.Now().Add(90*24*time.Hour))

	certs, err := agentdiscovery.WalkLinuxCerts([]string{dir})
	if err != nil {
		t.Fatalf("WalkLinuxCerts: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least 1 cert")
	}
	if certs[0].Fingerprint == "" {
		t.Error("expected non-empty Fingerprint")
	}
	// Should contain colons (colon-hex format).
	if len(certs[0].Fingerprint) < 10 {
		t.Errorf("fingerprint looks too short: %q", certs[0].Fingerprint)
	}
}
