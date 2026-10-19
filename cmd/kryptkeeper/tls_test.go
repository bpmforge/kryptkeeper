// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// fakeIssuedRecorder captures every RecordIssuedCertificate call so tests
// can assert on source label and call count without a real bootstrap
// CertificateProvider/DB.
type fakeIssuedRecorder struct {
	mu    sync.Mutex
	calls []fakeIssuedRecorderCall
}

type fakeIssuedRecorderCall struct {
	caID   string
	serial string
	source string
}

func (f *fakeIssuedRecorder) RecordIssuedCertificate(_ context.Context, caID string, cert *x509.Certificate, _ []byte, source string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeIssuedRecorderCall{caID: caID, serial: cert.SerialNumber.String(), source: source})
	return nil
}

func (f *fakeIssuedRecorder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeIssuedRecorder) last() fakeIssuedRecorderCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func newTLSTestEngine(t *testing.T) (ca.Service, string) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("tls-listener-test-pass-32bytes!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	return engine, root.ID
}

// TestSelfIssuedTLSCertificate_RecordsThroughRecorder covers W19-21: the
// self-issued listener cert previously bypassed
// bootstrap.CertificateProvider entirely (no inventory row, no lineage).
// It must now record through ca.IssuedCertificateRecorder with source
// "tls-listener", same as ACME/EST/SCEP/CMP.
func TestSelfIssuedTLSCertificate_RecordsThroughRecorder(t *testing.T) {
	engine, caID := newTLSTestEngine(t)
	recorder := &fakeIssuedRecorder{}

	cert, err := selfIssuedTLSCertificate(engine, recorder, caID, t.TempDir(), []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("selfIssuedTLSCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected a certificate")
	}
	if recorder.callCount() != 1 {
		t.Fatalf("expected 1 recorder call, got %d", recorder.callCount())
	}
	got := recorder.last()
	if got.caID != caID {
		t.Errorf("caID = %q, want %q", got.caID, caID)
	}
	if got.source != tlsListenerSource {
		t.Errorf("source = %q, want %q", got.source, tlsListenerSource)
	}
}

// TestSelfIssuedTLSCertificate_NilRecorderIsSafe proves a nil recorder
// (a certificate provider that doesn't implement the seam, e.g.
// APP_CERTIFICATE_PROVIDER != "ca") never breaks self-issuance -- matching
// how the protocol servers treat a missing recorder as best-effort/absent.
func TestSelfIssuedTLSCertificate_NilRecorderIsSafe(t *testing.T) {
	engine, caID := newTLSTestEngine(t)

	if _, err := selfIssuedTLSCertificate(engine, nil, caID, t.TempDir(), []string{"localhost"}); err != nil {
		t.Fatalf("selfIssuedTLSCertificate with nil recorder: %v", err)
	}
}

// TestSelfIssuedTLSCertificate_ReIssueRecordsAgain covers the re-issue path
// (30 days before expiry, or a SAN change): the new certificate must also
// be recorded, not just the first one minted at cold start.
func TestSelfIssuedTLSCertificate_ReIssueRecordsAgain(t *testing.T) {
	engine, caID := newTLSTestEngine(t)
	recorder := &fakeIssuedRecorder{}
	dataDir := t.TempDir()

	if _, err := selfIssuedTLSCertificate(engine, recorder, caID, dataDir, []string{"localhost"}); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	if recorder.callCount() != 1 {
		t.Fatalf("after first issuance, expected 1 recorder call, got %d", recorder.callCount())
	}

	// Changing the wanted SAN set forces sameSANs to fail, taking the same
	// re-issue branch a near-expiry certificate would.
	if _, err := selfIssuedTLSCertificate(engine, recorder, caID, dataDir, []string{"localhost", "example.test"}); err != nil {
		t.Fatalf("re-issuance: %v", err)
	}
	if recorder.callCount() != 2 {
		t.Fatalf("after re-issuance, expected 2 recorder calls, got %d", recorder.callCount())
	}
	if recorder.last().source != tlsListenerSource {
		t.Errorf("re-issued source = %q, want %q", recorder.last().source, tlsListenerSource)
	}
}

// TestSelfIssuedTLSCertificate_WritesCACertBundle covers W19-23: the
// compose healthcheck binary and dashboard's nginx proxy need a CA bundle
// to trust the self-issued listener cert without ever touching key
// material. ca.pem must exist, contain no private key, and its first
// certificate must be the one that verifies the issued leaf.
func TestSelfIssuedTLSCertificate_WritesCACertBundle(t *testing.T) {
	engine, caID := newTLSTestEngine(t)
	dataDir := t.TempDir()

	cert, err := selfIssuedTLSCertificate(engine, nil, caID, dataDir, []string{"localhost"})
	if err != nil {
		t.Fatalf("selfIssuedTLSCertificate: %v", err)
	}

	caPath := filepath.Join(dataDir, "tls", "ca.pem")
	bundle, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("reading ca.pem: %v", err)
	}
	if len(bundle) == 0 {
		t.Fatal("ca.pem is empty")
	}

	block, _ := pem.Decode(bundle)
	if block == nil {
		t.Fatal("ca.pem contains no PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("ca.pem first block type = %q, want CERTIFICATE (no key material must ever land here)", block.Type)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing ca.pem: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing issued leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not verify against ca.pem: %v", err)
	}
}

// TestSelfIssuedTLSCertificate_RefreshesCABundleOnReuse covers the reuse
// path (valid leaf, unchanged SANs): ca.pem must still exist afterward, not
// just on first issuance -- a client that starts after the hub's cold-boot
// issuance but before any renewal must still find a trust bundle.
func TestSelfIssuedTLSCertificate_RefreshesCABundleOnReuse(t *testing.T) {
	engine, caID := newTLSTestEngine(t)
	dataDir := t.TempDir()

	if _, err := selfIssuedTLSCertificate(engine, nil, caID, dataDir, []string{"localhost"}); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	caPath := filepath.Join(dataDir, "tls", "ca.pem")
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("removing ca.pem to prove reuse rewrites it: %v", err)
	}

	if _, err := selfIssuedTLSCertificate(engine, nil, caID, dataDir, []string{"localhost"}); err != nil {
		t.Fatalf("reuse call: %v", err)
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Fatalf("ca.pem missing after reuse path: %v", err)
	}
}

// TestSelfIssuedTLSCertificate_ExportsTrustDirWithoutKeys covers the
// cross-container sharing path: KRYPTKEEPER_TLS_TRUST_EXPORT_DIR gets a
// copy of ca.pem so compose can mount a dedicated, key-free volume into the
// dashboard/healthcheck consumers instead of the tls/ directory that also
// holds tls.key (CLAUDE.md: private key material never leaves its
// boundary).
func TestSelfIssuedTLSCertificate_ExportsTrustDirWithoutKeys(t *testing.T) {
	engine, caID := newTLSTestEngine(t)
	dataDir := t.TempDir()
	exportDir := t.TempDir()
	t.Setenv("KRYPTKEEPER_TLS_TRUST_EXPORT_DIR", exportDir)

	if _, err := selfIssuedTLSCertificate(engine, nil, caID, dataDir, []string{"localhost"}); err != nil {
		t.Fatalf("selfIssuedTLSCertificate: %v", err)
	}

	entries, err := os.ReadDir(exportDir)
	if err != nil {
		t.Fatalf("reading export dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ca.pem" {
		t.Fatalf("export dir contents = %v, want exactly [ca.pem] (never a key)", entries)
	}

	exported, err := os.ReadFile(filepath.Join(exportDir, "ca.pem"))
	if err != nil {
		t.Fatalf("reading exported ca.pem: %v", err)
	}
	inPlace, err := os.ReadFile(filepath.Join(dataDir, "tls", "ca.pem"))
	if err != nil {
		t.Fatalf("reading in-place ca.pem: %v", err)
	}
	if string(exported) != string(inPlace) {
		t.Error("exported ca.pem does not match the copy under KRYPTKEEPER_DATA_DIR/tls/")
	}
}

// Requesting client certificates is opt-in (W20-13): it breaks Windows'
// revocation fetch and prompts browsers, and only the WSTEP TLS renewal path
// for non-Windows clients needs it (D-110). When on, it requests but never
// verifies in the handshake. The TLS 1.2 floor is policy either way.
func TestBaseTLSConfig_ClientCertRequestIsOptIn(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want tls.ClientAuthType
	}{
		{"", tls.NoClientCert},
		{"false", tls.NoClientCert},
		{"1", tls.NoClientCert},
		{"yes", tls.NoClientCert},
		{"true", tls.RequestClientCert},
		{"TRUE", tls.RequestClientCert},
	} {
		t.Setenv("KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT", tc.env)
		cfg := baseTLSConfig(tls.Certificate{})
		if cfg.ClientAuth != tc.want {
			t.Errorf("%q: ClientAuth = %v, want %v", tc.env, cfg.ClientAuth, tc.want)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %x", cfg.MinVersion)
		}
	}
}

func TestResolveTLSMode_FirstRunNoCA(t *testing.T) {
	t.Setenv("KRYPTKEEPER_TLS_DISABLE", "")
	t.Setenv("KRYPTKEEPER_TLS_CERT_FILE", "")
	t.Setenv("KRYPTKEEPER_TLS_KEY_FILE", "")
	t.Setenv("KRYPTKEEPER_TLS_SELF_ISSUE", "")
	engine := ca.NewEngine(nil, ca.NewMemStore())
	dataDir, exportDir := t.TempDir(), t.TempDir()
	t.Setenv("KRYPTKEEPER_TLS_TRUST_EXPORT_DIR", exportDir)

	cfg, warn, err := resolveTLSMode(true, engine, nil, "", dataDir, ":0")
	if err != nil || cfg == nil || !strings.Contains(warn, "first-run") {
		t.Fatalf("default mode with no CA must warn and still serve TLS, got cfg=%v warn=%q err=%v", cfg, warn, err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf == nil || cfg.Certificates[0].Leaf.Subject.CommonName != "kryptkeeper first-run (ephemeral)" {
		t.Fatalf("first-run listener must use the ephemeral self-signed certificate, got %+v", cfg.Certificates)
	}
	// The public half is published as ca.pem (data dir and trust export) so the
	// compose dashboard and healthcheck can verify the listener; no key in it.
	for _, dir := range []string{filepath.Join(dataDir, "tls"), exportDir} {
		got, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
		if err != nil {
			t.Fatalf("first-run must publish ca.pem in %s: %v", dir, err)
		}
		block, _ := pem.Decode(got)
		if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, cfg.Certificates[0].Certificate[0]) || bytes.Contains(got, []byte("PRIVATE")) {
			t.Fatalf("%s/ca.pem must be exactly the ephemeral certificate", dir)
		}
	}

	t.Setenv("KRYPTKEEPER_TLS_SELF_ISSUE", "true")
	if _, _, err := resolveTLSMode(true, engine, nil, "", t.TempDir(), ":0"); err == nil || !strings.Contains(err.Error(), "first-run") {
		t.Fatalf("explicit self-issue with no CA must fail clearly, got %v", err)
	}
}
