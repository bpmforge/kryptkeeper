// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// W14-01: agentless SSH discovery through an in-memory executor — cert
// parsing, key-file paths without content, mixed bundles, host keys,
// and error tolerance.

// fakeExec is an in-memory agentinstall.Executor. It records every
// ReadFile so the test can prove key files are never read.
type fakeExec struct {
	files    map[string]string // path -> content
	findOut  map[string]string // "find <root>..." keyed by first path arg
	readLog  []string
	failRead map[string]bool
}

func (f *fakeExec) Exists(path string) bool { _, ok := f.files[path]; return ok }
func (f *fakeExec) ReadFile(path string) ([]byte, error) {
	f.readLog = append(f.readLog, path)
	if f.failRead[path] {
		return nil, fmt.Errorf("permission denied")
	}
	c, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("no such file")
	}
	return []byte(c), nil
}
func (f *fakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *fakeExec) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "find" || len(args) == 0 {
		return nil, fmt.Errorf("unexpected command %s", name)
	}
	out, ok := f.findOut[args[0]]
	if !ok {
		return nil, fmt.Errorf("no such root")
	}
	return []byte(out), nil
}

func certPEM(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAgentlessSSHScanFindsCertsNotKeys(t *testing.T) {
	leaf := certPEM(t, "web.example.com")
	mixed := certPEM(t, "bundle.example.com") + "\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	exec := &fakeExec{
		files: map[string]string{
			"/etc/ssl/certs/web.crt":            leaf,
			"/etc/ssl/certs/bundle.pem":         mixed,
			"/etc/ssl/certs/server.key":         "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
			"/etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 root@host",
		},
		findOut: map[string]string{
			"/etc/ssl/certs": "/etc/ssl/certs/web.crt\n/etc/ssl/certs/bundle.pem\n/etc/ssl/certs/server.key",
			"/etc/ssh":       "/etc/ssh/ssh_host_ed25519_key.pub",
		},
	}
	s := NewAgentlessSSHScanner(exec, "host-1", []string{"/etc/ssl/certs"})
	res := s.Scan(context.Background())

	// Two certs: the leaf and the bundle's cert (its key skipped).
	if len(res.Certs) != 2 {
		t.Fatalf("expected 2 certs, got %d: %+v", len(res.Certs), res.Certs)
	}
	// The .key file and the mixed bundle are listed by path.
	if !contains(res.KeyFilePaths, "/etc/ssl/certs/server.key") || !contains(res.KeyFilePaths, "/etc/ssl/certs/bundle.pem") {
		t.Fatalf("key file paths: %v", res.KeyFilePaths)
	}
	// The .key file was NEVER read.
	for _, p := range exec.readLog {
		if p == "/etc/ssl/certs/server.key" {
			t.Fatal("private key file must never be ReadFile'd")
		}
	}
	// No private-key bytes anywhere in the result.
	if strings.Contains(fmt.Sprintf("%+v", res), "PRIVATE KEY") || strings.Contains(fmt.Sprintf("%+v", res), "SECRET") {
		t.Fatal("result must not carry private key material")
	}
	// Host key captured.
	if len(res.HostKeys) != 1 || res.HostKeys[0].Algorithm != "ssh-ed25519" || !strings.HasPrefix(res.HostKeys[0].Fingerprint, "sha256:") {
		t.Fatalf("host key: %+v", res.HostKeys)
	}
	// Fingerprints match the agent's own parser.
	agentCerts, _ := parseCertsSkippingKeys([]byte(leaf), "x")
	found := false
	for _, c := range res.Certs {
		if c.Fingerprint == agentCerts[0].Fingerprint {
			found = true
		}
	}
	if !found {
		t.Fatal("agentless fingerprint must match the agent parser")
	}
}

func TestAgentlessSSHScanToleratesUnreadableFile(t *testing.T) {
	exec := &fakeExec{
		files:    map[string]string{"/etc/ssl/certs/ok.crt": certPEM(t, "ok.example.com")},
		failRead: map[string]bool{"/etc/ssl/certs/bad.crt": true},
		findOut:  map[string]string{"/etc/ssl/certs": "/etc/ssl/certs/ok.crt\n/etc/ssl/certs/bad.crt"},
	}
	// bad.crt is referenced by find but read fails.
	exec.files["/etc/ssl/certs/bad.crt"] = ""
	res := NewAgentlessSSHScanner(exec, "host-2", []string{"/etc/ssl/certs"}).Scan(context.Background())
	if len(res.Certs) != 1 {
		t.Fatalf("good cert must still be found: %+v", res.Certs)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "bad.crt") {
		t.Fatalf("unreadable file must land in Errors: %v", res.Errors)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
