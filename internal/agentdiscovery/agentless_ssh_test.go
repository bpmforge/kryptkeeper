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
	"encoding/base64"
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
	files   map[string]string // path -> content
	findOut map[string]string // "find <root>..." keyed by first path arg
	// findErr makes find report a non-zero exit while still returning its
	// (partial) output, as find does for an unreadable subdirectory.
	findErr  map[string]error
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
	if err := f.findErr[args[0]]; err != nil {
		return []byte(out), err
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
	agentCerts, _, _ := parseCertsSkippingKeys([]byte(leaf), "x")
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

// W24-08: a non-sudo user hits "Permission denied" on some subdirectories;
// find exits non-zero but its partial stdout still lists readable certs.
func TestAgentlessSSHScanKeepsPartialFindOutput(t *testing.T) {
	exec := &fakeExec{
		files: map[string]string{
			"/etc/ssl/certs/a.crt": certPEM(t, "a.example.com"),
			"/etc/ssl/certs/b.pem": certPEM(t, "b.example.com"),
		},
		findOut: map[string]string{"/etc/ssl/certs": "/etc/ssl/certs/a.crt\n" +
			"find: '/etc/ssl/certs/locked': Permission denied\n" +
			"find: '/etc/ssl/certs/gone': No such file or directory\n" +
			"/etc/ssl/certs/b.pem\n"},
		findErr: map[string]error{"/etc/ssl/certs": fmt.Errorf("exit status 1")},
	}
	res := NewAgentlessSSHScanner(exec, "h", []string{"/etc/ssl/certs"}).Scan(context.Background())
	if len(res.Certs) != 2 || len(res.Parsed) != 2 {
		t.Fatalf("readable certs must survive a non-zero find, Parsed in lockstep: certs=%d parsed=%d", len(res.Certs), len(res.Parsed))
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "Permission denied") {
		t.Fatalf("exactly the permission-denied line is a warning: %v", res.Errors)
	}
	for _, p := range exec.readLog {
		if strings.HasPrefix(p, "find:") {
			t.Fatalf("a find diagnostic was treated as a path: %q", p)
		}
	}
	if res.Parsed[0].Subject.CommonName != "a.example.com" || res.Certs[0].Source != "agentless-ssh:/etc/ssl/certs/a.crt" {
		t.Fatalf("Parsed/Certs out of lockstep: %s / %s", res.Parsed[0].Subject.CommonName, res.Certs[0].Source)
	}
}

func TestAgentlessSSHScanReadsJKSAndP12(t *testing.T) {
	jks := string(buildJKS(t, testDER(t, "trusted.example.com"), testDER(t, "keyentry.example.com")))
	p12, err := base64.StdEncoding.DecodeString(p12FixtureBase64)
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExec{
		files: map[string]string{
			"/opt/app/trust.jks": jks,
			"/opt/app/id.p12":    string(p12),
			"/opt/app/bad.pfx":   "not a keystore",
		},
		findOut: map[string]string{"/opt/app": "/opt/app/trust.jks\n/opt/app/id.p12\n/opt/app/bad.pfx"},
	}
	res := NewAgentlessSSHScanner(exec, "h", []string{"/opt/app"}).Scan(context.Background())
	if len(res.Certs) != 3 || len(res.Parsed) != 3 {
		t.Fatalf("2 JKS certs + 1 P12 cert expected, got %d", len(res.Certs))
	}
	if res.Certs[0].Source != "agentless-ssh:/opt/app/trust.jks" {
		t.Fatalf("source: %s", res.Certs[0].Source)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "bad.pfx") {
		t.Fatalf("a corrupt keystore is a warning: %v", res.Errors)
	}
	if strings.Contains(fmt.Sprintf("%+v", res), "PRIVATE KEY") {
		t.Fatal("no key material may reach the result")
	}
}

// W34-07: the listener sweep rides on the scan's own executor and never
// pollutes Errors (those become per-path findings).
func TestAgentlessSSHScanSweepsListeners(t *testing.T) {
	x := &scriptExec{
		run: map[string]string{
			"ss -ltnp": "LISTEN 0 1 *:8443 *:* users:((\"java\",pid=9,fd=1))\nLISTEN 0 1 *:25 *:*\n",
		},
		files: map[string]string{"/proc/9/status": statusFile("java", 1001, 1001), "/proc/9/cmdline": "java\x00-Dcatalina.base=/opt/tomcat\x00"},
	}
	res := NewAgentlessSSHScanner(x, "h", []string{"/nowhere"}).Scan(context.Background())
	if !res.ListenersScanned || res.ListenersHidden != 1 || len(res.Listeners) != 2 {
		t.Fatalf("%+v", res)
	}
	var tech string
	for _, l := range res.Listeners {
		if l.Port == 8443 {
			tech = l.Tech
		}
	}
	if tech != "tomcat" {
		t.Fatalf("tech = %q", tech)
	}
}

func TestAgentlessSSHScanListenerFailureIsNotAPathError(t *testing.T) {
	f := &fakeExec{findOut: map[string]string{"/etc/ssl": ""}}
	res := NewAgentlessSSHScanner(f, "h", []string{"/etc/ssl"}).Scan(context.Background())
	if res.ListenersScanned || res.ListenersErr == "" {
		t.Fatalf("expected a recorded listener failure: %+v", res)
	}
	for _, e := range res.Errors {
		if strings.Contains(e, "ss") && strings.Contains(e, "listen") {
			t.Fatalf("listener failure leaked into Errors: %v", res.Errors)
		}
	}
}

// W34-20: in helper mode a keystore comes back as PEM (the helper runs keytool
// on the host); it must be read as certificates, not rejected as a bad keystore.
func TestAgentlessSSHScanReadsKeystoreReturnedAsPEM(t *testing.T) {
	pemText := certPEM(t, "from-keytool.example.com")
	exec := &fakeExec{
		files:   map[string]string{"/opt/ssl/keystore.jks": pemText},
		findOut: map[string]string{"/opt/ssl": "/opt/ssl/keystore.jks"},
	}
	res := NewAgentlessSSHScanner(exec, "h", []string{"/opt/ssl"}).Scan(context.Background())
	if len(res.Certs) != 1 || len(res.Errors) != 0 {
		t.Fatalf("certs %d errors %v", len(res.Certs), res.Errors)
	}
	if res.Certs[0].Source != "agentless-ssh:/opt/ssl/keystore.jks" {
		t.Fatalf("source = %s", res.Certs[0].Source)
	}
}

// W34-20: a root the sudoers rule does not cover answers with sudo's refusal,
// not a listing. It must not be read as file paths, and the account's own
// permissions still discover what they can.
type sudoRefusingExec struct{ *fakeExec }

func (s sudoRefusingExec) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	return []byte("sudo: a password is required\n"), fmt.Errorf("exit status 1")
}

func TestAgentlessSSHScanFallsBackWhenSudoRefusesARoot(t *testing.T) {
	plain := &fakeExec{
		files:   map[string]string{"/etc/pki/tls/certs/site.crt": certPEM(t, "plain-readable.example.com")},
		findOut: map[string]string{"/etc/pki/tls/certs": "/etc/pki/tls/certs/site.crt"},
	}
	priv := sudoRefusingExec{&fakeExec{failRead: map[string]bool{"/etc/pki/tls/certs/site.crt": true}}}
	res := NewAgentlessSSHScanner(priv, "h", []string{"/etc/pki/tls/certs"}).WithUnprivileged(plain).Scan(context.Background())
	if len(res.Certs) != 1 || len(res.Errors) != 0 {
		t.Fatalf("certs %d errors %v", len(res.Certs), res.Errors)
	}
	// Without an unprivileged executor the refusal is dropped, never read as a path.
	res = NewAgentlessSSHScanner(priv, "h", []string{"/etc/pki/tls/certs"}).Scan(context.Background())
	for _, e := range res.Errors {
		if strings.Contains(e, "a password is required") {
			t.Fatalf("sudo's refusal was recorded as an unreadable path: %v", res.Errors)
		}
	}
	if len(res.Certs) != 0 {
		t.Fatalf("certs %d", len(res.Certs))
	}
}

// W34-09 regression: the agent's own scan keeps the pre-W34 inventory shape,
// "format:path" sources for keystores and kubeconfig coverage, which the SSH
// scan (agentless-ssh:path, no kubeconfig) never had.
func TestAgentScanKeepsKeystoreSourcesAndKubeconfig(t *testing.T) {
	jks := string(buildJKS(t, testDER(t, "trusted.example.com"), testDER(t, "keyentry.example.com")))
	p12, err := base64.StdEncoding.DecodeString(p12FixtureBase64)
	if err != nil {
		t.Fatal(err)
	}
	kube := "users:\n- name: a\n  user:\n    client-certificate-data: " +
		base64.StdEncoding.EncodeToString([]byte(certPEM(t, "kube-client.example.com"))) + "\n"
	exec := &fakeExec{
		files: map[string]string{
			"/opt/ks/trust.jks":  jks,
			"/opt/ks/id.p12":     string(p12),
			"/opt/ks/kubeconfig": kube,
			"/opt/ks/leaf.pem":   certPEM(t, "leaf.example.com"),
		},
		findOut: map[string]string{"/opt/ks": "/opt/ks/trust.jks\n/opt/ks/id.p12\n/opt/ks/kubeconfig\n/opt/ks/leaf.pem"},
	}
	res := NewAgentlessSSHScanner(exec, "h", []string{"/opt/ks"}).ForAgent().Scan(context.Background())
	got := map[string]int{}
	for _, c := range res.Certs {
		got[c.Source]++
	}
	want := map[string]int{"jks:/opt/ks/trust.jks": 2, "pkcs12:/opt/ks/id.p12": 1, "kubeconfig:/opt/ks/kubeconfig": 1, "/opt/ks/leaf.pem": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sources %v, want %v (errors %v)", got, want, res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
}
