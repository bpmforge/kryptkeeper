// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeExecutor is an in-memory Executor for tests: a virtual filesystem plus a
// scripted command runner.
type fakeExecutor struct {
	files map[string][]byte
	// failCmd, when it matches "name arg0 arg1...", makes Run return an error.
	failCmd string
	// ran records every command Run executed, in order.
	ran []string
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{files: map[string][]byte{}}
}

func (f *fakeExecutor) Exists(path string) bool { _, ok := f.files[path]; return ok }

func (f *fakeExecutor) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (f *fakeExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	cp := make([]byte, len(content))
	copy(cp, content)
	f.files[path] = cp
	return nil
}

func (f *fakeExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, cmd)
	if f.failCmd != "" && strings.HasPrefix(cmd, f.failCmd) {
		return []byte("simulated failure: " + cmd), fmt.Errorf("command failed: %s", cmd)
	}
	return []byte("ok"), nil
}

func nginxReq() InstallRequest {
	return InstallRequest{
		ServerType: "nginx",
		CertPath:   "/etc/nginx/ssl/site.crt",
		KeyPath:    "/etc/nginx/ssl/site.key",
		CertPEM:    []byte("NEW-CERT"),
		KeyPEM:     []byte("NEW-KEY"),
	}
}

func TestInstall_HappyPath(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")

	res, err := New(f).Install(context.Background(), nginxReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Installed || !res.Reloaded || res.RolledBack {
		t.Fatalf("unexpected result: %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "NEW-CERT" {
		t.Errorf("cert not written: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	if string(f.files["/etc/nginx/ssl/site.key"]) != "NEW-KEY" {
		t.Errorf("key not written: %q", f.files["/etc/nginx/ssl/site.key"])
	}
	// config test must precede reload.
	if len(f.ran) != 2 || f.ran[0] != "nginx -t" || f.ran[1] != "systemctl reload nginx" {
		t.Fatalf("unexpected command order: %v", f.ran)
	}
}

func TestInstall_ConfigTestFailsRollsBack(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	f.failCmd = "nginx -t"

	res, err := New(f).Install(context.Background(), nginxReq())
	if err == nil {
		t.Fatal("expected error when config test fails")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack, got %+v", res)
	}
	// Old contents must be restored; never reloaded.
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Errorf("cert not rolled back: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	if string(f.files["/etc/nginx/ssl/site.key"]) != "OLD-KEY" {
		t.Errorf("key not rolled back: %q", f.files["/etc/nginx/ssl/site.key"])
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl reload") {
			t.Fatalf("must NOT reload after failed config test; ran %v", f.ran)
		}
	}
}

func TestInstall_ReloadFailsRollsBackAndReloads(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	f.failCmd = "systemctl reload nginx"

	res, err := New(f).Install(context.Background(), nginxReq())
	if err == nil {
		t.Fatal("expected error when reload fails")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack, got %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Errorf("cert not rolled back: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	// reload attempted twice: once for the new cert, once after rollback.
	reloads := 0
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl reload") {
			reloads++
		}
	}
	if reloads != 2 {
		t.Fatalf("expected 2 reload attempts (install + post-rollback), got %d: %v", reloads, f.ran)
	}
}

func TestInstall_FirstTimeNoBackup(t *testing.T) {
	f := newFakeExecutor() // no pre-existing files
	res, err := New(f).Install(context.Background(), nginxReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Installed || !res.Reloaded {
		t.Fatalf("unexpected result: %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "NEW-CERT" {
		t.Errorf("cert not written on first install")
	}
}

func TestInstall_BinaryReloadMethod(t *testing.T) {
	f := newFakeExecutor()
	req := nginxReq()
	req.ReloadMethod = "binary"
	if _, err := New(f).Install(context.Background(), req); err != nil {
		t.Fatalf("install: %v", err)
	}
	if f.ran[len(f.ran)-1] != "nginx -s reload" {
		t.Fatalf("expected binary reload, got %v", f.ran)
	}
}

func TestInstall_RequiresCert(t *testing.T) {
	f := newFakeExecutor()
	_, err := New(f).Install(context.Background(), InstallRequest{ServerType: "nginx"})
	if err == nil {
		t.Fatal("expected error with no cert")
	}
}

func TestInstall_ApacheUsesConfigtest(t *testing.T) {
	f := newFakeExecutor()
	req := InstallRequest{
		ServerType: "apache",
		CertPath:   "/etc/apache2/ssl/site.crt",
		KeyPath:    "/etc/apache2/ssl/site.key",
		CertPEM:    []byte("C"),
		KeyPEM:     []byte("K"),
	}
	if _, err := New(f).Install(context.Background(), req); err != nil {
		t.Fatalf("install: %v", err)
	}
	if f.ran[0] != "apachectl configtest" || f.ran[1] != "systemctl reload apache2" {
		t.Fatalf("unexpected apache commands: %v", f.ran)
	}
}

// fakeVerifier returns a Verifier that yields servedFP (or err).
func fakeVerifier(servedFP string, err error) Verifier {
	return func(_ context.Context, _ string) (string, error) {
		return servedFP, err
	}
}

func verifyReq() InstallRequest {
	r := nginxReq()
	r.VerifyHostPort = "localhost:443"
	r.ExpectedFingerprint = "ABCD1234"
	return r
}

func TestInstall_VerifySuccess(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD")
	in := New(f).WithVerifier(fakeVerifier("abcd1234", nil)) // case-insensitive match

	res, err := in.Install(context.Background(), verifyReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Verified || res.Outcome != OutcomeInstalledVerified {
		t.Fatalf("expected verified outcome, got %+v", res)
	}
	if res.ServedFingerprint != "abcd1234" {
		t.Errorf("served fingerprint: %q", res.ServedFingerprint)
	}
}

func TestInstall_VerifyMismatchRollsBack(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	in := New(f).WithVerifier(fakeVerifier("deadbeef", nil)) // wrong cert served

	res, err := in.Install(context.Background(), verifyReq())
	if err == nil {
		t.Fatal("expected error on fingerprint mismatch")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed {
		t.Fatalf("expected verify_failed rollback, got %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Errorf("cert not rolled back after verify mismatch: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	// reload happens for install, then again after rollback.
	reloads := 0
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl reload") {
			reloads++
		}
	}
	if reloads != 2 {
		t.Fatalf("expected 2 reloads (install + post-rollback), got %d: %v", reloads, f.ran)
	}
}

func TestInstall_VerifyDialErrorRollsBack(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	in := New(f).WithVerifier(fakeVerifier("", fmt.Errorf("connection refused")))

	res, err := in.Install(context.Background(), verifyReq())
	if err == nil {
		t.Fatal("expected error when verify dial fails")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed {
		t.Fatalf("expected verify_failed rollback, got %+v", res)
	}
}

func TestInstall_NoVerifyWhenNotRequested(t *testing.T) {
	f := newFakeExecutor()
	// Verifier that would fail if called — proves it's skipped.
	in := New(f).WithVerifier(fakeVerifier("", fmt.Errorf("should not be called")))
	res, err := in.Install(context.Background(), nginxReq()) // no VerifyHostPort
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Verified || res.Outcome != OutcomeInstalled {
		t.Fatalf("expected installed (unverified) outcome, got %+v", res)
	}
}

func TestFingerprintSHA256(t *testing.T) {
	// SHA-256 of empty input is well-known.
	got := FingerprintSHA256(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("FingerprintSHA256(nil) = %q, want %q", got, want)
	}
}
