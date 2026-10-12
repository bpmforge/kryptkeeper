// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"strings"
	"testing"
)

// W5-02: HAProxy single-file install — combined chain+key, mandatory
// config test, no blind systemctl fall-through.

func haproxyReq() InstallRequest {
	return InstallRequest{
		ServerType: "haproxy",
		CertPath:   "/etc/haproxy/certs/site.pem",
		CertPEM:    []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"),
		KeyPEM:     []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
	}
}

func TestHAProxyInstallWritesCombinedFileTestsThenReloads(t *testing.T) {
	exec := newFakeExecutor()
	in := New(exec)

	res, err := in.Install(context.Background(), haproxyReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Outcome != OutcomeInstalled || !res.Installed || !res.Reloaded {
		t.Fatalf("unexpected result: %+v", res)
	}

	combined := string(exec.files["/etc/haproxy/certs/site.pem"])
	if !strings.Contains(combined, "BEGIN CERTIFICATE") || !strings.Contains(combined, "BEGIN PRIVATE KEY") {
		t.Fatalf("combined file must hold chain AND key, got:\n%s", combined)
	}
	// Chain first, key last — HAProxy's crt layout.
	if strings.Index(combined, "BEGIN PRIVATE KEY") < strings.Index(combined, "chain") {
		t.Fatalf("key must follow the chain, got:\n%s", combined)
	}

	// Command order: config test BEFORE reload, both present.
	if len(exec.ran) != 2 {
		t.Fatalf("expected exactly config-test then reload, ran: %v", exec.ran)
	}
	if !strings.HasPrefix(exec.ran[0], "haproxy -c -f /etc/haproxy/haproxy.cfg") {
		t.Fatalf("first command must be the haproxy config test, ran: %v", exec.ran)
	}
	if exec.ran[1] != "systemctl reload haproxy" {
		t.Fatalf("second command must be the reload, ran: %v", exec.ran)
	}
}

func TestHAProxyConfigTestFailureRollsBackAndNeverReloads(t *testing.T) {
	exec := newFakeExecutor()
	previous := []byte("OLD COMBINED PEM")
	exec.files["/etc/haproxy/certs/site.pem"] = previous
	exec.failCmd = "haproxy -c"
	in := New(exec)

	res, err := in.Install(context.Background(), haproxyReq())
	if err == nil {
		t.Fatal("config-test failure must error")
	}
	if !res.RolledBack || res.Outcome != OutcomeConfigTestFailed {
		t.Fatalf("expected rollback on config-test failure: %+v", res)
	}
	if string(exec.files["/etc/haproxy/certs/site.pem"]) != string(previous) {
		t.Fatal("old combined file must be restored")
	}
	// The acceptance's "no blind fall-through": nothing reloads after a
	// failed test.
	for _, cmd := range exec.ran {
		if strings.HasPrefix(cmd, "systemctl reload") {
			t.Fatalf("reload must never run after a failed config test, ran: %v", exec.ran)
		}
	}
}

func TestHAProxyVerifyMismatchRollsBack(t *testing.T) {
	exec := newFakeExecutor()
	exec.files["/etc/haproxy/certs/site.pem"] = []byte("OLD COMBINED PEM")
	in := New(exec).WithVerifier(func(context.Context, string) (string, error) {
		return "aaaa", nil
	})

	req := haproxyReq()
	req.VerifyHostPort = "site.example.com:443"
	req.ExpectedFingerprint = "bbbb"
	res, err := in.Install(context.Background(), req)
	if err == nil {
		t.Fatal("fingerprint mismatch must error")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed || res.ServedFingerprint != "aaaa" {
		t.Fatalf("expected verify-mismatch rollback: %+v", res)
	}
	if string(exec.files["/etc/haproxy/certs/site.pem"]) != "OLD COMBINED PEM" {
		t.Fatal("old combined file must be restored after verify mismatch")
	}
}

func TestHAProxyVerifiedInstall(t *testing.T) {
	exec := newFakeExecutor()
	in := New(exec).WithVerifier(func(context.Context, string) (string, error) {
		return "AB:CD", nil
	})
	req := haproxyReq()
	req.VerifyHostPort = "site.example.com:443"
	req.ExpectedFingerprint = "abcd"
	res, err := in.Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified || !res.Verified {
		t.Fatalf("expected verified install: %+v", res)
	}
}

func TestHAProxyRefusalsAreExplicit(t *testing.T) {
	exec := newFakeExecutor()
	in := New(exec)

	// Missing key: the combined file cannot exist without it.
	req := haproxyReq()
	req.KeyPEM = nil
	if _, err := in.Install(context.Background(), req); err == nil || !strings.Contains(err.Error(), "combined") {
		t.Fatalf("keyless haproxy install must be refused, got %v", err)
	}

	// Binary reload: refused, not faked.
	req = haproxyReq()
	req.ReloadMethod = "binary"
	if _, err := in.Install(context.Background(), req); err == nil || !strings.Contains(err.Error(), "master-socket") {
		t.Fatalf("binary reload must be refused with the reason, got %v", err)
	}
	if len(exec.ran) != 0 {
		t.Fatalf("refusals must run nothing, ran: %v", exec.ran)
	}
}

func TestHAProxyCustomConfigPath(t *testing.T) {
	exec := newFakeExecutor()
	in := New(exec)
	req := haproxyReq()
	req.HAProxyConfigPath = "/opt/haproxy/lb.cfg"
	if _, err := in.Install(context.Background(), req); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.HasPrefix(exec.ran[0], "haproxy -c -f /opt/haproxy/lb.cfg") {
		t.Fatalf("config test must use the overridden path, ran: %v", exec.ran)
	}
}
