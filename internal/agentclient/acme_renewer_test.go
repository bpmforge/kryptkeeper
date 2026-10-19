// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestEncodeCertChain_SingleCert(t *testing.T) {
	der := []byte{0x30, 0x03, 0x01, 0x01, 0x00}
	result := encodeCertChain([][]byte{der})

	block, _ := pem.Decode(result)
	if block == nil {
		t.Fatal("expected valid PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Error("PEM block bytes do not match input DER")
	}
}

func TestEncodeCertChain_MultiCert(t *testing.T) {
	der1 := []byte{0x30, 0x01, 0xAA}
	der2 := []byte{0x30, 0x01, 0xBB}
	result := encodeCertChain([][]byte{der1, der2})

	rest := result
	count := 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		count++
		rest = remaining
	}
	if count != 2 {
		t.Errorf("expected 2 PEM blocks, got %d", count)
	}
}

func TestServeChallenge_FileMode(t *testing.T) {
	webRoot := t.TempDir()
	token := "test-token-abc123"
	keyAuth := "test-token-abc123.thumbprint"

	cleanup, err := serveChallenge(context.Background(), token, keyAuth, webRoot, "")
	if err != nil {
		t.Fatalf("serveChallenge: %v", err)
	}

	challengeFile := filepath.Join(webRoot, ".well-known", "acme-challenge", token)
	data, err := os.ReadFile(challengeFile)
	if err != nil {
		t.Fatalf("challenge file not created: %v", err)
	}
	if string(data) != keyAuth {
		t.Errorf("expected %q in challenge file, got %q", keyAuth, string(data))
	}

	cleanup()
	if _, err := os.Stat(challengeFile); !os.IsNotExist(err) {
		t.Error("expected challenge file to be removed after cleanup")
	}
}

func TestBuildCSR_ContainsDomain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr, err := buildCSR([]string{"renew.example.com"}, key)
	if err != nil {
		t.Fatalf("buildCSR: %v", err)
	}
	if len(csr) == 0 {
		t.Error("expected non-empty CSR")
	}
}

func TestNewAcmeRenewer_SetsHubURL(t *testing.T) {
	r := NewAcmeRenewer("https://hub.example.com/", nil)
	if r.HubURL != "https://hub.example.com" {
		t.Errorf("expected trailing slash stripped, got %q", r.HubURL)
	}
}

func TestIsACMEConflict(t *testing.T) {
	cases := []struct {
		msg    string
		expect bool
	}{
		{"account already exists", true},
		{"urn:ietf:params:acme:error:accountDoesNotExist", true},
		{"conflict detected", true},
		{"connection refused", false},
	}
	for _, tc := range cases {
		err := fmt.Errorf("%s", tc.msg)
		got := isACMEConflict(err)
		if got != tc.expect {
			t.Errorf("isACMEConflict(%q) = %v, want %v", tc.msg, got, tc.expect)
		}
	}
	if isACMEConflict(nil) {
		t.Error("isACMEConflict(nil) should return false")
	}
}

func TestEncodeECKey_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemBytes, err := encodeECKey(key)
	if err != nil {
		t.Fatalf("encodeECKey: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("expected valid PEM block from encodeECKey")
	}
	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("expected EC PRIVATE KEY, got %q", block.Type)
	}
}

// A busy :80 must fail before any ACME traffic, with the cause named. The hub
// URL is unreachable on purpose: reaching it would mean the check came too late.
func TestRenew_FailsFastWhenHTTP01PortBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	r := NewAcmeRenewer("http://127.0.0.1:1", nil)
	r.HTTP01Addr = busy.Addr().String()
	_, err = r.Renew(context.Background(), []string{"example.test"}, "")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"port 80 in use or not permitted", "docs/ops/WINDOWS_AGENT.md", busy.Addr().String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestRenew_WebRootSkipsPortCheck(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	r := NewAcmeRenewer("http://127.0.0.1:1", nil)
	r.HTTP01Addr = busy.Addr().String()
	_, err = r.Renew(context.Background(), []string{"example.test"}, t.TempDir())
	if err == nil || strings.Contains(err.Error(), "port 80") {
		t.Fatalf("web-root renewal must not probe the port, got %v", err)
	}
}

// F1: an IPv4-only listener must be detected when the check has no host, as
// on Windows where a dual-stack bind alone would succeed beside it.
func TestListenHTTP01_DetectsIPv4OnlyListener(t *testing.T) {
	busy, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("no IPv4: %v", err)
	}
	defer busy.Close()
	_, port, _ := net.SplitHostPort(busy.Addr().String())

	if lns, err := listenHTTP01(":" + port); err == nil {
		closeAll(lns)
		t.Fatal("expected busy-port error for IPv4-only listener")
	} else if !strings.Contains(err.Error(), "port 80 in use or not permitted") {
		t.Errorf("error %q lacks cause", err)
	}
}

func TestListenHTTP01_ServesIPv4(t *testing.T) {
	probe, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("no IPv4: %v", err)
	}
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	probe.Close()

	cleanup, err := serveChallenge(context.Background(), "tok", "tok.key", "", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	resp, err := http.Get("http://127.0.0.1:" + port + "/.well-known/acme-challenge/tok")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "tok.key" {
		t.Errorf("body = %q", b)
	}
}

// N2: a CA that reports no challenge error still gets a hint in the message.
func TestDescribeAuthzError(t *testing.T) {
	empty := &acme.AuthorizationError{Identifier: "example.test"}
	if got := describeAuthzError(empty).Error(); !strings.Contains(got, "no detail") {
		t.Errorf("got %q", got)
	}
	withDetail := &acme.AuthorizationError{Identifier: "example.test", Errors: []error{&acme.Error{ProblemType: "urn:ietf:params:acme:error:connection", Detail: "connection timed out fetching http://example.test/.well-known/acme-challenge/x"}}}
	if got := describeAuthzError(withDetail); got != error(withDetail) || !strings.Contains(got.Error(), "timed out") {
		t.Errorf("detail lost: %v", got)
	}
}

func TestServeChallenge_RejectsNonBase64URLToken(t *testing.T) {
	webRoot := t.TempDir()
	for _, tok := range []string{"", "../../etc/cron.d/x", "a/b", "a.b", `a\b`} {
		if _, err := serveChallenge(context.Background(), tok, "k", webRoot, ""); err == nil {
			t.Errorf("token %q: want error, got nil", tok)
		}
	}
	if _, err := os.Stat(filepath.Join(webRoot, ".well-known")); !os.IsNotExist(err) {
		t.Fatalf("rejected tokens must not create anything under the webroot (stat err=%v)", err)
	}
}
