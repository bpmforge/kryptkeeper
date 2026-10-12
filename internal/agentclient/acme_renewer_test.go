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
	"os"
	"path/filepath"
	"testing"
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

	cleanup, err := serveChallenge(context.Background(), token, keyAuth, webRoot)
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
