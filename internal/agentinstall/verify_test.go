// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"kryptkeeper/internal/egress"
)

// The agent verifies its own server over loopback; that must keep working.
func TestDefaultVerifierAllowsLoopbackForTheAgent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if fp, err := defaultVerifier(context.Background(), u.Host); err != nil || fp != FingerprintSHA256(srv.Certificate().Raw) {
		t.Fatalf("fp=%q err=%v", fp, err)
	}
	if _, err := defaultVerifier(context.Background(), "169.254.169.254:80"); err == nil {
		t.Fatal("metadata address dialled")
	}
}

// RC1-A-04: the hub's verify dial must not reach metadata or loopback.
func TestHubVerifierRefusesLoopbackAndMetadata(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	for _, hp := range []string{u.Host, "169.254.169.254:80", "[::1]:443"} {
		_, err := HubVerifier(context.Background(), hp)
		if err == nil {
			t.Fatalf("HubVerifier(%s) dialled a forbidden address", hp)
		}
		if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "169.254") {
			t.Fatalf("error echoes the address: %v", err)
		}
	}
}

func TestVerifierWithPolicyAllowsPermittedLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	fp, err := verifierWithPolicy(egress.Policy{AllowLoopback: true})(context.Background(), u.Host)
	if err != nil || fp != FingerprintSHA256(srv.Certificate().Raw) {
		t.Fatalf("fp=%q err=%v", fp, err)
	}
	// Link-local stays refused even when loopback is permitted.
	if _, err := verifierWithPolicy(egress.Policy{AllowLoopback: true, AllowPrivate: true})(context.Background(), "169.254.169.254:443"); err == nil {
		t.Fatal("metadata address dialled")
	}
}
