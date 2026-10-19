// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"context"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"net/http/httptest"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// TestESTFirstRunZeroCAsThenLazyResolve: a hub started with zero CAs answers
// 503 "create a root CA" (audited on enroll), and once a root exists the same
// server resolves it with no restart.
func TestESTFirstRunZeroCAsThenLazyResolve(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("est-test-passphrase-32chars-ok!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	srv := NewServer(engine, "") // no default CA at startup
	var events []AuditEvent
	srv.WithAuditFunc(func(_ context.Context, ev AuditEvent) { events = append(events, ev) })
	if err := srv.WithBasicUsers(testUsers(t)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "create a root CA") {
		t.Fatalf("cacerts with zero CAs: %d %q", resp.StatusCode, body)
	}

	r2, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(generateCSRBase64(t, "first.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b2), "create a root CA") {
		t.Fatalf("enroll with zero CAs: %d %q", r2.StatusCode, b2)
	}
	if len(events) == 0 || events[len(events)-1].Outcome != "failure" {
		t.Fatalf("zero-CA enroll must be audited, got %+v", events)
	}

	if _, err := engine.CreateRootCA("Wizard Root", pkix.Name{CommonName: "Wizard Root"}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	r3, err := ts.Client().Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("cacerts after root creation, no restart: %d", r3.StatusCode)
	}
	r4, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(generateCSRBase64(t, "second.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	r4.Body.Close()
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("enroll after root creation: %d", r4.StatusCode)
	}
}
