// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W23-35: enrolment through a revoked CA is refused and records nothing.
func TestESTSimpleEnrollRefusedWhenCARevoked(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("est-test-passphrase-32chars-ok!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("EST Revoked Root", pkix.Name{CommonName: "EST Revoked Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &fakeIssuedRecorder{}
	srv := NewServer(engine, root.ID).WithIssuedRecorder(recorder)
	if err := srv.WithBasicUsers(testUsers(t)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()

	if err := engine.UpdateCAStatus(root.ID, "revoked"); err != nil {
		t.Fatal(err)
	}
	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(generateCSRBase64(t, "est-revoked.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "issuing CA revoked") {
		t.Fatalf("want 403 issuing CA revoked, got %d: %s", resp.StatusCode, body)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 0 {
		t.Fatalf("a certificate was recorded through a revoked CA: %d", recorder.calls)
	}
}
