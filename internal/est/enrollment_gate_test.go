// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func newGatedESTServer(t *testing.T, gate EnrollmentGate, recorder ca.IssuedCertificateRecorder) *httptest.Server {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("est-test-passphrase-32chars-ok!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("EST Gate Root", pkix.Name{CommonName: "EST Gate Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(engine, rootCA.ID).WithEnrollmentGate(gate)
	if recorder != nil {
		srv.WithIssuedRecorder(recorder)
	}
	if err := srv.WithBasicUsers(testUsers(t)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func enrollOnce(t *testing.T, ts *httptest.Server) (int, string) {
	t.Helper()
	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(generateCSRBase64(t, "gated.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, string(b)
}

func TestESTEnrollDeniedByTemplateRoles(t *testing.T) {
	recorder := &fakeIssuedRecorder{}
	var gotActor string
	ts := newGatedESTServer(t, func(_ context.Context, actor string) error {
		gotActor = actor
		return fmt.Errorf("%w: template tpl-x", ca.ErrEnrollmentDenied)
	}, recorder)

	status, body := enrollOnce(t, ts)
	if status != http.StatusForbidden || !strings.Contains(body, "enrollment not permitted for this template") {
		t.Fatalf("enroll = %d %q, want 403", status, body)
	}
	if gotActor == "" {
		t.Error("gate was not told the EST actor")
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 0 {
		t.Errorf("a denied enrollment was recorded %d time(s)", recorder.calls)
	}
}

// A gate that cannot be evaluated blocks issuance (fail closed).
func TestESTEnrollBlockedWhenGateErrors(t *testing.T) {
	ts := newGatedESTServer(t, func(context.Context, string) error { return errors.New("template store down") }, nil)
	if status, _ := enrollOnce(t, ts); status != http.StatusInternalServerError {
		t.Fatalf("enroll = %d, want 500", status)
	}
}

func TestESTEnrollAllowedWhenGateNil(t *testing.T) {
	ts := newGatedESTServer(t, nil, nil)
	if status, body := enrollOnce(t, ts); status != http.StatusOK {
		t.Fatalf("enroll without gate = %d %q", status, body)
	}
}

func TestESTEnrollAllowedWhenGatePasses(t *testing.T) {
	ts := newGatedESTServer(t, func(context.Context, string) error { return nil }, nil)
	if status, body := enrollOnce(t, ts); status != http.StatusOK {
		t.Fatalf("enroll = %d %q", status, body)
	}
}
