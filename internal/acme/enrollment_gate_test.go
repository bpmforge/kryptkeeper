// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto/x509/pkix"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func newGatedACMEServer(t *testing.T, gate EnrollmentGate, recorder IssuedCertificateRecorder) *httptest.Server {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("ACME Gate Root", pkix.Name{CommonName: "ACME Gate Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	srv := NewServerWithStore(ts.URL, engine, rootCA.ID, NewMemStore(), ca.NewMemRevocationStore()).WithEnrollmentGate(gate)
	if recorder != nil {
		srv.WithIssuedRecorder(recorder)
	}
	srv.SetHTTP01DialContext(testHTTP01Dial)
	ts.Config.Handler = srv.Handler()
	return ts
}

// A role the template does not list gets the order invalidated and an ACME
// unauthorized problem; nothing is issued or recorded.
func TestACMEFinalizeDeniedByTemplateRoles(t *testing.T) {
	recorder := &fakeIssuedRecorder{}
	var gotActor string
	ts := newGatedACMEServer(t, func(_ context.Context, actor string) error {
		gotActor = actor
		return fmt.Errorf("%w: template tpl-x", ca.ErrEnrollmentDenied)
	}, recorder)

	status, _, body, _, orderURL := runACMEOrderToFinalize(t, ts)
	if status != http.StatusForbidden || !strings.Contains(string(body), "urn:ietf:params:acme:error:unauthorized") {
		t.Fatalf("finalize = %d %s, want 403 unauthorized", status, body)
	}
	if gotActor == "" {
		t.Error("gate was not told the ACME account")
	}
	resp, err := http.Get(orderURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var order Order
	_ = json.NewDecoder(resp.Body).Decode(&order)
	if order.Status != "invalid" || order.Certificate != "" {
		t.Errorf("order after denial = %+v, want invalid with no certificate", order)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 0 {
		t.Errorf("recorder saw %d certificates from a denied finalize", recorder.calls)
	}
}

// A gate that cannot be evaluated blocks issuance too (fail closed), as a
// server error rather than an authorization one.
func TestACMEFinalizeBlockedWhenGateErrors(t *testing.T) {
	ts := newGatedACMEServer(t, func(context.Context, string) error { return errors.New("template store down") }, nil)
	status, _, body, _, _ := runACMEOrderToFinalize(t, ts)
	if status != http.StatusInternalServerError {
		t.Fatalf("finalize = %d %s, want 500", status, body)
	}
}

func TestACMEFinalizeAllowedWhenGatePasses(t *testing.T) {
	ts := newGatedACMEServer(t, func(context.Context, string) error { return nil }, nil)
	runACMEFullOrderFlow(t, ts)
}
