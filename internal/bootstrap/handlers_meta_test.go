// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/fips140"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

func TestReadyz_NilProbeIsStatic200(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyz_ProbeOK_Returns200(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, func(ctx context.Context) error { return nil })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
}

func TestReadyz_ProbeFails_Returns503WithoutDetailLeak(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, func(ctx context.Context) error {
		return errors.New("postgres: connection refused at 10.0.0.5:5432 user=admin")
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503. body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "10.0.0.5") || strings.Contains(body, "postgres") || strings.Contains(body, "admin") {
		t.Fatalf("response body leaks dependency error detail: %s", body)
	}
}

func TestHealthz_AlwaysStatic200RegardlessOfProbe(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, func(ctx context.Context) error {
		return errors.New("dependency is down")
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200 even with a failing readiness probe (liveness must not check dependencies)", rec.Code)
	}
}

// TestReadinessProbeFromDependencies_KeystoreErrorFailsReadiness proves the
// real probe built in RegisterHandlers (not just a hand-rolled test closure
// above) actually fails when the keystore errors — the discriminating case
// acceptance #1 names ("DB or keystore unavailable").
func TestReadinessProbeFromDependencies_KeystoreErrorFailsReadiness(t *testing.T) {
	summary := stubCertSummaryProvider{}
	probe := readinessProbeFromDependencies(summary, failingKeystore{})

	if err := probe(context.Background()); err == nil {
		t.Fatal("expected an error when the keystore is unreachable")
	}
}

func TestReadinessProbeFromDependencies_NilKeystoreOK(t *testing.T) {
	summary := stubCertSummaryProvider{}
	probe := readinessProbeFromDependencies(summary, nil)

	if err := probe(context.Background()); err != nil {
		t.Fatalf("expected no error with a nil keystore (not configured), got: %v", err)
	}
}

func TestReadinessProbeFromDependencies_SummaryErrorFailsReadiness(t *testing.T) {
	probe := readinessProbeFromDependencies(failingCertSummaryProvider{}, nil)

	if err := probe(context.Background()); err == nil {
		t.Fatal("expected an error when the cert summary storage is unreachable")
	}
}

// failingKeystore implements keystore.Store with every method unused by the
// readiness probe left as an unreachable stub — only List() is exercised.
type failingKeystore struct{}

func (failingKeystore) GenerateKey(string, keystore.Algorithm) (keystore.KeyMetadata, error) {
	panic("not used by readiness probe")
}
func (failingKeystore) Signer(string) (crypto.Signer, error) {
	panic("not used by readiness probe")
}
func (failingKeystore) PublicKey(string) (crypto.PublicKey, error) {
	panic("not used by readiness probe")
}
func (failingKeystore) Metadata(string) (keystore.KeyMetadata, error) {
	panic("not used by readiness probe")
}
func (failingKeystore) List() ([]keystore.KeyMetadata, error) {
	return nil, errors.New("keystore unreachable")
}
func (failingKeystore) Delete(string) error { panic("not used by readiness probe") }
func (failingKeystore) RotateKey(string, keystore.Algorithm) (keystore.KeyRotateResult, error) {
	panic("not used by readiness probe")
}
func (failingKeystore) ExportEncryptedKey(string, []byte) ([]byte, error) {
	panic("not used by readiness probe")
}
func (failingKeystore) ImportEncryptedKey(string, []byte, []byte) error {
	panic("not used by readiness probe")
}

var _ keystore.Store = failingKeystore{}

func TestMeta_ReportsLiveFIPSPosture(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/meta", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		FIPS *keystore.FIPSPostureInfo `json:"fips"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.FIPS == nil {
		t.Fatal("/api/v1/meta must carry a fips object")
	}
	if body.FIPS.Mode140_3 != fips140.Enabled() {
		t.Fatalf("fips.mode_140_3 = %v, want live fips140.Enabled() %v", body.FIPS.Mode140_3, fips140.Enabled())
	}
	if body.FIPS.Enforced != fips140.Enforced() {
		t.Fatalf("fips.enforced = %v, want live fips140.Enforced() %v", body.FIPS.Enforced, fips140.Enforced())
	}
}

func TestUnmountedAPIPathIsJSON404(t *testing.T) {
	mux := http.NewServeMux()
	registerMetaHandlers(mux, nil)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/scep/challenges", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", method, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s: Content-Type = %q, want JSON", method, ct)
		}
	}
}
