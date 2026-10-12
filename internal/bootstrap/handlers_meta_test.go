// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
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
