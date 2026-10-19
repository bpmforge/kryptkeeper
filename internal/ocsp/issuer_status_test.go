// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"
)

func ocspStatusOf(t *testing.T, r *Responder, ca *testCA, leaf *x509.Certificate) int {
	t.Helper()
	body := makeOCSPRequest(t, leaf, ca.cert)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(body))))
	resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status == goocsp.Revoked && resp.RevocationReason != 2 {
		t.Errorf("revoked reason = %d, want 2 (cACompromise)", resp.RevocationReason)
	}
	return resp.Status
}

func TestIssuerStatusRevokedOverridesGood(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 7000) // unknown to the store: statusFunc says good
	at := time.Now().Add(-time.Hour).UTC()
	r := newTestResponder(t, ca, nil).WithIssuerStatus(func(*x509.Certificate) (bool, time.Time, int, error) {
		return true, at, 2, nil
	})
	if got := ocspStatusOf(t, r, ca, leaf); got != goocsp.Revoked {
		t.Fatalf("status = %d, want Revoked", got)
	}
}

func TestIssuerStatusActiveIssuerStaysGood(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 7001)
	r := newTestResponder(t, ca, nil).WithIssuerStatus(func(*x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, nil
	})
	if got := ocspStatusOf(t, r, ca, leaf); got != goocsp.Good {
		t.Fatalf("status = %d, want Good", got)
	}
}

func TestInvalidateAllDropsCachedGood(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 7002)
	revoked := false
	r := newTestResponder(t, ca, nil).WithIssuerStatus(func(*x509.Certificate) (bool, time.Time, int, error) {
		return revoked, time.Now(), 2, nil
	})
	if got := ocspStatusOf(t, r, ca, leaf); got != goocsp.Good {
		t.Fatalf("before revoke: %d, want Good", got)
	}
	revoked = true
	if got := ocspStatusOf(t, r, ca, leaf); got != goocsp.Good {
		t.Fatalf("cache should still answer Good before flush, got %d", got)
	}
	r.InvalidateAll()
	if got := ocspStatusOf(t, r, ca, leaf); got != goocsp.Revoked {
		t.Fatalf("after InvalidateAll: %d, want Revoked", got)
	}
}

func TestIssuerStatusErrorIsReturned(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 7003)
	r := newTestResponder(t, ca, nil).WithIssuerStatus(func(*x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, errBoom
	})
	body := makeOCSPRequest(t, leaf, ca.cert)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(body))))
	resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
	if err == nil && resp.Status == goocsp.Good {
		t.Fatal("issuer status failure must not answer Good")
	}
}

var errBoom = errors.New("boom")
