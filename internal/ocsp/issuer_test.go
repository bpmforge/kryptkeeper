// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"
)

func serve(t *testing.T, r *Responder, leaf, issuer *x509.Certificate) []byte {
	t.Helper()
	reqBytes := makeOCSPRequest(t, leaf, issuer)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.Bytes()
}

func wantErrorStatus(t *testing.T, body []byte, want goocsp.ResponseStatus) {
	t.Helper()
	_, err := goocsp.ParseResponse(body, nil)
	var re goocsp.ResponseError
	if !errors.As(err, &re) || re.Status != want {
		t.Fatalf("response = %v, want an OCSP error response %v (never a signed status)", err, want)
	}
}

func neverRevoked(*big.Int, *x509.Certificate) (bool, time.Time, int, error) {
	return false, time.Time{}, 0, nil
}

// SEMGREP-012: a request naming an issuer the responder does not serve must
// not be answered from some other CA. The lookup here behaves like the old
// main.go fallback — it always hands back CA A — and the CertID hashes name
// CA B.
func TestOCSPUnknownIssuerIsUnauthorizedNotGood(t *testing.T) {
	caA, caB := newTestCA(t), newTestCA(t)
	leafB := issueTestCert(t, caB, 1000)
	r := NewResponder(neverRevoked, func([]byte) (*x509.Certificate, crypto.Signer, error) {
		return caA.cert, caA.key, nil
	}, time.Hour, 100)
	wantErrorStatus(t, serve(t, r, leafB, caB.cert), goocsp.Unauthorized)
}

func TestOCSPLookupReportsUnknownIssuer(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 1001)
	r := NewResponder(neverRevoked, func([]byte) (*x509.Certificate, crypto.Signer, error) {
		return nil, nil, fmt.Errorf("lookup: %w", ErrUnknownIssuer)
	}, time.Hour, 100)
	wantErrorStatus(t, serve(t, r, leaf, ca.cert), goocsp.Unauthorized)
}

// SEMGREP-012: a CA-list read failure is a transient fault, never a good.
func TestOCSPIssuerListFailureIsTryLater(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 1002)
	r := NewResponder(neverRevoked, func([]byte) (*x509.Certificate, crypto.Signer, error) {
		return nil, nil, errors.New("list CAs: database unavailable")
	}, time.Hour, 100)
	wantErrorStatus(t, serve(t, r, leaf, ca.cert), goocsp.TryLater)

	r = NewResponder(func(*big.Int, *x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, errors.New("revocation store down")
	}, func([]byte) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil }, time.Hour, 100)
	wantErrorStatus(t, serve(t, r, leaf, ca.cert), goocsp.TryLater)
}

// SEMGREP-013: the cache was keyed by serial alone, so a serial issued by two
// CAs got whichever CA's response was cached first.
func TestOCSPCacheKeyedPerIssuer(t *testing.T) {
	caA, caB := newTestCA(t), newTestCA(t)
	leafA, leafB := issueTestCert(t, caA, 1000), issueTestCert(t, caB, 1000)
	issuers := map[string]*testCA{}
	for _, c := range []*testCA{caA, caB} {
		issuers[string(keyHashOf(t, c.cert))] = c
	}
	r := NewResponder(neverRevoked, func(h []byte) (*x509.Certificate, crypto.Signer, error) {
		c, ok := issuers[string(h)]
		if !ok {
			return nil, nil, ErrUnknownIssuer
		}
		return c.cert, c.key, nil
	}, time.Hour, 100)

	respA, err := goocsp.ParseResponse(serve(t, r, leafA, caA.cert), caA.cert)
	if err != nil || respA.Status != goocsp.Good {
		t.Fatalf("CA A response: %v %+v", err, respA)
	}
	// Old code returned CA A's cached bytes here; they do not verify under CA B.
	respB, err := goocsp.ParseResponse(serve(t, r, leafB, caB.cert), caB.cert)
	if err != nil || respB.Status != goocsp.Good {
		t.Fatalf("CA B response must be signed by CA B: %v %+v", err, respB)
	}
	if bytes.Equal(respA.TBSResponseData, respB.TBSResponseData) {
		t.Fatal("two issuers' responses share a cache entry")
	}

	// Revocation invalidation works from the serial alone and clears both.
	r.InvalidateCache(big.NewInt(1000))
	if got := len(r.cache); got != 0 {
		t.Fatalf("InvalidateCache(serial) left %d entries", got)
	}
}

// A SHA-256 CertID is answered with a SHA-256 CertID, not silently a SHA-1 one.
func TestOCSPHonoursRequestHashAlgorithm(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 1003)
	r := newTestResponder(t, ca, nil)
	reqBytes, err := goocsp.CreateRequest(leaf, ca.cert, &goocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
	if err != nil || resp.Status != goocsp.Good || resp.IssuerHash != crypto.SHA256 {
		t.Fatalf("SHA-256 CertID: err=%v resp=%+v", err, resp)
	}
}

func keyHashOf(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	req, err := goocsp.CreateRequest(cert, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := goocsp.ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.IssuerKeyHash
}
