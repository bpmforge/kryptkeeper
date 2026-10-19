// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"
)

type testCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	serial *big.Int
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{cert: cert, key: key, serial: serial}
}

func issueTestCert(t *testing.T, ca *testCA, serial int64) *x509.Certificate {
	t.Helper()
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &clientKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issue test cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func newTestResponder(t *testing.T, ca *testCA, revokedSerials map[string]time.Time) *Responder {
	t.Helper()
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		if revokedAt, ok := revokedSerials[serial.String()]; ok {
			return true, revokedAt, 1, nil // keyCompromise
		}
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ca.cert, ca.key, nil
	}
	return NewResponder(statusFunc, issuerFunc, 1*time.Hour, 100)
}

func makeOCSPRequest(t *testing.T, cert, issuer *x509.Certificate) []byte {
	t.Helper()
	reqBytes, err := goocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Fatalf("create OCSP request: %v", err)
	}
	return reqBytes
}

func TestOCSPGoodStatus(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 1000)
	responder := newTestResponder(t, ca, map[string]time.Time{})

	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	handler := responder.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes)))
	req.Header.Set("Content-Type", "application/ocsp-request")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/ocsp-response" {
		t.Errorf("expected application/ocsp-response, got %s", rec.Header().Get("Content-Type"))
	}

	resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != goocsp.Good {
		t.Errorf("expected Good status, got %d", resp.Status)
	}
	if resp.SerialNumber.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected serial 1000, got %s", resp.SerialNumber)
	}
	if resp.NextUpdate.Before(resp.ThisUpdate) {
		t.Error("NextUpdate should be after ThisUpdate")
	}
}

func TestOCSPRevokedStatus(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 2000)
	revokedAt := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	responder := newTestResponder(t, ca, map[string]time.Time{
		"2000": revokedAt,
	})

	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	handler := responder.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes)))
	handler.ServeHTTP(rec, req)

	resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if resp.Status != goocsp.Revoked {
		t.Errorf("expected Revoked status, got %d", resp.Status)
	}
	if resp.RevocationReason != 1 {
		t.Errorf("expected reason keyCompromise (1), got %d", resp.RevocationReason)
	}
	if resp.RevokedAt.IsZero() {
		t.Error("expected non-zero RevokedAt")
	}
}

func TestOCSPCacheHit(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 3000)
	callCount := 0
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		callCount++
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ca.cert, ca.key, nil
	}
	responder := NewResponder(statusFunc, issuerFunc, 1*time.Hour, 100)

	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	handler := responder.Handler()

	// First request — cache miss.
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	if callCount != 1 {
		t.Errorf("expected 1 status lookup, got %d", callCount)
	}

	// Second request — cache hit.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	if callCount != 1 {
		t.Errorf("expected still 1 status lookup (cached), got %d", callCount)
	}
}

func TestOCSPCacheInvalidation(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 4000)
	revoked := false
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		if revoked {
			return true, time.Now(), 1, nil
		}
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ca.cert, ca.key, nil
	}
	responder := NewResponder(statusFunc, issuerFunc, 1*time.Hour, 100)

	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	handler := responder.Handler()

	// First: good status cached.
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	resp1, _ := goocsp.ParseResponse(rec1.Body.Bytes(), ca.cert)
	if resp1.Status != goocsp.Good {
		t.Fatal("expected Good before revocation")
	}

	// Revoke and invalidate cache.
	revoked = true
	responder.InvalidateCache(big.NewInt(4000))

	// Second: revoked status after invalidation.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	resp2, _ := goocsp.ParseResponse(rec2.Body.Bytes(), ca.cert)
	if resp2.Status != goocsp.Revoked {
		t.Error("expected Revoked after invalidation")
	}
}

func TestOCSPMalformedRequest(t *testing.T) {
	ca := newTestCA(t)
	responder := newTestResponder(t, ca, map[string]time.Time{})
	handler := responder.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader("not-an-ocsp-request"))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (OCSP error response), got %d", rec.Code)
	}
	// Body should be a MalformedRequest OCSP error response.
	if len(rec.Body.Bytes()) == 0 {
		t.Error("expected non-empty error response body")
	}
}

func TestOCSPMethodNotAllowed(t *testing.T) {
	ca := newTestCA(t)
	responder := newTestResponder(t, ca, map[string]time.Time{})
	handler := responder.Handler()

	// DELETE is not supported.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/ocsp", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestOCSPGetRequest(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5000)
	responder := newTestResponder(t, ca, map[string]time.Time{})
	handler := responder.Handler()

	// Build a base64url-encoded OCSP request for GET (URL-safe alphabet, no padding).
	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	encoded := base64.RawURLEncoding.EncodeToString(reqBytes)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ocsp/"+encoded, nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
	if err != nil {
		t.Fatalf("parse OCSP response from GET: %v", err)
	}
	if resp.Status != goocsp.Good {
		t.Errorf("expected Good status from GET, got %d", resp.Status)
	}
}

func TestOCSPGetMissingDER(t *testing.T) {
	ca := newTestCA(t)
	responder := newTestResponder(t, ca, map[string]time.Time{})
	handler := responder.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ocsp/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for GET with no DER, got %d", rec.Code)
	}
}

func TestOCSPGetInvalidBase64(t *testing.T) {
	ca := newTestCA(t)
	responder := newTestResponder(t, ca, map[string]time.Time{})
	handler := responder.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ocsp/not-valid-base64!!!", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for GET with invalid base64, got %d", rec.Code)
	}
}

func TestOCSPNewResponderDefaults(t *testing.T) {
	ca := newTestCA(t)
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ca.cert, ca.key, nil
	}
	// validity=0 and cacheSize=0 → both use defaults
	r := NewResponder(statusFunc, issuerFunc, 0, 0)
	if r == nil {
		t.Fatal("expected non-nil responder with defaults")
	}
}

func TestOCSPIssuerLookupError(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 6000)
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return nil, nil, fmt.Errorf("no issuer found")
	}
	responder := NewResponder(statusFunc, issuerFunc, time.Hour, 100)
	handler := responder.Handler()

	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes)))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with internal error OCSP response, got %d", rec.Code)
	}
}

func TestOCSPStatusLookupError(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 7000)
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, fmt.Errorf("database error")
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ca.cert, ca.key, nil
	}
	responder := NewResponder(statusFunc, issuerFunc, time.Hour, 100)
	handler := responder.Handler()

	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes)))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with internal error OCSP response, got %d", rec.Code)
	}
}

func TestOCSPCacheEviction(t *testing.T) {
	ca := newTestCA(t)
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ca.cert, ca.key, nil
	}
	// Small cache so we hit eviction.
	responder := NewResponder(statusFunc, issuerFunc, time.Hour, 2)
	handler := responder.Handler()

	// Issue certs with distinct serials to fill and evict the cache.
	for i := int64(8001); i <= 8005; i++ {
		leaf := issueTestCert(t, ca, i)
		reqBytes := makeOCSPRequest(t, leaf, ca.cert)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes)))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d for serial %d", rec.Code, i)
		}
	}
}

// W23-26: a changed revocation stamp drops every cached response, so the next
// request re-reads status from the (shared) store.
func TestResponderSyncVersionDropsCacheOnChange(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 3100)
	calls := 0
	statusFunc := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		calls++
		return false, time.Time{}, 0, nil
	}
	issuerFunc := func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil }
	responder := NewResponder(statusFunc, issuerFunc, 1*time.Hour, 100)
	reqBytes := makeOCSPRequest(t, leaf, ca.cert)
	handler := responder.Handler()
	query := func() {
		handler.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
	}

	query()
	if responder.SyncVersion("0|") {
		t.Fatal("first call only records the stamp")
	}
	query()
	if calls != 1 {
		t.Fatalf("status lookups = %d, want 1 (cached)", calls)
	}
	if responder.SyncVersion("0|") {
		t.Fatal("an unchanged stamp must report false")
	}
	if !responder.SyncVersion("1|2026-01-01") {
		t.Fatal("a changed stamp must report true")
	}
	query()
	if calls != 2 {
		t.Fatalf("status lookups = %d, want 2 (cache dropped)", calls)
	}
}

// --- W23-51: Cache-Control max-age ---

func ocspCacheControl(t *testing.T, r *Responder, leaf, issuer *x509.Certificate) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp",
		strings.NewReader(string(makeOCSPRequest(t, leaf, issuer)))))
	return rec.Header().Get("Cache-Control")
}

func newDayResponder(t *testing.T, ca *testCA) *Responder {
	t.Helper()
	return NewResponder(
		func(*big.Int, *x509.Certificate) (bool, time.Time, int, error) { return false, time.Time{}, 0, nil },
		func([]byte) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		24*time.Hour, 100)
}

func maxAgeSeconds(t *testing.T, cc string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(cc, "max-age=%d, public", &n); err != nil {
		t.Fatalf("unparseable Cache-Control %q: %v", cc, err)
	}
	return n
}

func TestOCSPCacheControlDefaultMaxAge14400(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5001)
	if got := ocspCacheControl(t, newDayResponder(t, ca), leaf, ca.cert); got != "max-age=14400, public" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestOCSPCacheControlHonoursConfiguredValue(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5002)
	r := newDayResponder(t, ca).WithMaxAge(90 * time.Minute)
	if got := ocspCacheControl(t, r, leaf, ca.cert); got != "max-age=5400, public" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestOCSPCacheControlClampedToRemainingValidity(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5003)
	r := newTestResponder(t, ca, nil) // 1h validity, default 4h max-age
	if n := maxAgeSeconds(t, ocspCacheControl(t, r, leaf, ca.cert)); n > 3600 || n < 3590 {
		t.Fatalf("max-age = %d, want <= 3600 (validity)", n)
	}
}

func TestOCSPCacheControlClampOnCachedResponse(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5004)
	r := newDayResponder(t, ca)
	_ = ocspCacheControl(t, r, leaf, ca.cert) // prime
	r.mu.Lock()
	for k, c := range r.cache {
		c.expiresAt = time.Now().Add(10 * time.Minute)
		r.cache[k] = c
	}
	r.mu.Unlock()
	if n := maxAgeSeconds(t, ocspCacheControl(t, r, leaf, ca.cert)); n < 1 || n > 600 {
		t.Fatalf("max-age = %d, want 1..600", n)
	}
}

func TestOCSPCacheControlZeroMeansNoStore(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5005)
	r := newDayResponder(t, ca).WithMaxAge(0)
	if got := ocspCacheControl(t, r, leaf, ca.cert); got != "no-cache, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestOCSPNegativeMaxAgeKeepsDefault(t *testing.T) {
	ca := newTestCA(t)
	leaf := issueTestCert(t, ca, 5006)
	r := newDayResponder(t, ca).WithMaxAge(-time.Second)
	if got := ocspCacheControl(t, r, leaf, ca.cert); got != "max-age=14400, public" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestOCSPErrorResponsesCarryNoCacheControl(t *testing.T) {
	ca := newTestCA(t)
	rec := httptest.NewRecorder()
	newDayResponder(t, ca).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader("garbage")))
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("error response Cache-Control = %q, want none", got)
	}
}

func TestMaxAgeFromEnv(t *testing.T) {
	cases := []struct {
		name, val string
		set       bool
		want      time.Duration
	}{
		{"unset", "", false, 4 * time.Hour},
		{"duration", "2h", true, 2 * time.Hour},
		{"seconds", "14400", true, 4 * time.Hour},
		{"zero", "0", true, 0},
		{"negative", "-5", true, 4 * time.Hour},
		{"garbage", "abc", true, 4 * time.Hour},
		{"bad unit", "1.5x", true, 4 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv("KRYPTKEEPER_OCSP_MAX_AGE", c.val)
			} else {
				t.Setenv("KRYPTKEEPER_OCSP_MAX_AGE", "")
			}
			if got := MaxAgeFromEnv(); got != c.want {
				t.Fatalf("MaxAgeFromEnv(%q) = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

// Standard base64 contains '/', which nginx percent-encodes (%2F) and some
// clients send raw. Both must reach the decoder intact.
func TestOCSPGetRequestWithSlashInBase64(t *testing.T) {
	ca := newTestCA(t)
	responder := newTestResponder(t, ca, map[string]time.Time{})
	handler := responder.Handler()

	var encoded string
	for serial := int64(6000); serial < 6400; serial++ {
		leaf := issueTestCert(t, ca, serial)
		e := base64.StdEncoding.EncodeToString(makeOCSPRequest(t, leaf, ca.cert))
		if strings.Contains(e, "/") {
			encoded = e
			break
		}
	}
	if encoded == "" {
		t.Fatal("no OCSP request with '/' in its base64 among 400 serials")
	}
	escaped := strings.NewReplacer("/", "%2F", "+", "%2B", "=", "%3D").Replace(encoded)

	for name, path := range map[string]string{
		"percent-encoded": "/ocsp/" + escaped,
		"raw":             "/ocsp/" + encoded,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			resp, err := goocsp.ParseResponse(rec.Body.Bytes(), ca.cert)
			if err != nil {
				t.Fatalf("parse OCSP response: %v", err)
			}
			if resp.Status != goocsp.Good {
				t.Errorf("expected Good, got %d", resp.Status)
			}
		})
	}
}
