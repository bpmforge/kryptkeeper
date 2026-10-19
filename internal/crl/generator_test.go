// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testCRLCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	id   string
}

func newTestCRLCA(t *testing.T) *testCRLCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CRL CA"},
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
	cert, _ := x509.ParseCertificate(certDER)
	return &testCRLCA{cert: cert, key: key, id: "test-ca-1"}
}

func TestCRLGenerateEmpty(t *testing.T) {
	ca := newTestCRLCA(t)
	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return nil, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		1*time.Hour,
	)

	crl, err := gen.Generate(ca.id)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("expected CRL number 1, got %s", crl.Number)
	}
	if len(crl.DER) == 0 {
		t.Error("expected non-empty DER")
	}
	if len(crl.PEM) == 0 {
		t.Error("expected non-empty PEM")
	}

	// Parse and verify.
	parsed, err := x509.ParseRevocationList(crl.DER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if err := parsed.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("CRL signature invalid: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Errorf("expected 0 revoked entries, got %d", len(parsed.RevokedCertificateEntries))
	}
}

func TestCRLGenerateWithRevokedCerts(t *testing.T) {
	ca := newTestCRLCA(t)
	revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) {
			return []RevokedCert{
				{SerialNumber: big.NewInt(100), RevokedAt: revokedAt, ReasonCode: 1},
				{SerialNumber: big.NewInt(200), RevokedAt: revokedAt, ReasonCode: 4},
			}, nil
		},
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		1*time.Hour,
	)

	crl, err := gen.Generate(ca.id)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	parsed, err := x509.ParseRevocationList(crl.DER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 2 {
		t.Fatalf("expected 2 revoked entries, got %d", len(parsed.RevokedCertificateEntries))
	}

	// Verify serial numbers are present.
	serials := make(map[string]bool)
	for _, entry := range parsed.RevokedCertificateEntries {
		serials[entry.SerialNumber.String()] = true
	}
	if !serials["100"] || !serials["200"] {
		t.Errorf("expected serials 100 and 200, got %v", serials)
	}
}

func TestCRLNumberIncrementsOnRegeneration(t *testing.T) {
	ca := newTestCRLCA(t)
	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return nil, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		1*time.Hour,
	)

	crl1, _ := gen.Generate(ca.id)
	crl2, _ := gen.Generate(ca.id)

	if crl2.Number.Cmp(crl1.Number) <= 0 {
		t.Errorf("CRL number should increment: %s <= %s", crl2.Number, crl1.Number)
	}
}

func TestCRLGetCachedCRL(t *testing.T) {
	ca := newTestCRLCA(t)
	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return nil, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		1*time.Hour,
	)

	// Before generation, GetCRL returns nil.
	if gen.GetCRL(ca.id) != nil {
		t.Error("expected nil before generation")
	}

	gen.Generate(ca.id)

	cached := gen.GetCRL(ca.id)
	if cached == nil {
		t.Fatal("expected cached CRL after generation")
	}
	if cached.CAAID != ca.id {
		t.Errorf("expected CA ID %s, got %s", ca.id, cached.CAAID)
	}
}

func TestCRLHTTPHandler(t *testing.T) {
	ca := newTestCRLCA(t)
	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return nil, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) {
			if caID == ca.id {
				return ca.cert, ca.key, nil
			}
			return nil, nil, fmt.Errorf("unknown CA")
		},
		1*time.Hour,
	)

	handler := gen.Handler()

	// Valid request.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/crl/"+ca.id+".crl", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Errorf("expected application/pkix-crl, got %s", rec.Header().Get("Content-Type"))
	}

	// Parse served CRL.
	parsed, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse served CRL: %v", err)
	}
	if err := parsed.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("served CRL signature invalid: %v", err)
	}

	// Unknown CA.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/crl/nonexistent.crl", nil)
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown CA, got %d", rec2.Code)
	}

	// Bad path.
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/crl/", nil)
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Errorf("expected 404 for bad path, got %d", rec3.Code)
	}

	// POST not allowed.
	rec4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodPost, "/crl/"+ca.id+".crl", nil)
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rec4.Code)
	}
}

// TestCRLHTTPHandlerReflectsRevocationsAcrossRequests is W19-01/W19-29: a
// revocation must be visible in the very next CRL fetch. W19-01 forced this
// by regenerating on every request (no cache at all); W19-29 restores the
// cache but requires the real caller-side contract instead -- a revoke call
// site persists to the store THEN calls InvalidateCache (see
// ca.RevocationCacheInvalidator's doc comment, and how
// cmd/kryptkeeper/main.go wires it into both the ACME and certificate-API
// revoke paths). Simulates that exact sequence: revoke A, serve (fills the
// cache), revoke B + invalidate, serve again -- B must appear and A must
// still be there.
func TestCRLHTTPHandlerReflectsRevocationsAcrossRequests(t *testing.T) {
	ca := newTestCRLCA(t)
	serialA := big.NewInt(1001)
	serialB := big.NewInt(1002)
	var revoked []RevokedCert

	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return revoked, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) {
			if caID == ca.id {
				return ca.cert, ca.key, nil
			}
			return nil, nil, fmt.Errorf("unknown CA")
		},
		1*time.Hour,
	)
	handler := gen.Handler()

	// certbot-equivalent: revoke A, then request the CRL (fills the cache).
	revoked = append(revoked, RevokedCert{SerialNumber: serialA, RevokedAt: time.Now()})
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/crl/"+ca.id+".crl", nil))
	crl1, err := x509.ParseRevocationList(rec1.Body.Bytes())
	if err != nil {
		t.Fatalf("parse first CRL: %v", err)
	}
	if !crlListsSerial(crl1, serialA) {
		t.Fatalf("first CRL missing serial A")
	}

	// lego-equivalent: revoke B (a distinct client, different certificate)
	// AND invalidate -- the real call-site contract -- then request the CRL
	// again: must reflect B too, not the cached snapshot from before B was
	// revoked.
	revoked = append(revoked, RevokedCert{SerialNumber: serialB, RevokedAt: time.Now()})
	gen.InvalidateCache(serialB)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/crl/"+ca.id+".crl", nil))
	crl2, err := x509.ParseRevocationList(rec2.Body.Bytes())
	if err != nil {
		t.Fatalf("parse second CRL: %v", err)
	}
	if !crlListsSerial(crl2, serialA) {
		t.Error("second CRL dropped serial A")
	}
	if !crlListsSerial(crl2, serialB) {
		t.Error("second CRL is missing serial B -- Handler served a stale cached CRL")
	}
}

// TestCRLInvalidateCacheLeavesUnrelatedCAUntouched is W19-29 acceptance: the
// InvalidateCache seam re-queries revokedFunc per already-cached CA (it only
// receives a serial, not a CA ID -- see InvalidateCache's doc comment), so a
// revocation on CA A must never evict CA B's cached CRL.
func TestCRLInvalidateCacheLeavesUnrelatedCAUntouched(t *testing.T) {
	caA := newTestCRLCA(t)
	caB := &testCRLCA{cert: caA.cert, key: caA.key, id: "test-ca-2"}
	serialA := big.NewInt(2001)

	revokedByCA := map[string][]RevokedCert{
		caA.id: {{SerialNumber: serialA, RevokedAt: time.Now()}},
		caB.id: {},
	}

	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return revokedByCA[caID], nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return caA.cert, caA.key, nil },
		1*time.Hour,
	)

	if _, err := gen.Generate(caA.id); err != nil {
		t.Fatalf("generate A: %v", err)
	}
	if _, err := gen.Generate(caB.id); err != nil {
		t.Fatalf("generate B: %v", err)
	}
	beforeB := gen.GetCRL(caB.id)

	// serialA belongs to CA A only -- invalidating it must drop A's cache
	// and leave B's untouched.
	gen.InvalidateCache(serialA)

	if gen.GetCRL(caA.id) != nil {
		t.Error("expected CA A's cache to be evicted")
	}
	afterB := gen.GetCRL(caB.id)
	if afterB == nil {
		t.Fatal("expected CA B's cache to remain")
	}
	if afterB.Number.Cmp(beforeB.Number) != 0 {
		t.Error("expected CA B's cached CRL to be untouched (same generation), got a different one")
	}
}

// TestCRLHandlerNeverServesPastNextUpdate is W19-29 acceptance: even with no
// invalidation call at all, the Handler must regenerate once the cached
// CRL's NextUpdate has passed -- a CRL is never served stale past its own
// declared validity window.
func TestCRLHandlerNeverServesPastNextUpdate(t *testing.T) {
	ca := newTestCRLCA(t)
	serial := big.NewInt(3001)
	var revoked []RevokedCert

	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return revoked, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		// A validity of effectively zero (floored to a tick below) forces
		// NextUpdate to be in the past by the time the second request runs,
		// without sleeping in the test.
		1*time.Nanosecond,
	)
	handler := gen.Handler()

	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/crl/"+ca.id+".crl", nil))
	crl1, err := x509.ParseRevocationList(rec1.Body.Bytes())
	if err != nil {
		t.Fatalf("parse first CRL: %v", err)
	}
	if crlListsSerial(crl1, serial) {
		t.Fatalf("first CRL should not list serial yet")
	}

	// Revoke without calling InvalidateCache -- only expiry should force a
	// regeneration here.
	revoked = append(revoked, RevokedCert{SerialNumber: serial, RevokedAt: time.Now()})
	time.Sleep(time.Millisecond) // ensure real-clock NextUpdate has passed
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/crl/"+ca.id+".crl", nil))
	crl2, err := x509.ParseRevocationList(rec2.Body.Bytes())
	if err != nil {
		t.Fatalf("parse second CRL: %v", err)
	}
	if !crlListsSerial(crl2, serial) {
		t.Error("expected NextUpdate expiry to force regeneration and pick up the new revocation")
	}
}

func crlListsSerial(crl *x509.RevocationList, serial *big.Int) bool {
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber != nil && e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// W23-26: a changed revocation stamp drops the cached CRLs; CRL numbers stay
// monotonic across the reset.
func TestGeneratorSyncVersionDropsCacheOnChange(t *testing.T) {
	ca := newTestCRLCA(t)
	gen := NewGenerator(
		func(caID string) ([]RevokedCert, error) { return nil, nil },
		func(caID string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		1*time.Hour,
	)
	first, err := gen.Generate(ca.id)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if gen.SyncVersion("0|") {
		t.Fatal("first call only records the stamp")
	}
	if gen.GetCRL(ca.id) == nil {
		t.Fatal("first SyncVersion must keep the cache")
	}
	if gen.SyncVersion("0|") || gen.GetCRL(ca.id) == nil {
		t.Fatal("an unchanged stamp must keep the cache")
	}
	if !gen.SyncVersion("1|2026-01-01") {
		t.Fatal("a changed stamp must report true")
	}
	if gen.GetCRL(ca.id) != nil {
		t.Fatal("a changed stamp must drop the cached CRL")
	}
	again, err := gen.Generate(ca.id)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if again.Number.Cmp(first.Number) <= 0 {
		t.Fatalf("CRL number must keep increasing: %s <= %s", again.Number, first.Number)
	}
}

// W23-35: a revoked child CA's serial is listed on its parent's CRL.
func TestParentCRLListsRevokedChildCA(t *testing.T) {
	parent := newTestCRLCA(t)
	childSerial := big.NewInt(4242)
	gen := NewGenerator(
		func(string) ([]RevokedCert, error) {
			return []RevokedCert{{SerialNumber: childSerial, RevokedAt: time.Now().Add(-time.Minute), ReasonCode: 2}}, nil
		},
		func(string) (*x509.Certificate, crypto.Signer, error) { return parent.cert, parent.key, nil },
		time.Hour,
	)
	got, err := gen.Generate(parent.id)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(got.DER)
	if err != nil {
		t.Fatal(err)
	}
	if !crlListsSerial(parsed, childSerial) {
		t.Fatal("child CA serial missing from parent CRL")
	}
}

// A revoked root keeps a self-keyed record; it must not appear in its own CRL.
func TestCRLSkipsOwnSerial(t *testing.T) {
	root := newTestCRLCA(t) // cert serial 1
	other := big.NewInt(99)
	gen := NewGenerator(
		func(string) ([]RevokedCert, error) {
			return []RevokedCert{
				{SerialNumber: root.cert.SerialNumber, RevokedAt: time.Now(), ReasonCode: 2},
				{SerialNumber: other, RevokedAt: time.Now(), ReasonCode: 1},
			}, nil
		},
		func(string) (*x509.Certificate, crypto.Signer, error) { return root.cert, root.key, nil },
		time.Hour,
	)
	got, err := gen.Generate(root.id)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseRevocationList(got.DER)
	if crlListsSerial(parsed, root.cert.SerialNumber) {
		t.Fatal("root's own serial listed in its CRL")
	}
	if !crlListsSerial(parsed, other) {
		t.Fatal("unrelated revoked serial dropped")
	}
}

func TestCRLInvalidateAll(t *testing.T) {
	ca := newTestCRLCA(t)
	gen := NewGenerator(
		func(string) ([]RevokedCert, error) { return nil, nil },
		func(string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		time.Hour,
	)
	if _, err := gen.Generate(ca.id); err != nil {
		t.Fatal(err)
	}
	if gen.GetCRL(ca.id) == nil {
		t.Fatal("expected cached CRL")
	}
	gen.InvalidateAll()
	if gen.GetCRL(ca.id) != nil {
		t.Fatal("InvalidateAll left a cached CRL")
	}
}
