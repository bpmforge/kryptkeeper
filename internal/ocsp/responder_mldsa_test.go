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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W31-05: an ML-DSA issuer gets a signed, parseable answer instead of the
// errSigning 500 that x/crypto/ocsp.CreateResponse produced.
func TestResponderSignsForMLDSAIssuer(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("mldsa-test-passphrase-32chars!!!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("ML-DSA OCSP Root", pkix.Name{CommonName: "ML-DSA OCSP Root"}, keystore.MLDSA65, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.Signer(root.KeyID)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	issued, err := engine.IssueCertificate(root.ID, ca.IssuanceRequest{CSR: csr, Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature})
	if err != nil {
		t.Fatal(err)
	}
	leaf := issued.Certificate

	revokedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	revoked := map[string]bool{}
	status := func(serial *big.Int, _ *x509.Certificate) (bool, time.Time, int, error) {
		if revoked[serial.String()] {
			return true, revokedAt, 1, nil
		}
		return false, time.Time{}, 0, nil
	}
	issuer := func([]byte) (*x509.Certificate, crypto.Signer, error) { return root.Certificate, signer, nil }
	resp := NewResponder(status, issuer, time.Hour, 10)
	h := resp.Handler()

	ask := func() *goocsp.Response {
		t.Helper()
		reqBytes, err := goocsp.CreateRequest(leaf, root.Certificate, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes)))
		req.Header.Set("Content-Type", "application/ocsp-request")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		body, _ := io.ReadAll(rec.Body)
		parsed, err := goocsp.ParseResponse(body, nil)
		if err != nil {
			t.Fatalf("response is not a successful OCSP response: %v", err)
		}
		return parsed
	}

	if got := ask(); got.Status != goocsp.Good || got.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("want good for leaf, got status %d", got.Status)
	}
	revoked[leaf.SerialNumber.String()] = true
	resp.InvalidateCache(leaf.SerialNumber) // what the revoke path does
	got := ask()
	if got.Status != goocsp.Revoked || got.RevocationReason != 1 || !got.RevokedAt.Equal(revokedAt) {
		t.Fatalf("want revoked/keyCompromise, got status=%d reason=%d at=%v", got.Status, got.RevocationReason, got.RevokedAt)
	}
}
