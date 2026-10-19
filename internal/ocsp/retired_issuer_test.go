// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"crypto"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"
)

// W23-19: after a CA key rotation, relying parties holding the OLD anchor send
// a CertID naming the OLD issuer. The response must be signed by the old key
// and verify against the old issuer certificate, or the client rejects it.
func TestOCSPRetiredIssuerAnsweredWithOldKey(t *testing.T) {
	oldCA, newCA := newTestCA(t), newTestCA(t)
	leaf := issueTestCert(t, oldCA, 4242)

	retiredAlive := true
	revoked := map[string]bool{}
	status := func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
		// The store is keyed by CA id + serial; the responder must hand the
		// OLD issuer through so the caller can resolve the same CA id.
		if !issuer.Equal(oldCA.cert) {
			t.Errorf("status lookup got issuer %v, want the old issuer", issuer.Subject)
		}
		if revoked[serial.String()] {
			return true, time.Now().Add(-time.Hour).UTC(), 1, nil
		}
		return false, time.Time{}, 0, nil
	}
	retired := func(kh []byte) (*x509.Certificate, crypto.Signer, error) {
		if !retiredAlive {
			return nil, nil, ErrUnknownIssuer
		}
		return oldCA.cert, oldCA.key, nil
	}
	// The live lookup serves only the new key; the old issuer is retired.
	liveNew := func(kh []byte) (*x509.Certificate, crypto.Signer, error) {
		if string(keyHashOf(t, newCA.cert)) == string(kh) {
			return newCA.cert, newCA.key, nil
		}
		return nil, nil, ErrUnknownIssuer
	}
	r := NewResponder(status, liveNew, time.Hour, 100).WithRetiredIssuers(retired)

	// Good, signed by the old key, verifies against the old issuer.
	resp, err := goocsp.ParseResponseForCert(serve(t, r, leaf, oldCA.cert), leaf, oldCA.cert)
	if err != nil {
		t.Fatalf("response does not verify against the old issuer: %v", err)
	}
	if resp.Status != goocsp.Good {
		t.Fatalf("status = %d, want good", resp.Status)
	}

	// Revoked comes from the same store.
	revoked[leaf.SerialNumber.String()] = true
	r.InvalidateAll()
	resp, err = goocsp.ParseResponseForCert(serve(t, r, leaf, oldCA.cert), leaf, oldCA.cert)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != goocsp.Revoked || resp.RevocationReason != 1 {
		t.Fatalf("status = %d reason %d, want revoked/1", resp.Status, resp.RevocationReason)
	}

	// A response signed by the old key must NOT verify against the new issuer.
	if _, err := goocsp.ParseResponseForCert(serve(t, r, leaf, oldCA.cert), leaf, newCA.cert); err == nil {
		t.Fatal("old-key response verified against the new issuer")
	}

	// Retired responses are not cached, so destruction takes effect at once.
	retiredAlive = false
	wantErrorStatus(t, serve(t, r, leaf, oldCA.cert), goocsp.Unauthorized)
}

// Without the retired lookup (the pre-W23-19 behaviour), the old issuer is
// "not served" and the answer is unauthorized.
func TestOCSPRetiredIssuerWithoutLookupIsUnauthorized(t *testing.T) {
	oldCA := newTestCA(t)
	leaf := issueTestCert(t, oldCA, 7)
	r := NewResponder(neverRevoked, func([]byte) (*x509.Certificate, crypto.Signer, error) {
		return nil, nil, ErrUnknownIssuer
	}, time.Hour, 100)
	wantErrorStatus(t, serve(t, r, leaf, oldCA.cert), goocsp.Unauthorized)
}

// The retired lookup is trusted no further than the live one: a cert whose
// hashes do not match the CertID is refused.
func TestOCSPRetiredLookupMismatchRefused(t *testing.T) {
	oldCA, other := newTestCA(t), newTestCA(t)
	leaf := issueTestCert(t, oldCA, 9)
	r := NewResponder(neverRevoked, func([]byte) (*x509.Certificate, crypto.Signer, error) {
		return nil, nil, ErrUnknownIssuer
	}, time.Hour, 100).WithRetiredIssuers(func([]byte) (*x509.Certificate, crypto.Signer, error) {
		return other.cert, other.key, nil
	})
	wantErrorStatus(t, serve(t, r, leaf, oldCA.cert), goocsp.Unauthorized)
}
