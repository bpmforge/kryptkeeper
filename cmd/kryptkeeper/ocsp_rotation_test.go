// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/ocsp"
)

// W23-19: through a real cross-sign rotation, an OCSP request naming the OLD
// issuer is answered, signed by the old key (verifies against the old
// certificate), with status from the same revocation store; once the retired
// key is destroyed it is "unauthorized" again. The ledger lives in the CA
// store (the DB in production), so no replica-local state is involved.
func TestOCSPAnswersForRotatedOutIssuer(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ocsp-rotation-test-pass-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Rot Root", pkix.Name{CommonName: "Rot Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCert := root.Certificate

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	issued, err := engine.IssueCertificate(root.ID, ca.IssuanceRequest{CSR: csr, Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature})
	if err != nil {
		t.Fatal(err)
	}
	leaf := issued.Certificate

	rotated, err := engine.CrossSignRotate(root.ID, ca.RotateCAOptions{})
	if err != nil {
		t.Fatal(err)
	}

	rs := ca.NewMemRevocationStore()
	responder := ocsp.NewResponder(
		func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
			id, err := ocspResolveCAID(engine, issuer)
			if err != nil {
				return false, time.Time{}, 0, err
			}
			return rs.IsRevoked(serial, id)
		},
		func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
			c, err := ocspResolveIssuerByKeyHash(engine, keyHash)
			if err != nil {
				return nil, nil, err
			}
			s, err := keys.Signer(c.KeyID)
			return c.Certificate, s, err
		},
		time.Hour, 100,
	).WithRetiredIssuers(func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
		return ocspResolveRetiredIssuer(engine, keys, keyHash)
	})

	query := func(issuer *x509.Certificate) []byte {
		t.Helper()
		reqBytes, err := goocsp.CreateRequest(leaf, issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		responder.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(reqBytes))))
		return rec.Body.Bytes()
	}

	// Pre-rotation leaf, old anchor: good, and the signature is the OLD key's.
	resp, err := goocsp.ParseResponseForCert(query(oldCert), leaf, oldCert)
	if err != nil {
		t.Fatalf("old-issuer response does not verify against the old certificate: %v", err)
	}
	if resp.Status != goocsp.Good {
		t.Fatalf("status = %d, want good", resp.Status)
	}

	// Revoked in the shared store under the CA id: the old-issuer query sees it.
	if err := rs.Revoke(leaf.SerialNumber, root.ID, 1, time.Now().Add(-time.Minute).UTC()); err != nil {
		t.Fatal(err)
	}
	responder.InvalidateCache(leaf.SerialNumber)
	resp, err = goocsp.ParseResponseForCert(query(oldCert), leaf, oldCert)
	if err != nil || resp.Status != goocsp.Revoked || resp.RevocationReason != 1 {
		t.Fatalf("revoked: resp=%+v err=%v", resp, err)
	}

	// The new issuer still answers for the new key (the old leaf was not
	// signed by it, but the issuer is served): signed by the NEW key.
	newIssuerResp := query(rotated.RolledCA.Certificate)
	if _, err := goocsp.ParseResponse(newIssuerResp, rotated.RolledCA.Certificate); err != nil {
		t.Fatalf("new-issuer response does not verify against the new certificate: %v", err)
	}

	// Destroy the retired key: the old issuer is no longer served.
	destroyed, err := engine.RetireRotatedKeys(time.Now().Add(time.Hour), 0, keys.Delete)
	if err != nil || len(destroyed) != 1 {
		t.Fatalf("RetireRotatedKeys = %v, %v", destroyed, err)
	}
	if _, err := goocsp.ParseResponse(query(oldCert), oldCert); err == nil {
		t.Fatal("old issuer still answered after its key was destroyed")
	} else if re, ok := err.(goocsp.ResponseError); !ok || re.Status != goocsp.Unauthorized {
		t.Fatalf("after retirement: %v, want unauthorized", err)
	}
}
