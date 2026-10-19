// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha1" //nolint:gosec // SHA-1 CertIDs
	"crypto/sha256"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/ocsp"
)

// failingListCAs is a ca.Service whose CA list cannot be read.
type failingListCAs struct{ ca.Service }

func (failingListCAs) ListCAs() ([]*ca.CA, error) { return nil, errors.New("store unavailable") }

func newOCSPResolveEngine(t *testing.T) (*ca.Engine, *ca.CA) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ocsp-resolve-test-pass-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("OCSP Resolve Root", pkix.Name{CommonName: "OCSP Resolve Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return engine, root
}

// SEMGREP-012: the resolvers used to fall back to the default CA on a miss
// and on a CA-list read failure, so the responder signed "good" for issuers
// it did not serve.
func TestOCSPResolveIssuerByKeyHash(t *testing.T) {
	engine, root := newOCSPResolveEngine(t)
	sha1Hash := ocspPublicKeyHash(root.Certificate, sha1.Size)
	sha256Hash := ocspPublicKeyHash(root.Certificate, sha256.Size)
	if sha1Hash == nil || sha256Hash == nil {
		t.Fatal("key hash not computed")
	}

	for name, h := range map[string][]byte{"sha1": sha1Hash, "sha256": sha256Hash} {
		got, err := ocspResolveIssuerByKeyHash(engine, h)
		if err != nil || got.ID != root.ID {
			t.Errorf("%s key hash: got %v, %v; want CA %s", name, got, err, root.ID)
		}
	}

	if _, err := ocspResolveIssuerByKeyHash(engine, make([]byte, sha1.Size)); !errors.Is(err, ocsp.ErrUnknownIssuer) {
		t.Errorf("unknown key hash: err = %v, want ocsp.ErrUnknownIssuer (no default-CA fallback)", err)
	}
	_, err := ocspResolveIssuerByKeyHash(failingListCAs{engine}, sha1Hash)
	if err == nil || errors.Is(err, ocsp.ErrUnknownIssuer) {
		t.Errorf("CA-list failure: err = %v, want a non-unknown-issuer error (tryLater)", err)
	}
}

func TestOCSPResolveCAID(t *testing.T) {
	engine, root := newOCSPResolveEngine(t)
	if id, err := ocspResolveCAID(engine, root.Certificate); err != nil || id != root.ID {
		t.Fatalf("known issuer: %q, %v", id, err)
	}

	otherEngine, other := newOCSPResolveEngine(t)
	_ = otherEngine
	if id, err := ocspResolveCAID(engine, other.Certificate); !errors.Is(err, ocsp.ErrUnknownIssuer) {
		t.Fatalf("foreign issuer resolved to %q (%v); must be ErrUnknownIssuer, not the default CA", id, err)
	}
	if _, err := ocspResolveCAID(failingListCAs{engine}, root.Certificate); err == nil || errors.Is(err, ocsp.ErrUnknownIssuer) {
		t.Fatalf("CA-list failure: err = %v, want a transient error", err)
	}
	if _, err := ocspResolveCAID(engine, nil); !errors.Is(err, ocsp.ErrUnknownIssuer) {
		t.Fatalf("nil issuer: err = %v", err)
	}
}

// W23-35: an issuer under a revoked CA (itself or an ancestor) reads revoked,
// with the revocation time the revoke recorded.
func TestOCSPIssuerStatusWalksAncestors(t *testing.T) {
	engine, root := newOCSPResolveEngine(t)
	inter, err := engine.CreateIntermediateCA("OCSP Resolve Inter", pkix.Name{CommonName: "OCSP Resolve Inter"}, keystore.ECDSAP256, root.ID, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rs := ca.NewMemRevocationStore()
	status := ocspIssuerStatus(engine, rs)

	if revoked, _, _, err := status(inter.Certificate); err != nil || revoked {
		t.Fatalf("active chain: revoked=%v err=%v", revoked, err)
	}
	when := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if _, err := ca.RevokeCA(engine, rs, inter.ID, when); err != nil {
		t.Fatal(err)
	}
	revoked, at, reason, err := status(inter.Certificate)
	if err != nil || !revoked || !at.Equal(when) || reason != 2 {
		t.Fatalf("revoked intermediate: revoked=%v at=%v reason=%d err=%v", revoked, at, reason, err)
	}
	// The root is untouched.
	if revoked, _, _, _ := status(root.Certificate); revoked {
		t.Fatal("root must not read revoked")
	}
}

func TestOCSPIssuerStatusRevokedRootCoversDescendants(t *testing.T) {
	engine, root := newOCSPResolveEngine(t)
	inter, err := engine.CreateIntermediateCA("OCSP Resolve Inter2", pkix.Name{CommonName: "OCSP Resolve Inter2"}, keystore.ECDSAP256, root.ID, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rs := ca.NewMemRevocationStore()
	if _, err := ca.RevokeCA(engine, rs, root.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if revoked, _, _, err := ocspIssuerStatus(engine, rs)(inter.Certificate); err != nil || !revoked {
		t.Fatalf("child of revoked root: revoked=%v err=%v", revoked, err)
	}
}
