// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// W6-07: re-key + cross-sign = zero-downtime rollover; both chains
// validate during the window.

func newCrossSignEngine(t *testing.T) *Engine {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("cross-sign-test-passphrase-32-b!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	return NewEngine(keys, NewMemStore())
}

func issueLeaf(t *testing.T, e *Engine, caID string) *x509.Certificate {
	t.Helper()
	leaf, err := e.issueProbeLeaf(caID)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	return leaf
}

func TestCrossSignRotateBothChainsValidate(t *testing.T) {
	e := newCrossSignEngine(t)
	root, err := e.CreateRootCA("Rollover Root", pkix.Name{CommonName: "Rollover Root CA"}, keystore.ECDSAP256, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	oldCert := root.Certificate
	preRotationLeaf := issueLeaf(t, e, root.ID)

	result, err := e.CrossSignRotate(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatalf("cross-sign rotate: %v", err)
	}
	newCert := result.RolledCA.Certificate
	if newCert.SerialNumber.Cmp(oldCert.SerialNumber) == 0 {
		t.Fatal("rotation must mint a new certificate")
	}

	cross, err := x509.ParseCertificate(pemToDER(t, result.CrossCertPEM))
	if err != nil {
		t.Fatalf("parse cross cert: %v", err)
	}
	// The bridge carries the NEW identity under the OLD signature.
	if !bytes.Equal(cross.RawSubjectPublicKeyInfo, newCert.RawSubjectPublicKeyInfo) {
		t.Fatal("bridge must carry the new CA's public key")
	}
	if err := cross.CheckSignatureFrom(oldCert); err != nil {
		t.Fatalf("bridge must be signed by the OLD certificate's key: %v", err)
	}
	// Same subject and issuer DN: without an AKI naming the old key, OpenSSL
	// treats the bridge as self-signed and the old-anchor path never builds.
	if len(cross.AuthorityKeyId) == 0 || !bytes.Equal(cross.AuthorityKeyId, oldCert.SubjectKeyId) {
		t.Fatalf("bridge AKI %x must equal the old certificate's SKI %x", cross.AuthorityKeyId, oldCert.SubjectKeyId)
	}
	// And it must not outlive its issuer's certificate.
	if cross.NotAfter.After(oldCert.NotAfter) {
		t.Fatalf("bridge NotAfter %v exceeds the old cert's %v", cross.NotAfter, oldCert.NotAfter)
	}

	// A leaf issued AFTER rotation (new key) validates both ways.
	postLeaf := issueLeaf(t, e, root.ID)

	newRoots := x509.NewCertPool()
	newRoots.AddCert(newCert)
	if _, err := postLeaf.Verify(x509.VerifyOptions{Roots: newRoots}); err != nil {
		t.Fatalf("post-rotation leaf must chain to the new root: %v", err)
	}
	oldRoots := x509.NewCertPool()
	oldRoots.AddCert(oldCert)
	bridge := x509.NewCertPool()
	bridge.AddCert(cross)
	if _, err := postLeaf.Verify(x509.VerifyOptions{Roots: oldRoots, Intermediates: bridge}); err != nil {
		t.Fatalf("post-rotation leaf must chain to the OLD root via the bridge: %v", err)
	}

	// Pre-rotation issuance is untouched: it still chains to the old root.
	if _, err := preRotationLeaf.Verify(x509.VerifyOptions{Roots: oldRoots}); err != nil {
		t.Fatalf("pre-rotation leaf must still chain to the old root: %v", err)
	}
}

func TestCrossSignRotateRefusesInactiveCA(t *testing.T) {
	e := newCrossSignEngine(t)
	root, err := e.CreateRootCA("Parked Root", pkix.Name{CommonName: "Parked Root CA"}, keystore.ECDSAP256, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if err := e.UpdateCAStatus(root.ID, "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := e.CrossSignRotate(root.ID, RotateCAOptions{}); err == nil {
		t.Fatal("cross-sign of a non-active CA must be refused (RotateCA's rule)")
	}
}

func pemToDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("expected a PEM block")
	}
	return block.Bytes
}
