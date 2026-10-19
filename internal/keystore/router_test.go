// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// countingStore counts Signer lookups so tests can prove which backend served a key.
type countingStore struct {
	keystore.Store
	signers atomic.Int32
}

func (c *countingStore) Signer(id string) (crypto.Signer, error) {
	c.signers.Add(1)
	return c.Store.Signer(id)
}

func newCounting(t *testing.T, pass string) *countingStore {
	t.Helper()
	s, err := keystore.NewSoftwareStore(t.TempDir(), []byte(pass))
	if err != nil {
		t.Fatalf("software store: %v", err)
	}
	t.Cleanup(s.Close)
	return &countingStore{Store: s}
}

func newTestRouter(t *testing.T) (*keystore.Router, *countingStore, *countingStore) {
	t.Helper()
	sw := newCounting(t, "router-software-passphrase-32-by!")
	kms := newCounting(t, "router-cloudkms-passphrase-32-by")
	r, err := keystore.NewRouter("software", map[string]keystore.Store{"software": sw, "cloudkms": kms})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return r, sw, kms
}

func TestRouterRoutesByBackend(t *testing.T) {
	r, sw, kms := newTestRouter(t)
	if err := r.WithCreateBackend("cloudkms", func() error {
		_, err := r.GenerateKey("k1", keystore.ECDSAP256)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GenerateKey("k2", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Signer("k1"); err != nil {
		t.Fatal(err)
	}
	if kms.signers.Load() != 1 || sw.signers.Load() != 0 {
		t.Fatalf("k1 should hit only cloudkms: kms=%d sw=%d", kms.signers.Load(), sw.signers.Load())
	}
	if _, err := r.Signer("k2"); err != nil {
		t.Fatal(err)
	}
	if kms.signers.Load() != 1 || sw.signers.Load() != 1 {
		t.Fatalf("k2 should hit only software: kms=%d sw=%d", kms.signers.Load(), sw.signers.Load())
	}
	list, err := r.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %v, %v; want 2 keys once each", list, err)
	}
}

func TestRouterRefusesNotEnabledBackend(t *testing.T) {
	r, _, _ := newTestRouter(t)
	err := r.WithCreateBackend("pkcs11", func() error { t.Fatal("fn must not run"); return nil })
	if err == nil || !strings.Contains(err.Error(), "cloudkms, software") {
		t.Fatalf("want error listing enabled backends, got %v", err)
	}
}

func TestRouterCreateLabelResetsAfterError(t *testing.T) {
	r, _, _ := newTestRouter(t)
	_ = r.WithCreateBackend("cloudkms", func() error { return errors.New("boom") })
	if got := r.CurrentBackendLabel(); got != "software" {
		t.Fatalf("label after error = %q, want default", got)
	}
}

func TestRouterRawKeyGoesToDefault(t *testing.T) {
	r, sw, kms := newTestRouter(t)
	if _, err := r.GenerateKey("raw", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Metadata("raw"); err != nil {
		t.Fatalf("raw key should be on default: %v", err)
	}
	if _, err := kms.Metadata("raw"); !errors.Is(err, keystore.ErrKeyNotFound) {
		t.Fatalf("raw key leaked to non-default backend: %v", err)
	}
}

func TestSingleBackendNoRouterDelegates(t *testing.T) {
	sw := newCounting(t, "router-single-passphrase-32-byte!")
	r, err := keystore.NewRouter("", map[string]keystore.Store{"software": sw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.GenerateKey("a", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Signer("a"); err != nil || sw.signers.Load() != 1 {
		t.Fatalf("single backend must delegate: err=%v n=%d", err, sw.signers.Load())
	}
	if _, err := keystore.NewRouter("pkcs11", map[string]keystore.Store{"software": sw}); err == nil {
		t.Fatal("default outside backends must error")
	}
}

func TestBackendLabelFromStorageType(t *testing.T) {
	for in, want := range map[string]string{
		"cloud_kms": "cloudkms", "cloudkms": "cloudkms", "software": "software",
		"pkcs11": "pkcs11", "vault": "vault", "": "",
	} {
		if got := keystore.BackendLabelFromStorageType(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func leafCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	ks, err := keystore.NewSoftwareStore(t.TempDir(), []byte("router-leaf-passphrase-32-bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	if _, err := ks.GenerateKey("leaf", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	signer, _ := ks.Signer("leaf")
	der, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.com"}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func issue(t *testing.T, e *ca.Engine, caID string) {
	t.Helper()
	if _, err := e.IssueCertificate(caID, ca.IssuanceRequest{CSR: leafCSR(t), Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature}); err != nil {
		t.Fatalf("issue from %s: %v", caID, err)
	}
}

func TestTwoCAsOnDifferentBackendsIssueAndSurviveRestart(t *testing.T) {
	r, sw, kms := newTestRouter(t)
	store := ca.NewMemStore()
	e := ca.NewEngine(r, store)

	root1, err := e.CreateRootCA("r1", pkix.Name{CommonName: "Root One"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var root2 *ca.CA
	if err := r.WithCreateBackend("cloudkms", func() error {
		var cerr error
		root2, cerr = e.CreateRootCA("r2", pkix.Name{CommonName: "Root Two"}, keystore.ECDSAP256, 24*time.Hour)
		return cerr
	}); err != nil {
		t.Fatal(err)
	}
	if root1.KeyStorageType == root2.KeyStorageType {
		t.Fatalf("rows must record different backends, both %q", root1.KeyStorageType)
	}
	issue(t, e, root1.ID)
	issue(t, e, root2.ID)

	// Restart: fresh router with empty assign map, resolver from CA rows only.
	swB, kmsB := newCounting(t, "x"), newCounting(t, "y")
	swB.Store, kmsB.Store = sw.Store, kms.Store // same on-disk keys
	rB, err := keystore.NewRouter("software", map[string]keystore.Store{"software": swB, "cloudkms": kmsB})
	if err != nil {
		t.Fatal(err)
	}
	cas, _ := store.List()
	byKey := map[string]string{}
	for _, c := range cas {
		byKey[c.KeyID] = keystore.BackendLabelFromStorageType(c.KeyStorageType)
	}
	rB.SetResolver(func(id string) (string, bool) { l, ok := byKey[id]; return l, ok })
	eB := ca.NewEngine(rB, store)
	issue(t, eB, root1.ID)
	issue(t, eB, root2.ID)
	if swB.signers.Load() == 0 || kmsB.signers.Load() == 0 {
		t.Fatalf("each backend must sign after restart: sw=%d kms=%d", swB.signers.Load(), kmsB.signers.Load())
	}
	// Prove the negative: root2's key must not be signable from the software backend.
	if _, err := swB.Store.Signer(root2.KeyID); err == nil {
		t.Fatal("root2 key unexpectedly present on software backend")
	}
}

func TestIntermediateOnOtherBackendThanParent(t *testing.T) {
	r, sw, kms := newTestRouter(t)
	e := ca.NewEngine(r, ca.NewMemStore())
	root, err := e.CreateRootCA("r", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var inter *ca.CA
	if err := r.WithCreateBackend("cloudkms", func() error {
		var cerr error
		inter, cerr = e.CreateIntermediateCA("i", pkix.Name{CommonName: "Inter"}, keystore.ECDSAP256, root.ID, time.Hour)
		return cerr
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Store.Metadata(root.KeyID); err != nil {
		t.Fatalf("parent key should be software: %v", err)
	}
	if _, err := kms.Store.Metadata(inter.KeyID); err != nil {
		t.Fatalf("child key should be cloudkms: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Certificate)
	if _, err := inter.Certificate.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("intermediate must verify against root: %v", err)
	}
}

func TestPQCRefusedOnHardwareBackendViaRouter(t *testing.T) {
	r, _, _ := newTestRouter(t)
	e := ca.NewEngine(r, ca.NewMemStore())
	err := r.WithCreateBackend("cloudkms", func() error {
		_, cerr := e.CreateRootCA("pq", pkix.Name{CommonName: "PQ"}, keystore.MLDSA65, time.Hour)
		return cerr
	})
	if !errors.Is(err, keystore.ErrPQCHSMUnsupported) {
		t.Fatalf("want ErrPQCHSMUnsupported, got %v", err)
	}
	if _, err := e.CreateRootCA("pq2", pkix.Name{CommonName: "PQ"}, keystore.MLDSA65, time.Hour); err != nil {
		t.Fatalf("ML-DSA on default software backend must work: %v", err)
	}
}

// W23-16: a rotated-out key ("<id>-retired-<ts>") must stay on its parent's backend.
func TestRouterRetiredKeyFollowsParentBackend(t *testing.T) {
	r, sw, kms := newTestRouter(t)
	if err := r.WithCreateBackend("cloudkms", func() error {
		_, err := r.GenerateKey("ca-key", keystore.ECDSAP256)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := r.RotateKey("ca-key", keystore.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Metadata(res.PreviousID); err != nil {
		t.Fatalf("retired key must resolve through the router: %v", err)
	}
	if _, err := kms.Metadata(res.PreviousID); err != nil {
		t.Fatalf("retired key must live on the parent's backend: %v", err)
	}
	if _, err := sw.Metadata(res.PreviousID); !errors.Is(err, keystore.ErrKeyNotFound) {
		t.Fatalf("retired key leaked to the default backend: %v", err)
	}
	if err := r.Delete(res.PreviousID); err != nil {
		t.Fatalf("destroying the retired key must reach the parent's backend: %v", err)
	}
}
