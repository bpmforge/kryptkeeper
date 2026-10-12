// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// saveFailsAfterStore wraps a Store and makes every Save call after the
// first N succeed fail, simulating a CA-store write failure (disk-full,
// dropped DB connection) that lands AFTER keystore.RotateKey has already
// mutated the keystore -- the discriminating scenario for
// ErrCARotationInconsistent.
type saveFailsAfterStore struct {
	Store
	allowSaves int
	saveCalls  int
}

var errSimulatedSaveFailure = errors.New("simulated ca-store save failure")

func (s *saveFailsAfterStore) Save(ca *CA) error {
	s.saveCalls++
	if s.saveCalls > s.allowSaves {
		return errSimulatedSaveFailure
	}
	return s.Store.Save(ca)
}

func issueTestLeaf(t *testing.T, engine *Engine, caID string) *x509.Certificate {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, clientKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	leaf, err := engine.IssueCertificate(caID, IssuanceRequest{
		CSR:      csr,
		Validity: 90 * 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	return leaf.Certificate
}

// TestRotateCA_Root proves the acceptance-critical shape from the spec: a
// new key, a re-issued certificate with a different SKI that still
// validates as the same subject, a ledger row, and that certs issued
// before rotation still chain -- against the PRE-rotation root certificate
// specifically. Without cross-signing (W6-07 not landed), a leaf signed by
// the old key cannot verify against the NEW CA certificate (different
// key/SKI, no cryptographic link) -- that is expected, disclosed behavior,
// not a bug; "still chain" means the old leaf remains valid against a
// retained copy of the old root, which is what a relying party who cached
// the pre-rotation CA cert would have.
func TestRotateCA_Root(t *testing.T) {
	engine := newTestEngine(t)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	oldCert := root.Certificate
	oldPub := oldCert.PublicKey
	oldSKI := oldCert.SubjectKeyId

	preRotationLeaf := issueTestLeaf(t, engine, root.ID)

	result, err := engine.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}

	// New key: different public key.
	newPub, err := engine.keys.PublicKey(root.KeyID)
	if err != nil {
		t.Fatalf("PublicKey after rotation: %v", err)
	}
	newECDSAPub, ok := newPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", newPub)
	}
	oldECDSAPub, ok := oldPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected old public key type %T", oldPub)
	}
	if newECDSAPub.Equal(oldECDSAPub) {
		t.Fatal("public key unchanged after rotation")
	}

	// Re-issued cert: different SKI, same subject, still self-signed/valid.
	if string(result.CA.Certificate.SubjectKeyId) == string(oldSKI) {
		t.Fatal("SKI unchanged after rotation")
	}
	if result.CA.Certificate.Subject.CommonName != "Root" {
		t.Errorf("subject changed after rotation: %q", result.CA.Certificate.Subject.CommonName)
	}
	roots := x509.NewCertPool()
	roots.AddCert(result.CA.Certificate)
	if _, err := result.CA.Certificate.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("re-issued root does not self-verify: %v", err)
	}

	// Same key ID (rotates in place), key ID unchanged in the CA record too.
	if result.NewKeyID != root.KeyID {
		t.Errorf("NewKeyID = %q, want unchanged %q", result.NewKeyID, root.KeyID)
	}
	if result.CA.KeyID != root.KeyID {
		t.Errorf("CA.KeyID changed after rotation: %q", result.CA.KeyID)
	}

	// Ledger row recorded.
	if result.Rotation.CAID != root.ID {
		t.Errorf("ledger CAID = %q, want %q", result.Rotation.CAID, root.ID)
	}
	if result.Rotation.Method != "rekey_reissue" {
		t.Errorf("ledger method = %q, want rekey_reissue", result.Rotation.Method)
	}
	rotations, err := engine.store.ListKeyRotations(root.ID)
	if err != nil {
		t.Fatalf("ListKeyRotations: %v", err)
	}
	if len(rotations) != 1 {
		t.Fatalf("ListKeyRotations returned %d rows, want 1", len(rotations))
	}

	// Pre-rotation leaf still chains -- against the RETAINED pre-rotation
	// root cert specifically, not the live (now-rotated) CA record.
	oldRoots := x509.NewCertPool()
	oldRoots.AddCert(oldCert)
	if _, err := preRotationLeaf.Verify(x509.VerifyOptions{Roots: oldRoots}); err != nil {
		t.Fatalf("pre-rotation leaf does not chain to the retained pre-rotation root: %v", err)
	}

	// A NEW leaf issued after rotation chains to the NEW (current) root.
	postRotationLeaf := issueTestLeaf(t, engine, root.ID)
	newRoots := x509.NewCertPool()
	newRoots.AddCert(result.CA.Certificate)
	if _, err := postRotationLeaf.Verify(x509.VerifyOptions{Roots: newRoots}); err != nil {
		t.Fatalf("post-rotation leaf does not chain to the new root: %v", err)
	}
}

// TestRotateCA_Intermediate proves re-key of an intermediate CA re-signs
// under its (unchanged) parent, with the same AuthorityKeyId linkage and
// NotAfter clamping CreateIntermediateCA itself uses.
func TestRotateCA_Intermediate(t *testing.T) {
	engine := newTestEngine(t)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	inter, err := engine.CreateIntermediateCA("Inter", pkix.Name{CommonName: "Inter"}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}
	oldSKI := inter.Certificate.SubjectKeyId

	result, err := engine.RotateCA(inter.ID, RotateCAOptions{})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}

	if string(result.CA.Certificate.SubjectKeyId) == string(oldSKI) {
		t.Fatal("SKI unchanged after rotation")
	}
	if string(result.CA.Certificate.AuthorityKeyId) != string(root.Certificate.SubjectKeyId) {
		t.Error("re-issued intermediate's AuthorityKeyId does not match the (unchanged) parent's SubjectKeyId")
	}

	// Chains to the (unchanged) root.
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)
	chain, err := result.CA.Certificate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chain) == 0 {
		t.Fatalf("re-issued intermediate does not chain to root: %v", err)
	}

	// A new leaf issued after rotation chains through the re-issued
	// intermediate to the root.
	leaf := issueTestLeaf(t, engine, inter.ID)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: func() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(result.CA.Certificate); return p }(),
	}); err != nil {
		t.Fatalf("post-rotation leaf does not chain through the re-issued intermediate: %v", err)
	}
}

func TestRotateCA_RejectsInactiveCA(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	if err := engine.UpdateCAStatus(root.ID, "suspended"); err != nil {
		t.Fatalf("UpdateCAStatus: %v", err)
	}
	if _, err := engine.RotateCA(root.ID, RotateCAOptions{}); err == nil {
		t.Fatal("expected an error rotating a suspended CA")
	}
}

func TestRotateCA_UnknownCA(t *testing.T) {
	engine := newTestEngine(t)
	if _, err := engine.RotateCA("does-not-exist", RotateCAOptions{}); err != ErrCANotFound {
		t.Fatalf("err = %v, want ErrCANotFound", err)
	}
}

func TestRotateCA_AlgorithmOverride(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	result, err := engine.RotateCA(root.ID, RotateCAOptions{Algorithm: keystore.ECDSAP384})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	meta, err := engine.keys.Metadata(result.NewKeyID)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.Algorithm != keystore.ECDSAP384 {
		t.Errorf("algorithm = %q, want %q", meta.Algorithm, keystore.ECDSAP384)
	}
}

// TestRotateCA_PreservesValidityWindowLength proves the re-issued cert gets
// a FRESH full-length term (now -> now+duration), not the remaining time on
// the original cert -- a deliberate, disclosed design choice (see
// rotation.go's doc comment).
func TestRotateCA_PreservesValidityWindowLength(t *testing.T) {
	engine := newTestEngine(t)
	validity := 5 * 365 * 24 * time.Hour
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, validity)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	result, err := engine.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	gotWindow := result.CA.Certificate.NotAfter.Sub(result.CA.Certificate.NotBefore)
	diff := gotWindow - validity
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Minute {
		t.Errorf("validity window = %v, want ~%v", gotWindow, validity)
	}
	// x509 certificate timestamps truncate to whole seconds, so a fast test
	// running CreateRootCA and RotateCA within the same wall-clock second
	// can legitimately produce an EQUAL NotBefore -- assert not-before
	// (>=), not strictly-after, to avoid that flake while still proving the
	// re-issued cert isn't using some much-earlier stale timestamp.
	if result.CA.Certificate.NotBefore.Before(root.Certificate.NotBefore) {
		t.Error("re-issued cert's NotBefore is earlier than the original CA's NotBefore")
	}
}

// TestRotateCA_StoreSaveFailureIsLoudAndActionable is the discriminating
// test for ErrCARotationInconsistent: keystore.Store.RotateKey succeeds
// (irreversibly retiring the old key and generating a new one under the
// same ID) but the CA-store write that persists the re-issued certificate
// fails afterward. Before this test existed, that path returned a bare
// error and left the CA silently broken -- the exact G-35 footgun this
// ticket exists to prevent, now reachable through partial failure of the
// fix itself. This proves the failure is now loud (wraps
// ErrCARotationInconsistent, names the retired key and the DR recovery
// path) instead of silent, and confirms the actual on-disk inconsistency
// the error is warning about.
func TestRotateCA_StoreSaveFailureIsLoudAndActionable(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("save-failure-test-passphrase-32b"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := &saveFailsAfterStore{Store: NewMemStore(), allowSaves: 1}
	engine := NewEngine(keys, store)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	oldPub := root.Certificate.PublicKey

	result, err := engine.RotateCA(root.ID, RotateCAOptions{})
	if err == nil {
		t.Fatal("expected RotateCA to fail when the CA-store save fails")
	}
	if !errors.Is(err, ErrCARotationInconsistent) {
		t.Fatalf("error does not wrap ErrCARotationInconsistent: %v", err)
	}
	if !errors.Is(err, errSimulatedSaveFailure) {
		t.Fatalf("error does not wrap the underlying save failure: %v", err)
	}
	if result.CA != nil {
		t.Fatalf("expected a nil CA in the result on this failure path, got %+v", result.CA)
	}
	msg := err.Error()
	for _, want := range []string{root.KeyID, "DR_RUNBOOK", "do NOT retry"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}

	// Confirm the actual inconsistency the error is warning about: the
	// keystore already holds a NEW key under the CA's KeyID (RotateKey is
	// irreversible), but the CA store's record of this CA still has the
	// OLD certificate/pubkey, because the save that would have updated it
	// failed. A caller trusting the stale CA record without heeding the
	// error would be exposed to exactly the G-35 footgun.
	newPub, err := engine.keys.PublicKey(root.KeyID)
	if err != nil {
		t.Fatalf("PublicKey after failed rotation: %v", err)
	}
	newECDSA, ok := newPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", newPub)
	}
	oldECDSA, ok := oldPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected old public key type %T", oldPub)
	}
	if newECDSA.Equal(oldECDSA) {
		t.Fatal("keystore key was NOT rotated -- test setup invalid, this scenario cannot occur")
	}
	stale, err := store.Load(root.ID)
	if err != nil {
		t.Fatalf("Load after failed rotation: %v", err)
	}
	staleECDSA, ok := stale.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected stale public key type %T", stale.Certificate.PublicKey)
	}
	if !staleECDSA.Equal(oldECDSA) {
		t.Fatal("CA store record changed despite the simulated save failure -- test double is wrong")
	}
}

func TestKeyInUseByCA(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	caID, found, err := KeyInUseByCA(engine.store, root.KeyID)
	if err != nil {
		t.Fatalf("KeyInUseByCA: %v", err)
	}
	if !found || caID != root.ID {
		t.Errorf("KeyInUseByCA(%q) = (%q, %v), want (%q, true)", root.KeyID, caID, found, root.ID)
	}

	_, found, err = KeyInUseByCA(engine.store, "some-unrelated-key")
	if err != nil {
		t.Fatalf("KeyInUseByCA: %v", err)
	}
	if found {
		t.Error("KeyInUseByCA reported an unrelated key as backing a CA")
	}
}
