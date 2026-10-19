// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestCheckKeyConsistency_HealthyCAsProduceNoFindings(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("consistency-test-passphrase-32by"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := NewMemStore()
	engine := NewEngine(keys, store)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	findings, err := CheckKeyConsistency(keys, store)
	if err != nil {
		t.Fatalf("CheckKeyConsistency: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for an unrotated CA, got %+v", findings)
	}

	// A clean, fully-completed rotation must also leave no finding -- the
	// keystore key and the re-issued certificate are consistent afterward.
	if _, err := engine.RotateCA(root.ID, RotateCAOptions{}); err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	findings, err = CheckKeyConsistency(keys, store)
	if err != nil {
		t.Fatalf("CheckKeyConsistency after clean rotation: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings after a clean rotation, got %+v", findings)
	}
}

// TestCheckKeyConsistency_DetectsCrashWindowDivergence reproduces the exact
// G-78 scenario: keystore.Store.RotateKey succeeds (irreversible), but the
// CA-store write that would persist the re-issued certificate never lands --
// simulating a process crash in that window, not just a returned error.
func TestCheckKeyConsistency_DetectsCrashWindowDivergence(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("consistency-test-passphrase-32by"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := &saveFailsAfterStore{Store: NewMemStore(), allowSaves: 1}
	engine := NewEngine(noSnapshotKeys{keys}, store)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	if _, err := engine.RotateCA(root.ID, RotateCAOptions{}); err == nil || !errors.Is(err, ErrCARotationInconsistent) {
		t.Fatalf("expected RotateCA to fail with ErrCARotationInconsistent, got %v", err)
	}

	findings, err := CheckKeyConsistency(keys, store)
	if err != nil {
		t.Fatalf("CheckKeyConsistency: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].CAID != root.ID {
		t.Fatalf("finding names the wrong CA: %+v", findings[0])
	}
	if findings[0].KeyID != root.KeyID {
		t.Fatalf("finding names the wrong key: %+v", findings[0])
	}

	// Must not panic and must not lose the finding when logged.
	LogKeyConsistencyFindings(findings)
}

// TestCheckKeyConsistency_PureMLDSACADoesNotFalsePositive proves a healthy,
// never-rotated pure ML-DSA CA is not reported as inconsistent on every
// boot. The shape of the trap changed with the toolchain: before Go 1.27,
// x509 could not decode an ML-DSA SPKI and left PublicKey nil (so the nil
// guard in publicKeysEqual was the fix); from 1.27 on it yields a stdlib
// crypto/mldsa key that a circl-typed comparison would call "different".
// Both cases must read as consistent.
func TestCheckKeyConsistency_PureMLDSACADoesNotFalsePositive(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("consistency-test-passphrase-32by"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := NewMemStore()
	engine := NewEngine(keys, store)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA (MLDSA65): %v", err)
	}
	if root.Certificate == nil {
		t.Fatal("test premise broken: CreateRootCA returned no certificate")
	}

	findings, err := CheckKeyConsistency(keys, store)
	if err != nil {
		t.Fatalf("CheckKeyConsistency: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected a healthy pure ML-DSA CA to produce no findings (not-comparable != inconsistent), got %+v", findings)
	}
}

func TestCheckKeyConsistency_SuspendedCASkipped(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("consistency-test-passphrase-32by"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := &saveFailsAfterStore{Store: NewMemStore(), allowSaves: 1}
	engine := NewEngine(noSnapshotKeys{keys}, store)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	if _, err := engine.RotateCA(root.ID, RotateCAOptions{}); err == nil || !errors.Is(err, ErrCARotationInconsistent) {
		t.Fatalf("expected RotateCA to fail with ErrCARotationInconsistent, got %v", err)
	}

	// Suspend the now-inconsistent CA directly in the underlying store
	// (bypassing UpdateCAStatus's cache write, which isn't the point here).
	stale, err := store.Load(root.ID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stale.Status = "suspended"
	if err := store.Store.Save(stale); err != nil {
		t.Fatalf("Save: %v", err)
	}

	findings, err := CheckKeyConsistency(keys, store)
	if err != nil {
		t.Fatalf("CheckKeyConsistency: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected a suspended CA to be skipped, got %+v", findings)
	}
}

// TestCheckKeyConsistency_MLDSADetectsDivergence is the ML-DSA twin of the
// G-78 crash-window test: it proves the ML-DSA path performs a REAL
// comparison of the two key encodings, not a "not comparable" skip that
// would hide a genuine divergence behind the no-false-positive guarantee.
func TestCheckKeyConsistency_MLDSADetectsDivergence(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("consistency-test-passphrase-32by"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := &saveFailsAfterStore{Store: NewMemStore(), allowSaves: 1}
	engine := NewEngine(noSnapshotKeys{keys}, store)

	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA (MLDSA65): %v", err)
	}
	if root.Certificate.PublicKey == nil {
		t.Skip("this toolchain's x509 does not parse an ML-DSA SPKI; the nil-guard test above covers it")
	}
	if _, err := engine.RotateCA(root.ID, RotateCAOptions{}); err == nil {
		t.Fatal("expected RotateCA to fail when the CA-store save is refused")
	}

	findings, err := CheckKeyConsistency(keys, store)
	if err != nil {
		t.Fatalf("CheckKeyConsistency: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding for a rotated-key/stale-cert ML-DSA CA, got %+v", findings)
	}
	if findings[0].CAID != root.ID {
		t.Fatalf("finding names the wrong CA: %+v", findings[0])
	}
}
