// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/crl"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/ocsp"
)

// W23-16: rotation rollback, retirement and signer swap.

var errForced = errors.New("forced failure")

func newRotEngine(t *testing.T) (*Engine, *keystore.SoftwareStore, Store) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("rollback-test-passphrase-32byte!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	store := NewMemStore()
	return NewEngine(keys, store), keys, store
}

func newRoot(t *testing.T, e *Engine, algo keystore.Algorithm) *CA {
	t.Helper()
	root, err := e.CreateRootCA("Root", pkix.Name{CommonName: "Rollback Root"}, algo, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertOldKeyActive(t *testing.T, e *Engine, keys keystore.Store, store Store, before *CA, oldRaw []byte) {
	t.Helper()
	got, err := e.GetCA(before.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Certificate.Raw, oldRaw) {
		t.Fatal("CA certificate changed despite rollback")
	}
	stored, err := store.Load(before.ID)
	if err != nil || !bytes.Equal(stored.Certificate.Raw, oldRaw) {
		t.Fatalf("stored CA certificate changed despite rollback: %v", err)
	}
	pub, err := keys.PublicKey(before.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if eq, ok := publicKeysEqual(pub, before.Certificate.PublicKey); !ok || !eq {
		t.Fatal("keystore key is not the pre-rotation key after rollback")
	}
	if rots, _ := store.ListKeyRotations(before.ID); len(rots) != 0 {
		t.Fatalf("a rolled-back rotation must leave no ledger row, got %d", len(rots))
	}
	all, _ := keys.List()
	for _, m := range all {
		if strings.Contains(m.ID, "-retired-") {
			t.Fatalf("retired copy %s left behind after rollback", m.ID)
		}
	}
	// The old key still issues, and the leaf verifies against the OLD certificate.
	leaf := issueTestLeaf(t, e, before.ID)
	roots := x509.NewCertPool()
	roots.AddCert(before.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("leaf after rollback does not verify against the old certificate: %v", err)
	}
}

func TestRotateCA_RollbackAtEachStep(t *testing.T) {
	for _, step := range []RotateStep{StepGenerate, StepCertWrite, StepProbeVerify, StepSignerSwap} {
		for _, cross := range []bool{false, true} {
			name := string(step)
			if cross {
				name += "/cross-sign"
			}
			t.Run(name, func(t *testing.T) {
				e, keys, store := newRotEngine(t)
				root := newRoot(t, e, keystore.ECDSAP256)
				oldRaw := append([]byte(nil), root.Certificate.Raw...)
				e.SetRotationFaultHook(func(s RotateStep) error {
					if s == step {
						return errForced
					}
					return nil
				})
				var err error
				if cross {
					_, err = e.CrossSignRotate(root.ID, RotateCAOptions{})
				} else {
					_, err = e.RotateCA(root.ID, RotateCAOptions{})
				}
				var rb *RotationRolledBackError
				if !errors.As(err, &rb) || rb.Step != step || rb.CAID != root.ID {
					t.Fatalf("want *RotationRolledBackError at %s, got %v", step, err)
				}
				if !errors.Is(err, errForced) {
					t.Fatalf("cause must be wrapped: %v", err)
				}
				assertOldKeyActive(t, e, keys, store, root, oldRaw)
			})
		}
	}
}

func TestRotateCA_RollbackThenRetrySucceeds(t *testing.T) {
	e, keys, _ := newRotEngine(t)
	root := newRoot(t, e, keystore.ECDSAP256)
	fail := true
	e.SetRotationFaultHook(func(s RotateStep) error {
		if fail && s == StepProbeVerify {
			return errForced
		}
		return nil
	})
	if _, err := e.RotateCA(root.ID, RotateCAOptions{}); err == nil {
		t.Fatal("first attempt must fail")
	}
	fail = false
	res, err := e.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	pub, _ := keys.PublicKey(root.KeyID)
	if eq, _ := publicKeysEqual(pub, res.CA.Certificate.PublicKey); !eq {
		t.Fatal("rotated CA certificate does not match the keystore key")
	}
}

// A real store failure at cert write now restores the old key instead of
// leaving the CA inconsistent.
func TestRotateCA_StoreFailureRollsBack(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("rollback-test-passphrase-32byte!"))
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	store := &saveFailsAfterStore{Store: NewMemStore(), allowSaves: 1}
	e := NewEngine(keys, store)
	root := newRoot(t, e, keystore.ECDSAP256)
	oldRaw := append([]byte(nil), root.Certificate.Raw...)
	_, err = e.RotateCA(root.ID, RotateCAOptions{})
	var rb *RotationRolledBackError
	if !errors.As(err, &rb) || rb.Step != StepCertWrite || !errors.Is(err, errSimulatedSaveFailure) {
		t.Fatalf("want cert_write rollback, got %v", err)
	}
	if findings, _ := CheckKeyConsistency(keys, store.Store); len(findings) != 0 {
		t.Fatalf("rolled-back CA must be consistent, got %+v", findings)
	}
	got, _ := e.GetCA(root.ID)
	if !bytes.Equal(got.Certificate.Raw, oldRaw) {
		t.Fatal("certificate changed")
	}
}

type importFails struct{ keystore.Store }

func (importFails) ImportEncryptedKey(string, []byte, []byte) error {
	return errors.New("import refused")
}

func TestRotateCA_RollbackFailureIsInconsistent(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("rollback-test-passphrase-32byte!"))
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	e := NewEngine(importFails{keys}, NewMemStore())
	root := newRoot(t, e, keystore.ECDSAP256)
	e.SetRotationFaultHook(func(s RotateStep) error {
		if s == StepProbeVerify {
			return errForced
		}
		return nil
	})
	_, err = e.RotateCA(root.ID, RotateCAOptions{})
	if !errors.Is(err, ErrCARotationInconsistent) || !strings.Contains(err.Error(), "DR_RUNBOOK") {
		t.Fatalf("want ErrCARotationInconsistent, got %v", err)
	}
}

func TestRotateCA_MLDSARotationPassesProbe(t *testing.T) {
	e, keys, _ := newRotEngine(t)
	root := newRoot(t, e, keystore.MLDSA65)
	res, err := e.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatalf("ML-DSA rotation must pass the probe step: %v", err)
	}
	if findings, _ := CheckKeyConsistency(keys, e.store); len(findings) != 0 {
		t.Fatalf("inconsistent after ML-DSA rotation: %+v", findings)
	}
	_ = res
}

// crlOCSPFixture wires a CRL generator and OCSP responder to the engine the
// way cmd/kryptkeeper does.
func crlOCSPFixture(e *Engine, keys keystore.Store, wire bool) (*crl.Generator, *ocsp.Responder) {
	lookup := func(caID string) (*x509.Certificate, crypto.Signer, error) {
		c, err := e.GetCA(caID)
		if err != nil {
			return nil, nil, err
		}
		s, err := keys.Signer(c.KeyID)
		return c.Certificate, s, err
	}
	gen := crl.NewGenerator(func(string) ([]crl.RevokedCert, error) {
		return []crl.RevokedCert{{SerialNumber: big.NewInt(42), RevokedAt: time.Now(), ReasonCode: 1}}, nil
	}, lookup, time.Hour)
	resp := ocsp.NewResponder(
		func(*big.Int, *x509.Certificate) (bool, time.Time, int, error) { return false, time.Time{}, 0, nil },
		func([]byte) (*x509.Certificate, crypto.Signer, error) {
			cas, _ := e.ListCAs()
			c := cas[0]
			s, err := keys.Signer(c.KeyID)
			return c.Certificate, s, err
		}, time.Hour, 100)
	if wire {
		e.OnRotate(func(caID string) { gen.InvalidateCA(caID); resp.InvalidateAll() })
	}
	return gen, resp
}

func ocspStatus(t *testing.T, resp *ocsp.Responder, leaf, issuer *x509.Certificate) (*goocsp.Response, error) {
	t.Helper()
	reqDER, err := goocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	resp.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER)))
	return goocsp.ParseResponseForCert(rec.Body.Bytes(), leaf, issuer)
}

func TestRotation_SwapsCRLAndOCSPSigner(t *testing.T) {
	start := time.Now()
	e, keys, _ := newRotEngine(t)
	gen, resp := crlOCSPFixture(e, keys, true)
	root := newRoot(t, e, keystore.ECDSAP256)
	oldCert := root.Certificate
	leaf := issueTestLeaf(t, e, root.ID)

	oldCRL, err := gen.Generate(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := ocspStatus(t, resp, leaf, oldCert); err != nil || r.Status != goocsp.Good {
		t.Fatalf("pre-rotation OCSP: %v", err)
	}

	res, err := e.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	newCert := res.CA.Certificate

	if gen.GetCRL(root.ID) != nil {
		t.Fatal("CRL cache must be dropped on rotation")
	}
	fresh, err := gen.Generate(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Number.Cmp(oldCRL.Number) <= 0 {
		t.Fatalf("CRL number must stay monotonic across the swap: %v -> %v", oldCRL.Number, fresh.Number)
	}
	list, err := x509.ParseRevocationList(fresh.DER)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.CheckSignatureFrom(newCert); err != nil {
		t.Fatalf("CRL after rotation must verify against the new key: %v", err)
	}
	if err := list.CheckSignatureFrom(oldCert); err == nil {
		t.Fatal("CRL after rotation verified against the OLD key: signer was not swapped")
	}
	if r, err := ocspStatus(t, resp, leaf, newCert); err != nil || r.Status != goocsp.Good {
		t.Fatalf("OCSP after rotation must verify against the new key: %v", err)
	}
	if time.Since(start) > time.Minute {
		t.Fatal("signer swap must complete within 60s")
	}
}

// Negative control: without the OnRotate wiring the cache serves a CRL signed
// by the retired key, which the new certificate does not verify.
func TestRotation_WithoutInvalidationServesStaleCRL(t *testing.T) {
	e, keys, _ := newRotEngine(t)
	gen, _ := crlOCSPFixture(e, keys, false)
	root := newRoot(t, e, keystore.ECDSAP256)
	if _, err := gen.Generate(root.ID); err != nil {
		t.Fatal(err)
	}
	res, err := e.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stale := gen.GetCRL(root.ID)
	if stale == nil {
		t.Fatal("expected the stale cached CRL")
	}
	list, _ := x509.ParseRevocationList(stale.DER)
	if err := list.CheckSignatureFrom(res.CA.Certificate); err == nil {
		t.Fatal("stale CRL unexpectedly verifies against the new key")
	}
}

func TestRetireRotatedKeys_GraceWithInjectedClock(t *testing.T) {
	e, keys, _ := newRotEngine(t)
	root := newRoot(t, e, keystore.ECDSAP256)
	res, err := e.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rotatedAt := res.Rotation.RotatedAt
	grace := DefaultRetiredKeyGrace
	var destroyed []string
	destroy := func(id string) error { destroyed = append(destroyed, id); return keys.Delete(id) }

	if done, err := e.RetireRotatedKeys(rotatedAt.Add(89*24*time.Hour), grace, destroy); err != nil || len(done) != 0 || len(destroyed) != 0 {
		t.Fatalf("day 89 must destroy nothing: %v %v", done, err)
	}
	if _, err := keys.Signer(res.OldKeyID); err != nil {
		t.Fatalf("retired key must still resolve inside the grace period: %v", err)
	}
	done, err := e.RetireRotatedKeys(rotatedAt.Add(91*24*time.Hour), grace, destroy)
	if err != nil || len(done) != 1 || done[0] != res.OldKeyID {
		t.Fatalf("day 91 must destroy exactly the old key once: %v %v", done, err)
	}
	if _, err := keys.Signer(res.OldKeyID); err == nil {
		t.Fatal("retired key must be gone after the destroy path ran")
	}
	if done, _ := e.RetireRotatedKeys(rotatedAt.Add(92*24*time.Hour), grace, destroy); len(done) != 0 {
		t.Fatalf("an already destroyed key must not be offered again: %v", done)
	}
}

func TestRetiredKeyNeverSignsNewLeaves(t *testing.T) {
	e, _, _ := newRotEngine(t)
	root := newRoot(t, e, keystore.ECDSAP256)
	res, err := e.RotateCA(root.ID, RotateCAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueTestLeaf(t, e, root.ID)
	if !bytes.Equal(leaf.AuthorityKeyId, res.CA.Certificate.SubjectKeyId) {
		t.Fatal("leaf issued after rotation is not bound to the new CA key")
	}
	if bytes.Equal(leaf.AuthorityKeyId, root.Certificate.SubjectKeyId) {
		t.Fatal("leaf issued after rotation names the retired key")
	}
}

func TestRetiredKeyGraceFromEnv(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": DefaultRetiredKeyGrace, "720h": 720 * time.Hour, "garbage": DefaultRetiredKeyGrace,
		"0s": DefaultRetiredKeyGrace, "-5h": DefaultRetiredKeyGrace,
	} {
		t.Setenv(RetiredKeyGraceEnv, in)
		if got := RetiredKeyGraceFromEnv(); got != want {
			t.Errorf("%q -> %v, want %v", in, got, want)
		}
	}
	if DefaultRetiredKeyGrace != 90*24*time.Hour {
		t.Fatal("default grace must be 90d")
	}
}

func TestReconcileRotationCrash_RepairsInterruptedRotation(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("rollback-test-passphrase-32byte!"))
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	store := NewMemStore()
	// A backend that cannot export has no snapshot, so no rollback: the
	// failure leaves the crash-window state a real process death would.
	e := NewEngine(noSnapshotKeys{keys}, store)
	root := newRoot(t, e, keystore.ECDSAP256)
	e.SetRotationFaultHook(func(s RotateStep) error {
		if s == StepCertWrite {
			return errors.New("simulated crash")
		}
		return nil
	})
	if _, err := e.RotateCA(root.ID, RotateCAOptions{}); !errors.Is(err, ErrCARotationInconsistent) {
		t.Fatalf("want inconsistent, got %v", err)
	}
	if f, _ := CheckKeyConsistency(keys, store); len(f) != 1 {
		t.Fatalf("crash must be detected, got %+v", f)
	}
	found, err := ReconcileRotationCrash(keys, store)
	if err != nil || len(found) != 1 || found[0].RetiredKeyID == "" {
		t.Fatalf("crash-window CA must be reported as repairable: %+v %v", found, err)
	}

	// A restart: fresh engine, no fault hook.
	e2 := NewEngine(noSnapshotKeys{keys}, store)
	if err := e2.RepairRotationCrash(root.ID); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if f, _ := CheckKeyConsistency(keys, store); len(f) != 0 {
		t.Fatalf("repair must clear the finding, got %+v", f)
	}
	repaired, _ := e2.GetCA(root.ID)
	leaf := issueTestLeaf(t, e2, root.ID)
	roots := x509.NewCertPool()
	roots.AddCert(repaired.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("leaf from the repaired CA must verify: %v", err)
	}
	if rots, _ := store.ListKeyRotations(root.ID); len(rots) != 1 {
		t.Fatalf("repair must record the rotation, got %d rows", len(rots))
	}
	// Repair refuses a healthy CA.
	if err := e2.RepairRotationCrash(root.ID); err == nil {
		t.Fatal("repairing a consistent CA must be refused")
	}
}

func TestReconcileRotationCrash_IgnoresUnrelatedDivergence(t *testing.T) {
	e, keys, store := newRotEngine(t)
	root := newRoot(t, e, keystore.ECDSAP256)
	// Replace the key with no retired sibling: manual DR, not repairable.
	if err := keys.Delete(root.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.GenerateKey(root.KeyID, keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	if found, _ := ReconcileRotationCrash(keys, store); len(found) != 0 {
		t.Fatalf("must not claim a repair path: %+v", found)
	}
	if err := e.RepairRotationCrash(root.ID); err == nil {
		t.Fatal("repair must refuse divergence that is not an interrupted rotation")
	}
}
