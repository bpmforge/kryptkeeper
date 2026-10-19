// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"kryptkeeper/internal/keystore"
)

// RotateCAOptions configures RotateCA. Algorithm is optional -- when empty,
// the new key is generated with the same algorithm as the CA's current key.
type RotateCAOptions struct {
	Algorithm keystore.Algorithm

	// afterProbe runs inside the probe-verify step, so a failure rolls the
	// rotation back (CrossSignRotate builds and checks its bridge here).
	afterProbe func(rotated *CA, retiredKeyID string) error
}

// RotateCAResult describes the outcome of a RotateCA call. CA is non-nil as
// soon as the re-issued certificate has been persisted -- including the
// ledger-write-failure case, where err is non-nil but the rotation itself
// fully succeeded (see the RecordKeyRotation handling below). CA is nil
// only when rotation failed before reaching that point.
type RotateCAResult struct {
	CA       *CA
	OldKeyID string // the retired key's on-disk reference (keystore.KeyRotateResult.PreviousID)
	NewKeyID string // unchanged from before rotation -- keystore.RotateKey replaces the key
	// material in place under the same ID, so the CA record's KeyID field
	// never needs to change.
	Rotation KeyRotation
}

// ErrCARotationInconsistent wraps any error that occurs AFTER
// keystore.Store.RotateKey has already mutated the keystore (retiring the
// old key, generating a new one under the same ID) but BEFORE the
// re-issued certificate has been persisted to the CA store. That mutation
// is irreversible through this API -- a failure in this window (a failed
// signer load, certificate build, or CA-store write; the disk-full
// condition hit elsewhere in this project is a real example of the last
// one) leaves the keystore holding the new key while the CA store still
// records the OLD certificate, embedding the OLD public key/SKI --
// precisely the G-35 footgun this ticket exists to prevent, now reachable
// through partial failure of the fix itself.
//
// There is no atomic multi-system transaction available here (the
// keystore is files, the CA store is a SQL database, and RotateKey has no
// "generate but don't commit" primitive), so this cannot be prevented
// outright -- it is caught and reported loudly instead of failing
// silently. The narrower crash-window case (the process dies between
// RotateKey and the CA-store write, so no Go error handling runs at all)
// is NOT caught by this; see G-78 for the boot-time reconciliation check
// that closes that gap.
var ErrCARotationInconsistent = errors.New("ca rotation left the CA store and keystore inconsistent")

// RotateCA re-keys a CA in place: generates a new key under the CA's
// existing keystore ID (retiring, not deleting, the old key -- see
// keystore.Store.RotateKey), re-issues the CA's own certificate under the
// new public key (self-signed for a root, parent-signed for an
// intermediate), and records the event in the ca_key_rotations ledger.
//
// W6-07 (cross-signing) has not landed as of this ticket -- there is no
// overlap chain between the old and new CA certificate. Relying parties
// that pinned or distributed the OLD CA certificate will need to be updated
// out-of-band; this is inherent to re-key-without-cross-sign; see the
// ticket notes for why this scope was chosen over blocking on W6-07.
func (e *Engine) RotateCA(caID string, opts RotateCAOptions) (RotateCAResult, error) {
	res, notify, err := e.rotateCA(caID, opts)
	if notify {
		// After unlock: callbacks may call back into the engine.
		e.fireOnRotate(caID)
	}
	return res, err
}

// rotateCA does the work under e.mu. notify is true when CRL/OCSP signer
// caches must be dropped: the rotation took effect, or it was rolled back
// after a window in which the new key was live.
func (e *Engine) rotateCA(caID string, opts RotateCAOptions) (res RotateCAResult, notify bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	target, ok := e.get(caID)
	if !ok {
		return RotateCAResult{}, false, ErrCANotFound
	}
	if target.Status != "active" {
		return RotateCAResult{}, false, fmt.Errorf("CA %s is not active (status=%s)", caID, target.Status)
	}
	if target.Certificate == nil {
		return RotateCAResult{}, false, fmt.Errorf("CA %s has no certificate on record", caID)
	}

	algo := opts.Algorithm
	if algo == "" {
		meta, err := e.keys.Metadata(target.KeyID)
		if err != nil {
			return RotateCAResult{}, false, fmt.Errorf("look up current key algorithm: %w", err)
		}
		algo = meta.Algorithm
	}

	// Snapshot the outgoing key so any later failure can restore it. The
	// blob never leaves this function and the passphrase is random and
	// in-memory only. A backend that refuses export (HSM/KMS) yields no
	// snapshot, and failures then stay ErrCARotationInconsistent.
	oldRec := *target
	pass := make([]byte, 32)
	if _, rerr := rand.Read(pass); rerr != nil {
		return RotateCAResult{}, false, fmt.Errorf("rotation snapshot: %w", rerr)
	}
	blob, exportErr := e.keys.ExportEncryptedKey(target.KeyID, pass)
	if exportErr != nil {
		blob = nil
	}
	defer func() {
		for i := range pass {
			pass[i] = 0
		}
	}()

	if herr := e.faultAt(StepGenerate); herr != nil {
		return RotateCAResult{}, true, &RotationRolledBackError{CAID: caID, Step: StepGenerate, Cause: herr}
	}
	// keystore.RotateKey itself refuses hybrid algorithms today ("hybrid key
	// rotation not yet supported") -- that error surfaces here unmodified
	// rather than being duplicated. It mutates nothing when it fails.
	rotateResult, err := e.keys.RotateKey(target.KeyID, algo)
	if err != nil {
		return RotateCAResult{}, false, &RotationRolledBackError{CAID: caID, Step: StepGenerate, Cause: fmt.Errorf("rotate key: %w", err)}
	}

	// From here on, keys.RotateKey has ALREADY mutated the keystore. Every
	// failure restores the old key (rollback) or, when it cannot, reports
	// ErrCARotationInconsistent so the operator goes to the DR runbook
	// instead of retrying.
	storeUpdated := false
	fail := func(step RotateStep, what string, cause error) (RotateCAResult, bool, error) {
		if blob == nil {
			return RotateCAResult{}, true, e.inconsistentRotation(caID, target.KeyID, rotateResult.PreviousID, what, cause)
		}
		if rerr := e.rollbackRotation(&oldRec, rotateResult.PreviousID, blob, pass, storeUpdated); rerr != nil {
			return RotateCAResult{}, true, e.inconsistentRotation(caID, target.KeyID, rotateResult.PreviousID, what,
				fmt.Errorf("%w (rollback also failed: %v)", cause, rerr))
		}
		return RotateCAResult{}, true, &RotationRolledBackError{CAID: caID, Step: step, Cause: cause}
	}

	if herr := e.faultAt(StepCertWrite); herr != nil {
		return fail(StepCertWrite, "writing the re-issued certificate", herr)
	}
	newSigner, err := e.keys.Signer(target.KeyID)
	if err != nil {
		return fail(StepCertWrite, "loading the signer for the rotated key", err)
	}
	cert, certPEM, err := e.buildRotatedCert(target, algo, newSigner)
	if err != nil {
		return fail(StepCertWrite, "re-issuing the CA certificate", err)
	}

	updated := *target
	updated.Certificate = cert
	updated.CertPEM = certPEM
	if err := e.saveCA(&updated); err != nil {
		return fail(StepCertWrite, "persisting the re-issued CA record", err)
	}
	storeUpdated = true

	if herr := e.faultAt(StepProbeVerify); herr != nil {
		return fail(StepProbeVerify, "verifying a probe leaf under the new key", herr)
	}
	if err := e.verifyProbeLocked(&updated); err != nil {
		return fail(StepProbeVerify, "verifying a probe leaf under the new key", err)
	}
	if opts.afterProbe != nil {
		if err := opts.afterProbe(&updated, rotateResult.PreviousID); err != nil {
			return fail(StepProbeVerify, "verifying the rollover chains", err)
		}
	}

	if herr := e.faultAt(StepSignerSwap); herr != nil {
		return fail(StepSignerSwap, "swapping the CRL/OCSP signers", herr)
	}

	// The ledger is append-only, so it is written only once nothing can
	// still be rolled back.
	rotation := KeyRotation{
		ID:        newCAID(),
		CAID:      target.ID,
		OldKeyID:  rotateResult.PreviousID,
		NewKeyID:  target.KeyID,
		NewCertSN: cert.SerialNumber.String(),
		Method:    "rekey_reissue",
		RotatedAt: time.Now().UTC(),
		// The outgoing certificate, kept so OCSP can still answer for leaves
		// it issued while the retired key exists (W23-19).
		OldCertPEM: oldRec.CertPEM,
	}
	res = RotateCAResult{CA: &updated, OldKeyID: rotateResult.PreviousID, NewKeyID: target.KeyID, Rotation: rotation}
	if err := e.store.RecordKeyRotation(rotation); err != nil {
		// The key rotation and cert re-issuance already succeeded and are
		// persisted -- a ledger-write failure must not be reported as if
		// the rotation itself failed (the caller would retry a rotation
		// that already happened, generating ANOTHER new key unnecessarily).
		// Surface it as a distinct, clearly-labeled partial-failure error.
		return res, true, fmt.Errorf("CA %s rotated successfully but the rotation ledger entry failed to persist: %w", caID, err)
	}
	return res, true, nil
}

// buildRotatedCert issues the CA's own certificate under the key currently
// held for it: self-signed for a root, parent-signed for an intermediate.
// Must be called with e.mu held. Re-key preserves the CA's ORIGINAL validity
// window LENGTH (not the original NotAfter): the new key gets a fresh full
// term starting now (a deliberate, disclosed choice).
func (e *Engine) buildRotatedCert(target *CA, algo keystore.Algorithm, newSigner crypto.Signer) (*x509.Certificate, []byte, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generating a serial number: %w", err)
	}
	ski, err := computeSKIAny(newSigner.Public(), algo)
	if err != nil {
		return nil, nil, fmt.Errorf("computing the subject key identifier: %w", err)
	}
	validityWindow := target.Certificate.NotAfter.Sub(target.Certificate.NotBefore)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               target.Certificate.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(validityWindow),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
	}

	var certDER []byte
	if target.Type == "root" {
		template.MaxPathLen = target.Certificate.MaxPathLen
		template.MaxPathLenZero = target.Certificate.MaxPathLenZero
		certDER, err = createCertDER(template, template, algo, newSigner.Public(), newSigner)
		if err != nil {
			return nil, nil, fmt.Errorf("re-issuing the root certificate: %w", err)
		}
	} else {
		parent, ok := e.get(target.ParentCAID)
		if !ok {
			return nil, nil, fmt.Errorf("parent CA %s not found", target.ParentCAID)
		}
		if parent.Status != "active" {
			return nil, nil, fmt.Errorf("parent CA %s is not active", parent.ID)
		}
		parentSigner, err := e.keys.Signer(parent.KeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("loading the parent CA's signer: %w", err)
		}
		parentMeta, err := e.keys.Metadata(parent.KeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("loading the parent CA's key metadata: %w", err)
		}
		if template.NotAfter.After(parent.Certificate.NotAfter) {
			template.NotAfter = parent.Certificate.NotAfter
		}
		template.AuthorityKeyId = parent.Certificate.SubjectKeyId
		template.MaxPathLen = target.Certificate.MaxPathLen
		template.MaxPathLenZero = target.Certificate.MaxPathLenZero
		certDER, err = createCertDER(template, parent.Certificate, parentMeta.Algorithm, newSigner.Public(), parentSigner)
		if err != nil {
			return nil, nil, fmt.Errorf("re-issuing the intermediate certificate: %w", err)
		}
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the re-issued certificate: %w", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// verifyProbeLocked proves the rotated CA signs a leaf that chains to its new
// certificate. Must be called with e.mu held and the new record saved.
func (e *Engine) verifyProbeLocked(ca *CA) error {
	probe, err := e.issueProbeLeafLocked(ca)
	if err != nil {
		return fmt.Errorf("issue probe leaf: %w", err)
	}
	meta, err := e.keys.Metadata(ca.KeyID)
	if err != nil {
		return err
	}
	if keystore.IsMLDSA(meta.Algorithm) {
		// The standard library does not verify ML-DSA certificate
		// signatures, so check the probe's signature against the CA key.
		pub, err := e.keys.PublicKey(ca.KeyID)
		if err != nil {
			return err
		}
		mp, ok := pub.(keystore.MLDSAPublicKey)
		if !ok || !verifyMLDSA(meta.Algorithm, mp, probe.RawTBSCertificate, probe.Signature) {
			return errors.New("probe leaf signature does not verify under the new CA key")
		}
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	if _, err := probe.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		return fmt.Errorf("probe leaf does not chain to the new CA certificate: %w", err)
	}
	return nil
}

// rollbackRotation restores the pre-rotation key (and CA record, if the new
// one was persisted) and discards the unreferenced new key and retired copy.
func (e *Engine) rollbackRotation(oldRec *CA, retiredID string, blob, pass []byte, storeUpdated bool) error {
	if err := e.keys.Delete(oldRec.KeyID); err != nil {
		return fmt.Errorf("remove new key: %w", err)
	}
	if err := e.keys.ImportEncryptedKey(oldRec.KeyID, blob, pass); err != nil {
		return fmt.Errorf("restore old key: %w", err)
	}
	if storeUpdated {
		if err := e.saveCA(oldRec); err != nil {
			return fmt.Errorf("restore CA record: %w", err)
		}
	}
	_ = e.keys.Delete(retiredID) // best effort: the restored key supersedes the retired copy
	return nil
}

func (e *Engine) inconsistentRotation(caID, keyID, retiredID, step string, err error) error {
	return fmt.Errorf(
		"%w: CA %s key was rotated (new key live under %s, old key retained on disk as %s) but %s failed: %w -- "+
			"do NOT retry this rotation (it would generate ANOTHER new key on top of an already-inconsistent CA); "+
			"inspect CA %s directly and, if its certificate no longer matches its keystore key, recover it from a "+
			"pre-rotation backup via the DR procedure (docs/ops/DR_RUNBOOK.md) rather than rotating again",
		ErrCARotationInconsistent, caID, keyID, retiredID, step, err, caID)
}

// KeyInUseByCA reports whether keyID currently backs any CA in caStore, and
// which one. Used by the raw keystore key-rotate endpoint
// (internal/bootstrap/handlers_keys.go) to refuse rotating a CA's key
// directly -- rotating it via keystore.Store.RotateKey alone would silently
// break the CA (its certificate would still embed the old public key/SKI,
// with nothing re-issuing it) -- callers must go through RotateCA instead.
func KeyInUseByCA(caStore Store, keyID string) (caID string, found bool, err error) {
	cas, err := caStore.List()
	if err != nil {
		return "", false, err
	}
	for _, c := range cas {
		if c.KeyID == keyID {
			return c.ID, true, nil
		}
	}
	return "", false, nil
}
