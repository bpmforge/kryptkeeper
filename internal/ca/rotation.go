// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
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
	e.mu.Lock()
	defer e.mu.Unlock()

	target, ok := e.get(caID)
	if !ok {
		return RotateCAResult{}, ErrCANotFound
	}
	if target.Status != "active" {
		return RotateCAResult{}, fmt.Errorf("CA %s is not active (status=%s)", caID, target.Status)
	}
	if target.Certificate == nil {
		return RotateCAResult{}, fmt.Errorf("CA %s has no certificate on record", caID)
	}

	algo := opts.Algorithm
	if algo == "" {
		meta, err := e.keys.Metadata(target.KeyID)
		if err != nil {
			return RotateCAResult{}, fmt.Errorf("look up current key algorithm: %w", err)
		}
		algo = meta.Algorithm
	}

	// keystore.RotateKey itself refuses hybrid algorithms today ("hybrid key
	// rotation not yet supported") -- that error surfaces here unmodified
	// rather than being duplicated.
	rotateResult, err := e.keys.RotateKey(target.KeyID, algo)
	if err != nil {
		return RotateCAResult{}, fmt.Errorf("rotate key: %w", err)
	}

	// From here on, keys.RotateKey has ALREADY mutated the keystore
	// irreversibly -- see ErrCARotationInconsistent's doc comment. Every
	// error return between here and the CA record being saved goes
	// through inconsistent() so the caller is told loudly, rather than
	// bare, that this CA may now need DR recovery instead of a retry.
	inconsistent := func(step string, err error) error {
		return fmt.Errorf(
			"%w: CA %s key was rotated (new key live under %s, old key retained on disk as %s) but %s failed: %w -- "+
				"do NOT retry this rotation (it would generate ANOTHER new key on top of an already-inconsistent CA); "+
				"inspect CA %s directly and, if its certificate no longer matches its keystore key, recover it from a "+
				"pre-rotation backup via the DR procedure (docs/ops/DR_RUNBOOK.md) rather than rotating again",
			ErrCARotationInconsistent, caID, target.KeyID, rotateResult.PreviousID, step, err, caID)
	}

	newSigner, err := e.keys.Signer(target.KeyID)
	if err != nil {
		return RotateCAResult{}, inconsistent("loading the signer for the rotated key", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return RotateCAResult{}, inconsistent("generating a serial number for the re-issued certificate", err)
	}

	ski, err := computeSKIAny(newSigner.Public(), algo)
	if err != nil {
		return RotateCAResult{}, inconsistent("computing the subject key identifier", err)
	}

	// Re-key preserves the CA's ORIGINAL validity window LENGTH (not the
	// original NotAfter): the new key gets a fresh full term starting now,
	// matching normal re-key practice (a re-key is typically performed to
	// replace an aging/compromised key with a fresh one, not to inherit
	// however little of the original term happened to remain). This is a
	// deliberate, disclosed choice -- see ticket notes.
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
			return RotateCAResult{}, inconsistent("re-issuing the root certificate", err)
		}
	} else {
		parent, ok := e.get(target.ParentCAID)
		if !ok {
			return RotateCAResult{}, inconsistent("re-issuing the intermediate certificate", fmt.Errorf("parent CA %s not found", target.ParentCAID))
		}
		if parent.Status != "active" {
			return RotateCAResult{}, inconsistent("re-issuing the intermediate certificate", fmt.Errorf("parent CA %s is not active", parent.ID))
		}
		parentSigner, err := e.keys.Signer(parent.KeyID)
		if err != nil {
			return RotateCAResult{}, inconsistent("loading the parent CA's signer", err)
		}
		parentMeta, err := e.keys.Metadata(parent.KeyID)
		if err != nil {
			return RotateCAResult{}, inconsistent("loading the parent CA's key metadata", err)
		}
		if template.NotAfter.After(parent.Certificate.NotAfter) {
			template.NotAfter = parent.Certificate.NotAfter
		}
		template.AuthorityKeyId = parent.Certificate.SubjectKeyId
		template.MaxPathLen = target.Certificate.MaxPathLen
		template.MaxPathLenZero = target.Certificate.MaxPathLenZero
		certDER, err = createCertDER(template, parent.Certificate, parentMeta.Algorithm, newSigner.Public(), parentSigner)
		if err != nil {
			return RotateCAResult{}, inconsistent("re-issuing the intermediate certificate", err)
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return RotateCAResult{}, inconsistent("parsing the re-issued certificate", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	updated := *target
	updated.Certificate = cert
	updated.CertPEM = certPEM
	if err := e.saveCA(&updated); err != nil {
		return RotateCAResult{}, inconsistent("persisting the re-issued CA record", err)
	}

	rotation := KeyRotation{
		ID:        newCAID(),
		CAID:      target.ID,
		OldKeyID:  rotateResult.PreviousID,
		NewKeyID:  target.KeyID,
		NewCertSN: cert.SerialNumber.String(),
		Method:    "rekey_reissue",
		RotatedAt: now,
	}
	if err := e.store.RecordKeyRotation(rotation); err != nil {
		// The key rotation and cert re-issuance already succeeded and are
		// persisted -- a ledger-write failure must not be reported as if
		// the rotation itself failed (the caller would retry a rotation
		// that already happened, generating ANOTHER new key unnecessarily).
		// Surface it as a distinct, clearly-labeled partial-failure error.
		return RotateCAResult{CA: &updated, OldKeyID: rotateResult.PreviousID, NewKeyID: target.KeyID, Rotation: rotation},
			fmt.Errorf("CA %s rotated successfully but the rotation ledger entry failed to persist: %w", caID, err)
	}

	return RotateCAResult{CA: &updated, OldKeyID: rotateResult.PreviousID, NewKeyID: target.KeyID, Rotation: rotation}, nil
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
