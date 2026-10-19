// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// KeyConsistencyFinding describes an active CA whose keystore key no longer
// matches the public key embedded in its recorded certificate.
type KeyConsistencyFinding struct {
	CAID   string
	CAName string
	KeyID  string
	Detail string
	// Missing is true when the keystore could not produce the CA's public key
	// at all (as opposed to producing a different one). The usual cause is a
	// moved/unmounted keystore directory, and it makes the CA unable to sign.
	Missing bool
	// RetiredKeyID is set when the divergence matches an interrupted
	// rotation: the CA's recorded certificate carries the public key of this
	// retired sibling, so the keystore holds the NEW key and only the
	// certificate write was lost. Such a CA is repairable (RepairRotationCrash).
	RetiredKeyID string
}

// CheckKeyConsistency compares, for every active CA, the public key
// currently held by the keystore under ca.KeyID against the public key
// embedded in ca.Certificate. A mismatch means keystore.Store.RotateKey (an
// irreversible mutation) committed during a prior RotateCA call but the
// re-issued certificate never got persisted to the CA store -- most likely
// because the process crashed in that exact window, before any Go error
// handling could run. See ErrCARotationInconsistent's doc comment for the
// in-process failure case this closes the remaining gap on (G-78).
//
// CAs whose certificate's public key type cannot be compared (an
// unrecognized SPKI algorithm, or a type this function doesn't know how to
// read) are skipped rather than reported -- that is a coverage gap, not a
// detected divergence, and asserting a finding neither side can verify
// would be its own false signal.
func CheckKeyConsistency(keys keystore.Store, store Store) ([]KeyConsistencyFinding, error) {
	cas, err := store.List()
	if err != nil {
		return nil, fmt.Errorf("list CAs for key-consistency check: %w", err)
	}

	var findings []KeyConsistencyFinding
	for _, c := range cas {
		if c.Status != "active" || c.Certificate == nil || c.KeyID == "" {
			continue
		}

		keystorePub, err := keys.PublicKey(c.KeyID)
		if err != nil {
			findings = append(findings, KeyConsistencyFinding{
				CAID:    c.ID,
				CAName:  c.Name,
				KeyID:   c.KeyID,
				Detail:  fmt.Sprintf("keystore has no public key for %s: %v", c.KeyID, err),
				Missing: true,
			})
			continue
		}

		match, comparable := publicKeysEqual(keystorePub, c.Certificate.PublicKey)
		if !comparable {
			// Not a finding -- a coverage gap, not a detected divergence. This
			// used to be the normal case for a pure ML-DSA CA (pre-1.27 x509
			// left its PublicKey nil); it is now reserved for a certificate
			// whose key type publicKeysEqual has no encoding for. Logged for
			// visibility, not as an alarm.
			logging.Warnf("CA key-consistency check: cannot verify CA %s (%q) -- certificate public key type is not comparable (keystore key %s); manual verification needed if a rotation on this CA was recently interrupted", c.ID, c.Name, c.KeyID)
			continue
		}
		if !match {
			findings = append(findings, KeyConsistencyFinding{
				CAID:   c.ID,
				CAName: c.Name,
				KeyID:  c.KeyID,
				Detail: fmt.Sprintf("keystore key %s no longer matches the public key embedded in CA %s's recorded certificate", c.KeyID, c.ID),
			})
		}
	}
	return findings, nil
}

// publicKeysEqual reports whether a and b are the same public key
// (equal=true/false), and whether the comparison was possible at all
// (comparable=false means "couldn't tell", not "different").
//
// b (the certificate's embedded public key) is checked for nil FIRST and
// unconditionally treated as not-comparable, before any type-specific
// comparison runs. This matters because some crypto.PublicKey
// implementations (e.g. circl's ML-DSA PublicKey.Equal) satisfy an
// Equal(crypto.PublicKey) bool interface that returns a bare `false` -- not
// an error -- for a nil or differently-typed argument, which would
// otherwise look identical to a genuine mismatch.
//
// ML-DSA is compared by its FIPS 204 public-key encoding rather than by
// type, because the two sides come from different libraries: the keystore
// holds a circl key (MarshalBinary), while the certificate's key is
// whatever x509 parsed -- nil before Go 1.27, and a stdlib crypto/mldsa
// *PublicKey (Bytes) from 1.27 on. Both produce the same rho||t1 bytes, so
// the raw encoding is the one representation they share. The stdlib type
// is matched structurally rather than by name so this builds on the go.mod
// floor without importing crypto/mldsa.
func publicKeysEqual(a, b crypto.PublicKey) (equal bool, comparable bool) {
	if b == nil {
		return false, false
	}
	if am, ok := a.(keystore.MLDSAPublicKey); ok {
		ab, err := am.MarshalBinary()
		if err != nil {
			return false, false
		}
		bb, ok := mldsaEncoding(b)
		if !ok {
			return false, false
		}
		return bytes.Equal(ab, bb), true
	}
	type equaler interface {
		Equal(x crypto.PublicKey) bool
	}
	if ae, ok := a.(equaler); ok {
		return ae.Equal(b), true
	}
	return false, false
}

// mldsaEncoding returns the FIPS 204 public-key encoding of an ML-DSA key
// held as either a circl key or a stdlib crypto/mldsa key.
func mldsaEncoding(k crypto.PublicKey) ([]byte, bool) {
	switch v := k.(type) {
	case keystore.MLDSAPublicKey:
		b, err := v.MarshalBinary()
		return b, err == nil
	case interface{ Bytes() []byte }:
		return v.Bytes(), true
	}
	return nil, false
}

// LogKeyConsistencyFindings logs each finding loudly at startup, pointing at
// the DR runbook, rather than letting the hub silently issue certificates
// under a CA whose keystore key no longer matches its recorded certificate.
func LogKeyConsistencyFindings(findings []KeyConsistencyFinding) {
	for _, f := range findings {
		logging.Infof(
			"CA KEY INCONSISTENCY: CA %s (%q) keystore key %s: %s -- do NOT rotate or issue from this CA; "+
				"recover it from a pre-rotation backup via the DR procedure (docs/ops/DR_RUNBOOK.md)",
			f.CAID, f.CAName, f.KeyID, f.Detail,
		)
	}
}

// AllowMissingCAKeysEnv is the explicit opt-out for StartupKeyCheckDecision.
const AllowMissingCAKeysEnv = "KRYPTKEEPER_ALLOW_MISSING_CA_KEYS"

// StartupKeyCheckDecision decides whether boot may continue given the key
// consistency findings. A CA whose key is missing from the keystore cannot
// sign: issuance returns 503 and CRL/OCSP come back empty, while the hub
// looks healthy. That is almost always an operator error (KEYSTORE_DIR or
// DATA_DIR changed, volume not mounted, wrong passphrase), so it is fatal
// unless allowMissing is set for a deliberate recovery. A key that is present
// but no longer matches the certificate (interrupted rotation) stays a loud
// log line handled by LogKeyConsistencyFindings, not a boot veto. It also
// covers the check itself failing (checkErr). A check that could not run proves nothing about
// the keys, so booting on it would fail open; it is fatal unless allowMissing.
func StartupKeyCheckDecision(findings []KeyConsistencyFinding, checkErr error, allowMissing bool) error {
	if checkErr != nil {
		if allowMissing {
			logging.Warnf("CA key-consistency check failed to run (continuing: %s=true): %v", AllowMissingCAKeysEnv, checkErr)
			return nil
		}
		return fmt.Errorf("refusing to start: CA key-consistency check failed to run: %w. "+
			"Fix the keystore/CA store access, or set %s=true to start anyway for recovery", checkErr, AllowMissingCAKeysEnv)
	}
	var missing []KeyConsistencyFinding
	for _, f := range findings {
		if f.Missing {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 || allowMissing {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to start: %d active CA(s) have no usable key in the keystore:", len(missing))
	for _, f := range missing {
		fmt.Fprintf(&b, "\n  - CA %s (%q) key id %s: %s", f.CAID, f.CAName, f.KeyID, f.Detail)
	}
	fmt.Fprintf(&b, "\nLikely cause: KRYPTKEEPER_KEYSTORE_DIR (or KRYPTKEEPER_DATA_DIR) changed or the keystore volume is not mounted, "+
		"or KRYPTKEEPER_KEYSTORE_PASSPHRASE is wrong. Point the hub back at the directory that holds these key ids. "+
		"To start anyway for recovery (issuance, CRL and OCSP for these CAs will not work), set %s=true.", AllowMissingCAKeysEnv)
	return errors.New(b.String())
}

// ReconcileRotationCrash narrows CheckKeyConsistency to the crash window
// RotateCA cannot undo (the process died between keystore.RotateKey and the
// certificate write): active CAs whose recorded certificate carries the public
// key of a "<KeyID>-retired-*" sibling in the keystore. Findings that do not
// match that pattern stay manual DR cases and are not returned.
func ReconcileRotationCrash(keys keystore.Store, store Store) ([]KeyConsistencyFinding, error) {
	findings, err := CheckKeyConsistency(keys, store)
	if err != nil {
		return nil, err
	}
	var out []KeyConsistencyFinding
	for _, f := range findings {
		if f.Missing {
			continue
		}
		c, err := store.Load(f.CAID)
		if err != nil {
			return nil, fmt.Errorf("load CA %s: %w", f.CAID, err)
		}
		retired, err := retiredSiblingMatching(keys, c)
		if err != nil {
			return nil, err
		}
		if retired == "" {
			continue
		}
		f.RetiredKeyID = retired
		f.Detail += fmt.Sprintf("; the recorded certificate matches retired key %s, so the rotation was interrupted before the certificate write (repair re-issues the CA certificate under the current key)", retired)
		out = append(out, f)
	}
	return out, nil
}

// retiredSiblingMatching returns the "<KeyID>-retired-*" key whose public key
// equals the one in c's certificate, or "".
func retiredSiblingMatching(keys keystore.Store, c *CA) (string, error) {
	all, err := keys.List()
	if err != nil {
		return "", fmt.Errorf("list keys: %w", err)
	}
	prefix := c.KeyID + "-retired-"
	for _, m := range all {
		if !strings.HasPrefix(m.ID, prefix) {
			continue
		}
		pub, err := keys.PublicKey(m.ID)
		if err != nil {
			continue
		}
		if eq, comparable := publicKeysEqual(pub, c.Certificate.PublicKey); comparable && eq {
			return m.ID, nil
		}
	}
	return "", nil
}

// RepairRotationCrash completes a rotation that was interrupted after the key
// swap: it re-issues the CA certificate under the key the keystore now holds,
// proves it with a probe leaf and records the ledger entry. It refuses any CA
// that does not show the crash-window pattern, so it cannot paper over other
// divergence.
func (e *Engine) RepairRotationCrash(caID string) error {
	e.mu.Lock()
	err := e.repairRotationCrashLocked(caID)
	e.mu.Unlock()
	if err == nil {
		e.fireOnRotate(caID)
	}
	return err
}

func (e *Engine) repairRotationCrashLocked(caID string) error {
	target, ok := e.get(caID)
	if !ok {
		return ErrCANotFound
	}
	if target.Certificate == nil || target.KeyID == "" {
		return fmt.Errorf("CA %s has no certificate or key on record", caID)
	}
	pub, err := e.keys.PublicKey(target.KeyID)
	if err != nil {
		return fmt.Errorf("keystore key for CA %s: %w", caID, err)
	}
	if eq, comparable := publicKeysEqual(pub, target.Certificate.PublicKey); !comparable || eq {
		return fmt.Errorf("CA %s is not divergent; nothing to repair", caID)
	}
	retired, err := retiredSiblingMatching(e.keys, target)
	if err != nil {
		return err
	}
	if retired == "" {
		return fmt.Errorf("CA %s diverges but matches no retired key: not an interrupted rotation, recover via docs/ops/DR_RUNBOOK.md", caID)
	}
	meta, err := e.keys.Metadata(target.KeyID)
	if err != nil {
		return err
	}
	signer, err := e.keys.Signer(target.KeyID)
	if err != nil {
		return err
	}
	cert, certPEM, err := e.buildRotatedCert(target, meta.Algorithm, signer)
	if err != nil {
		return err
	}
	updated := *target
	updated.Certificate = cert
	updated.CertPEM = certPEM
	if err := e.saveCA(&updated); err != nil {
		return fmt.Errorf("persist repaired CA record: %w", err)
	}
	if err := e.verifyProbeLocked(&updated); err != nil {
		// Put the old record back: the CA is no worse off than before.
		if rerr := e.saveCA(target); rerr != nil {
			logging.Warnf("CA %s: restoring the pre-repair record failed: %v", caID, rerr)
		}
		return fmt.Errorf("repaired certificate failed its probe: %w", err)
	}
	return e.store.RecordKeyRotation(KeyRotation{
		ID: newCAID(), CAID: caID, OldKeyID: retired, NewKeyID: target.KeyID,
		NewCertSN: cert.SerialNumber.String(), Method: "rekey_reissue", RotatedAt: time.Now().UTC(),
		OldCertPEM: target.CertPEM, // the record still holds the certificate the retired key signed
	})
}
