// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// RotateStep names a point in RotateCA where a failure rolls the rotation back.
type RotateStep string

const (
	StepGenerate    RotateStep = "generate"
	StepCertWrite   RotateStep = "cert_write"
	StepProbeVerify RotateStep = "probe_verify"
	StepSignerSwap  RotateStep = "signer_swap"
)

// RotationRolledBackError reports a rotation that failed at Step and was
// undone: the old key and certificate are active again. The bootstrap layer
// audits it as ca.rotate_key_rollback (internal/ca has no audit dependency).
type RotationRolledBackError struct {
	CAID  string
	Step  RotateStep
	Cause error
}

func (e *RotationRolledBackError) Error() string {
	return fmt.Sprintf("CA %s rotation failed at %s and was rolled back (old key still active): %v", e.CAID, e.Step, e.Cause)
}

func (e *RotationRolledBackError) Unwrap() error { return e.Cause }

// SetRotationFaultHook installs a test seam called at the start of each
// rotation step; a non-nil return forces that step to fail.
func (e *Engine) SetRotationFaultHook(h func(RotateStep) error) { e.rotateFault = h }

func (e *Engine) faultAt(step RotateStep) error {
	if e.rotateFault == nil {
		return nil
	}
	return e.rotateFault(step)
}

// OnRotate registers fn to run after a CA rotation takes effect (or is rolled
// back after the new key was briefly live), so CRL/OCSP caches drop responses
// signed by the other key. Register at startup, before serving.
func (e *Engine) OnRotate(fn func(caID string)) { e.onRotate = append(e.onRotate, fn) }

func (e *Engine) fireOnRotate(caID string) {
	for _, fn := range e.onRotate {
		fn(caID)
	}
}

// DefaultRetiredKeyGrace is how long a rotated-out key is kept before it
// becomes due for destruction.
const DefaultRetiredKeyGrace = 90 * 24 * time.Hour

// RetiredKeyGraceEnv overrides DefaultRetiredKeyGrace (a Go duration, e.g. "720h").
const RetiredKeyGraceEnv = "KRYPTKEEPER_CA_OLD_KEY_GRACE"

// RetiredKeyGraceFromEnv reads RetiredKeyGraceEnv; unset, invalid or
// non-positive values give the default.
func RetiredKeyGraceFromEnv() time.Duration {
	v := strings.TrimSpace(os.Getenv(RetiredKeyGraceEnv))
	if v == "" {
		return DefaultRetiredKeyGrace
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return DefaultRetiredKeyGrace
	}
	return d
}

// RetiredKeysDue lists ledger rotations whose retired key is past its grace
// period and still present in the keystore.
func (e *Engine) RetiredKeysDue(now time.Time, grace time.Duration) ([]KeyRotation, error) {
	cas, err := e.store.List()
	if err != nil {
		return nil, fmt.Errorf("list CAs: %w", err)
	}
	var due []KeyRotation
	for _, c := range cas {
		rots, err := e.store.ListKeyRotations(c.ID)
		if err != nil {
			return nil, fmt.Errorf("list rotations for %s: %w", c.ID, err)
		}
		for _, r := range rots {
			if r.OldKeyID == "" || now.Before(r.RotatedAt.Add(grace)) {
				continue
			}
			if _, err := e.keys.Metadata(r.OldKeyID); err != nil {
				continue // already destroyed
			}
			due = append(due, r)
		}
	}
	return due, nil
}

// RetireRotatedKeys hands every due retired key to destroy and returns the key
// ids it was called with. The engine never deletes a key itself: the caller
// supplies the destroy path so dual control stays in the bootstrap layer.
func (e *Engine) RetireRotatedKeys(now time.Time, grace time.Duration, destroy func(keyID string) error) ([]string, error) {
	due, err := e.RetiredKeysDue(now, grace)
	if err != nil {
		return nil, err
	}
	var done []string
	for _, r := range due {
		if err := destroy(r.OldKeyID); err != nil {
			return done, fmt.Errorf("destroy retired key %s: %w", r.OldKeyID, err)
		}
		done = append(done, r.OldKeyID)
	}
	return done, nil
}

// RetiredIssuer is a CA certificate a rotation retired whose key still exists.
type RetiredIssuer struct {
	CAID  string // the CA that was re-keyed (revocation records stay under it)
	Cert  *x509.Certificate
	KeyID string // the retired key's keystore reference
}

// RetiredIssuerSource is implemented by *Engine. OCSP uses it (W23-19) to
// answer a CertID that names the OLD issuer while that issuer's key exists:
// RFC 6960 requires the response to verify against the issuer the client
// named, and relying parties holding the old anchor name it.
type RetiredIssuerSource interface {
	RetiredIssuers() ([]RetiredIssuer, error)
}

// RetiredIssuers lists rotated-out CA certificates from the ledger (the
// database, so every replica sees the same set) whose retired key is still in
// the keystore. Once RetireRotatedKeys destroys the key the entry disappears.
// Ledger rows without a certificate (written before migration 000129) are
// skipped.
func (e *Engine) RetiredIssuers() ([]RetiredIssuer, error) {
	cas, err := e.store.List()
	if err != nil {
		return nil, fmt.Errorf("list CAs: %w", err)
	}
	var out []RetiredIssuer
	for _, c := range cas {
		rots, err := e.store.ListKeyRotations(c.ID)
		if err != nil {
			return nil, fmt.Errorf("list rotations for %s: %w", c.ID, err)
		}
		for _, r := range rots {
			if r.OldKeyID == "" || len(r.OldCertPEM) == 0 {
				continue
			}
			block, _ := pem.Decode(r.OldCertPEM)
			if block == nil {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			if _, err := e.keys.Metadata(r.OldKeyID); err != nil {
				continue // destroyed
			}
			out = append(out, RetiredIssuer{CAID: c.ID, Cert: cert, KeyID: r.OldKeyID})
		}
	}
	return out, nil
}
