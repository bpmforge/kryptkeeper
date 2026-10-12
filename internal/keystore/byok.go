// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	kwp "github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// W15-04 (jurisdictional/BYOK): export an escrow-recovered CA key into a
// customer-controlled cloud KMS. This moves OUR OWN root across a custody
// boundary into the customer's HSM — no new custody is taken on — but it
// must never let plaintext survive outside the wrap, and every step is
// audited.
//
// Cloud KMS ImportKeyMaterial dictates the wire format: RSA_AES_KEY_WRAP_SHA_256
//   EncryptedKeyMaterial = RSAES-OAEP-SHA256(ephemeral AES-256 key)
//                        || AES-KWP(ephemeral key, key material)
// AES Key Wrap with Padding (RFC 5649 / NIST SP 800-38F KWP) is in neither
// the Go stdlib nor x/crypto, so the KWP primitive comes from Tink
// (github.com/tink-crypto/tink-go/v2/kwp/subtle, Apache-2.0); the outer
// RSA-OAEP wrap and the ephemeral key are stdlib. A GCM envelope — what we
// use for escrow at rest — is NOT importable; the KMS demands this exact
// format, which is why the primitive is required here.

// BYOKEvent is one step of a BYOK export. It carries who/what/when/outcome
// only — never key or custodian material.
type BYOKEvent struct {
	KeyID    string
	Provider string
	Step     string // byok.export | byok.params | byok.wrap | byok.import
	Outcome  string // success | denied | failure
	At       time.Time
}

// BYOKAudit sinks BYOK steps into the append-only audit trail.
type BYOKAudit interface {
	Record(ev BYOKEvent)
}

// KMSImportTarget is the injected per-cloud import boundary. AWS, Azure,
// and GCP each expose a get-parameters / import pair; the concrete
// adapters wrap their SDKs. Keeping it an interface lets the wrap format
// be tested against a KMS stand-in with no cloud.
type KMSImportTarget interface {
	// ImportParameters returns the KMS wrapping public key (DER-encoded
	// SubjectPublicKeyInfo) and the opaque import token, requested for
	// RSA_AES_KEY_WRAP_SHA_256.
	ImportParameters(ctx context.Context) (wrappingPublicKeyDER, importToken []byte, err error)
	// Import uploads the wrapped material under the import token.
	Import(ctx context.Context, encryptedKeyMaterial, importToken []byte) error
	Provider() string
	KeyID() string
}

func byokRecord(audit BYOKAudit, target KMSImportTarget, step, outcome string, now time.Time) {
	if audit == nil {
		return
	}
	audit.Record(BYOKEvent{KeyID: target.KeyID(), Provider: target.Provider(), Step: step, Outcome: outcome, At: now.UTC()})
}

// wrapForRSAAESKeyWrap builds the RSA_AES_KEY_WRAP_SHA_256 EncryptedKeyMaterial
// blob. The ephemeral AES key is zeroized before return on every path.
func wrapForRSAAESKeyWrap(keyMaterial, wrappingPublicKeyDER []byte) ([]byte, error) {
	pubAny, err := x509.ParsePKIXPublicKey(wrappingPublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("byok: parse KMS wrapping key: %w", err)
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("byok: KMS wrapping key is not RSA")
	}

	aesKey := make([]byte, 32) // AES-256 ephemeral
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("byok: ephemeral key: %w", err)
	}
	defer zeroizeBytes(aesKey)

	kw, err := kwp.NewKWP(aesKey)
	if err != nil {
		return nil, fmt.Errorf("byok: kwp init: %w", err)
	}
	wrappedMaterial, err := kw.Wrap(keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("byok: kwp wrap: %w", err)
	}
	wrappedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("byok: rsa-oaep wrap: %w", err)
	}
	return append(wrappedAESKey, wrappedMaterial...), nil
}

// ExportEscrowedKeyToKMS wraps escrow-recovered key material and imports
// it into the injected cloud KMS. It is dual-control gated (two differing
// custodian secrets — the same ceremony that recovered the material) and
// audits every step. The caller passes the recovered plaintext DER; this
// function guarantees it is zeroized on EVERY exit path, so plaintext
// never survives outside the wrap.
func ExportEscrowedKeyToKMS(ctx context.Context, target KMSImportTarget, audit BYOKAudit, keyMaterial, custodianA, custodianB []byte, now time.Time) error {
	// Wipe the caller's plaintext on every path — success, refusal, error.
	defer zeroizeBytes(keyMaterial)

	if err := requireDualControl(custodianA, custodianB); err != nil {
		byokRecord(audit, target, "byok.export", "denied", now)
		return fmt.Errorf("byok export refused: %w", err)
	}

	pubDER, token, err := target.ImportParameters(ctx)
	if err != nil {
		byokRecord(audit, target, "byok.params", "failure", now)
		return fmt.Errorf("byok: import parameters: %w", err)
	}
	byokRecord(audit, target, "byok.params", "success", now)

	wrapped, err := wrapForRSAAESKeyWrap(keyMaterial, pubDER)
	if err != nil {
		byokRecord(audit, target, "byok.wrap", "failure", now)
		return err
	}
	byokRecord(audit, target, "byok.wrap", "success", now)

	if err := target.Import(ctx, wrapped, token); err != nil {
		byokRecord(audit, target, "byok.import", "failure", now)
		return fmt.Errorf("byok: kms import: %w", err)
	}
	byokRecord(audit, target, "byok.import", "success", now)
	return nil
}
