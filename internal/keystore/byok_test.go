// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	kwp "github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// W15-04: BYOK export of escrow-recovered key material into a cloud KMS
// via RSA_AES_KEY_WRAP_SHA_256. The KMS boundary is injected, so the
// test acts as the KMS: it hands out an RSA wrapping key and then
// UNWRAPS what the exporter produced, proving the wire format is exactly
// what AWS/Azure/GCP ImportKeyMaterial expects — with no cloud.

// fakeKMSTarget plays the KMS import side: it owns the wrapping RSA key
// and reverses the exporter's wrap to recover the original material.
type fakeKMSTarget struct {
	priv      *rsa.PrivateKey
	token     []byte
	imported  []byte // material recovered by reversing the wrap
	importErr error
	paramsErr error
}

func newFakeKMSTarget(t *testing.T) *fakeKMSTarget {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return &fakeKMSTarget{priv: priv, token: []byte("import-token-xyz")}
}

func (f *fakeKMSTarget) Provider() string { return "aws" }
func (f *fakeKMSTarget) KeyID() string    { return "arn:aws:kms:...:key/imported" }

func (f *fakeKMSTarget) ImportParameters(context.Context) ([]byte, []byte, error) {
	if f.paramsErr != nil {
		return nil, nil, f.paramsErr
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pubDER, f.token, nil
}

func (f *fakeKMSTarget) Import(_ context.Context, encryptedKeyMaterial, importToken []byte) error {
	if f.importErr != nil {
		return f.importErr
	}
	if !bytes.Equal(importToken, f.token) {
		return errors.New("import token mismatch")
	}
	// Reverse RSA_AES_KEY_WRAP: [RSA-OAEP(aesKey)] || [KWP(aesKey, material)].
	rsaLen := f.priv.Size()
	if len(encryptedKeyMaterial) <= rsaLen {
		return errors.New("wrapped material too short")
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.priv, encryptedKeyMaterial[:rsaLen], nil)
	if err != nil {
		return err
	}
	kw, err := kwp.NewKWP(aesKey)
	if err != nil {
		return err
	}
	material, err := kw.Unwrap(encryptedKeyMaterial[rsaLen:])
	if err != nil {
		return err
	}
	f.imported = material
	return nil
}

type recordingBYOKAudit struct{ events []BYOKEvent }

func (r *recordingBYOKAudit) Record(ev BYOKEvent) { r.events = append(r.events, ev) }
func (r *recordingBYOKAudit) has(step, outcome string) bool {
	for _, e := range r.events {
		if e.Step == step && e.Outcome == outcome {
			return true
		}
	}
	return false
}

var (
	byokPassA = []byte("byok-custodian-alpha")
	byokPassB = []byte("byok-custodian-bravo")
)

func TestBYOKWrapsAndImportsRoundTrip(t *testing.T) {
	target := newFakeKMSTarget(t)
	audit := &recordingBYOKAudit{}
	material := bytes.Repeat([]byte{0xA5}, 200) // stand-in CA private-key DER
	original := append([]byte(nil), material...)

	err := ExportEscrowedKeyToKMS(context.Background(), target, audit, material, byokPassA, byokPassB, time.Now())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !bytes.Equal(target.imported, original) {
		t.Fatal("KMS-side unwrap must recover the exact original key material")
	}
	// Plaintext must never survive outside the wrap: the input buffer is
	// zeroized on the way out.
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("key material buffer must be zeroized after export")
	}
	for _, step := range []string{"byok.params", "byok.wrap", "byok.import"} {
		if !audit.has(step, "success") {
			t.Fatalf("step %s must be audited success: %+v", step, audit.events)
		}
	}
}

func TestBYOKRefusesSingleController(t *testing.T) {
	target := newFakeKMSTarget(t)
	audit := &recordingBYOKAudit{}
	material := bytes.Repeat([]byte{0x11}, 64)

	// Single controller: no second custodian secret.
	err := ExportEscrowedKeyToKMS(context.Background(), target, audit, material, byokPassA, nil, time.Now())
	if err == nil {
		t.Fatal("BYOK export with a single controller must be refused")
	}
	if target.imported != nil {
		t.Fatal("nothing may be imported when dual control fails")
	}
	if !audit.has("byok.export", "denied") {
		t.Fatalf("a refused export must be audited: %+v", audit.events)
	}
	// Even on refusal, the material must be wiped.
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("key material must be zeroized even when the ceremony is refused")
	}
}

func TestBYOKImportFailureIsAuditedAndSurfaced(t *testing.T) {
	target := newFakeKMSTarget(t)
	target.importErr = errors.New("kms throttled")
	audit := &recordingBYOKAudit{}
	material := bytes.Repeat([]byte{0x22}, 100)

	err := ExportEscrowedKeyToKMS(context.Background(), target, audit, material, byokPassA, byokPassB, time.Now())
	if err == nil {
		t.Fatal("a KMS import failure must surface")
	}
	if !audit.has("byok.import", "failure") {
		t.Fatalf("import failure must be audited: %+v", audit.events)
	}
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("key material must be zeroized on the import-failure path too")
	}
}
