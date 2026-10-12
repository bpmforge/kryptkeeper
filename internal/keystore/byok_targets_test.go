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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	kwp "github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// W17-12: the AWS adapter, exercised end-to-end against a fake KMS that
// REVERSES the wrap — proving the bytes AWS would receive are the bytes
// AWS's format specifies, with no cloud involved.

type fakeAWSKMS struct {
	priv        *rsa.PrivateKey
	token       []byte
	gotSpec     types.AlgorithmSpec
	gotKeySpec  types.WrappingKeySpec
	gotExpiry   types.ExpirationModelType
	recovered   []byte
	importCalls int
}

func newFakeAWSKMS(t *testing.T) *fakeAWSKMS {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return &fakeAWSKMS{priv: priv, token: []byte("import-token")}
}

func (f *fakeAWSKMS) GetParametersForImport(_ context.Context, in *kms.GetParametersForImportInput, _ ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
	f.gotSpec = in.WrappingAlgorithm
	f.gotKeySpec = in.WrappingKeySpec
	pubDER, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetParametersForImportOutput{PublicKey: pubDER, ImportToken: f.token}, nil
}

func (f *fakeAWSKMS) ImportKeyMaterial(_ context.Context, in *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
	f.importCalls++
	f.gotExpiry = in.ExpirationModel
	// Reverse AWS's RSA_AES_KEY_WRAP: RSA-OAEP(aes) || KWP(aes, material).
	rsaLen := f.priv.Size()
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.priv, in.EncryptedKeyMaterial[:rsaLen], nil)
	if err != nil {
		return nil, err
	}
	kw, err := kwp.NewKWP(aesKey)
	if err != nil {
		return nil, err
	}
	material, err := kw.Unwrap(in.EncryptedKeyMaterial[rsaLen:])
	if err != nil {
		return nil, err
	}
	f.recovered = material
	return &kms.ImportKeyMaterialOutput{}, nil
}

type nopBYOKAudit struct{}

func (nopBYOKAudit) Record(BYOKEvent) {}

// End-to-end: escrowed key → recovered → wrapped → what AWS receives is
// byte-identical to the original key material.
func TestAWSImportTargetRoundTripsRealKeyMaterial(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("aws-root", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	bundle, err := EscrowKey(store, "aws-root", passA, passB)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}
	material, err := RecoverEscrowedKeyMaterial(bundle, passA, passB)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	original := append([]byte(nil), material...)

	fake := newFakeAWSKMS(t)
	target := newAWSKMSImportTargetWithAPI(fake, "arn:aws:kms:eu-west-1:1:key/abc")

	if err := ExportEscrowedKeyToKMS(context.Background(), target, nopBYOKAudit{},
		material, passA, passB, timeNowForTest()); err != nil {
		t.Fatalf("export: %v", err)
	}

	if string(fake.recovered) != string(original) {
		t.Fatal("AWS must receive exactly the escrowed key material")
	}
	// The wrap format is pinned: asking for a different spec would hand
	// back a key the wrap does not match.
	if fake.gotSpec != types.AlgorithmSpecRsaAesKeyWrapSha256 {
		t.Fatalf("wrapping algorithm must be RSA_AES_KEY_WRAP_SHA_256, got %q", fake.gotSpec)
	}
	if fake.gotKeySpec != types.WrappingKeySpecRsa4096 {
		t.Fatalf("wrapping key spec: %q", fake.gotKeySpec)
	}
	// An expiring import silently disables a CA key when it lapses.
	if fake.gotExpiry != types.ExpirationModelTypeKeyMaterialDoesNotExpire {
		t.Fatalf("CA key material must not be imported with an expiry, got %q", fake.gotExpiry)
	}
	// And the caller's buffer was wiped.
	if string(material) == string(original) {
		t.Fatal("key material must be zeroized after export")
	}
}

// Azure and GCP wrap differently. Refusing beats producing a blob they
// reject — or worse, one that looks right until a real import.
func TestUnimplementedProvidersRefuseExplicitly(t *testing.T) {
	for _, p := range []string{"azure", "gcp"} {
		_, err := NewKMSImportTarget(context.Background(), p, "eu-west-1", "key-1")
		if err == nil {
			t.Fatalf("%s must refuse rather than appear to work", p)
		}
		if !strings.Contains(err.Error(), "not implemented") {
			t.Fatalf("%s refusal must say what is missing: %v", p, err)
		}
	}
	if _, err := NewKMSImportTarget(context.Background(), "carrier-pigeon", "", "k"); err == nil {
		t.Fatal("an unknown provider must be refused")
	}
}

func timeNowForTest() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
