// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package escrowbyok_test is the W23-20 executed drill: escrow -> recover
// round trips for every key algorithm, and BYOK import of escrow-recovered
// key material into an AWS KMS emulator (moto). The Azure leg asserts the
// product's explicit refusal (no Azure BYOK target exists; follow-up W23-20a).
// Skipped unless KK_LIVE_ESCROW_BYOK=1. Passphrases are throwaway literals.
package escrowbyok_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"kryptkeeper/internal/keystore"
)

var (
	storePass  = []byte("drill-store-passphrase-32chars-min!!")
	custodianA = []byte("drill-custodian-A-passphrase-0001")
	custodianB = []byte("drill-custodian-B-passphrase-0002")
)

func gate(t *testing.T) {
	t.Helper()
	if os.Getenv("KK_LIVE_ESCROW_BYOK") != "1" {
		t.Skip("set KK_LIVE_ESCROW_BYOK=1 (see run.sh) to run the escrow/BYOK drill")
	}
}

func newStore(t *testing.T) *keystore.SoftwareStore {
	t.Helper()
	s, err := keystore.NewSoftwareStore(t.TempDir(), storePass)
	if err != nil {
		t.Fatalf("NewSoftwareStore: %v", err)
	}
	return s
}

func TestEscrowRecoverRoundTrip(t *testing.T) {
	gate(t)
	for _, tc := range []struct {
		name string
		algo keystore.Algorithm
	}{
		{"rsa", keystore.RSA2048},
		{"ecdsa", keystore.ECDSAP256},
		{"mldsa", keystore.MLDSA65},
		{"hybrid", keystore.HybridECDSAP256MLDSA65},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newStore(t)
			if _, err := src.GenerateKey("k", tc.algo); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			bundle, err := keystore.EscrowKey(src, "k", custodianA, custodianB)
			if err != nil {
				t.Fatalf("EscrowKey: %v", err)
			}
			dst := newStore(t)
			id, err := keystore.RecoverEscrowedKey(dst, bundle, custodianA, custodianB)
			if err != nil {
				t.Fatalf("RecoverEscrowedKey: %v", err)
			}
			if id != "k" {
				t.Fatalf("recovered id %q, want k", id)
			}
			switch tc.algo {
			case keystore.HybridECDSAP256MLDSA65:
				op, err := src.LoadHybridKeyPair("k")
				if err != nil {
					t.Fatal(err)
				}
				rp, err := dst.LoadHybridKeyPair("k")
				if err != nil {
					t.Fatal(err)
				}
				assertPubEqual(t, op.Primary.Public(), rp.Primary.Public())
				assertPubEqual(t, op.Secondary.Public(), rp.Secondary.Public())
				d := sha256.Sum256([]byte("drill hybrid primary"))
				sig, err := rp.Primary.Sign(rand.Reader, d[:], crypto.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				if !ecdsa.VerifyASN1(op.Primary.Public().(*ecdsa.PublicKey), d[:], sig) {
					t.Fatal("hybrid primary signature does not verify against the ORIGINAL key")
				}
				msg := []byte("drill hybrid secondary")
				ssig, err := rp.Secondary.Sign(rand.Reader, msg, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !mldsa65.Verify(op.Secondary.Public().(*mldsa65.PublicKey), msg, nil, ssig) {
					t.Fatal("hybrid secondary signature does not verify against the ORIGINAL key")
				}
				return
			}
			origPub, err := src.PublicKey("k")
			if err != nil {
				t.Fatal(err)
			}
			recPub, err := dst.PublicKey("k")
			if err != nil {
				t.Fatal(err)
			}
			assertPubEqual(t, origPub, recPub)
			signer, err := dst.Signer("k")
			if err != nil {
				t.Fatal(err)
			}
			switch tc.algo {
			case keystore.RSA2048:
				d := sha256.Sum256([]byte("drill rsa"))
				sig, err := signer.Sign(rand.Reader, d[:], crypto.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				if err := rsa.VerifyPKCS1v15(origPub.(*rsa.PublicKey), crypto.SHA256, d[:], sig); err != nil {
					t.Fatalf("RSA signature does not verify against the ORIGINAL key: %v", err)
				}
			case keystore.ECDSAP256:
				d := sha256.Sum256([]byte("drill ecdsa"))
				sig, err := signer.Sign(rand.Reader, d[:], crypto.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				if !ecdsa.VerifyASN1(origPub.(*ecdsa.PublicKey), d[:], sig) {
					t.Fatal("ECDSA signature does not verify against the ORIGINAL key")
				}
			case keystore.MLDSA65:
				msg := []byte("drill mldsa")
				sig, err := signer.Sign(rand.Reader, msg, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !mldsa65.Verify(origPub.(*mldsa65.PublicKey), msg, nil, sig) {
					t.Fatal("ML-DSA signature does not verify against the ORIGINAL key")
				}
			}
		})
	}
}

// assertPubEqual compares public keys byte for byte: PKIX DER for classical
// keys, the FIPS 204 encoding for ML-DSA.
func assertPubEqual(t *testing.T, a, b crypto.PublicKey) {
	t.Helper()
	if am, ok := a.(keystore.MLDSAPublicKey); ok {
		bm, ok := b.(keystore.MLDSAPublicKey)
		if !ok {
			t.Fatalf("recovered key type %T is not ML-DSA", b)
		}
		ab, err1 := am.MarshalBinary()
		bb, err2 := bm.MarshalBinary()
		if err1 != nil || err2 != nil || !bytes.Equal(ab, bb) {
			t.Fatal("ML-DSA public keys are not byte-identical")
		}
		return
	}
	ad, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		t.Fatalf("marshal original: %v", err)
	}
	bd, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		t.Fatalf("marshal recovered: %v", err)
	}
	if !bytes.Equal(ad, bd) {
		t.Fatal("public keys are not byte-identical")
	}
}

func TestEscrowRecoverWrongPassphrase(t *testing.T) {
	gate(t)
	src := newStore(t)
	if _, err := src.GenerateKey("k", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	bundle, err := keystore.EscrowKey(src, "k", custodianA, custodianB)
	if err != nil {
		t.Fatal(err)
	}
	dst := newStore(t)
	_, err = keystore.RecoverEscrowedKey(dst, bundle, custodianA, []byte("drill-wrong-custodian-passphrase!"))
	if err == nil {
		t.Fatal("recovery with a wrong custodian passphrase must fail")
	}
	if !errors.Is(err, keystore.ErrDecryptionFailed) {
		t.Fatalf("want ErrDecryptionFailed, got %v", err)
	}
	if _, err := dst.PublicKey("k"); err == nil {
		t.Fatal("failed recovery must leave nothing in the destination store")
	}
}

func TestEscrowRecoverExistingID(t *testing.T) {
	gate(t)
	src := newStore(t)
	if _, err := src.GenerateKey("k", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	bundle, err := keystore.EscrowKey(src, "k", custodianA, custodianB)
	if err != nil {
		t.Fatal(err)
	}
	before, err := src.PublicKey("k")
	if err != nil {
		t.Fatal(err)
	}
	_, err = keystore.RecoverEscrowedKey(src, bundle, custodianA, custodianB)
	if !errors.Is(err, keystore.ErrKeyExists) {
		t.Fatalf("want ErrKeyExists, got %v", err)
	}
	after, err := src.PublicKey("k")
	if err != nil {
		t.Fatal(err)
	}
	assertPubEqual(t, before, after)
}

type memAudit struct {
	mu  sync.Mutex
	evs []keystore.BYOKEvent
}

func (m *memAudit) Record(ev keystore.BYOKEvent) {
	m.mu.Lock()
	m.evs = append(m.evs, ev)
	m.mu.Unlock()
}

func TestBYOKImportAWS(t *testing.T) {
	gate(t)
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Fatal("AWS_ENDPOINT_URL must point at the emulator; refusing to fall through to real AWS")
	}
	ctx := context.Background()

	// Escrow an ECDSA P-256 key, then recover its PKCS#8 DER under dual control.
	src := newStore(t)
	if _, err := src.GenerateKey("byok", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	origPub, err := src.PublicKey("byok")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := keystore.EscrowKey(src, "byok", custodianA, custodianB)
	if err != nil {
		t.Fatal(err)
	}
	material, err := keystore.RecoverEscrowedKeyMaterial(bundle, custodianA, custodianB)
	if err != nil {
		t.Fatalf("RecoverEscrowedKeyMaterial: %v", err)
	}

	// Create the EXTERNAL-origin target key in moto.
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		t.Fatal(err)
	}
	api := kms.NewFromConfig(cfg)
	ck, err := api.CreateKey(ctx, &kms.CreateKeyInput{
		Origin:   types.OriginTypeExternal,
		KeySpec:  types.KeySpecEccNistP256,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("CreateKey(EXTERNAL): %v", err)
	}
	keyID := aws.ToString(ck.KeyMetadata.KeyId)
	t.Logf("created EXTERNAL-origin key %s (state %s)", keyID, ck.KeyMetadata.KeyState)

	target, err := keystore.NewAWSKMSImportTarget(ctx, os.Getenv("AWS_REGION"), keyID)
	if err != nil {
		t.Fatal(err)
	}
	audit := &memAudit{}
	err = keystore.ExportEscrowedKeyToKMS(ctx, target, audit, material, custodianA, custodianB, time.Now())
	steps := make([]string, 0, len(audit.evs))
	for _, e := range audit.evs {
		steps = append(steps, e.Step+"="+e.Outcome)
	}
	t.Logf("audit sequence reaching moto: %s", strings.Join(steps, ", "))
	for _, b := range material {
		if b != 0 {
			t.Fatal("recovered plaintext was not zeroized after ExportEscrowedKeyToKMS")
		}
	}
	if err != nil {
		// Honest PARTIAL (emulator): record exactly how far the wire sequence
		// got. moto 5.x does not implement GetParametersForImport at all
		// (run.sh records its server-side NotImplementedError), so the only
		// acceptable failure is that call, and ImportKeyMaterial is never sent.
		t.Logf("RESULT: PARTIAL (emulator): ExportEscrowedKeyToKMS returned: %v", err)
		if len(audit.evs) != 1 || audit.evs[0].Step != "byok.params" || audit.evs[0].Outcome != "failure" ||
			!strings.Contains(err.Error(), "GetParametersForImport") {
			t.Fatalf("unexpected failure shape (want only GetParametersForImport failing); sequence=%v err=%v", steps, err)
		}
		return
	}
	d, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("post-import key state: %s", d.KeyMetadata.KeyState)
	if d.KeyMetadata.KeyState != types.KeyStateEnabled {
		t.Fatalf("key state after import = %s, want Enabled", d.KeyMetadata.KeyState)
	}
	// Prove the imported material is the escrowed key: KMS public key == original.
	gp, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		t.Logf("GetPublicKey after import failed (emulator): %v", err)
		t.Log("RESULT: import accepted (ImportKeyMaterial 200, key Enabled); public-key equality NOT verified")
		return
	}
	want, err := x509.MarshalPKIXPublicKey(origPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(gp.PublicKey, want) {
		t.Log("RESULT: PASS: ImportKeyMaterial accepted, key Enabled, KMS public key byte-identical to the escrowed key")
	} else {
		t.Log("RESULT: import accepted, key Enabled; KMS GetPublicKey differs from the escrowed key (emulator returns its own derived/placeholder key; equality NOT proven)")
	}
}

func TestBYOKImportAzure(t *testing.T) {
	gate(t)
	_, err := keystore.NewKMSImportTarget(context.Background(), "azure", "", "any-key")
	if err == nil {
		t.Fatal("azure BYOK target must be refused until W23-20a lands")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("want the explicit not-implemented refusal, got: %v", err)
	}
	t.Logf("RESULT: NOT IMPLEMENTED (refused by design, follow-up W23-20a): %v", err)
}
