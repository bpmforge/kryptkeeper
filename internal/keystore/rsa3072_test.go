// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestRSA3072SoftwareGenerateSignPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-3072 generation is slow")
	}
	store := newTestStore(t)
	meta, err := store.GenerateKey("rsa3072-test", RSA3072)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if meta.Algorithm != RSA3072 {
		t.Fatalf("meta.Algorithm = %s", meta.Algorithm)
	}
	pub, err := store.PublicKey("rsa3072-test")
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok || rsaPub.N.BitLen() != 3072 {
		t.Fatalf("public key = %T, bits ok=%v", pub, ok)
	}
	signer, err := store.Signer("rsa3072-test")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("rsa3072"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	m, err := store.Metadata("rsa3072-test")
	if err != nil || m.Algorithm != RSA3072 {
		t.Fatalf("Metadata = %v, %v", m.Algorithm, err)
	}
	list, err := store.List()
	if err != nil || len(list) != 1 || list[0].Algorithm != RSA3072 {
		t.Fatalf("List = %v, %v", list, err)
	}

	// Export/import round trip keeps the algorithm.
	blob, err := store.ExportEncryptedKey("rsa3072-test", []byte("backup-passphrase-32chars-min!!!"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ImportEncryptedKey("rsa3072-copy", blob, []byte("backup-passphrase-32chars-min!!!")); err != nil {
		t.Fatal(err)
	}
	cm, err := store.Metadata("rsa3072-copy")
	if err != nil || cm.Algorithm != RSA3072 {
		t.Fatalf("imported Metadata = %v, %v", cm.Algorithm, err)
	}
}

func TestRSAAlgorithmForBitsBuckets(t *testing.T) {
	for bits, want := range map[int]Algorithm{2048: RSA2048, 2049: RSA3072, 3072: RSA3072, 3073: RSA4096, 4096: RSA4096} {
		if got := rsaAlgorithmForBits(bits); got != want {
			t.Errorf("rsaAlgorithmForBits(%d) = %s, want %s", bits, got, want)
		}
	}
}

func TestCloudKeySpecsRSA3072(t *testing.T) {
	if spec, err := awsKeySpec(RSA3072); err != nil || spec != types.KeySpecRsa3072 {
		t.Errorf("awsKeySpec = %v, %v", spec, err)
	}
	if a, err := gcpKeyAlgorithm(RSA3072); err != nil || a != "RSA_SIGN_PKCS1_3072_SHA256" {
		t.Errorf("gcpKeyAlgorithm = %v, %v", a, err)
	}
	if kty, _, _, err := azureKeyParams(RSA3072); err != nil || kty != "RSA" {
		t.Errorf("azureKeyParams = %v, %v", kty, err)
	}
	for algo, want := range map[Algorithm]int{RSA2048: 2048, RSA3072: 3072, RSA4096: 4096, ECDSAP256: 0} {
		if got := azureRSAKeySize(algo); got != want {
			t.Errorf("azureRSAKeySize(%s) = %d, want %d", algo, got, want)
		}
	}
}

func TestVaultTypeMappingRSA3072(t *testing.T) {
	if v, err := algoToVaultType(RSA3072); err != nil || v != "rsa-3072" {
		t.Errorf("algoToVaultType = %v, %v", v, err)
	}
	if got := vaultTypeToAlgo("rsa-3072"); got != RSA3072 {
		t.Errorf("vaultTypeToAlgo = %s", got)
	}
}
