// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// --- SoftwareStore edge cases ---

func TestNewSoftwareStoreNonExistentDir(t *testing.T) {
	_, err := NewSoftwareStore("/nonexistent/path/xyz", []byte("passphrase-test-32chars-exactly!"))
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestNewSoftwareStoreFileNotDir(t *testing.T) {
	f, err := os.CreateTemp("", "keystore-test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	_, err = NewSoftwareStore(f.Name(), []byte("passphrase-test-32chars-exactly!"))
	if err == nil {
		t.Error("expected error when path is a file, not directory")
	}
}

func TestDetectAlgorithmRSA4096(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-4096 generation is slow")
	}
	store := newTestStore(t)
	if _, err := store.GenerateKey("rsa4096-algo", RSA4096); err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Fresh store to force detectAlgorithm via loadAndDecrypt.
	store2, _ := NewSoftwareStore(store.dir, store.passphrase)
	meta, err := store2.Metadata("rsa4096-algo")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.Algorithm != RSA4096 {
		t.Errorf("expected RSA4096, got %s", meta.Algorithm)
	}
}

func TestDetectAlgorithmECDSAP384(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("p384-algo", ECDSAP384); err != nil {
		t.Fatalf("generate: %v", err)
	}
	store2, _ := NewSoftwareStore(store.dir, store.passphrase)
	meta, err := store2.Metadata("p384-algo")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.Algorithm != ECDSAP384 {
		t.Errorf("expected ECDSAP384, got %s", meta.Algorithm)
	}
}

func TestHexDecodeInvalidHex(t *testing.T) {
	_, err := hexDecode("not-valid-hex!!", 16)
	if err == nil {
		t.Error("expected error for invalid hex string")
	}
}

func TestHexDecodeWrongLength(t *testing.T) {
	// 4 bytes decoded but expected 16
	_, err := hexDecode("deadbeef", 16)
	if err == nil {
		t.Error("expected error for wrong decoded length")
	}
}

func TestHexDecodeSuccess(t *testing.T) {
	b, err := hexDecode("deadbeefdeadbeefdeadbeefdeadbeef", 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(b))
	}
}

func TestLoadAndDecryptInvalidPEM(t *testing.T) {
	store := newTestStore(t)
	// Write a file that is not valid PEM.
	path := filepath.Join(store.dir, "badpem.key.enc")
	os.WriteFile(path, []byte("this is not pem"), 0o600)

	_, err := store.loadAndDecrypt("badpem")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadAndDecryptWrongPEMType(t *testing.T) {
	store := newTestStore(t)
	path := filepath.Join(store.dir, "wrongtype.key.enc")
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")}
	os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600)

	_, err := store.loadAndDecrypt("wrongtype")
	if err == nil {
		t.Error("expected error for wrong PEM type")
	}
}

func TestLoadAndDecryptMissingSaltHeader(t *testing.T) {
	store := newTestStore(t)
	path := filepath.Join(store.dir, "nosalt.key.enc")
	pemBlock := &pem.Block{
		Type:    "ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{"Nonce": "aabbccddaabbccddaabbccdd"},
		Bytes:   []byte("fakedata"),
	}
	os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600)

	_, err := store.loadAndDecrypt("nosalt")
	if err == nil {
		t.Error("expected error for missing Salt header")
	}
}

func TestLoadAndDecryptMissingNonceHeader(t *testing.T) {
	store := newTestStore(t)
	path := filepath.Join(store.dir, "nononce.key.enc")
	pemBlock := &pem.Block{
		Type:    "ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{"Salt": "aabbccddaabbccddaabbccddaabbccdd"},
		Bytes:   []byte("fakedata"),
	}
	os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600)

	_, err := store.loadAndDecrypt("nononce")
	if err == nil {
		t.Error("expected error for missing Nonce header")
	}
}

// --- NewCloudKMSStore ---

func TestNewCloudKMSStoreUnsupportedProvider(t *testing.T) {
	_, err := NewCloudKMSStore("hsm")
	if err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestNewCloudKMSStoreSupportedProviders(t *testing.T) {
	for _, p := range []string{"aws", "gcp", "azure"} {
		store, err := NewCloudKMSStore(p)
		if err != nil {
			t.Errorf("NewCloudKMSStore(%q) error: %v", p, err)
		}
		if store == nil {
			t.Errorf("NewCloudKMSStore(%q) returned nil", p)
		}
	}
}

// --- Pure lookup functions ---

func TestGCPKeyAlgorithm(t *testing.T) {
	cases := []struct {
		algo Algorithm
		want string
	}{
		{ECDSAP256, "EC_SIGN_P256_SHA256"},
		{ECDSAP384, "EC_SIGN_P384_SHA384"},
		{RSA2048, "RSA_SIGN_PKCS1_2048_SHA256"},
		{RSA4096, "RSA_SIGN_PKCS1_4096_SHA256"},
	}
	for _, tc := range cases {
		got, err := gcpKeyAlgorithm(tc.algo)
		if err != nil {
			t.Errorf("gcpKeyAlgorithm(%s): unexpected error: %v", tc.algo, err)
		}
		if got != tc.want {
			t.Errorf("gcpKeyAlgorithm(%s) = %q, want %q", tc.algo, got, tc.want)
		}
	}

	_, err := gcpKeyAlgorithm(Ed25519)
	if err == nil {
		t.Error("expected error for unsupported Ed25519")
	}
}

func TestGCPDigestField(t *testing.T) {
	cases := []struct {
		hash crypto.Hash
		want string
	}{
		{crypto.SHA256, "sha256"},
		{crypto.SHA384, "sha384"},
		{crypto.SHA512, "sha512"},
		{crypto.SHA1, "sha256"}, // default fallback
	}
	for _, tc := range cases {
		got := gcpDigestField(tc.hash)
		if got != tc.want {
			t.Errorf("gcpDigestField(%v) = %q, want %q", tc.hash, got, tc.want)
		}
	}
}

func TestGCPTruncate(t *testing.T) {
	short := "short"
	if gcpTruncate(short) != short {
		t.Error("short string should not be truncated")
	}
	long := make([]byte, 210)
	for i := range long {
		long[i] = 'x'
	}
	result := gcpTruncate(string(long))
	if len(result) != 203 { // 200 + "..."
		t.Errorf("truncated string has wrong length: %d", len(result))
	}
}

func TestAzureKeyParams(t *testing.T) {
	cases := []struct {
		algo    Algorithm
		wantKty string
	}{
		{ECDSAP256, "EC"},
		{ECDSAP384, "EC"},
		{RSA2048, "RSA"},
		{RSA4096, "RSA"},
	}
	for _, tc := range cases {
		kty, _, _, err := azureKeyParams(tc.algo)
		if err != nil {
			t.Errorf("azureKeyParams(%s): %v", tc.algo, err)
		}
		if kty != tc.wantKty {
			t.Errorf("azureKeyParams(%s) kty = %q, want %q", tc.algo, kty, tc.wantKty)
		}
	}

	_, _, _, err := azureKeyParams(Ed25519)
	if err == nil {
		t.Error("expected error for unsupported Ed25519")
	}
}

func TestAzureSigningAlgorithm(t *testing.T) {
	ecKey := &ecdsa.PublicKey{}
	rsaKey := &rsa.PublicKey{}

	cases := []struct {
		pub  crypto.PublicKey
		hash crypto.Hash
		want string
	}{
		{ecKey, crypto.SHA256, "ES256"},
		{ecKey, crypto.SHA384, "ES384"},
		{ecKey, crypto.SHA512, "ES512"},
		{rsaKey, crypto.SHA256, "RS256"},
		{rsaKey, crypto.SHA384, "RS384"},
		{rsaKey, crypto.SHA512, "RS512"},
	}
	for _, tc := range cases {
		got, err := azureSigningAlgorithm(tc.pub, tc.hash)
		if err != nil {
			t.Errorf("azureSigningAlgorithm(%v): %v", tc.hash, err)
		}
		if got != tc.want {
			t.Errorf("azureSigningAlgorithm = %q, want %q", got, tc.want)
		}
	}

	// Unsupported combination.
	_, err := azureSigningAlgorithm(ecKey, crypto.SHA1)
	if err == nil {
		t.Error("expected error for unsupported EC+SHA1")
	}
}

func TestAzureTruncate(t *testing.T) {
	if azureTruncate("hi") != "hi" {
		t.Error("short string should pass through")
	}
	long := make([]byte, 250)
	for i := range long {
		long[i] = 'y'
	}
	got := azureTruncate(string(long))
	if len(got) != 203 {
		t.Errorf("expected 203 chars, got %d", len(got))
	}
}

// --- awsSigningAlgorithm ---

func TestAWSSigningAlgorithm(t *testing.T) {
	ecKey := &ecdsa.PublicKey{}
	rsaKey := &rsa.PublicKey{}

	cases := []struct {
		pub  crypto.PublicKey
		opts crypto.SignerOpts
		want kmsTypes.SigningAlgorithmSpec
	}{
		{ecKey, crypto.SHA256, kmsTypes.SigningAlgorithmSpecEcdsaSha256},
		{ecKey, crypto.SHA384, kmsTypes.SigningAlgorithmSpecEcdsaSha384},
		{ecKey, crypto.SHA512, kmsTypes.SigningAlgorithmSpecEcdsaSha512},
		{rsaKey, crypto.SHA256, kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
		{rsaKey, crypto.SHA384, kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384},
		{rsaKey, crypto.SHA512, kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
		{rsaKey, &rsa.PSSOptions{Hash: crypto.SHA256}, kmsTypes.SigningAlgorithmSpecRsassaPssSha256},
		{rsaKey, &rsa.PSSOptions{Hash: crypto.SHA384}, kmsTypes.SigningAlgorithmSpecRsassaPssSha384},
		{rsaKey, &rsa.PSSOptions{Hash: crypto.SHA512}, kmsTypes.SigningAlgorithmSpecRsassaPssSha512},
	}
	for _, tc := range cases {
		got, err := awsSigningAlgorithm(tc.pub, tc.opts)
		if err != nil {
			t.Errorf("awsSigningAlgorithm(%T, %v): %v", tc.pub, tc.opts.HashFunc(), err)
		}
		if got != tc.want {
			t.Errorf("awsSigningAlgorithm = %q, want %q", got, tc.want)
		}
	}

	_, err := awsSigningAlgorithm(ecKey, crypto.SHA1)
	if err == nil {
		t.Error("expected error for unsupported EC+SHA1")
	}
	_, err = awsSigningAlgorithm(rsaKey, crypto.SHA1)
	if err == nil {
		t.Error("expected error for unsupported RSA+SHA1")
	}
}

// --- azureParseJWK ---

func TestAzureParseJWKRSAInvalidBase64(t *testing.T) {
	// "fake-n" and "fake-e" are not valid base64url — expect an error.
	_, err := azureParseJWK("RSA", "!invalid!", "!invalid!", "", "", "")
	if err == nil {
		t.Error("expected error for invalid base64 RSA JWK n/e values")
	}
}

func TestAzureParseJWKRSAValid(t *testing.T) {
	// Construct a minimal valid RSA-2048 JWK (n=256 bytes, e=3 bytes).
	pub, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nB64 := base64.RawURLEncoding.EncodeToString(pub.PublicKey.N.Bytes())
	eBytes := big.NewInt(int64(pub.PublicKey.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	result, err := azureParseJWK("RSA", nB64, eB64, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error parsing valid RSA JWK: %v", err)
	}
	rsaPub, ok := result.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", result)
	}
	if rsaPub.N.Cmp(pub.PublicKey.N) != 0 {
		t.Error("parsed N does not match original")
	}
}

func TestAzureParseJWKUnsupportedType(t *testing.T) {
	_, err := azureParseJWK("OKP", "", "", "", "", "")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestAzureParseJWKECInvalidX(t *testing.T) {
	_, err := azureParseJWK("EC", "!!invalid-base64!!", "", "", "", "P-256")
	if err == nil {
		t.Error("expected error for invalid x coordinate")
	}
}

func TestAzureParseJWKECInvalidY(t *testing.T) {
	// Valid x (32 bytes base64url), invalid y
	x := make([]byte, 32)
	import_x := encode32(x)
	_, err := azureParseJWK("EC", "", "", import_x, "!!bad!!", "P-256")
	if err == nil {
		t.Error("expected error for invalid y coordinate")
	}
}

func TestAzureParseJWKECUnsupportedCurve(t *testing.T) {
	coords := make([]byte, 32)
	encoded := encode32(coords)
	_, err := azureParseJWK("EC", "", "", encoded, encoded, "P-224")
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
}

func TestAzureParseJWKECValidP256(t *testing.T) {
	// Generate a real P-256 key to get valid coordinates.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	import_x := encodeCoord(key.X.Bytes(), 32)
	import_y := encodeCoord(key.Y.Bytes(), 32)

	pub, err := azureParseJWK("EC", "", "", import_x, import_y, "P-256")
	if err != nil {
		t.Fatalf("azureParseJWK P-256: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func encode32(b []byte) string {
	import_enc := make([]byte, 32)
	copy(import_enc[32-len(b):], b)
	return encodeRawURLBase64(import_enc)
}

func encodeCoord(b []byte, size int) string {
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return encodeRawURLBase64(padded)
}

func encodeRawURLBase64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	_ = alphabet
	// Use the standard library encoding
	import_result := make([]byte, (len(b)+2)/3*4)
	n := encodeBase64URL(b, import_result)
	return string(import_result[:n])
}

func encodeBase64URL(src, dst []byte) int {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = enc[val>>18&0x3F]
		dst[di+1] = enc[val>>12&0x3F]
		dst[di+2] = enc[val>>6&0x3F]
		dst[di+3] = enc[val>>0&0x3F]
		si += 3
		di += 4
	}
	rem := len(src) - si
	if rem == 2 {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8
		dst[di+0] = enc[val>>18&0x3F]
		dst[di+1] = enc[val>>12&0x3F]
		dst[di+2] = enc[val>>6&0x3F]
		di += 3
	} else if rem == 1 {
		val := uint(src[si+0]) << 16
		dst[di+0] = enc[val>>18&0x3F]
		dst[di+1] = enc[val>>12&0x3F]
		di += 2
	}
	return di
}

// --- azureECPublicKeyDER ---

func TestAzureECPublicKeyDER(t *testing.T) {
	point := make([]byte, 65) // 0x04 + 32+32
	point[0] = 0x04
	for _, crv := range []string{"P-256", "P-384", "P-521"} {
		der := azureECPublicKeyDER(crv, point)
		if der == nil {
			t.Errorf("azureECPublicKeyDER(%s) returned nil", crv)
		}
		if len(der) == 0 {
			t.Errorf("azureECPublicKeyDER(%s) returned empty", crv)
		}
	}
	if got := azureECPublicKeyDER("P-999", point); got != nil {
		t.Error("expected nil for unsupported curve")
	}
}

// --- CloudKMSStore methods (without external API calls) ---

func newTestCloudStore(t *testing.T) *CloudKMSStore {
	t.Helper()
	store, err := NewCloudKMSStore("aws")
	if err != nil {
		t.Fatalf("NewCloudKMSStore: %v", err)
	}
	return store
}

func injectKey(store *CloudKMSStore, id string, pub crypto.PublicKey) {
	store.mu.Lock()
	store.keys[id] = &cloudKMSKeyEntry{
		meta:   KeyMetadata{ID: id, Algorithm: ECDSAP256},
		pubKey: pub,
		config: CloudKMSConfig{Provider: "aws", KeyURI: "arn:aws:kms:us-east-1:123456789012:key/test"},
	}
	store.mu.Unlock()
}

func TestCloudKMSStoreSigner(t *testing.T) {
	store := newTestCloudStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	injectKey(store, "ks-1", &key.PublicKey)

	signer, err := store.Signer("ks-1")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer.Public() == nil {
		t.Error("signer.Public() is nil")
	}

	_, err = store.Signer("nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestCloudKMSStorePublicKey(t *testing.T) {
	store := newTestCloudStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	injectKey(store, "pk-1", &key.PublicKey)

	pub, err := store.PublicKey("pk-1")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Error("PublicKey returned nil")
	}

	_, err = store.PublicKey("missing")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestCloudKMSStoreMetadata(t *testing.T) {
	store := newTestCloudStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	injectKey(store, "meta-1", &key.PublicKey)

	meta, err := store.Metadata("meta-1")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.ID != "meta-1" {
		t.Errorf("expected ID=meta-1, got %s", meta.ID)
	}

	_, err = store.Metadata("missing")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestCloudKMSStoreList(t *testing.T) {
	store := newTestCloudStore(t)
	if list, _ := store.List(); len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	injectKey(store, "list-1", &key.PublicKey)
	injectKey(store, "list-2", &key.PublicKey)

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 keys, got %d", len(list))
	}
}

func TestCloudKMSStoreDelete(t *testing.T) {
	store := newTestCloudStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	injectKey(store, "del-1", &key.PublicKey)
	store.destroyKey = func(context.Context, CloudKMSConfig) error { return nil }

	if err := store.Delete("del-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Signer("del-1")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound after delete, got %v", err)
	}

	if err := store.Delete("missing"); err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound for missing key, got %v", err)
	}
}

func TestCloudKMSSignerPublic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &CloudKMSSigner{publicKey: &key.PublicKey}
	if s.Public() == nil {
		t.Error("Public() returned nil")
	}
}
