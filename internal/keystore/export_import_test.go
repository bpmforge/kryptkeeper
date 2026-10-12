// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var backupPassphrase = []byte("backup-passphrase-32chars-min!!")

// TestExportImportEncryptedKey_RSA proves ExportEncryptedKey/ImportEncryptedKey
// round-trip a classical key via the existing PKCS#8 path (regression guard —
// W9-03 only changes behavior for ML-DSA/hybrid, this must stay unchanged).
func TestExportImportEncryptedKey_RSA(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("export-rsa", RSA2048); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	origPub, err := store.PublicKey("export-rsa")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	data, err := store.ExportEncryptedKey("export-rsa", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey: %v", err)
	}
	if err := store.ImportEncryptedKey("export-rsa-restored", data, backupPassphrase); err != nil {
		t.Fatalf("ImportEncryptedKey: %v", err)
	}

	signer, err := store.Signer("export-rsa-restored")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	digest := sha256.Sum256([]byte("export/import roundtrip"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(origPub.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature from restored key does not verify against the ORIGINAL public key: %v", err)
	}
}

// TestExportImportEncryptedKey_ECDSA is the ECDSA half of the classical
// regression guard.
func TestExportImportEncryptedKey_ECDSA(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("export-ecdsa", ECDSAP256); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	origPub, err := store.PublicKey("export-ecdsa")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	data, err := store.ExportEncryptedKey("export-ecdsa", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey: %v", err)
	}
	if err := store.ImportEncryptedKey("export-ecdsa-restored", data, backupPassphrase); err != nil {
		t.Fatalf("ImportEncryptedKey: %v", err)
	}

	signer, err := store.Signer("export-ecdsa-restored")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	digest := sha256.Sum256([]byte("export/import roundtrip"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(origPub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature from restored key does not verify against the ORIGINAL public key")
	}
}

// TestExportImportEncryptedKey_MLDSA65 is the acceptance-critical case (G-31):
// x509.MarshalPKCS8PrivateKey rejects ML-DSA keys, so before W9-03 this failed
// at the ExportEncryptedKey call itself.
func TestExportImportEncryptedKey_MLDSA65(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("export-mldsa", MLDSA65); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	origPub, err := store.PublicKey("export-mldsa")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	data, err := store.ExportEncryptedKey("export-mldsa", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey: %v", err)
	}
	if err := store.ImportEncryptedKey("export-mldsa-restored", data, backupPassphrase); err != nil {
		t.Fatalf("ImportEncryptedKey: %v", err)
	}

	signer, err := store.Signer("export-mldsa-restored")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	msg := []byte("export/import roundtrip for ML-DSA")
	sig, err := signer.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !mldsa65.Verify(origPub.(*mldsa65.PublicKey), msg, nil, sig) {
		t.Fatal("signature from restored key does not verify against the ORIGINAL public key")
	}
}

// TestExportImportEncryptedKey_Hybrid is the other acceptance-critical case
// (G-31): a hybrid ID has no single private key (see hybrid.go) — export must
// back up both components and import must reconstruct the composite.
func TestExportImportEncryptedKey_Hybrid(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("export-hybrid", HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	origPair, err := store.LoadHybridKeyPair("export-hybrid")
	if err != nil {
		t.Fatalf("LoadHybridKeyPair: %v", err)
	}
	origPrimaryPub := origPair.Primary.Public().(*ecdsa.PublicKey)
	origSecondaryPub := origPair.Secondary.Public().(*mldsa65.PublicKey)

	data, err := store.ExportEncryptedKey("export-hybrid", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey: %v", err)
	}
	if err := store.ImportEncryptedKey("export-hybrid-restored", data, backupPassphrase); err != nil {
		t.Fatalf("ImportEncryptedKey: %v", err)
	}

	restoredPair, err := store.LoadHybridKeyPair("export-hybrid-restored")
	if err != nil {
		t.Fatalf("LoadHybridKeyPair (restored): %v", err)
	}
	if restoredPair.Algo != HybridECDSAP256MLDSA65 {
		t.Errorf("restored Algo = %q, want %q", restoredPair.Algo, HybridECDSAP256MLDSA65)
	}

	digest := sha256.Sum256([]byte("export/import roundtrip for hybrid primary"))
	primarySig, err := restoredPair.Primary.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign (primary): %v", err)
	}
	if !ecdsa.VerifyASN1(origPrimaryPub, digest[:], primarySig) {
		t.Fatal("hybrid primary signature does not verify against the ORIGINAL primary public key")
	}

	msg := []byte("export/import roundtrip for hybrid secondary")
	secondarySig, err := restoredPair.Secondary.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("Sign (secondary): %v", err)
	}
	if !mldsa65.Verify(origSecondaryPub, msg, nil, secondarySig) {
		t.Fatal("hybrid secondary signature does not verify against the ORIGINAL secondary public key")
	}
}

// TestImportEncryptedKey_WrongPassphraseFails proves the backup envelope is
// still genuinely passphrase-gated for the new ML-DSA/hybrid paths, not just
// the pre-existing classical one.
func TestImportEncryptedKey_WrongPassphraseFails(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("wrongpass-mldsa", MLDSA65); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data, err := store.ExportEncryptedKey("wrongpass-mldsa", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey: %v", err)
	}
	err = store.ImportEncryptedKey("wrongpass-mldsa-restored", data, []byte("totally-different-passphrase!!!"))
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

// TestExportImportEncryptedKey_CrossInstance proves the actual point of a
// backup/DR feature: the exported blob is self-contained and portable to a
// SEPARATE store instance with a DIFFERENT store passphrase, keyed only by
// the shared backup passphrase — not accidentally coupled to the origin
// store's state. Covers both ML-DSA and hybrid, the two paths this ticket
// changes. All other export/import tests above round-trip within a single
// store instance, which never actually exercises this property.
func TestExportImportEncryptedKey_CrossInstance(t *testing.T) {
	storeA := newTestStore(t)

	if _, err := storeA.GenerateKey("cross-mldsa", MLDSA65); err != nil {
		t.Fatalf("GenerateKey (mldsa): %v", err)
	}
	mldsaPub, err := storeA.PublicKey("cross-mldsa")
	if err != nil {
		t.Fatalf("PublicKey (mldsa): %v", err)
	}
	mldsaBlob, err := storeA.ExportEncryptedKey("cross-mldsa", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey (mldsa): %v", err)
	}

	if _, err := storeA.GenerateKey("cross-hybrid", HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("GenerateKey (hybrid): %v", err)
	}
	hybridPair, err := storeA.LoadHybridKeyPair("cross-hybrid")
	if err != nil {
		t.Fatalf("LoadHybridKeyPair: %v", err)
	}
	hybridPrimaryPub := hybridPair.Primary.Public().(*ecdsa.PublicKey)
	hybridSecondaryPub := hybridPair.Secondary.Public().(*mldsa65.PublicKey)
	hybridBlob, err := storeA.ExportEncryptedKey("cross-hybrid", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey (hybrid): %v", err)
	}

	// A separate instance: different directory, different STORE passphrase.
	// Only the BACKUP passphrase is shared, as a real operator restoring from
	// escrow onto new/replacement hardware would do.
	storeB, err := NewSoftwareStore(t.TempDir(), []byte("store-B-has-a-totally-different-passphrase!"))
	if err != nil {
		t.Fatalf("NewSoftwareStore (B): %v", err)
	}

	if err := storeB.ImportEncryptedKey("cross-mldsa", mldsaBlob, backupPassphrase); err != nil {
		t.Fatalf("ImportEncryptedKey (mldsa) into store B: %v", err)
	}
	mldsaSigner, err := storeB.Signer("cross-mldsa")
	if err != nil {
		t.Fatalf("Signer (mldsa) from store B: %v", err)
	}
	msg := []byte("cross-instance restore for ML-DSA")
	mldsaSig, err := mldsaSigner.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("Sign (mldsa) from store B: %v", err)
	}
	if !mldsa65.Verify(mldsaPub.(*mldsa65.PublicKey), msg, nil, mldsaSig) {
		t.Fatal("ML-DSA signature from store B does not verify against store A's original public key")
	}

	if err := storeB.ImportEncryptedKey("cross-hybrid", hybridBlob, backupPassphrase); err != nil {
		t.Fatalf("ImportEncryptedKey (hybrid) into store B: %v", err)
	}
	restoredPair, err := storeB.LoadHybridKeyPair("cross-hybrid")
	if err != nil {
		t.Fatalf("LoadHybridKeyPair from store B: %v", err)
	}
	digest := sha256.Sum256([]byte("cross-instance restore for hybrid primary"))
	primarySig, err := restoredPair.Primary.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign (hybrid primary) from store B: %v", err)
	}
	if !ecdsa.VerifyASN1(hybridPrimaryPub, digest[:], primarySig) {
		t.Fatal("hybrid primary signature from store B does not verify against store A's original public key")
	}
	secondaryMsg := []byte("cross-instance restore for hybrid secondary")
	secondarySig, err := restoredPair.Secondary.Sign(rand.Reader, secondaryMsg, nil)
	if err != nil {
		t.Fatalf("Sign (hybrid secondary) from store B: %v", err)
	}
	if !mldsa65.Verify(hybridSecondaryPub, secondaryMsg, nil, secondarySig) {
		t.Fatal("hybrid secondary signature from store B does not verify against store A's original public key")
	}
}

// TestImportEncryptedKey_HybridDuplicateIDRejected mirrors the existing
// classical ErrKeyExists guard for the hybrid import path.
func TestImportEncryptedKey_HybridDuplicateIDRejected(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GenerateKey("dup-hybrid", HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data, err := store.ExportEncryptedKey("dup-hybrid", backupPassphrase)
	if err != nil {
		t.Fatalf("ExportEncryptedKey: %v", err)
	}
	if err := store.ImportEncryptedKey("dup-hybrid", data, backupPassphrase); err != ErrKeyExists {
		t.Fatalf("expected ErrKeyExists, got %v", err)
	}
}
