// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// W9-08: PQC-keys-are-software-only is an explicit, ADR-citing refusal —
// and the software store really does hold+sign ML-DSA today.

func TestHSMBackendsRefusePQCAlgorithms(t *testing.T) {
	pqc := []Algorithm{MLDSA44, MLDSA65, MLDSA87, HybridECDSAP256MLDSA65, HybridECDSAP384MLDSA87}
	for _, backend := range []string{"pkcs11", "cloudkms", "vault"} {
		for _, algo := range pqc {
			err := CheckHSMPQCSupport(backend, algo)
			if err == nil {
				t.Errorf("%s/%s: PQC on a hardware backend must be refused", backend, algo)
				continue
			}
			if !errors.Is(err, ErrPQCHSMUnsupported) {
				t.Errorf("%s/%s: refusal must wrap ErrPQCHSMUnsupported, got %v", backend, algo, err)
			}
			if !strings.Contains(err.Error(), "ADR_PQC_KEYS_SOFTWARE_ONLY") {
				t.Errorf("%s/%s: refusal must cite the ADR, got: %v", backend, algo, err)
			}
		}
	}
}

func TestClassicalAlgorithmsPassHSMCheck(t *testing.T) {
	for _, algo := range []Algorithm{RSA2048, RSA4096, ECDSAP256, ECDSAP384, Ed25519} {
		if err := CheckHSMPQCSupport("pkcs11", algo); err != nil {
			t.Errorf("pkcs11/%s: classical algorithm wrongly refused: %v", algo, err)
		}
	}
}

func TestSoftwareBackendAcceptsPQC(t *testing.T) {
	// The ADR's asymmetry: software is the sanctioned home for PQC keys.
	if err := CheckHSMPQCSupport("software", MLDSA65); err != nil {
		t.Fatalf("software backend must accept ML-DSA: %v", err)
	}
	if err := CheckHSMPQCSupport("", HybridECDSAP384MLDSA87); err != nil {
		t.Fatalf("default backend must accept hybrids: %v", err)
	}
}

func TestSoftwareStoreStillGeneratesAndSignsMLDSA(t *testing.T) {
	// The risk the ADR accepts only makes sense if PQC actually works in
	// the software store — pin that.
	store, err := NewSoftwareStore(t.TempDir(), []byte("pqc-software-only-passphrase-32!"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	if _, err := store.GenerateKey("pqc-proof", MLDSA65); err != nil {
		t.Fatalf("software ML-DSA generate: %v", err)
	}
	signer, err := store.Signer("pqc-proof")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	sig, err := signer.Sign(rand.Reader, []byte("adr-w9-08 signing proof"), crypto.Hash(0))
	if err != nil {
		t.Fatalf("software ML-DSA sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty ML-DSA signature")
	}
}
