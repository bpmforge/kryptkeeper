// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// MinRSAKeyBits is the smallest RSA modulus the unauthenticated-by-policy
// enrolment protocols (ACME, CMP) will certify. PolicyEngine.Check passes
// when no policy rows exist, so this floor cannot live in data alone.
const MinRSAKeyBits = 2048

// CheckPublicKeyStrength rejects keys too weak to certify: RSA below
// MinRSAKeyBits, ECDSA curves other than P-256/P-384/P-521, and any key type
// other than RSA, ECDSA or Ed25519 (ML-DSA/hybrid requests do not arrive as
// x509.CertificateRequest and are gated by the engine's own algorithm checks).
func CheckPublicKeyStrength(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N == nil || k.N.BitLen() < MinRSAKeyBits {
			return fmt.Errorf("RSA key must be at least %d bits", MinRSAKeyBits)
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return fmt.Errorf("ECDSA curve %s is not allowed", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	return nil
}

// PublicKeyBits reports the classical key size in bits (RSA modulus length,
// EC curve size, 256 for Ed25519), or 0 when the key is not one Go's x509
// parser exposes. A pure ML-DSA subject key is not parseable by crypto/x509
// (PublicKey is nil), and a hybrid cert's SubjectPublicKeyInfo is classical by
// design, so for both the reported size is the classical SPKI or 0 -- never a
// guessed PQC strength that no consumer of this field could interpret
// alongside RSA/EC bit lengths.
func PublicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N == nil {
			return 0
		}
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
