// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

// ML-DSA key storage for NIST FIPS 204 post-quantum digital signatures.
//
// Go's x509 package only supports RSA, ECDSA, and Ed25519 — it rejects ML-DSA keys in
// both MarshalPKCS8PrivateKey and CreateCertificate. We therefore:
//   - Store ML-DSA private keys using raw MarshalBinary bytes (not PKCS#8)
//   - Use custom PEM block types that encode the algorithm ("ENCRYPTED ML-DSA-65 PRIVATE KEY")
//   - Use our own CreateCertificateMLDSA in internal/ca/ instead of x509.CreateCertificate
//
// Migration path: when Go adds crypto/mldsa (~Go 1.27), drop this file and use stdlib.

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ML-DSA OIDs per NIST FIPS 204 / draft-ietf-lamps-dilithium-certificates.
var (
	OIDMLDsa44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDsa65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDsa87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// PEM block types used to identify ML-DSA key files on disk.
const (
	pemTypeMLDSA44 = "ENCRYPTED ML-DSA-44 PRIVATE KEY"
	pemTypeMLDSA65 = "ENCRYPTED ML-DSA-65 PRIVATE KEY"
	pemTypeMLDSA87 = "ENCRYPTED ML-DSA-87 PRIVATE KEY"
)

// MLDSAPublicKey is a common interface for all ML-DSA public key variants.
type MLDSAPublicKey interface {
	crypto.PublicKey
	MarshalBinary() ([]byte, error)
}

// mldsaAlgoFromPEMType returns the Algorithm for a given ML-DSA PEM block type.
func mldsaAlgoFromPEMType(t string) (Algorithm, bool) {
	switch t {
	case pemTypeMLDSA44:
		return MLDSA44, true
	case pemTypeMLDSA65:
		return MLDSA65, true
	case pemTypeMLDSA87:
		return MLDSA87, true
	}
	return "", false
}

// mldsaPEMTypeForAlgo returns the PEM block type for a given ML-DSA Algorithm.
func mldsaPEMTypeForAlgo(algo Algorithm) (string, bool) {
	switch algo {
	case MLDSA44:
		return pemTypeMLDSA44, true
	case MLDSA65:
		return pemTypeMLDSA65, true
	case MLDSA87:
		return pemTypeMLDSA87, true
	}
	return "", false
}

// MLDSAOIDForAlgo returns the ASN.1 OID for the given ML-DSA algorithm.
// Exported so internal/ca/mldsa_cert.go can reference it without duplication.
func MLDSAOIDForAlgo(algo Algorithm) (asn1.ObjectIdentifier, bool) {
	switch algo {
	case MLDSA44:
		return OIDMLDsa44, true
	case MLDSA65:
		return OIDMLDsa65, true
	case MLDSA87:
		return OIDMLDsa87, true
	}
	return nil, false
}

// IsMLDSA reports whether the algorithm is an ML-DSA variant.
// Exported so internal/ca can dispatch to the custom cert-creation path.
func IsMLDSA(algo Algorithm) bool {
	_, ok := MLDSAOIDForAlgo(algo)
	return ok
}

// isMLDSA is the package-private alias used within keystore itself.
func isMLDSA(algo Algorithm) bool { return IsMLDSA(algo) }

// generateMLDSAKey creates a new ML-DSA keypair and returns
// (signerBytes, publicKey, crypto.Signer, error).
// signerBytes is the raw private key from MarshalBinary — used for encrypted storage.
func generateMLDSAKey(rand io.Reader, algo Algorithm) (privBytes []byte, pub MLDSAPublicKey, signer crypto.Signer, err error) {
	switch algo {
	case MLDSA44:
		pk, sk, e := mldsa44.GenerateKey(rand)
		if e != nil {
			return nil, nil, nil, e
		}
		b, e := sk.MarshalBinary()
		if e != nil {
			return nil, nil, nil, e
		}
		return b, pk, sk, nil

	case MLDSA65:
		pk, sk, e := mldsa65.GenerateKey(rand)
		if e != nil {
			return nil, nil, nil, e
		}
		b, e := sk.MarshalBinary()
		if e != nil {
			return nil, nil, nil, e
		}
		return b, pk, sk, nil

	case MLDSA87:
		pk, sk, e := mldsa87.GenerateKey(rand)
		if e != nil {
			return nil, nil, nil, e
		}
		b, e := sk.MarshalBinary()
		if e != nil {
			return nil, nil, nil, e
		}
		return b, pk, sk, nil

	default:
		return nil, nil, nil, fmt.Errorf("not an ML-DSA algorithm: %s", algo)
	}
}

// reconstructMLDSASigner rebuilds a crypto.Signer from raw key bytes stored on disk.
func reconstructMLDSASigner(algo Algorithm, privBytes []byte) (crypto.Signer, error) {
	switch algo {
	case MLDSA44:
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(privBytes); err != nil {
			return nil, fmt.Errorf("unmarshal ML-DSA-44 key: %w", err)
		}
		return &sk, nil

	case MLDSA65:
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(privBytes); err != nil {
			return nil, fmt.Errorf("unmarshal ML-DSA-65 key: %w", err)
		}
		return &sk, nil

	case MLDSA87:
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(privBytes); err != nil {
			return nil, fmt.Errorf("unmarshal ML-DSA-87 key: %w", err)
		}
		return &sk, nil

	default:
		return nil, fmt.Errorf("not an ML-DSA algorithm: %s", algo)
	}
}

// marshalMLDSAPrivateKey returns the algorithm and raw MarshalBinary bytes for
// an already-loaded ML-DSA private key (e.g. one returned by loadAndDecrypt),
// or ok=false if privKey is not an ML-DSA key. Used by ExportEncryptedKey
// (W9-03) since x509.MarshalPKCS8PrivateKey rejects these key types.
func marshalMLDSAPrivateKey(privKey crypto.PrivateKey) (algo Algorithm, raw []byte, ok bool) {
	switch sk := privKey.(type) {
	case *mldsa44.PrivateKey:
		b, err := sk.MarshalBinary()
		if err != nil {
			return "", nil, false
		}
		return MLDSA44, b, true
	case *mldsa65.PrivateKey:
		b, err := sk.MarshalBinary()
		if err != nil {
			return "", nil, false
		}
		return MLDSA65, b, true
	case *mldsa87.PrivateKey:
		b, err := sk.MarshalBinary()
		if err != nil {
			return "", nil, false
		}
		return MLDSA87, b, true
	default:
		return "", nil, false
	}
}
