// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

// PKCS#8 (RFC 5958 OneAsymmetricKey) encoding of ML-DSA private keys per
// RFC 9881 section 6, for delivery to TLS endpoints that need a standard
// "PRIVATE KEY" file. x509.MarshalPKCS8PrivateKey rejects ML-DSA keys, so this
// is hand-built DER.
//
//	OneAsymmetricKey ::= SEQUENCE {
//	  version              INTEGER (0),
//	  privateKeyAlgorithm  SEQUENCE { OID id-ml-dsa-XX }   -- parameters ABSENT
//	  privateKey           OCTET STRING (CONTAINING ML-DSA-XX-PrivateKey)
//	}
//	ML-DSA-XX-PrivateKey ::= CHOICE {
//	  seed        [0] IMPLICIT OCTET STRING (SIZE (32)),   -- 80 20 <32 bytes>
//	  expandedKey     OCTET STRING (SIZE (2560|4032|4896)),
//	  both        SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }
//
// Form chosen: the seed form (RFC-RECOMMENDED) when the circl key still holds
// its seed (freshly generated in-process); otherwise expandedKey. Keys loaded
// from the software store were persisted as MarshalBinary (expanded) bytes and
// UnmarshalBinary cannot recover the seed, so stored keys export as expandedKey.
// The parser accepts all three CHOICE forms and, for "both", checks that the
// seed regenerates the expanded key.

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ErrPrivateKeyNotExportable is returned when a backend cannot (or must not)
// release private key material as PKCS#8 (HSM, cloud KMS, Vault, hybrid IDs).
var ErrPrivateKeyNotExportable = errors.New("private key is not exportable from this backend")

const mldsaSeedSize = 32

type pkcs8AlgID struct {
	Algorithm asn1.ObjectIdentifier // parameters deliberately absent
}

type pkcs8Envelope struct {
	Version    int
	Algo       pkcs8AlgID
	PrivateKey []byte
}

type mldsaBoth struct {
	Seed        []byte
	ExpandedKey []byte
}

// mldsaSizes returns the expanded private-key size for each level.
func mldsaExpandedSize(algo Algorithm) int {
	switch algo {
	case MLDSA44:
		return mldsa44.PrivateKeySize
	case MLDSA65:
		return mldsa65.PrivateKeySize
	default:
		return mldsa87.PrivateKeySize
	}
}

// MarshalMLDSAPKCS8 encodes an ML-DSA private key as unencrypted PKCS#8 DER.
// The caller owns the result and should zeroize it after use. Intermediate
// private buffers are zeroized before return.
func MarshalMLDSAPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	algo, expanded, ok := marshalMLDSAPrivateKey(priv)
	if !ok {
		return nil, fmt.Errorf("%w: not an ML-DSA private key", ErrUnsupportedAlgo)
	}
	defer zeroizeBytes(expanded)
	oid, _ := MLDSAOIDForAlgo(algo)

	var seed []byte
	switch sk := priv.(type) {
	case *mldsa44.PrivateKey:
		seed = sk.Seed()
	case *mldsa65.PrivateKey:
		seed = sk.Seed()
	case *mldsa87.PrivateKey:
		seed = sk.Seed()
	}

	var inner []byte
	var err error
	if len(seed) == mldsaSeedSize {
		// [0] IMPLICIT OCTET STRING: context tag 0, primitive => 0x80.
		inner = append([]byte{0x80, byte(mldsaSeedSize)}, seed...)
	} else {
		inner, err = asn1.Marshal(expanded) // plain OCTET STRING
		if err != nil {
			return nil, fmt.Errorf("encode expandedKey: %w", err)
		}
	}
	defer zeroizeBytes(inner)

	der, err := asn1.Marshal(pkcs8Envelope{Version: 0, Algo: pkcs8AlgID{Algorithm: oid}, PrivateKey: inner})
	if err != nil {
		return nil, fmt.Errorf("encode PKCS#8: %w", err)
	}
	return der, nil
}

func mldsaAlgoFromOID(oid asn1.ObjectIdentifier) (Algorithm, bool) {
	for _, a := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		if o, _ := MLDSAOIDForAlgo(a); o.Equal(oid) {
			return a, true
		}
	}
	return "", false
}

// ParseMLDSAPKCS8 parses an RFC 9881 PKCS#8 ML-DSA private key (seed,
// expandedKey or both forms). It rejects non-ML-DSA OIDs, present algorithm
// parameters, trailing data, an attributes/publicKey extension, and wrong lengths.
func ParseMLDSAPKCS8(der []byte) (crypto.Signer, Algorithm, error) {
	var raw struct {
		Version int
		Algo    struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PrivateKey []byte
	}
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse PKCS#8: %w", err)
	}
	if len(rest) != 0 {
		return nil, "", errors.New("parse PKCS#8: trailing data")
	}
	defer zeroizeBytes(raw.PrivateKey)
	if raw.Version != 0 {
		return nil, "", fmt.Errorf("unsupported PKCS#8 version %d", raw.Version)
	}
	algo, ok := mldsaAlgoFromOID(raw.Algo.Algorithm)
	if !ok {
		return nil, "", fmt.Errorf("%w: OID %v is not ML-DSA", ErrUnsupportedAlgo, raw.Algo.Algorithm)
	}
	if len(raw.Algo.Parameters.FullBytes) != 0 {
		return nil, "", errors.New("ML-DSA AlgorithmIdentifier parameters must be absent")
	}

	pk := raw.PrivateKey
	if len(pk) == 0 {
		return nil, "", errors.New("empty privateKey")
	}
	var seed, expanded []byte
	switch pk[0] {
	case 0x80: // seed [0]
		if len(pk) != 2+mldsaSeedSize || pk[1] != mldsaSeedSize {
			return nil, "", errors.New("invalid ML-DSA seed encoding")
		}
		seed = pk[2:]
	case 0x04: // expandedKey
		var b []byte
		r, err := asn1.Unmarshal(pk, &b)
		if err != nil || len(r) != 0 {
			return nil, "", errors.New("invalid ML-DSA expandedKey encoding")
		}
		expanded = b
		defer zeroizeBytes(b)
	case 0x30: // both
		var bo mldsaBoth
		r, err := asn1.Unmarshal(pk, &bo)
		if err != nil || len(r) != 0 {
			return nil, "", errors.New("invalid ML-DSA both encoding")
		}
		defer zeroizeBytes(bo.Seed)
		defer zeroizeBytes(bo.ExpandedKey)
		seed, expanded = bo.Seed, bo.ExpandedKey
	default:
		return nil, "", errors.New("unrecognised ML-DSA-PrivateKey CHOICE")
	}
	if seed != nil && len(seed) != mldsaSeedSize {
		return nil, "", errors.New("ML-DSA seed must be 32 bytes")
	}
	if expanded != nil && len(expanded) != mldsaExpandedSize(algo) {
		return nil, "", fmt.Errorf("ML-DSA expandedKey must be %d bytes for %s", mldsaExpandedSize(algo), algo)
	}

	var signer crypto.Signer
	if seed != nil {
		signer = mldsaFromSeed(algo, seed)
	}
	if expanded != nil {
		sk, err := reconstructMLDSASigner(algo, expanded)
		if err != nil {
			return nil, "", err
		}
		if signer != nil { // "both": seed must regenerate the expanded key
			_, a, _ := marshalMLDSAPrivateKey(signer)
			_, b, _ := marshalMLDSAPrivateKey(sk)
			same := bytes.Equal(a, b)
			zeroizeBytes(a)
			zeroizeBytes(b)
			if !same {
				return nil, "", errors.New("ML-DSA seed does not match expandedKey")
			}
		} else {
			signer = sk
		}
	}
	return signer, algo, nil
}

func mldsaFromSeed(algo Algorithm, seed []byte) crypto.Signer {
	switch algo {
	case MLDSA44:
		var s [mldsa44.SeedSize]byte
		copy(s[:], seed)
		_, sk := mldsa44.NewKeyFromSeed(&s)
		return sk
	case MLDSA65:
		var s [mldsa65.SeedSize]byte
		copy(s[:], seed)
		_, sk := mldsa65.NewKeyFromSeed(&s)
		return sk
	default:
		var s [mldsa87.SeedSize]byte
		copy(s[:], seed)
		_, sk := mldsa87.NewKeyFromSeed(&s)
		return sk
	}
}

// marshalPrivateKeyPKCS8 encodes any supported private key (ML-DSA or classical)
// as PKCS#8 DER.
func marshalPrivateKeyPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	if _, _, ok := marshalMLDSAPrivateKey(priv); ok {
		return MarshalMLDSAPKCS8(priv)
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

// PrivateKeyPKCS8Exporter is implemented by stores that hold exportable
// software keys. Deliberately not part of Store and not exposed over HTTP.
type PrivateKeyPKCS8Exporter interface {
	ExportPrivateKeyPKCS8(id string) ([]byte, error)
}

// ExportPrivateKeyPKCS8 returns unencrypted PKCS#8 DER for key id. The caller
// MUST zeroize the result. Refused (ErrPrivateKeyNotExportable) for hybrid IDs
// and for HSM/cloud/Vault backends.
func (s *SoftwareStore) ExportPrivateKeyPKCS8(id string) ([]byte, error) {
	if s.isHybridID(id) {
		return nil, fmt.Errorf("%w: hybrid keys have no single PKCS#8 form", ErrPrivateKeyNotExportable)
	}
	s.mu.Lock()
	priv, err := s.loadAndDecrypt(id)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("export pkcs8: %w", err)
	}
	return marshalPrivateKeyPKCS8(priv)
}

// ExportPrivateKeyPKCS8 routes to the owning backend; non-software backends
// return ErrPrivateKeyNotExportable.
func (r *Router) ExportPrivateKeyPKCS8(id string) ([]byte, error) {
	if e, ok := r.storeFor(id).(PrivateKeyPKCS8Exporter); ok {
		return e.ExportPrivateKeyPKCS8(id)
	}
	return nil, fmt.Errorf("%w: key %s lives in a non-software backend", ErrPrivateKeyNotExportable, id)
}
