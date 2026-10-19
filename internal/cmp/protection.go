// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // owf/mac algorithm choice, not used for confidentiality; SHA-1 tolerated per RFC 4210 §5.1.3.1 legacy interop
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"

	"kryptkeeper/internal/logging"
)

// oidPasswordBasedMac is RFC 4210 §5.1.3.1's id-PasswordBasedMac
// (1.2.840.113533.7.66.13) — the only protection scheme this server
// verifies or produces. Signature-based protection (RFC 4210 §5.1.3.2,
// client cert+key) is a documented gap: see docs/STATUS.md W19-16.
var oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}

// Well-known owf/mac algorithm OIDs a PBMParameter plausibly names.
var (
	oidSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	// oidPBMHMACSHA1 is the original CMP (RFC 2510) default MAC alg under
	// the PasswordBasedMac arc itself, still sent by some clients.
	oidPBMHMACSHA1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
)

// pbmParameter is RFC 4210 §5.1.3.1's PBMParameter.
type pbmParameter struct {
	Salt           []byte
	Owf            pkix.AlgorithmIdentifier
	IterationCount int
	Mac            pkix.AlgorithmIdentifier
}

func hashForOID(oid asn1.ObjectIdentifier) (func() hash.Hash, bool, error) {
	switch {
	case oid.Equal(oidSHA256):
		return sha256.New, false, nil
	case oid.Equal(oidSHA1):
		return sha1.New, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported owf algorithm OID %s", oid.String())
	}
}

func macHashForOID(oid asn1.ObjectIdentifier) (func() hash.Hash, bool, error) {
	switch {
	case oid.Equal(oidHMACSHA256):
		return sha256.New, false, nil
	case oid.Equal(oidHMACSHA1), oid.Equal(oidPBMHMACSHA1):
		return sha1.New, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported mac algorithm OID %s", oid.String())
	}
}

// computePBM implements RFC 4210 §5.1.3.1's key derivation and MAC: the
// shared secret is concatenated with salt and hashed with owf
// iterationCount times to derive the HMAC key, which then MACs
// protectedPart.
func computePBM(secret []byte, param pbmParameter, protectedPart []byte) ([]byte, bool, error) {
	owf, owfIsSHA1, err := hashForOID(param.Owf.Algorithm)
	if err != nil {
		return nil, false, err
	}
	macAlg, macIsSHA1, err := macHashForOID(param.Mac.Algorithm)
	if err != nil {
		return nil, false, err
	}
	if param.IterationCount <= 0 || param.IterationCount > 1_000_000 {
		return nil, false, fmt.Errorf("iterationCount %d out of range", param.IterationCount)
	}

	key := append(append([]byte{}, secret...), param.Salt...)
	h := owf()
	for i := 0; i < param.IterationCount; i++ {
		h.Reset()
		h.Write(key)
		key = h.Sum(nil)
	}

	mac := hmac.New(macAlg, key)
	mac.Write(protectedPart)
	return mac.Sum(nil), owfIsSHA1 || macIsSHA1, nil
}

// protectedPartDER re-encodes ProtectedPart ::= SEQUENCE { header, body }
// from the header/body's already-captured DER (RawValue.FullBytes) —
// RFC 4210 §5.1.3 protects exactly these two fields' encoded bytes.
func protectedPartDER(headerFullBytes, bodyFullBytes []byte) ([]byte, error) {
	content := make([]byte, 0, len(headerFullBytes)+len(bodyFullBytes))
	content = append(content, headerFullBytes...)
	content = append(content, bodyFullBytes...)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// verifyPBMProtection checks a PKIMessage's [0] protection field against the
// configured shared secret. It is the RFC 4210 §5.1.3 gate: no protection,
// an unsupported protection algorithm, or a MAC mismatch are all rejected
// identically (badMessageCheck) so as not to leak which failed.
func verifyPBMProtection(hdr *parsedHeader, protection asn1.RawValue, bodyFullBytes []byte, secret []byte) error {
	if hdr.ProtectionAlg == nil {
		return fmt.Errorf("badMessageCheck: message is not protected")
	}
	if !hdr.ProtectionAlg.Algorithm.Equal(oidPasswordBasedMac) {
		return fmt.Errorf("badMessageCheck: unsupported protection algorithm %s (only PasswordBasedMac is supported)", hdr.ProtectionAlg.Algorithm.String())
	}
	if len(protection.FullBytes) == 0 {
		return fmt.Errorf("badMessageCheck: protection field missing")
	}

	var param pbmParameter
	if _, err := asn1.Unmarshal(hdr.ProtectionAlg.Parameters.FullBytes, &param); err != nil {
		return fmt.Errorf("badMessageCheck: parse PBMParameter: %w", err)
	}

	// PKIMessage's [0] protection field is EXPLICIT (RFC 4210's PKIXCMP
	// module default), so protection.Bytes is already the complete BIT
	// STRING encoding, not bare content needing a re-tag.
	var received asn1.BitString
	if _, err := asn1.Unmarshal(protection.Bytes, &received); err != nil {
		return fmt.Errorf("badMessageCheck: parse protection BIT STRING: %w", err)
	}

	protectedPart, err := protectedPartDER(hdr.RawFullBytes, bodyFullBytes)
	if err != nil {
		return fmt.Errorf("badMessageCheck: %w", err)
	}

	expected, usedSHA1, err := computePBM(secret, param, protectedPart)
	if err != nil {
		return fmt.Errorf("badMessageCheck: %w", err)
	}
	if usedSHA1 {
		logging.Info("cmp: peer used SHA-1 in PBM owf/mac — tolerated for interop, prefer SHA-256")
	}

	if !hmac.Equal(expected, received.RightAlign()) {
		return fmt.Errorf("badMessageCheck: MAC mismatch")
	}
	return nil
}

// newPBMAlgorithmIdentifier picks fresh PBM parameters (random salt,
// SHA-256 owf/mac, a fixed iteration count matching common client defaults)
// for a response this server is about to protect. Returns both the
// AlgorithmIdentifier to place in the header's protectionAlg and the
// pbmParameter itself so the caller can MAC over the exact header it builds
// from that AlgorithmIdentifier's DER.
func newPBMAlgorithmIdentifier() (pkix.AlgorithmIdentifier, pbmParameter, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return pkix.AlgorithmIdentifier{}, pbmParameter{}, fmt.Errorf("cmp: generate PBM salt: %w", err)
	}
	const iterationCount = 1000

	param := pbmParameter{
		Salt:           salt,
		Owf:            pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		IterationCount: iterationCount,
		Mac:            pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256},
	}
	paramDER, err := asn1.Marshal(param)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, pbmParameter{}, fmt.Errorf("cmp: marshal PBMParameter: %w", err)
	}

	return pkix.AlgorithmIdentifier{
		Algorithm:  oidPasswordBasedMac,
		Parameters: asn1.RawValue{FullBytes: paramDER},
	}, param, nil
}
