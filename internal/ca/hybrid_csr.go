// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// hybrid_csr.go — custom PKCS#10 CSR creation/parsing for hybrid
// (classical + ML-DSA) keys (G-68/W4-08).
//
// Mirrors hybrid_cert.go's two-pass sign protocol (draft-ounsworth-x509-alt-sig-alg-07)
// but for a CertificationRequestInfo instead of a TBSCertificate: the primary
// SPKI is always classical (encodeLeafSPKI already handles it), and the
// ML-DSA alt-key + alt-signature-algorithm + alt-signature-value are carried
// as a PKCS#9 extensionRequest attribute (RFC 2985 §5.4.2) rather than X.509
// certificate extensions, since a CSR has no top-level Extensions field of
// its own -- reusing encodeExtensionsAttribute/decodeExtensionsAttribute
// (mldsa_csr.go) for the attribute-wrapping mechanics.

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"

	"kryptkeeper/internal/keystore"
)

// HybridCertificateRequest is the parsed, ALREADY-VERIFIED (both primary AND
// alt self-signature) result of a hand-rolled hybrid CSR.
type HybridCertificateRequest struct {
	Subject          pkix.Name
	DNSNames         []string
	IPAddresses      []net.IP
	PrimaryPublicKey crypto.PublicKey // always classical -- keystore.HybridComponents guarantees this
	AltPublicKey     keystore.MLDSAPublicKey
	Algorithm        keystore.Algorithm // e.g. keystore.HybridECDSAP256MLDSA65
}

// CreateCertificateRequestHybrid builds a PKCS#10 CSR carrying a classical
// primary public key AND an ML-DSA alt public key, both self-signed by the
// caller (proving possession of both private keys at CSR time -- this is
// what makes it safe for issueCertificateFromHybridCSR to skip re-proving
// possession on the final cert, per the corrected D-104/G-70 reasoning: a
// classical issuing CA couldn't produce a real ML-DSA issuer signature
// regardless, and chain-level PQC protection isn't this product's accepted
// scope). PEM-encode the result with block type "HYBRID CERTIFICATE
// REQUEST".
//
// Two-pass sign, mirroring CreateCertificateHybrid's protocol exactly:
//  1. Build csrInfo with SAN + AltPublicKey + AltSigAlgorithm attributes
//     (no AltSignatureValue yet). Sign THIS with the ML-DSA signer
//     (full-message) -> altSig.
//  2. Rebuild csrInfo with AltSignatureValue added (containing altSig).
//     Sign the FINAL bytes with the classical signer (hash-then-sign per
//     classicalSignatureAlgOID) -> primary sig. This is the CSR's outer
//     Signature.
func CreateCertificateRequestHybrid(subject pkix.Name, dnsNames []string, ipAddresses []net.IP, classicalSigner, mldsaSigner crypto.Signer, algo keystore.Algorithm) ([]byte, error) {
	classicalAlgo, mldsaAlgo, ok := keystore.HybridComponents(algo)
	if !ok {
		return nil, fmt.Errorf("not a hybrid algorithm: %s", algo)
	}
	classicalOID, hash, ok := classicalSignatureAlgOID(classicalAlgo)
	if !ok {
		return nil, fmt.Errorf("no signature algorithm OID for %s", classicalAlgo)
	}
	mldsaOID, ok := keystore.MLDSAOIDForAlgo(mldsaAlgo)
	if !ok {
		return nil, fmt.Errorf("no OID for ML-DSA algorithm %s", mldsaAlgo)
	}

	primarySPKI, err := encodeLeafSPKI(classicalSigner.Public())
	if err != nil {
		return nil, fmt.Errorf("encode primary public key: %w", err)
	}
	altPub, ok := mldsaSigner.Public().(keystore.MLDSAPublicKey)
	if !ok {
		return nil, fmt.Errorf("ML-DSA signer public key is not MLDSAPublicKey: %T", mldsaSigner.Public())
	}
	altPubBytes, err := altPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal alt public key: %w", err)
	}
	altSPKIDER, err := asn1.Marshal(certSPKI{
		Algorithm: certAlgID{Algorithm: mldsaOID},
		PublicKey: asn1.BitString{Bytes: altPubBytes, BitLength: len(altPubBytes) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal alt SPKI: %w", err)
	}
	altSigAlgoDER, err := asn1.Marshal(certAlgID{Algorithm: mldsaOID})
	if err != nil {
		return nil, fmt.Errorf("marshal alt signature algorithm: %w", err)
	}

	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}

	sanValue, err := marshalSANValue(dnsNames, ipAddresses)
	if err != nil {
		return nil, fmt.Errorf("marshal SAN value: %w", err)
	}

	// Pass 1: SAN + AltPublicKey + AltSigAlgorithm, no AltSignatureValue yet.
	extsPass1 := []certExtension{}
	if sanValue != nil {
		extsPass1 = append(extsPass1, certExtension{Id: oidSubjectAltName, Value: sanValue})
	}
	extsPass1 = append(extsPass1,
		certExtension{Id: oidAltSubjectPublicKeyInfo, Value: altSPKIDER},
		certExtension{Id: oidAltSignatureAlgorithm, Value: altSigAlgoDER},
	)
	attrsPass1, err := encodeExtensionsAttribute(extsPass1)
	if err != nil {
		return nil, fmt.Errorf("encode pass-1 attributes: %w", err)
	}
	if attrsPass1 == nil {
		attrsPass1 = []asn1.RawValue{}
	}
	infoPass1 := csrInfo{Subject: asn1.RawValue{FullBytes: subjectDER}, PublicKey: primarySPKI, Attributes: attrsPass1}
	infoPass1DER, err := asn1.Marshal(infoPass1)
	if err != nil {
		return nil, fmt.Errorf("marshal pass-1 CertificationRequestInfo: %w", err)
	}

	altSig, err := mldsaSigner.Sign(rand.Reader, infoPass1DER, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ML-DSA sign pass-1: %w", err)
	}
	altSigDER, err := asn1.Marshal(asn1.BitString{Bytes: altSig, BitLength: len(altSig) * 8})
	if err != nil {
		return nil, fmt.Errorf("marshal alt signature value: %w", err)
	}

	// Pass 2: same extensions plus AltSignatureValue.
	extsFinal := append(extsPass1, certExtension{Id: oidAltSignatureValue, Value: altSigDER})
	attrsFinal, err := encodeExtensionsAttribute(extsFinal)
	if err != nil {
		return nil, fmt.Errorf("encode final attributes: %w", err)
	}
	infoFinal := csrInfo{Subject: asn1.RawValue{FullBytes: subjectDER}, PublicKey: primarySPKI, Attributes: attrsFinal}
	infoFinalDER, err := asn1.Marshal(infoFinal)
	if err != nil {
		return nil, fmt.Errorf("marshal final CertificationRequestInfo: %w", err)
	}

	sig, err := signTBS(classicalSigner, infoFinalDER, hash)
	if err != nil {
		return nil, fmt.Errorf("sign final CertificationRequestInfo: %w", err)
	}

	outer := outerCSR{
		CertificationRequestInfo: asn1.RawValue{FullBytes: infoFinalDER},
		SignatureAlgorithm:       certAlgID{Algorithm: classicalOID},
		Signature:                asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	return asn1.Marshal(outer)
}

// ParseCertificateRequestHybrid parses AND verifies BOTH the primary
// (classical) and alt (ML-DSA) self-signatures -- a hybrid CSR with only
// one valid signature is a parse error, not a partial success. This is the
// direct fix for G-67's original failure mode: never let a caller mistake a
// classical-only-verified result for a fully-verified hybrid one.
func ParseCertificateRequestHybrid(der []byte) (*HybridCertificateRequest, error) {
	var outer outerCSR
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CertificationRequest: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after CertificationRequest")
	}

	var infoFinal csrInfo
	if _, err := asn1.Unmarshal(outer.CertificationRequestInfo.FullBytes, &infoFinal); err != nil {
		return nil, fmt.Errorf("unmarshal CertificationRequestInfo: %w", err)
	}

	// Reconstruct the classical primary public key: certSPKI's shape IS
	// exactly SubjectPublicKeyInfo's shape, so re-marshal it standalone and
	// hand it to x509.ParsePKIXPublicKey (encodeLeafSPKI's classical branch's
	// exact inverse).
	primarySPKIDER, err := asn1.Marshal(infoFinal.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("re-marshal primary SPKI: %w", err)
	}
	primaryPub, err := x509.ParsePKIXPublicKey(primarySPKIDER)
	if err != nil {
		return nil, fmt.Errorf("parse primary public key: %w", err)
	}

	exts, err := decodeExtensionsAttribute(infoFinal.Attributes)
	if err != nil {
		return nil, fmt.Errorf("decode extensionRequest attributes: %w", err)
	}
	var altSPKIDER, altSigDER []byte
	var sanValue []byte
	for _, ext := range exts {
		switch {
		case ext.Id.Equal(oidAltSubjectPublicKeyInfo):
			var spki certSPKI
			if _, err := asn1.Unmarshal(ext.Value, &spki); err != nil {
				return nil, fmt.Errorf("unmarshal alt SPKI: %w", err)
			}
			altSPKIDER = ext.Value
			_ = spki
		case ext.Id.Equal(oidAltSignatureValue):
			altSigDER = ext.Value
		case ext.Id.Equal(oidSubjectAltName):
			sanValue = ext.Value
		}
	}
	if altSPKIDER == nil || altSigDER == nil {
		return nil, fmt.Errorf("not a valid hybrid CSR: missing alt public key or alt signature")
	}

	var altSPKI certSPKI
	if _, err := asn1.Unmarshal(altSPKIDER, &altSPKI); err != nil {
		return nil, fmt.Errorf("unmarshal alt SPKI: %w", err)
	}
	mldsaAlgo, ok := mldsaAlgoFromOID(altSPKI.Algorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("unrecognized alt algorithm OID %v", altSPKI.Algorithm.Algorithm)
	}
	altPub, err := unmarshalMLDSAPublicKey(mldsaAlgo, altSPKI.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal alt public key: %w", err)
	}

	var altSigBS asn1.BitString
	if _, err := asn1.Unmarshal(altSigDER, &altSigBS); err != nil {
		return nil, fmt.Errorf("unmarshal alt signature: %w", err)
	}

	// Re-derive pass-1 bytes: same extension set MINUS AltSignatureValue, in
	// the SAME order encode used (SAN, AltPublicKey, AltSigAlgorithm) -- no
	// shortcut, the pass-1 bytes are not otherwise recoverable from the final DER.
	extsPass1 := []certExtension{}
	if sanValue != nil {
		extsPass1 = append(extsPass1, certExtension{Id: oidSubjectAltName, Value: sanValue})
	}
	extsPass1 = append(extsPass1,
		certExtension{Id: oidAltSubjectPublicKeyInfo, Value: altSPKIDER},
		certExtension{Id: oidAltSignatureAlgorithm, Value: mustMarshalAltSigAlgo(altSPKI.Algorithm.Algorithm)},
	)
	attrsPass1, err := encodeExtensionsAttribute(extsPass1)
	if err != nil {
		return nil, fmt.Errorf("re-encode pass-1 attributes: %w", err)
	}
	if attrsPass1 == nil {
		attrsPass1 = []asn1.RawValue{}
	}
	infoPass1 := csrInfo{Subject: infoFinal.Subject, PublicKey: infoFinal.PublicKey, Attributes: attrsPass1}
	infoPass1DER, err := asn1.Marshal(infoPass1)
	if err != nil {
		return nil, fmt.Errorf("re-marshal pass-1 CertificationRequestInfo: %w", err)
	}

	if !verifyMLDSA(mldsaAlgo, altPub, infoPass1DER, altSigBS.Bytes) {
		return nil, fmt.Errorf("invalid alt (ML-DSA) CSR self-signature")
	}

	classicalAlgo, hash, ok := classicalAlgoFromOID(outer.SignatureAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("unrecognized primary signature algorithm OID %v", outer.SignatureAlgorithm.Algorithm)
	}
	if !verifyClassicalCSRSignature(classicalAlgo, hash, primaryPub, outer.CertificationRequestInfo.FullBytes, outer.Signature.Bytes) {
		return nil, fmt.Errorf("invalid primary (classical) CSR self-signature")
	}

	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(infoFinal.Subject.FullBytes, &rdn); err != nil {
		return nil, fmt.Errorf("unmarshal subject: %w", err)
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&rdn)

	dnsNames, ipAddresses, err := unmarshalSANValue(sanValue)
	if sanValue != nil && err != nil {
		return nil, fmt.Errorf("unmarshal SAN: %w", err)
	}

	hybridAlgo, ok := hybridAlgoFromComponents(classicalAlgo, mldsaAlgo)
	if !ok {
		return nil, fmt.Errorf("no hybrid algorithm for classical=%s mldsa=%s", classicalAlgo, mldsaAlgo)
	}

	return &HybridCertificateRequest{
		Subject:          subject,
		DNSNames:         dnsNames,
		IPAddresses:      ipAddresses,
		PrimaryPublicKey: primaryPub,
		AltPublicKey:     altPub,
		Algorithm:        hybridAlgo,
	}, nil
}

// mustMarshalAltSigAlgo re-marshals an already-known OID back into a
// certAlgID DER blob, for re-deriving pass-1 bytes during parse (mirrors
// exactly what CreateCertificateRequestHybrid marshaled in pass 1).
func mustMarshalAltSigAlgo(oid asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(certAlgID{Algorithm: oid})
	if err != nil {
		// Re-marshaling an OID we just successfully unmarshaled cannot fail.
		panic(fmt.Sprintf("re-marshal alt sig algorithm: %v", err))
	}
	return der
}

// classicalAlgoFromOID maps a classical AlgorithmIdentifier OID back to a
// keystore.Algorithm + its hash function -- the parse-side counterpart of
// classicalSignatureAlgOID.
func classicalAlgoFromOID(oid asn1.ObjectIdentifier) (keystore.Algorithm, crypto.Hash, bool) {
	for _, algo := range []keystore.Algorithm{keystore.ECDSAP256, keystore.ECDSAP384, keystore.RSA2048, keystore.Ed25519} {
		candidateOID, hash, _ := classicalSignatureAlgOID(algo)
		if candidateOID.Equal(oid) {
			return algo, hash, true
		}
	}
	return "", 0, false
}

// hybridAlgoFromComponents maps a (classical, ML-DSA) pair back to the
// keystore.Algorithm hybrid constant -- the inverse of keystore.HybridComponents.
func hybridAlgoFromComponents(classical, mldsa keystore.Algorithm) (keystore.Algorithm, bool) {
	for _, algo := range []keystore.Algorithm{keystore.HybridECDSAP256MLDSA65, keystore.HybridECDSAP384MLDSA87} {
		c, m, _ := keystore.HybridComponents(algo)
		if c == classical && m == mldsa {
			return algo, true
		}
	}
	return "", false
}
