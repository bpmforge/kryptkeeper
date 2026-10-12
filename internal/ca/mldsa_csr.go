// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// mldsa_csr.go — custom PKCS#10 CSR creation/parsing for ML-DSA keys (G-67/W4-07).
//
// Go's x509.CreateCertificateRequest/ParseCertificateRequest only support RSA,
// ECDSA, and Ed25519, the same restriction mldsa_cert.go already documents for
// certificate creation. This file is the CSR-shaped equivalent: it hand-rolls
// RFC 2986's CertificationRequest ASN.1 structure, reusing mldsa_cert.go's
// certAlgID/certSPKI types and encodeLeafSPKI/mldsaOIDFromPubSize helpers
// (same package, no export needed).

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"kryptkeeper/internal/keystore"
)

// oidExtensionRequest is the PKCS#9 extensionRequest attribute OID (RFC 2985
// §5.4.2) -- the conventional way a PKCS#10 CSR carries "requested
// extensions" like SANs, since CertificationRequestInfo has no top-level
// Extensions field of its own (unlike a certificate's TBSCertificate).
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// encodeExtensionsAttribute wraps exts in a single PKCS#9 extensionRequest
// attribute (RFC 2985 §5.4.2) -- the conventional way a PKCS#10 CSR carries
// "requested extensions", since CertificationRequestInfo has no top-level
// Extensions field of its own (unlike a certificate's TBSCertificate).
// Returns nil (no attributes) when exts is empty. Shared by mldsa_csr.go's
// SAN-only case and hybrid_csr.go's SAN+alt-key+alt-sig case (W4-08) --
// generalized from what was originally a single-purpose encodeSANAttribute.
func encodeExtensionsAttribute(exts []certExtension) ([]asn1.RawValue, error) {
	if len(exts) == 0 {
		return nil, nil
	}
	extsDER, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions: %w", err)
	}
	// The Attribute's "values" field is a SET OF AttributeValue -- wrap the
	// SEQUENCE OF Extension as the SET's single member.
	setDER, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: extsDER})
	if err != nil {
		return nil, fmt.Errorf("marshal attribute value SET: %w", err)
	}
	attr := struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{Type: oidExtensionRequest, Values: asn1.RawValue{FullBytes: setDER}}
	attrDER, err := asn1.Marshal(attr)
	if err != nil {
		return nil, fmt.Errorf("marshal extensionRequest attribute: %w", err)
	}
	return []asn1.RawValue{{FullBytes: attrDER}}, nil
}

// decodeExtensionsAttribute extracts the raw extension list from a parsed
// CSR's attributes, if a PKCS#9 extensionRequest is present. Unrecognized
// attributes are skipped, not an error. Callers filter the returned list for
// the specific extension OIDs they care about (mldsa_csr.go: SAN only;
// hybrid_csr.go: SAN + alt-key + alt-sig-algorithm + alt-sig-value).
func decodeExtensionsAttribute(attrs []asn1.RawValue) ([]certExtension, error) {
	for _, raw := range attrs {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &attr); err != nil {
			continue
		}
		if !attr.Type.Equal(oidExtensionRequest) {
			continue
		}
		var exts []certExtension
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &exts); err != nil {
			return nil, fmt.Errorf("unmarshal extensionRequest extensions: %w", err)
		}
		return exts, nil
	}
	return nil, nil
}

// oidSubjectAltName is the standard X.509 SAN extension OID (RFC 5280 §4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// marshalSANValue encodes dnsNames/ipAddresses as a SAN extension's DER
// value (the GeneralNames SEQUENCE, not wrapped in a certExtension). Shared
// by mldsa_csr.go and hybrid_csr.go.
func marshalSANValue(dnsNames []string, ipAddresses []net.IP) ([]byte, error) {
	if len(dnsNames) == 0 && len(ipAddresses) == 0 {
		return nil, nil
	}
	var rawNames []asn1.RawValue
	for _, dns := range dnsNames {
		rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(dns)})
	}
	for _, ip := range ipAddresses {
		rawNames = append(rawNames, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	return asn1.Marshal(rawNames)
}

// unmarshalSANValue decodes a SAN extension's DER value back into
// dnsNames/ipAddresses. Shared by mldsa_csr.go and hybrid_csr.go.
func unmarshalSANValue(value []byte) ([]string, []net.IP, error) {
	var rawNames []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &rawNames); err != nil {
		return nil, nil, fmt.Errorf("unmarshal SAN GeneralNames: %w", err)
	}
	var dnsNames []string
	var ips []net.IP
	for _, rn := range rawNames {
		switch rn.Tag {
		case 2:
			dnsNames = append(dnsNames, string(rn.Bytes))
		case 7:
			ips = append(ips, net.IP(rn.Bytes))
		}
	}
	return dnsNames, ips, nil
}

// encodeSANAttribute builds a single PKCS#9 extensionRequest attribute
// carrying a SubjectAltName extension, matching the same SAN encoding
// buildMLDSAExtensions already uses for certificates.
func encodeSANAttribute(dnsNames []string, ipAddresses []net.IP) ([]asn1.RawValue, error) {
	sanValue, err := marshalSANValue(dnsNames, ipAddresses)
	if err != nil {
		return nil, fmt.Errorf("marshal SAN value: %w", err)
	}
	if sanValue == nil {
		return nil, nil
	}
	return encodeExtensionsAttribute([]certExtension{{Id: oidSubjectAltName, Value: sanValue}})
}

// decodeSANAttribute extracts DNSNames/IPAddresses from a parsed CSR's
// attributes, if a PKCS#9 extensionRequest carrying a SAN extension is
// present.
func decodeSANAttribute(attrs []asn1.RawValue) ([]string, []net.IP, error) {
	exts, err := decodeExtensionsAttribute(attrs)
	if err != nil {
		return nil, nil, err
	}
	for _, ext := range exts {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		return unmarshalSANValue(ext.Value)
	}
	return nil, nil, nil
}

// csrInfo is CertificationRequestInfo (RFC 2986 §4). Attributes is a [0]
// IMPLICIT SET carrying a PKCS#9 extensionRequest when there's anything to
// request (SANs today; SANs + hybrid alt-key/alt-sig as of W4-08's
// hybrid_csr.go), empty otherwise -- see encodeExtensionsAttribute/
// decodeExtensionsAttribute.
type csrInfo struct {
	Version    int `asn1:"default:0"`
	Subject    asn1.RawValue
	PublicKey  certSPKI
	Attributes []asn1.RawValue `asn1:"tag:0"`
}

// outerCSR is CertificationRequest (RFC 2986 §4).
type outerCSR struct {
	CertificationRequestInfo asn1.RawValue
	SignatureAlgorithm       certAlgID
	Signature                asn1.BitString
}

// CreateCertificateRequestMLDSA builds a self-signed PKCS#10 CSR for an ML-DSA
// key, carrying dnsNames/ipAddresses as a PKCS#9 extensionRequest attribute
// (matching how a classical CSR's own SANs flow through
// certificate_ca_provider.go's req.CSR.DNSNames fallback -- see
// issueCertificateFromPQCCSR). Callers PEM-encode the result with block type
// "ML-DSA CERTIFICATE REQUEST" (NOT "CERTIFICATE REQUEST" -- see
// certificate_ca_provider.go's PEM block-type dispatch). algo must be one of
// keystore.MLDSA44/65/87.
func CreateCertificateRequestMLDSA(subject pkix.Name, dnsNames []string, ipAddresses []net.IP, signer crypto.Signer, algo keystore.Algorithm) ([]byte, error) {
	oid, ok := keystore.MLDSAOIDForAlgo(algo)
	if !ok {
		return nil, fmt.Errorf("no OID for algorithm %s", algo)
	}

	spki, err := encodeLeafSPKI(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}

	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}

	attrs, err := encodeSANAttribute(dnsNames, ipAddresses)
	if err != nil {
		return nil, fmt.Errorf("encode SAN attribute: %w", err)
	}
	if attrs == nil {
		attrs = []asn1.RawValue{}
	}

	info := csrInfo{
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  spki,
		Attributes: attrs,
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("marshal CertificationRequestInfo: %w", err)
	}

	// ML-DSA signs the full message, matching CreateCertificateMLDSA's convention.
	sig, err := signer.Sign(rand.Reader, infoDER, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign CertificationRequestInfo: %w", err)
	}

	outer := outerCSR{
		CertificationRequestInfo: asn1.RawValue{FullBytes: infoDER},
		SignatureAlgorithm:       certAlgID{Algorithm: oid},
		Signature:                asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	return asn1.Marshal(outer)
}

// PQCCertificateRequest is the parsed, ALREADY-SIGNATURE-VERIFIED result of a
// hand-rolled ML-DSA CSR. Deliberately not shaped like *x509.CertificateRequest
// -- see certificate_ca_provider.go's Known traps note on why
// req.CSR.CheckSignature() cannot be reused for ML-DSA.
type PQCCertificateRequest struct {
	Subject     pkix.Name
	DNSNames    []string
	IPAddresses []net.IP
	PublicKey   keystore.MLDSAPublicKey
	Algorithm   keystore.Algorithm
}

// ParseCertificateRequestMLDSA parses AND verifies (fails closed on an
// invalid self-signature -- there is no equivalent of CheckSignature() a
// caller could invoke separately afterward) an ML-DSA CSR built by
// CreateCertificateRequestMLDSA.
func ParseCertificateRequestMLDSA(der []byte) (*PQCCertificateRequest, error) {
	var outer outerCSR
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CertificationRequest: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after CertificationRequest")
	}

	var info csrInfo
	if _, err := asn1.Unmarshal(outer.CertificationRequestInfo.FullBytes, &info); err != nil {
		return nil, fmt.Errorf("unmarshal CertificationRequestInfo: %w", err)
	}

	algo, ok := mldsaAlgoFromOID(info.PublicKey.Algorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("unrecognized ML-DSA algorithm OID %v", info.PublicKey.Algorithm.Algorithm)
	}
	pub, err := unmarshalMLDSAPublicKey(algo, info.PublicKey.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ML-DSA public key: %w", err)
	}

	if !verifyMLDSA(algo, pub, outer.CertificationRequestInfo.FullBytes, outer.Signature.Bytes) {
		return nil, fmt.Errorf("invalid CSR self-signature")
	}

	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(info.Subject.FullBytes, &rdn); err != nil {
		return nil, fmt.Errorf("unmarshal subject: %w", err)
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&rdn)

	dnsNames, ipAddresses, err := decodeSANAttribute(info.Attributes)
	if err != nil {
		return nil, fmt.Errorf("decode SAN attribute: %w", err)
	}

	return &PQCCertificateRequest{
		Subject:     subject,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		PublicKey:   pub,
		Algorithm:   algo,
	}, nil
}

// mldsaAlgoFromOID maps an ML-DSA AlgorithmIdentifier OID back to a
// keystore.Algorithm -- the parse-side counterpart of MLDSAOIDForAlgo, and
// preferred over mldsaOIDFromPubSize's byte-length dispatch here since the
// OID is already present and unambiguous on the parse side.
func mldsaAlgoFromOID(oid asn1.ObjectIdentifier) (keystore.Algorithm, bool) {
	switch {
	case oid.Equal(keystore.OIDMLDsa44):
		return keystore.MLDSA44, true
	case oid.Equal(keystore.OIDMLDsa65):
		return keystore.MLDSA65, true
	case oid.Equal(keystore.OIDMLDsa87):
		return keystore.MLDSA87, true
	}
	return "", false
}

// unmarshalMLDSAPublicKey reconstructs a CIRCL ML-DSA public key of the
// variant matching algo from its raw MarshalBinary bytes.
func unmarshalMLDSAPublicKey(algo keystore.Algorithm, raw []byte) (keystore.MLDSAPublicKey, error) {
	switch algo {
	case keystore.MLDSA44:
		pub := &mldsa44.PublicKey{}
		if err := pub.UnmarshalBinary(raw); err != nil {
			return nil, err
		}
		return pub, nil
	case keystore.MLDSA65:
		pub := &mldsa65.PublicKey{}
		if err := pub.UnmarshalBinary(raw); err != nil {
			return nil, err
		}
		return pub, nil
	case keystore.MLDSA87:
		pub := &mldsa87.PublicKey{}
		if err := pub.UnmarshalBinary(raw); err != nil {
			return nil, err
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported ML-DSA algorithm %s", algo)
}

// verifyMLDSA dispatches to the CIRCL variant's own Verify function -- there
// is no generic cross-variant Verify, each of 44/65/87 has its own.
func verifyMLDSA(algo keystore.Algorithm, pub keystore.MLDSAPublicKey, msg, sig []byte) bool {
	switch algo {
	case keystore.MLDSA44:
		p, ok := pub.(*mldsa44.PublicKey)
		return ok && mldsa44.Verify(p, msg, nil, sig)
	case keystore.MLDSA65:
		p, ok := pub.(*mldsa65.PublicKey)
		return ok && mldsa65.Verify(p, msg, nil, sig)
	case keystore.MLDSA87:
		p, ok := pub.(*mldsa87.PublicKey)
		return ok && mldsa87.Verify(p, msg, nil, sig)
	}
	return false
}
