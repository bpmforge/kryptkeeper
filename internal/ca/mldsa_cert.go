// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// mldsa_cert.go — custom X.509 certificate creation for ML-DSA keys.
//
// Go's x509.CreateCertificate only supports RSA, ECDSA, and Ed25519. This file
// manually builds DER-encoded certificates for ML-DSA keys using encoding/asn1.
//
// Migration path: when Go stdlib adds crypto/mldsa (~Go 1.27), replace callers
// of CreateCertificateMLDSA with x509.CreateCertificate and delete this file.

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"kryptkeeper/internal/keystore"
)

// certAlgID is the ASN.1 AlgorithmIdentifier used inside our hand-rolled cert.
type certAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// certValidity encodes the Validity SEQUENCE.
type certValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// certSPKI is the SubjectPublicKeyInfo for an ML-DSA public key.
type certSPKI struct {
	Algorithm certAlgID
	PublicKey asn1.BitString
}

// certExtension mirrors pkix.Extension for direct ASN.1 marshaling.
type certExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// tbsCert is the TBSCertificate ASN.1 structure (RFC 5280 §4.1).
type tbsCert struct {
	Version            int `asn1:"explicit,tag:0,default:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm certAlgID
	Issuer             asn1.RawValue
	Validity           certValidity
	Subject            asn1.RawValue
	PublicKey          certSPKI
	Extensions         []certExtension `asn1:"optional,explicit,tag:3"`
}

// outerCert is the outer Certificate SEQUENCE.
type outerCert struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm certAlgID
	Signature          asn1.BitString
}

// CreateCertificateMLDSA creates a DER-encoded X.509 certificate signed with an
// ML-DSA CA key. The leaf's public key (pub) may be any type — classical (ECDSA/RSA)
// or ML-DSA. The signer is always the ML-DSA CA key.
// The signer's Sign method receives the full TBSCertificate DER bytes — ML-DSA
// signs the complete message, not a pre-computed hash.
func CreateCertificateMLDSA(
	template, parent *x509.Certificate,
	pub crypto.PublicKey,
	signer crypto.Signer,
	algo keystore.Algorithm,
) ([]byte, error) {
	oid, ok := keystore.MLDSAOIDForAlgo(algo)
	if !ok {
		return nil, fmt.Errorf("no OID for algorithm %s", algo)
	}

	// Encode the leaf's SubjectPublicKeyInfo. If the leaf key is classical
	// (ECDSA/RSA/Ed25519), x509.MarshalPKIXPublicKey handles it. If it is
	// itself ML-DSA, use the CIRCL MarshalBinary path.
	spki, err := encodeLeafSPKI(pub)
	if err != nil {
		return nil, fmt.Errorf("encode leaf public key: %w", err)
	}

	issuerRaw, err := encodeDN(parent)
	if err != nil {
		return nil, fmt.Errorf("encode issuer DN: %w", err)
	}

	subjectRaw, err := encodeDN(template)
	if err != nil {
		return nil, fmt.Errorf("encode subject DN: %w", err)
	}

	exts, err := buildMLDSAExtensions(template)
	if err != nil {
		return nil, fmt.Errorf("build extensions: %w", err)
	}

	tbs := tbsCert{
		Version:            2, // v3
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: certAlgID{Algorithm: oid},
		Issuer:             issuerRaw,
		Validity: certValidity{
			NotBefore: template.NotBefore.UTC().Truncate(time.Second),
			NotAfter:  template.NotAfter.UTC().Truncate(time.Second),
		},
		Subject:    subjectRaw,
		PublicKey:  spki,
		Extensions: exts,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal TBSCertificate: %w", err)
	}

	// ML-DSA signs the full message. Pass crypto.Hash(0) — CIRCL ignores hash opts.
	sig, err := signer.Sign(rand.Reader, tbsDER, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign TBSCertificate: %w", err)
	}

	outer := outerCert{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: certAlgID{Algorithm: oid},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}

	return asn1.Marshal(outer)
}

// encodeDN returns the RawSubject bytes if already encoded, otherwise marshals
// the certificate's Subject pkix.Name into a raw ASN.1 RDNSequence.
func encodeDN(cert *x509.Certificate) (asn1.RawValue, error) {
	if len(cert.RawSubject) > 0 {
		return asn1.RawValue{FullBytes: cert.RawSubject}, nil
	}
	b, err := asn1.Marshal(cert.Subject.ToRDNSequence())
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: b}, nil
}

// encodeLeafSPKI encodes the leaf certificate's SubjectPublicKeyInfo.
// For classical keys (ECDSA/RSA/Ed25519), it uses x509.MarshalPKIXPublicKey.
// For ML-DSA keys, it uses CIRCL's MarshalBinary with the correct OID.
func encodeLeafSPKI(pub crypto.PublicKey) (certSPKI, error) {
	// ML-DSA public key — use raw bytes + ML-DSA OID.
	if mlPub, ok := pub.(keystore.MLDSAPublicKey); ok {
		// Determine which ML-DSA variant by checking the key size.
		raw, err := mlPub.MarshalBinary()
		if err != nil {
			return certSPKI{}, fmt.Errorf("marshal ML-DSA public key: %w", err)
		}
		leafOID := mldsaOIDFromPubSize(len(raw))
		if leafOID == nil {
			return certSPKI{}, fmt.Errorf("unrecognized ML-DSA public key size %d", len(raw))
		}
		return certSPKI{
			Algorithm: certAlgID{Algorithm: leafOID},
			PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
		}, nil
	}

	// Classical key — x509.MarshalPKIXPublicKey produces a full SubjectPublicKeyInfo.
	pkixDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return certSPKI{}, fmt.Errorf("marshal classical public key: %w", err)
	}
	// Parse the PKIX DER to extract the AlgorithmIdentifier and bit string.
	var spki struct {
		Algorithm certAlgID
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pkixDER, &spki); err != nil {
		return certSPKI{}, fmt.Errorf("parse PKIX public key: %w", err)
	}
	return spki, nil
}

// mldsaOIDFromPubSize infers the ML-DSA variant from the raw public key size.
// ML-DSA-44 pubkey = 1312 bytes, ML-DSA-65 = 1952 bytes, ML-DSA-87 = 2592 bytes.
func mldsaOIDFromPubSize(size int) asn1.ObjectIdentifier {
	switch size {
	case 1312:
		return keystore.OIDMLDsa44
	case 1952:
		return keystore.OIDMLDsa65
	case 2592:
		return keystore.OIDMLDsa87
	}
	return nil
}

// buildMLDSAExtensions encodes the standard X.509 v3 extensions from the template.
func buildMLDSAExtensions(tmpl *x509.Certificate) ([]certExtension, error) {
	var exts []certExtension

	// BasicConstraints (critical for CAs).
	if tmpl.BasicConstraintsValid {
		bc := struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}{IsCA: tmpl.IsCA, MaxPathLen: tmpl.MaxPathLen}
		val, err := asn1.Marshal(bc)
		if err != nil {
			return nil, err
		}
		exts = append(exts, certExtension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Critical: true,
			Value:    val,
		})
	}

	// SubjectKeyIdentifier.
	if len(tmpl.SubjectKeyId) > 0 {
		val, err := asn1.Marshal(tmpl.SubjectKeyId)
		if err != nil {
			return nil, err
		}
		exts = append(exts, certExtension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
			Value: val,
		})
	}

	// KeyUsage (critical).
	if tmpl.KeyUsage != 0 {
		val, err := asn1.Marshal(keyUsageBitString(tmpl.KeyUsage))
		if err != nil {
			return nil, err
		}
		exts = append(exts, certExtension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
			Critical: true,
			Value:    val,
		})
	}

	// AuthorityKeyIdentifier (for non-self-signed certs — caller sets AuthorityKeyId).
	if len(tmpl.AuthorityKeyId) > 0 {
		aki := struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{KeyIdentifier: tmpl.AuthorityKeyId}
		val, err := asn1.Marshal(aki)
		if err != nil {
			return nil, err
		}
		exts = append(exts, certExtension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35},
			Value: val,
		})
	}

	// Subject Alternative Names.
	if len(tmpl.DNSNames) > 0 || len(tmpl.IPAddresses) > 0 || len(tmpl.EmailAddresses) > 0 {
		var rawNames []asn1.RawValue
		for _, dns := range tmpl.DNSNames {
			rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(dns)})
		}
		for _, ip := range tmpl.IPAddresses {
			rawNames = append(rawNames, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
		}
		for _, email := range tmpl.EmailAddresses {
			rawNames = append(rawNames, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
		}
		val, err := asn1.Marshal(rawNames)
		if err != nil {
			return nil, err
		}
		exts = append(exts, certExtension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: val,
		})
	}

	// Extended Key Usage.
	if len(tmpl.ExtKeyUsage) > 0 {
		var oids []asn1.ObjectIdentifier
		for _, eku := range tmpl.ExtKeyUsage {
			if o, ok := ekuOID(eku); ok {
				oids = append(oids, o)
			}
		}
		if len(oids) > 0 {
			val, err := asn1.Marshal(oids)
			if err != nil {
				return nil, err
			}
			exts = append(exts, certExtension{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
				Value: val,
			})
		}
	}

	// Pass through any extra extensions the caller set.
	for _, ext := range tmpl.ExtraExtensions {
		exts = append(exts, certExtension{
			Id:       ext.Id,
			Critical: ext.Critical,
			Value:    ext.Value,
		})
	}

	return exts, nil
}

// ekuOID maps x509.ExtKeyUsage values to their ASN.1 OIDs.
func ekuOID(eku x509.ExtKeyUsage) (asn1.ObjectIdentifier, bool) {
	// OIDs from RFC 5280 §4.2.1.12.
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, true
	case x509.ExtKeyUsageClientAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, true
	case x509.ExtKeyUsageCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, true
	case x509.ExtKeyUsageEmailProtection:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, true
	case x509.ExtKeyUsageTimeStamping:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, true
	case x509.ExtKeyUsageOCSPSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, true
	}
	return nil, false
}

// suppress unused import warning — pkix is used by engine.go in this package
var _ = pkix.Name{}

// keyUsageBitString encodes x509.KeyUsage as the RFC 5280 named BIT STRING:
// bit 0 (digitalSignature) is the MSB of the first byte, and DER drops
// trailing zero bits. A plain shift of the Go bitmask puts keyCertSign on
// keyEncipherment, so openssl rejects every ML-DSA CA ("invalid CA
// certificate", W23-02).
func keyUsageBitString(ku x509.KeyUsage) asn1.BitString {
	var b [2]byte
	last := -1
	for i := 0; i < 9; i++ {
		if ku&(1<<uint(i)) != 0 {
			b[i/8] |= 0x80 >> uint(i%8)
			last = i
		}
	}
	n := 1
	if last >= 8 {
		n = 2
	}
	return asn1.BitString{Bytes: b[:n], BitLength: last + 1}
}
