// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package revsign signs CRLs and OCSP responses for ML-DSA issuers (W31-05).
//
// It is its own package (not internal/ca) because internal/crl and
// internal/ocsp need it and internal/ca's tests import both of them.
//
// x509.CreateRevocationList and golang.org/x/crypto/ocsp.CreateResponse reject
// the keystore's circl signers, so ML-DSA issuers get hand-rolled DER here,
// the same way mldsa_cert.go handles certificates. Structures follow RFC 5280
// section 5.1 (CertificateList) and RFC 6960 section 4.2 (BasicOCSPResponse).
// ML-DSA signs the whole TBS message (never a pre-hash). Issuer detection keys
// off the SPKI OID, not x509.SignatureAlgorithm, which differs between Go
// toolchains.
package revsign

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6960 ResponderID byKey is defined as SHA-1 of the key bits, not a security use
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"kryptkeeper/internal/keystore"
)

// Revocation signing modes exposed on the CA API.
const (
	RevocationSigningClassical = "classical"
	RevocationSigningMLDSA     = "ml-dsa"
)

var (
	oidCRLNumber      = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidCRLReason      = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidOCSPBasic      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

	oidHashSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHashSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHashSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidHashSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// algID is an ASN.1 AlgorithmIdentifier.
type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// extension mirrors pkix.Extension for direct ASN.1 marshaling.
type extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type spkiInfo struct {
	Algorithm algID
	PublicKey asn1.BitString
}

type signedDER struct {
	TBS       asn1.RawValue
	Algorithm algID
	Signature asn1.BitString
}

func mldsaOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(keystore.OIDMLDsa44) || oid.Equal(keystore.OIDMLDsa65) || oid.Equal(keystore.OIDMLDsa87)
}

// IsMLDSAIssuer reports whether cert's subject key is ML-DSA. The SPKI OID is
// the authority: crypto/x509 names ML-DSA differently across Go toolchains.
func IsMLDSAIssuer(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	var spki spkiInfo
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return false
	}
	return mldsaOID(spki.Algorithm.Algorithm)
}

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

// issuerMLDSAOID returns the signature algorithm OID for an ML-DSA issuer;
// the ML-DSA SPKI and signature algorithm identifiers share one OID.
func issuerMLDSAOID(cert *x509.Certificate) (asn1.ObjectIdentifier, error) {
	var spki spkiInfo
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("parse issuer SPKI: %w", err)
	}
	if !mldsaOID(spki.Algorithm.Algorithm) {
		return nil, errors.New("issuer key is not ML-DSA")
	}
	return spki.Algorithm.Algorithm, nil
}

// crlEntry is one revokedCertificates element (RFC 5280 5.1.2.6).
type crlEntry struct {
	SerialNumber   *big.Int
	RevocationDate time.Time
	Extensions     []extension `asn1:"optional"`
}

// tbsCRL is TBSCertList (RFC 5280 5.1.2). Version 1 means v2.
type tbsCRL struct {
	Version    int `asn1:"optional,default:0"`
	Signature  algID
	Issuer     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time   `asn1:"optional"`
	Revoked    []crlEntry  `asn1:"optional"`
	Extensions []extension `asn1:"optional,explicit,tag:0"`
}

// CreateRevocationList is x509.CreateRevocationList for any issuer: ML-DSA
// issuers use the hand-rolled path, everything else delegates to the stdlib.
func CreateRevocationList(rand io.Reader, tmpl *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if !IsMLDSAIssuer(issuer) {
		return x509.CreateRevocationList(rand, tmpl, issuer, signer)
	}
	if tmpl == nil {
		return nil, errors.New("ca: CRL template can not be nil")
	}
	if issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, errors.New("ca: issuer must have the crlSign key usage bit set")
	}
	if len(issuer.SubjectKeyId) == 0 {
		return nil, errors.New("ca: issuer certificate doesn't contain a subject key identifier")
	}
	if tmpl.NextUpdate.Before(tmpl.ThisUpdate) {
		return nil, errors.New("ca: template.ThisUpdate is after template.NextUpdate")
	}
	if tmpl.Number == nil {
		return nil, errors.New("ca: template contains nil Number field")
	}
	if n := tmpl.Number.Bytes(); len(n) > 20 || (len(n) == 20 && n[0]&0x80 != 0) || tmpl.Number.Sign() < 0 {
		return nil, errors.New("ca: CRL number must be non-negative and at most 20 octets")
	}
	oid, err := issuerMLDSAOID(issuer)
	if err != nil {
		return nil, err
	}

	// nil (not empty) when there are no entries: RFC 5280 5.1.2.6 requires the
	// list to be absent then, and asn1 "optional" only omits a nil slice.
	var revoked []crlEntry
	for _, e := range tmpl.RevokedCertificateEntries {
		if e.SerialNumber == nil {
			return nil, errors.New("ca: template contains entry with nil SerialNumber field")
		}
		if e.RevocationTime.IsZero() {
			return nil, errors.New("ca: template contains entry with zero RevocationTime field")
		}
		var exts []extension
		for _, x := range e.ExtraExtensions {
			if x.Id.Equal(oidCRLReason) {
				return nil, errors.New("ca: entry carries a ReasonCode ExtraExtension; use ReasonCode")
			}
			exts = append(exts, extension{Id: x.Id, Critical: x.Critical, Value: x.Value})
		}
		if e.ReasonCode != 0 {
			v, err := asn1.Marshal(asn1.Enumerated(e.ReasonCode))
			if err != nil {
				return nil, err
			}
			exts = append(exts, extension{Id: oidCRLReason, Value: v})
		}
		revoked = append(revoked, crlEntry{
			SerialNumber:   e.SerialNumber,
			RevocationDate: e.RevocationTime.UTC().Truncate(time.Second),
			Extensions:     exts,
		})
	}

	aki, err := asn1.Marshal(struct {
		KeyIdentifier []byte `asn1:"optional,tag:0"`
	}{KeyIdentifier: issuer.SubjectKeyId})
	if err != nil {
		return nil, err
	}
	num, err := asn1.Marshal(tmpl.Number)
	if err != nil {
		return nil, err
	}
	exts := []extension{
		{Id: oidAuthorityKeyID, Value: aki},
		{Id: oidCRLNumber, Value: num},
	}
	for _, x := range tmpl.ExtraExtensions {
		exts = append(exts, extension{Id: x.Id, Critical: x.Critical, Value: x.Value})
	}

	issuerRaw, err := encodeDN(issuer)
	if err != nil {
		return nil, fmt.Errorf("encode issuer DN: %w", err)
	}
	tbs := tbsCRL{
		Version:    1,
		Signature:  algID{Algorithm: oid},
		Issuer:     issuerRaw,
		ThisUpdate: tmpl.ThisUpdate.UTC().Truncate(time.Second),
		NextUpdate: tmpl.NextUpdate.UTC().Truncate(time.Second),
		Revoked:    revoked,
		Extensions: exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal TBSCertList: %w", err)
	}
	sig, err := signer.Sign(rand, tbsDER, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign TBSCertList: %w", err)
	}
	return asn1.Marshal(signedDER{
		TBS:       asn1.RawValue{FullBytes: tbsDER},
		Algorithm: algID{Algorithm: oid},
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
}

// OCSPResponseInput describes one single-certificate OCSP answer.
type OCSPResponseInput struct {
	SerialNumber   *big.Int
	HashAlgorithm  crypto.Hash // echo the request's CertID hash
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	Revoked        bool
	RevokedAt      time.Time
	Reason         int
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

type ocspCertID struct {
	HashAlgorithm algID
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  *big.Int
}

type ocspSingleResponse struct {
	CertID     ocspCertID
	Status     asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"generalized,explicit,tag:0,optional"`
}

type ocspResponseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingleResponse
}

type ocspBasicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm algID
	Signature          asn1.BitString
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspResponse struct {
	Status        asn1.Enumerated
	ResponseBytes ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

func ocspHashOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA1:
		return oidHashSHA1, nil
	case crypto.SHA256:
		return oidHashSHA256, nil
	case crypto.SHA384:
		return oidHashSHA384, nil
	case crypto.SHA512:
		return oidHashSHA512, nil
	}
	return nil, fmt.Errorf("unsupported OCSP CertID hash %d", h)
}

// CreateOCSPResponseMLDSA returns a DER OCSPResponse (status successful,
// id-pkix-ocsp-basic), responderID byKey (SHA-1 of the issuer key bits),
// signed by the ML-DSA issuer key. The issuer cert is not embedded: a relying
// party already holds it, and the response is signed by the issuer itself
// (RFC 6960 4.2.2.2, no delegated responder).
func CreateOCSPResponseMLDSA(issuer *x509.Certificate, signer crypto.Signer, in OCSPResponseInput) ([]byte, error) {
	if in.SerialNumber == nil {
		return nil, errors.New("ca: OCSP response needs a serial number")
	}
	oid, err := issuerMLDSAOID(issuer)
	if err != nil {
		return nil, err
	}
	hashOID, err := ocspHashOID(in.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	var spki spkiInfo
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("parse issuer SPKI: %w", err)
	}
	keyHash := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // see import note
	// ResponderID ::= [2] EXPLICIT KeyHash (OCTET STRING)
	keyHashOctets, err := asn1.Marshal(keyHash[:])
	if err != nil {
		return nil, err
	}
	responderID := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: keyHashOctets}

	// CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo }
	status := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}
	if in.Revoked {
		info, err := asn1.Marshal(struct {
			RevocationTime time.Time       `asn1:"generalized"`
			Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
		}{RevocationTime: in.RevokedAt.UTC().Truncate(time.Second), Reason: asn1.Enumerated(in.Reason)})
		if err != nil {
			return nil, err
		}
		// Strip the SEQUENCE header: IMPLICIT [1] replaces it.
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(info, &seq); err != nil {
			return nil, err
		}
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: seq.Bytes}
	}

	thisUpdate := in.ThisUpdate.UTC().Truncate(time.Second)
	data := ocspResponseData{
		ResponderID: responderID,
		ProducedAt:  thisUpdate,
		Responses: []ocspSingleResponse{{
			CertID: ocspCertID{
				HashAlgorithm: algID{Algorithm: hashOID, Parameters: asn1.NullRawValue},
				NameHash:      in.IssuerNameHash,
				KeyHash:       in.IssuerKeyHash,
				SerialNumber:  in.SerialNumber,
			},
			Status:     status,
			ThisUpdate: thisUpdate,
			NextUpdate: in.NextUpdate.UTC().Truncate(time.Second),
		}},
	}
	tbsDER, err := asn1.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal ResponseData: %w", err)
	}
	sig, err := signer.Sign(rand.Reader, tbsDER, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign ResponseData: %w", err)
	}
	basic, err := asn1.Marshal(ocspBasicResponse{
		TBSResponseData:    asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algID{Algorithm: oid},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ocspResponse{
		Status:        0, // successful
		ResponseBytes: ocspResponseBytes{ResponseType: oidOCSPBasic, Response: basic},
	})
}
