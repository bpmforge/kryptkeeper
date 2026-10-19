// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

// A Windows renewal request is SignedData with two SignerInfos: version 3,
// identified by subject key identifier (the new key signing itself), and
// version 1, identified by issuer and serial (the old certificate, which is
// embedded). Both go.mozilla.org/pkcs7 and github.com/smallstep/pkcs7 parse
// such a message as having no signers at all (measured on a real kk-win11
// renewal, W20-11), so the old-key signature is verified here, per RFC 5652
// 5.4, for the one shape needed: a version-1 SignerInfo with signed
// attributes whose certificate is in the message. The result only labels
// the audit row as a renewal; Kerberos alone authorizes.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1" //nolint:gosec // Windows signs renewal requests with SHA-1; this labels an audit row, it authorizes nothing
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

var (
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	digestByOID      = map[string]crypto.Hash{
		"1.3.14.3.2.26":          crypto.SHA1,
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	}
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// oldKeySigner returns the embedded certificate whose key signed content in
// the SignedData der, through a version-1 SignerInfo with signed
// attributes, or nil. content is the encapsulated content's octets.
func oldKeySigner(der, content []byte, certs []*x509.Certificate) *x509.Certificate {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil
	}
	rest := sd.SignerInfos.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil
		}
		var si cmsSignerInfo
		if _, err := asn1.Unmarshal(raw.FullBytes, &si); err != nil || si.Version != 1 || len(si.SignedAttrs.FullBytes) == 0 {
			continue
		}
		var ias cmsIssuerAndSerial
		if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err != nil || ias.Serial == nil {
			continue
		}
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 && signerInfoVerifies(si, content, c) {
				return c
			}
		}
	}
	return nil
}

// signerInfoVerifies checks RFC 5652 5.4: the messageDigest attribute equals
// the content's digest, and the signature over the signed attributes,
// re-encoded as an explicit SET OF, verifies with cert's key.
func signerInfoVerifies(si cmsSignerInfo, content []byte, cert *x509.Certificate) bool {
	h, ok := digestByOID[si.DigestAlgorithm.Algorithm.String()]
	if !ok || !h.Available() {
		return false
	}
	var digest []byte
	for rest := si.SignedAttrs.Bytes; len(rest) > 0; {
		var a cmsAttribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return false
		}
		if a.Type.Equal(oidMessageDigest) {
			if digest != nil {
				return false // RFC 5652 11.2: exactly one messageDigest
			}
			if _, err := asn1.Unmarshal(a.Values.Bytes, &digest); err != nil {
				return false
			}
		}
	}
	sum := h.New()
	sum.Write(content)
	if digest == nil || !bytes.Equal(digest, sum.Sum(nil)) {
		return false
	}
	signed := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	hs := h.New()
	hs.Write(signed)
	hashed := hs.Sum(nil)
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, h, hashed, si.Signature) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, hashed, si.Signature)
	}
	return false
}
