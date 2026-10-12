// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
)

// RFC 4211 CRMF structures for parsing a real client's CertReqMessages.
//
// CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
// CertReqMsg ::= SEQUENCE {
//     certReq   CertRequest,
//     popo      ProofOfPossession OPTIONAL,
//     regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
// CertRequest ::= SEQUENCE {
//     certReqId     INTEGER,
//     certTemplate  CertTemplate,
//     controls      Controls OPTIONAL }
// CertTemplate ::= SEQUENCE {
//     version      [0] Version               OPTIONAL,
//     serialNumber [1] INTEGER               OPTIONAL,
//     signingAlg   [2] AlgorithmIdentifier    OPTIONAL,
//     issuer       [3] Name                  OPTIONAL,
//     validity     [4] OptionalValidity       OPTIONAL,
//     subject      [5] Name                  OPTIONAL,
//     publicKey    [6] SubjectPublicKeyInfo   OPTIONAL,
//     issuerUID    [7] UniqueIdentifier       OPTIONAL,
//     subjectUID   [8] UniqueIdentifier       OPTIONAL,
//     extensions   [9] Extensions             OPTIONAL }
// ProofOfPossession ::= CHOICE {
//     raVerified      [0] NULL,
//     signature       [1] POPOSigningKey,
//     keyEncipherment [2] POPOPrivKey,
//     keyAgreement    [3] POPOPrivKey }
// POPOSigningKey ::= SEQUENCE {
//     poposkInput          [0] POPOSigningKeyInput OPTIONAL,
//     algorithmIdentifier      AlgorithmIdentifier,
//     signature                BIT STRING }

type certReqMsgV2 struct {
	CertReq asn1.RawValue // full CertRequest SEQUENCE — FullBytes is what a POPO with no poposkInput signs
	Popo    asn1.RawValue `asn1:"optional"`
	RegInfo asn1.RawValue `asn1:"optional"`
}

type certRequestV2 struct {
	CertReqID    int
	CertTemplate asn1.RawValue
	Controls     asn1.RawValue `asn1:"optional"`
}

type popoSigningKeyV2 struct {
	PoposkInput asn1.RawValue `asn1:"optional,tag:0"`
	AlgID       pkix.AlgorithmIdentifier
	Signature   asn1.BitString
}

// crmfRequest is one CertReqMsg reduced to what the CA engine needs, after
// its ProofOfPossession has already been checked.
type crmfRequest struct {
	CertReqID int
	// CSR is a synthetic *x509.CertificateRequest built from the CertTemplate
	// plus the already-verified POPO signature. Its CheckSignature() call
	// re-derives the exact verification ca.Engine.IssueCertificate performs
	// on any CSR (see engine.go), so this is not a bypass of that gate: the
	// signature and signed bytes are the client's real POPO over the real
	// CertRequest DER, just carried in x509.CertificateRequest's exported
	// fields instead of a PKCS#10 envelope (CRMF has no such envelope).
	CSR *x509.CertificateRequest
}

// asUniversalSequence re-tags an IMPLICIT context-tagged constructed value
// (e.g. CertTemplate's [5] subject or [6] publicKey) as a plain universal
// SEQUENCE so it can be re-parsed with the standard library's Name/
// SubjectPublicKeyInfo decoders. IMPLICIT tagging on a constructed type only
// changes the outer tag, not the content encoding, so this round-trips
// cleanly.
func asUniversalSequence(v asn1.RawValue) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      v.Bytes,
	})
}

// parseCertReqMessages decodes a CertReqMessages body (IR/CR/KUR) into one
// crmfRequest per CertReqMsg, verifying each entry's ProofOfPossession along
// the way. A CertReqMsg with no POPO, an unsupported POPO choice (only
// signature/POPOSigningKey with no poposkInput is supported — the common
// case for openssl and every mainstream CMP client), or an invalid POPO
// signature is rejected with an error naming that entry.
func parseCertReqMessages(bodyBytes []byte) ([]crmfRequest, error) {
	// PKIBody's alternatives are EXPLICIT (RFC 4210's PKIXCMP module default),
	// so bodyBytes -- the content of the ir/cr/kur context tag -- is already
	// the complete CertReqMessages encoding (its own SEQUENCE tag+length
	// included), not bare content needing a synthetic wrapper.
	var msgs []certReqMsgV2
	if _, err := asn1.Unmarshal(bodyBytes, &msgs); err != nil {
		return nil, fmt.Errorf("cmp: parse CertReqMessages: %w", err)
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("cmp: CertReqMessages is empty")
	}

	out := make([]crmfRequest, 0, len(msgs))
	for i, msg := range msgs {
		req, err := parseOneCertReqMsg(msg)
		if err != nil {
			return nil, fmt.Errorf("cmp: CertReqMsg[%d]: %w", i, err)
		}
		out = append(out, req)
	}
	return out, nil
}

func parseOneCertReqMsg(msg certReqMsgV2) (crmfRequest, error) {
	var certReq certRequestV2
	if _, err := asn1.Unmarshal(msg.CertReq.FullBytes, &certReq); err != nil {
		return crmfRequest{}, fmt.Errorf("parse CertRequest: %w", err)
	}

	name, pub, dnsNames, ipAddrs, uris, err := parseCertTemplate(certReq.CertTemplate)
	if err != nil {
		return crmfRequest{}, fmt.Errorf("parse CertTemplate: %w", err)
	}

	sigAlg, sig, err := parsePOPOSignature(msg.Popo)
	if err != nil {
		return crmfRequest{}, fmt.Errorf("badPOP: %w", err)
	}

	csr := &x509.CertificateRequest{
		RawTBSCertificateRequest: msg.CertReq.FullBytes,
		Signature:                sig,
		SignatureAlgorithm:       sigAlg,
		PublicKey:                pub,
		Subject:                  name,
		DNSNames:                 dnsNames,
		IPAddresses:              ipAddrs,
		URIs:                     uris,
	}
	if err := csr.CheckSignature(); err != nil {
		return crmfRequest{}, fmt.Errorf("badPOP: proof-of-possession signature invalid: %w", err)
	}

	return crmfRequest{CertReqID: certReq.CertReqID, CSR: csr}, nil
}

// parsePOPOSignature extracts and validates the shape of a ProofOfPossession
// CHOICE, returning the signature algorithm and raw signature bytes for the
// signature (POPOSigningKey) choice. Only that choice, with poposkInput
// absent, is supported (see crmfRequest doc comment); every other choice or
// shape is rejected rather than silently treated as verified.
func parsePOPOSignature(popo asn1.RawValue) (x509.SignatureAlgorithm, []byte, error) {
	if popo.Tag == 0 && len(popo.Bytes) == 0 && popo.FullBytes == nil {
		return 0, nil, fmt.Errorf("missing ProofOfPossession")
	}
	if popo.Class != asn1.ClassContextSpecific || popo.Tag != 1 {
		return 0, nil, fmt.Errorf("unsupported ProofOfPossession choice %d (only signature/POPOSigningKey is supported)", popo.Tag)
	}

	der, err := asUniversalSequence(popo)
	if err != nil {
		return 0, nil, fmt.Errorf("re-tag POPOSigningKey: %w", err)
	}
	var psk popoSigningKeyV2
	if _, err := asn1.Unmarshal(der, &psk); err != nil {
		return 0, nil, fmt.Errorf("parse POPOSigningKey: %w", err)
	}
	if len(psk.PoposkInput.FullBytes) > 0 {
		return 0, nil, fmt.Errorf("POPOSigningKeyInput is not supported")
	}

	sigAlg, err := signatureAlgorithmFromOID(psk.AlgID.Algorithm)
	if err != nil {
		return 0, nil, err
	}
	return sigAlg, psk.Signature.RightAlign(), nil
}

// parseCertTemplate reads the subject, public key and SAN-relevant
// extensions out of a CertTemplate's optional context-tagged fields.
func parseCertTemplate(tmpl asn1.RawValue) (pkix.Name, any, []string, []net.IP, []*url.URL, error) {
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(tmpl.FullBytes, &fields); err != nil {
		return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("parse CertTemplate fields: %w", err)
	}

	var name pkix.Name
	var pub any
	var dnsNames []string
	var ipAddrs []net.IP
	var uris []*url.URL

	for _, f := range fields {
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		switch f.Tag {
		case 5: // subject [5] Name -- Name is a CHOICE (rdnSequence RDNSequence),
			// and X.680 always tags a CHOICE-typed field EXPLICITLY regardless
			// of CRMF's module default, so f.Bytes is already the complete
			// RDNSequence encoding (its own SEQUENCE tag+length included), not
			// bare content needing a re-tag the way publicKey/extensions do.
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(f.Bytes, &rdns); err != nil {
				return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("parse subject Name: %w", err)
			}
			name.FillFromRDNSequence(&rdns)
		case 6: // publicKey [6] IMPLICIT SubjectPublicKeyInfo
			der, err := asUniversalSequence(f)
			if err != nil {
				return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("re-tag publicKey: %w", err)
			}
			pub, err = x509.ParsePKIXPublicKey(der)
			if err != nil {
				return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("parse SubjectPublicKeyInfo: %w", err)
			}
		case 9: // extensions [9] IMPLICIT Extensions
			der, err := asUniversalSequence(f)
			if err != nil {
				return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("re-tag extensions: %w", err)
			}
			var exts []pkix.Extension
			if _, err := asn1.Unmarshal(der, &exts); err != nil {
				return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("parse Extensions: %w", err)
			}
			dnsNames, ipAddrs, uris, err = parseSANExtension(exts)
			if err != nil {
				return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("parse SAN extension: %w", err)
			}
		}
	}

	if pub == nil {
		return pkix.Name{}, nil, nil, nil, nil, fmt.Errorf("CertTemplate has no publicKey")
	}
	return name, pub, dnsNames, ipAddrs, uris, nil
}

// oidSubjectAltName is 2.5.29.17 (id-ce-subjectAltName, RFC 5280 §4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// parseSANExtension decodes the SAN GeneralNames sequence for the field
// types a certificate template plausibly needs: dNSName [2], URI [6] and
// iPAddress [7]. Other GeneralName choices (otherName, rfc822Name,
// directoryName, ediPartyName, registeredID) are not needed for CMP interop
// today and are skipped rather than rejected.
func parseSANExtension(exts []pkix.Extension) ([]string, []net.IP, []*url.URL, error) {
	for _, ext := range exts {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
			return nil, nil, nil, fmt.Errorf("parse SAN GeneralNames: %w", err)
		}
		var dnsNames []string
		var ipAddrs []net.IP
		var uris []*url.URL
		for _, n := range names {
			if n.Class != asn1.ClassContextSpecific {
				continue
			}
			switch n.Tag {
			case 2: // dNSName
				dnsNames = append(dnsNames, string(n.Bytes))
			case 6: // uniformResourceIdentifier
				u, err := url.Parse(string(n.Bytes))
				if err != nil {
					return nil, nil, nil, fmt.Errorf("parse SAN URI: %w", err)
				}
				uris = append(uris, u)
			case 7: // iPAddress
				ipAddrs = append(ipAddrs, net.IP(n.Bytes))
			}
		}
		return dnsNames, ipAddrs, uris, nil
	}
	return nil, nil, nil, nil
}

// Well-known signature algorithm OIDs a CMP client's POPOSigningKey is
// realistically signed with (RFC 5280/8017/8410/3279). Kept to a small,
// explicit allowlist rather than a generic OID->algorithm library: an
// unrecognized OID is rejected, never guessed.
var signatureOIDs = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.5":  x509.SHA1WithRSA,
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.10045.4.1":     x509.ECDSAWithSHA1,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	"1.3.101.112":           x509.PureEd25519,
}

func signatureAlgorithmFromOID(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	if alg, ok := signatureOIDs[oid.String()]; ok {
		return alg, nil
	}
	return 0, fmt.Errorf("unsupported POPO signature algorithm OID %s", oid.String())
}
