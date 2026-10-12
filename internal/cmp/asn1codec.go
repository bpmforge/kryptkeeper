// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
)

// RFC 4210 ASN.1 structures for CMP PKIMessage parsing.
//
// PKIMessage ::= SEQUENCE {
//     header      PKIHeader,
//     body        PKIBody,
//     protection  [0] PKIProtection OPTIONAL,
//     extraCerts  [1] SEQUENCE OF CMPCertificate OPTIONAL
// }
//
// PKIHeader ::= SEQUENCE {
//     pvno                INTEGER,
//     sender              GeneralName,
//     recipient           GeneralName,
//     messageTime     [0] GeneralizedTime OPTIONAL,
//     protectionAlg   [1] AlgorithmIdentifier OPTIONAL,
//     senderKID       [2] KeyIdentifier OPTIONAL,
//     recipKID        [3] KeyIdentifier OPTIONAL,
//     transactionID   [4] OCTET STRING OPTIONAL,
//     senderNonce     [5] OCTET STRING OPTIONAL,
//     recipNonce      [6] OCTET STRING OPTIONAL,
//     freeText        [7] PKIFreeText OPTIONAL,
//     generalInfo     [8] SEQUENCE OF InfoTypeAndValue OPTIONAL
// }
//
// PKIBody is a CHOICE tagged [0]..[26]; we handle IR=0, CR=2, KUR=7,
// certConf=24.

// pkiMessageRaw holds the outer PKIMessage with header/body/protection kept
// as RawValue so their exact DER (needed for protection verification) is
// preserved.
type pkiMessageRaw struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.RawValue `asn1:"optional,tag:0"`
	ExtraCerts asn1.RawValue `asn1:"optional,tag:1"`
}

// pkiHeaderRaw mirrors PKIHeader field-for-field so optional tagged fields
// can be picked out positionally without a hand-rolled GeneralName decoder
// (sender/recipient are captured as opaque RawValue — this server never
// needs to interpret their contents). RFC 4210's PKIXCMP ASN.1 module is
// declared EXPLICIT TAGS, so every context-tagged optional field here is
// "explicit,tag:N" — confirmed against a real openssl cmp request's DER
// (asn1parse shows each cont[N] wrapping a nested universal-tag TLV, not
// replacing it). Getting this wrong produces "tags don't match" parse
// errors against any real client while still round-tripping against
// hand-built Go fixtures that share the same (wrong) assumption.
type pkiHeaderRaw struct {
	Pvno          int
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	MessageTime   asn1.RawValue            `asn1:"optional,explicit,tag:0"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SenderKID     []byte                   `asn1:"optional,explicit,tag:2"`
	RecipKID      []byte                   `asn1:"optional,explicit,tag:3"`
	TransactionID []byte                   `asn1:"optional,explicit,tag:4"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6"`
	FreeText      asn1.RawValue            `asn1:"optional,explicit,tag:7"`
	GeneralInfo   asn1.RawValue            `asn1:"optional,explicit,tag:8"`
}

// parsedHeader is pkiHeaderRaw reduced to the fields the protection check
// and response builder actually need, with IMPLICIT-tagged fields decoded
// to their real types.
type parsedHeader struct {
	RawFullBytes  []byte // the header's own DER, for ProtectedPart
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	ProtectionAlg *pkix.AlgorithmIdentifier // nil if the request carried no protectionAlg
	SenderKID     []byte
	TransactionID []byte
	SenderNonce   []byte
}

// parsedMessage is a fully-decoded PKIMessage ready for protection
// verification and body dispatch.
type parsedMessage struct {
	Header     parsedHeader
	BodyType   int
	BodyBytes  []byte // content of the PKIBody CHOICE
	BodyRaw    asn1.RawValue
	Protection asn1.RawValue // zero value if the message carried no protection
}

// parsePKIMessage decodes a DER (or base64-of-DER) CMP PKIMessage into a
// parsedMessage. Protection verification and body-specific parsing (CRMF,
// certConf) happen later in server.go / crmf.go — this function only
// establishes structure.
func parsePKIMessage(data []byte) (*parsedMessage, error) {
	der, err := ensureDER(data)
	if err != nil {
		return nil, err
	}

	var msg pkiMessageRaw
	if _, err := asn1.Unmarshal(der, &msg); err != nil {
		return nil, fmt.Errorf("cmp: parse PKIMessage: %w", err)
	}
	if msg.Header.Class != asn1.ClassUniversal || msg.Header.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("cmp: PKIHeader has unexpected ASN.1 shape")
	}
	if msg.Body.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("cmp: PKIBody has unexpected ASN.1 class %d", msg.Body.Class)
	}

	hdr, err := parseHeader(msg.Header)
	if err != nil {
		return nil, fmt.Errorf("cmp: parse PKIHeader: %w", err)
	}

	return &parsedMessage{
		Header:     hdr,
		BodyType:   msg.Body.Tag,
		BodyBytes:  msg.Body.Bytes,
		BodyRaw:    msg.Body,
		Protection: msg.Protection,
	}, nil
}

func parseHeader(raw asn1.RawValue) (parsedHeader, error) {
	var h pkiHeaderRaw
	if _, err := asn1.Unmarshal(raw.FullBytes, &h); err != nil {
		return parsedHeader{}, err
	}

	out := parsedHeader{
		RawFullBytes:  raw.FullBytes,
		Sender:        h.Sender,
		Recipient:     h.Recipient,
		SenderKID:     h.SenderKID,
		TransactionID: h.TransactionID,
		SenderNonce:   h.SenderNonce,
	}
	if len(h.ProtectionAlg.Algorithm) > 0 {
		out.ProtectionAlg = &h.ProtectionAlg
	}
	return out, nil
}

// ensureDER returns the input as DER bytes. If the input is not valid ASN.1,
// it attempts standard-alphabet base64 decoding (stripping whitespace first).
func ensureDER(data []byte) ([]byte, error) {
	var probe asn1.RawValue
	if _, err := asn1.Unmarshal(data, &probe); err == nil {
		return data, nil
	}
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, string(data))
	decoded, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("cmp: not valid DER or base64-encoded DER")
	}
	return decoded, nil
}
