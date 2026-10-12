// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// PKIMessage builder per RFC 4210. Encodes the fields required for a valid
// certification response (ip/cp/kup), a pkiconf, and a protection-failure
// rejection (error) — every response this server sends is PBM-protected
// with the same shared secret configured for verification (see
// protection.go), because a real CMP client (openssl included) verifies
// response protection by default.

// pkiStatusInfo per RFC 4210 §5.1.1. failInfo is a PKIFailureInfo BIT
// STRING; badMessageCheck is bit 0, so its DER encoding as a single-byte
// bitstring is 0x80 with 7 unused trailing bits — encoded directly rather
// than via a named-bits helper since this server only ever emits that one
// failure reason.
type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"` // PKIFreeText ::= SEQUENCE OF UTF8String
	FailInfo     asn1.BitString  `asn1:"optional"`
}

// utf8FreeText builds a one-element PKIFreeText carrying s as a UTF8String —
// built as a RawValue rather than a plain Go string field because
// encoding/asn1 does not support the "utf8" string-type override on a slice
// element, only on a scalar string field.
func utf8FreeText(s string) []asn1.RawValue {
	return []asn1.RawValue{{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte(s),
	}}
}

var failInfoBadMessageCheck = asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}

// certOrEncCert wraps the issued certificate as a [0] CONTEXT tag.
type certOrEncCert struct {
	Bytes []byte
}

// buildCertResponse constructs a DER-encoded CMP PKIMessage containing the
// issued certificate, protected with the shared secret. bodyTag must be
// PKIBodyIP, PKIBodyCP or PKIBodyKUP.
func buildCertResponse(cert *x509.Certificate, bodyTag int, reqHdr parsedHeader, secret, reference []byte) ([]byte, error) {
	body, err := marshalCertRepBody(cert, bodyTag)
	if err != nil {
		return nil, err
	}
	return buildProtectedMessage(body, reqHdr, secret, reference)
}

func marshalCertRepBody(cert *x509.Certificate, bodyTag int) ([]byte, error) {
	// CMPCertificate = [0] EXPLICIT Certificate (the raw DER)
	certTagged, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      cert.Raw,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal CMPCertificate: %w", err)
	}

	// CertifiedKeyPair ::= SEQUENCE { certOrEncCert CertOrEncCert, ... }
	ckp, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certTagged,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal CertifiedKeyPair: %w", err)
	}

	// PKIStatusInfo ::= SEQUENCE { status INTEGER(0) }  — accepted
	statusBytes, err := asn1.Marshal(pkiStatusInfo{Status: 0})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal PKIStatusInfo: %w", err)
	}

	// certReqId INTEGER — always 0 for single-cert response
	reqIDBytes, err := asn1.Marshal(big.NewInt(0))
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal certReqId: %w", err)
	}

	// CertResponse ::= SEQUENCE { certReqId INTEGER, status PKIStatusInfo, certifiedKeyPair ... }
	var certRespContent []byte
	certRespContent = append(certRespContent, reqIDBytes...)
	certRespContent = append(certRespContent, statusBytes...)
	certRespContent = append(certRespContent, ckp...)

	certResp, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certRespContent,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal CertResponse: %w", err)
	}

	// CertRepMessage ::= SEQUENCE { response SEQUENCE OF CertResponse }
	respSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certResp,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal response seq: %w", err)
	}

	certRepMsg, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      respSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal CertRepMessage: %w", err)
	}

	// PKIBody = [bodyTag] IMPLICIT CertRepMessage
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        bodyTag,
		IsCompound: true,
		Bytes:      certRepMsg,
	})
}

// buildPKIConf constructs a pkiconf (body type 19) response to a client's
// certConf, protected with the shared secret. PKIConfirmContent is NULL.
func buildPKIConf(reqHdr parsedHeader, secret, reference []byte) ([]byte, error) {
	null, err := asn1.Marshal(asn1.NullRawValue)
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal PKIConfirmContent: %w", err)
	}
	body, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        PKIBodyPKIConf,
		IsCompound: true,
		Bytes:      null,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal PKIBody(pkiconf): %w", err)
	}
	return buildProtectedMessage(body, reqHdr, secret, reference)
}

// buildErrorResponse constructs a rejection (body type 23, ErrorMsgContent)
// with PKIStatusInfo{status: rejection, failInfo: badMessageCheck},
// protected with the shared secret — RFC 4210 §5.1.3's requirement that
// protection failures are reported, not silently dropped, and that the
// rejection is itself authenticated so a MITM cannot forge it either.
func buildErrorResponse(reqHdr parsedHeader, statusText string, secret, reference []byte) ([]byte, error) {
	status := pkiStatusInfo{
		Status:       2, // rejection
		StatusString: utf8FreeText(statusText),
		FailInfo:     failInfoBadMessageCheck,
	}
	statusBytes, err := asn1.Marshal(status)
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal PKIStatusInfo: %w", err)
	}
	// ErrorMsgContent ::= SEQUENCE { pKIStatusInfo PKIStatusInfo, ... }
	errContent, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      statusBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal ErrorMsgContent: %w", err)
	}
	body, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        PKIBodyError,
		IsCompound: true,
		Bytes:      errContent,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal PKIBody(error): %w", err)
	}
	return buildProtectedMessage(body, reqHdr, secret, reference)
}

// buildProtectedMessage wraps an already-encoded PKIBody in a PKIHeader that
// echoes the request's transactionID and senderNonce (as recipNonce), signs
// header+body with the configured PBM secret, and returns the full
// DER-encoded, protected PKIMessage. The protection algorithm's parameters
// (fresh salt included) are chosen once, up front, so the header carrying
// them and the MAC computed over that same header are built in one pass —
// there is no chicken-and-egg between "what does the header say" and "what
// did we MAC" the way there would be if the params were generated lazily.
func buildProtectedMessage(body []byte, reqHdr parsedHeader, secret, reference []byte) ([]byte, error) {
	protAlg, param, err := newPBMAlgorithmIdentifier()
	if err != nil {
		return nil, err
	}
	protAlgDER, err := asn1.MarshalWithParams(protAlg, "explicit,tag:1")
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal response protectionAlg: %w", err)
	}

	header, err := marshalHeader(reqHdr, reference, protAlgDER)
	if err != nil {
		return nil, fmt.Errorf("cmp: build PKIHeader: %w", err)
	}

	protectedPart, err := protectedPartDER(header, body)
	if err != nil {
		return nil, fmt.Errorf("cmp: build ProtectedPart: %w", err)
	}
	mac, _, err := computePBM(secret, param, protectedPart)
	if err != nil {
		return nil, err
	}

	// PKIMessage's [0] protection field is EXPLICIT (RFC 4210's PKIXCMP
	// module default): the outer context tag wraps a complete BIT STRING
	// TLV, it does not replace the BIT STRING's own tag.
	bitStringDER, err := asn1.Marshal(asn1.BitString{Bytes: mac, BitLength: len(mac) * 8})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal protection BIT STRING: %w", err)
	}
	protField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      bitStringDER,
	})
	if err != nil {
		return nil, fmt.Errorf("cmp: marshal protection field: %w", err)
	}

	var msgContent []byte
	msgContent = append(msgContent, header...)
	msgContent = append(msgContent, body...)
	msgContent = append(msgContent, protField...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      msgContent,
	})
}

func marshalHeader(reqHdr parsedHeader, reference, protAlgDER []byte) ([]byte, error) {
	emptyDN, err := generalNameEmptyDirectoryName()
	if err != nil {
		return nil, err
	}

	pvno, err := asn1.Marshal(2)
	if err != nil {
		return nil, fmt.Errorf("marshal pvno: %w", err)
	}

	var content []byte
	content = append(content, pvno...)
	content = append(content, emptyDN...) // sender

	if len(reqHdr.Sender.FullBytes) > 0 {
		content = append(content, reqHdr.Sender.FullBytes...) // recipient = echo request's sender
	} else {
		content = append(content, emptyDN...)
	}

	content = append(content, protAlgDER...)

	if len(reference) > 0 {
		kid, err := asn1.MarshalWithParams(reference, "explicit,tag:2")
		if err != nil {
			return nil, fmt.Errorf("marshal senderKID: %w", err)
		}
		content = append(content, kid...)
	}

	if len(reqHdr.TransactionID) > 0 {
		txn, err := asn1.MarshalWithParams(reqHdr.TransactionID, "explicit,tag:4")
		if err != nil {
			return nil, fmt.Errorf("marshal transactionID: %w", err)
		}
		content = append(content, txn...)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate senderNonce: %w", err)
	}
	senderNonce, err := asn1.MarshalWithParams(nonce, "explicit,tag:5")
	if err != nil {
		return nil, fmt.Errorf("marshal senderNonce: %w", err)
	}
	content = append(content, senderNonce...)

	if len(reqHdr.SenderNonce) > 0 {
		recipNonce, err := asn1.MarshalWithParams(reqHdr.SenderNonce, "explicit,tag:6")
		if err != nil {
			return nil, fmt.Errorf("marshal recipNonce: %w", err)
		}
		content = append(content, recipNonce...)
	}

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
}

// generalNameEmptyDirectoryName returns GeneralName directoryName [4] ::=
// an empty RDNSequence — a placeholder identity used for this hub's sender
// field. No tested CMP client (openssl included) validates it.
func generalNameEmptyDirectoryName() ([]byte, error) {
	emptySeq, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      emptySeq,
	})
}
