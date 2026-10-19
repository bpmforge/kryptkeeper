// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tsa

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// PKIFailureInfo bit positions used by this package (RFC 3161 2.4.2).
const (
	FailBadAlg           = 0
	FailBadRequest       = 2
	FailBadDataFormat    = 5
	FailSystemFailure    = 25
	pkiStatusGranted     = 0
	pkiStatusRejection   = 2
	timeStampReqVersion1 = 1
)

// ErrUnsupportedHash is wrapped by the RejectError returned for a request
// whose hash algorithm is not SHA-256, SHA-384 or SHA-512.
var ErrUnsupportedHash = errors.New("tsa: unsupported hash algorithm")

// RejectError is a well-formed refusal: Respond returns a TimeStampResp with
// PKIStatus rejection and this error.
type RejectError struct {
	FailInfo int
	Reason   string
	Err      error
}

func (e *RejectError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("tsa: request rejected (failInfo %d): %s: %v", e.FailInfo, e.Reason, e.Err)
	}
	return fmt.Sprintf("tsa: request rejected (failInfo %d): %s", e.FailInfo, e.Reason)
}

func (e *RejectError) Unwrap() error { return e.Err }

func reject(fail int, reason string) *RejectError {
	return &RejectError{FailInfo: fail, Reason: reason}
}

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

var hashByOID = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{oidSHA256, crypto.SHA256},
	{oidSHA384, crypto.SHA384},
	{oidSHA512, crypto.SHA512},
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	for _, h := range hashByOID {
		if h.oid.Equal(oid) {
			return h.hash, true
		}
	}
	return 0, false
}

func oidFromHash(h crypto.Hash) asn1.ObjectIdentifier {
	for _, e := range hashByOID {
		if e.hash == h {
			return e.oid
		}
	}
	return nil
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// Request is a parsed, validated TimeStampReq.
type Request struct {
	Hash      crypto.Hash
	Digest    []byte
	Nonce     *big.Int
	CertReq   bool
	ReqPolicy asn1.ObjectIdentifier
}

// ParseRequest decodes a DER TimeStampReq. Every failure is a *RejectError
// carrying the PKIFailureInfo bit a response should report.
func ParseRequest(der []byte) (*Request, error) {
	var raw timeStampReq
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 {
		return nil, reject(FailBadDataFormat, "malformed TimeStampReq")
	}
	if raw.Version != timeStampReqVersion1 {
		return nil, reject(FailBadDataFormat, "unsupported TimeStampReq version")
	}
	for _, ext := range raw.Extensions {
		if ext.Critical {
			return nil, reject(FailBadRequest, "unknown critical extension "+ext.Id.String())
		}
	}
	h, ok := hashFromOID(raw.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return nil, &RejectError{FailInfo: FailBadAlg, Reason: "hash algorithm " + raw.MessageImprint.HashAlgorithm.Algorithm.String(), Err: ErrUnsupportedHash}
	}
	if len(raw.MessageImprint.HashedMessage) != h.Size() {
		return nil, reject(FailBadDataFormat, "digest length does not match hash algorithm")
	}
	return &Request{
		Hash:      h,
		Digest:    raw.MessageImprint.HashedMessage,
		Nonce:     raw.Nonce,
		CertReq:   raw.CertReq,
		ReqPolicy: raw.ReqPolicy,
	}, nil
}
