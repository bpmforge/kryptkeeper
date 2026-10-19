// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package tsa implements the RFC 3161 Time-Stamp Authority token format: it
// parses a TimeStampReq and returns a TimeStampResp whose token is a CMS
// SignedData over a TSTInfo. It is a leaf package with no HTTP surface; the
// caller owns transport, authorization and audit.
package tsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/smallstep/pkcs7"
)

var (
	oidTSTInfo          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSigningCertV2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidAnyPolicy        = asn1.ObjectIdentifier{2, 5, 29, 32, 0}
	errSignerKeyMissing = errors.New("tsa: Signer and Cert are required")
)

// Config configures an Authority.
type Config struct {
	// Signer is the TSA private key (ECDSA or RSA).
	Signer crypto.Signer
	// Cert must carry the timeStamping EKU only, marked critical (RFC 3161 2.3).
	Cert *x509.Certificate
	// Chain holds issuers embedded in the token when the request sets certReq.
	Chain []*x509.Certificate
	// PolicyOID defaults to anyPolicy (2.5.29.32.0).
	PolicyOID asn1.ObjectIdentifier
	// Now is the injected clock; defaults to time.Now.
	Now func() time.Time
	// Serial returns a fresh serial; defaults to a 127-bit random positive value.
	Serial func() (*big.Int, error)
}

// Authority issues timestamp tokens.
type Authority struct {
	cfg Config
}

// Granted describes an issued token for the caller's audit record.
type Granted struct {
	Serial  *big.Int
	GenTime time.Time
	Hash    crypto.Hash
	Digest  []byte
	Nonce   *big.Int
}

// New validates cfg and returns an Authority.
func New(cfg Config) (*Authority, error) {
	if cfg.Signer == nil || cfg.Cert == nil {
		return nil, errSignerKeyMissing
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Serial == nil {
		cfg.Serial = randomSerial
	}
	if len(cfg.PolicyOID) == 0 {
		cfg.PolicyOID = oidAnyPolicy
	}
	if !publicKeysEqual(cfg.Signer.Public(), cfg.Cert.PublicKey) {
		return nil, errors.New("tsa: Signer does not match Cert public key")
	}
	if len(cfg.Cert.ExtKeyUsage) != 1 || cfg.Cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(cfg.Cert.UnknownExtKeyUsage) != 0 {
		return nil, errors.New("tsa: Cert EKU must be exactly timeStamping")
	}
	critical := false
	for _, e := range cfg.Cert.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			critical = e.Critical
		}
	}
	if !critical {
		return nil, errors.New("tsa: Cert EKU must be marked critical")
	}
	now := cfg.Now()
	if now.Before(cfg.Cert.NotBefore) || now.After(cfg.Cert.NotAfter) {
		return nil, errors.New("tsa: Cert is not valid at the current time")
	}
	return &Authority{cfg: cfg}, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	k, ok := a.(eq)
	return ok && k.Equal(b)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil // 1..2^127, always positive
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"` // PKIFreeText: SEQUENCE OF UTF8String
	FailInfo     asn1.BitString  `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	CertHash []byte
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}

// Respond answers a DER TimeStampReq with a DER TimeStampResp.
//
// It returns a response when err == nil (granted) or err is a *RejectError
// (rejection, no token). A plain error means systemFailure (signing failed);
// respDER is then a rejection with failInfo systemFailure.
func (a *Authority) Respond(reqDER []byte) ([]byte, *Granted, error) {
	req, err := ParseRequest(reqDER)
	if err != nil {
		var re *RejectError
		if errors.As(err, &re) {
			return rejection(re.FailInfo, re.Reason), nil, err
		}
		return rejection(FailBadDataFormat, "malformed request"), nil, err
	}
	if len(req.ReqPolicy) != 0 && !req.ReqPolicy.Equal(a.cfg.PolicyOID) {
		re := reject(FailBadRequest, "requested policy not supported")
		return rejection(re.FailInfo, re.Reason), nil, re
	}
	g, token, err := a.issue(req)
	if err != nil {
		return rejection(FailSystemFailure, "internal error"), nil, err
	}
	respDER, err := asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: pkiStatusGranted},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	})
	if err != nil {
		return rejection(FailSystemFailure, "internal error"), nil, err
	}
	return respDER, g, nil
}

func (a *Authority) issue(req *Request) (*Granted, []byte, error) {
	serial, err := a.cfg.Serial()
	if err != nil {
		return nil, nil, fmt.Errorf("tsa: serial: %w", err)
	}
	genTime := a.cfg.Now().UTC().Truncate(time.Second)
	infoDER, err := asn1.Marshal(tstInfo{
		Version: 1,
		Policy:  a.cfg.PolicyOID,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidFromHash(req.Hash), Parameters: asn1.NullRawValue},
			HashedMessage: req.Digest,
		},
		SerialNumber: serial,
		GenTime:      genTime,
		Nonce:        req.Nonce,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tsa: marshal TSTInfo: %w", err)
	}

	sd, err := pkcs7.NewSignedData(infoDER)
	if err != nil {
		return nil, nil, err
	}
	// The library hard-codes eContentType id-data; the exported field lets
	// us set id-ct-TSTInfo before the contentType signed attribute is built.
	sd.GetSignedData().ContentInfo.ContentType = oidTSTInfo
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	certHash := sha256.Sum256(a.cfg.Cert.Raw)
	cfg := pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{{
		Type:  oidSigningCertV2,
		Value: signingCertificateV2{Certs: []essCertIDv2{{CertHash: certHash[:]}}},
	}}}
	var parents []*x509.Certificate
	if req.CertReq {
		parents = a.cfg.Chain
	}
	if err := sd.AddSignerChain(a.cfg.Cert, a.cfg.Signer, parents, cfg); err != nil {
		return nil, nil, fmt.Errorf("tsa: sign: %w", err)
	}
	token, err := sd.Finish()
	if err != nil {
		return nil, nil, fmt.Errorf("tsa: finish: %w", err)
	}
	return &Granted{Serial: serial, GenTime: genTime, Hash: req.Hash, Digest: req.Digest, Nonce: req.Nonce}, token, nil
}

// rejection builds a TimeStampResp with PKIStatus rejection and one failInfo bit.
func rejection(failBit int, reason string) []byte {
	bytes := make([]byte, failBit/8+1)
	bytes[failBit/8] |= 0x80 >> (failBit % 8)
	text, err := asn1.MarshalWithParams(reason, "utf8")
	if err != nil {
		return nil
	}
	der, err := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{
		Status:       pkiStatusRejection,
		StatusString: []asn1.RawValue{{FullBytes: text}},
		FailInfo:     asn1.BitString{Bytes: bytes, BitLength: failBit + 1},
	}})
	if err != nil { // static shapes; cannot fail
		return nil
	}
	return der
}
