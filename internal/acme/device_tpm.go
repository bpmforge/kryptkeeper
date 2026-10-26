// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

// WebAuthn "tpm" attestation statement (W40-02, D-316): the byte layouts of
// TPMS_ATTEST, TPMT_PUBLIC and TPMT_SIGNATURE. There is no TPM library in
// go.mod and these three structures are small, so they are parsed here, strictly
// (a truncated or over-long structure is refused) and with the section of the
// TPM 2.0 Library specification each layout comes from:
//   - TPMS_ATTEST / TPMS_CERTIFY_INFO: Part 2 sections 10.12.8 and 10.12.3
//   - TPMT_PUBLIC: Part 2 section 12.2.4 (parameters 12.2.3.5/12.2.3.6)
//   - TPMT_SIGNATURE: Part 2 section 11.3.4
//   - Name of an object: Part 1 section 16 (nameAlg || H_nameAlg(TPMT_PUBLIC))
//
// Statement semantics: https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	tpmGeneratedValue  = 0xff544347 // TPM_GENERATED_VALUE, Part 2 section 6.2
	tpmSTAttestCertify = 0x8017     // TPM_ST_ATTEST_CERTIFY, Part 2 section 6.9

	tpmAlgRSA       = 0x0001
	tpmAlgSHA1      = 0x0004
	tpmAlgSHA256    = 0x000b
	tpmAlgSHA384    = 0x000c
	tpmAlgSHA512    = 0x000d
	tpmAlgNull      = 0x0010
	tpmAlgRSASSA    = 0x0014
	tpmAlgRSAES     = 0x0015
	tpmAlgRSAPSS    = 0x0016
	tpmAlgOAEP      = 0x0017
	tpmAlgECDSA     = 0x0018
	tpmAlgECDH      = 0x0019
	tpmAlgECDAA     = 0x001a
	tpmAlgECC       = 0x0023
	tpmAlgECSCHNORR = 0x001c

	tpmCurveP256 = 0x0003
	tpmCurveP384 = 0x0004
	tpmCurveP521 = 0x0005
)

var errTPMMalformed = errors.New("malformed TPM structure")

// tpmReader reads big-endian TPM wire types; the first short read poisons it.
type tpmReader struct {
	b   []byte
	err error
}

func (r *tpmReader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.err = errTPMMalformed
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *tpmReader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *tpmReader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

// sized reads a TPM2B: a 16-bit length then that many bytes.
func (r *tpmReader) sized() []byte {
	n := int(r.u16())
	return r.take(n)
}

// tpmCertify is the part of a TPMS_ATTEST of type CERTIFY the verifier uses.
type tpmCertify struct {
	ExtraData []byte
	Name      []byte // attested.name
}

// parseTPMCertInfo parses a TPMS_ATTEST; the remaining header fields
// (qualifiedSigner, clockInfo, firmwareVersion) are skipped as WebAuthn says.
func parseTPMCertInfo(b []byte) (*tpmCertify, error) {
	r := &tpmReader{b: b}
	if r.u32() != tpmGeneratedValue {
		if r.err != nil {
			return nil, r.err
		}
		return nil, errors.New("certInfo magic is not TPM_GENERATED_VALUE")
	}
	if t := r.u16(); t != tpmSTAttestCertify && r.err == nil {
		return nil, errors.New("certInfo type is not TPM_ST_ATTEST_CERTIFY")
	}
	r.sized() // qualifiedSigner
	extra := r.sized()
	r.take(8 + 4 + 4 + 1) // clockInfo: clock, resetCount, restartCount, safe
	r.take(8)             // firmwareVersion
	name := r.sized()     // attested.name
	r.sized()             // attested.qualifiedName
	if r.err != nil || len(r.b) != 0 {
		return nil, errTPMMalformed
	}
	return &tpmCertify{ExtraData: extra, Name: name}, nil
}

// tpmPublic is a parsed TPMT_PUBLIC.
type tpmPublic struct {
	NameAlg uint16
	Key     crypto.PublicKey
}

func parseTPMPublic(b []byte) (*tpmPublic, error) {
	r := &tpmReader{b: b}
	typ := r.u16()
	nameAlg := r.u16()
	r.u32()   // objectAttributes
	r.sized() // authPolicy
	skipSym := func() {
		if alg := r.u16(); alg != tpmAlgNull {
			r.u16() // keyBits
			r.u16() // mode
		}
	}
	var key crypto.PublicKey
	switch typ {
	case tpmAlgRSA:
		skipSym()
		switch scheme := r.u16(); scheme {
		case tpmAlgNull, tpmAlgRSAES:
		case tpmAlgRSASSA, tpmAlgRSAPSS, tpmAlgOAEP:
			r.u16() // hashAlg
		default:
			return nil, errors.New("unsupported RSA scheme in pubArea")
		}
		keyBits := int(r.u16())
		exp := r.u32()
		mod := r.sized()
		if r.err != nil {
			return nil, r.err
		}
		if exp == 0 {
			exp = 65537
		}
		if keyBits != 8*len(mod) || keyBits < 2048 || exp > 1<<31-1 {
			return nil, errors.New("RSA key in pubArea is inconsistent or below 2048 bits")
		}
		key = &rsa.PublicKey{N: new(big.Int).SetBytes(mod), E: int(exp)}
	case tpmAlgECC:
		skipSym()
		switch scheme := r.u16(); scheme {
		case tpmAlgNull:
		case tpmAlgECDSA, tpmAlgECDH, tpmAlgECSCHNORR:
			r.u16()
		case tpmAlgECDAA:
			r.u16()
			r.u16()
		default:
			return nil, errors.New("unsupported ECC scheme in pubArea")
		}
		curveID := r.u16()
		if kdf := r.u16(); kdf != tpmAlgNull {
			r.u16()
		}
		x, y := r.sized(), r.sized()
		if r.err != nil {
			return nil, r.err
		}
		var curve elliptic.Curve
		switch curveID {
		case tpmCurveP256:
			curve = elliptic.P256()
		case tpmCurveP384:
			curve = elliptic.P384()
		case tpmCurveP521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported ECC curve in pubArea")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("ECC point in pubArea is not on its curve")
		}
		key = pub
	default:
		return nil, errors.New("unsupported key type in pubArea")
	}
	if r.err != nil || len(r.b) != 0 {
		return nil, errTPMMalformed
	}
	return &tpmPublic{NameAlg: nameAlg, Key: key}, nil
}

func tpmHash(alg uint16) (crypto.Hash, bool) {
	switch alg {
	case tpmAlgSHA256:
		return crypto.SHA256, true
	case tpmAlgSHA384:
		return crypto.SHA384, true
	case tpmAlgSHA512:
		return crypto.SHA512, true
	}
	// SHA-1 (tpmAlgSHA1) is deliberately absent: a name or signature digest
	// with practical collisions must not bind the attested key.
	return 0, false
}

// checkTPMName verifies that name is nameAlg || H(pubArea) for the pubArea's
// own nameAlg (Part 1 section 16), tying certInfo to the exact public area.
func checkTPMName(name, pubArea []byte, nameAlg uint16) error {
	h, ok := tpmHash(nameAlg)
	if !ok {
		return errors.New("pubArea nameAlg is not an accepted digest (SHA-256 or stronger)")
	}
	hh := h.New()
	hh.Write(pubArea)
	want := binary.BigEndian.AppendUint16(nil, nameAlg)
	want = hh.Sum(want)
	if subtle.ConstantTimeCompare(want, name) != 1 {
		return errors.New("certInfo does not name pubArea")
	}
	return nil
}

// coseHash maps a COSE algorithm identifier to the signature scheme and digest
// the statement uses. RS1 (-65535) is refused.
func coseSignature(alg int64) (hash crypto.Hash, ecdsaSig bool, ok bool) {
	switch alg {
	case -7:
		return crypto.SHA256, true, true
	case -35:
		return crypto.SHA384, true, true
	case -257:
		return crypto.SHA256, false, true
	case -258:
		return crypto.SHA384, false, true
	}
	return 0, false, false
}

// verifyTPMSignature checks sig over certInfo with the AIK public key. sig is a
// TPMT_SIGNATURE (Part 2 section 11.3.4); the raw ASN.1 ECDSA / PKCS#1 forms
// the WebAuthn test vector uses are accepted as the same cryptographic check
// under a different encoding.
func verifyTPMSignature(pub crypto.PublicKey, alg int64, certInfo, sig []byte) error {
	hash, wantECDSA, ok := coseSignature(alg)
	if !ok {
		return errors.New("signature algorithm is not accepted (ES256, ES384, RS256, RS384)")
	}
	h := hash.New()
	h.Write(certInfo)
	digest := h.Sum(nil)

	var ecR, ecS, rsaSig []byte
	r := &tpmReader{b: sig}
	sigAlg := r.u16()
	hashAlg := r.u16()
	switch {
	case r.err == nil && wantECDSA && sigAlg == tpmAlgECDSA:
		ecR, ecS = r.sized(), r.sized()
	case r.err == nil && !wantECDSA && (sigAlg == tpmAlgRSASSA):
		rsaSig = r.sized()
	default:
		r.err = errTPMMalformed
	}
	if r.err == nil && len(r.b) == 0 {
		if th, ok := tpmHash(hashAlg); !ok || th != hash {
			return errors.New("TPMT_SIGNATURE hash does not match alg")
		}
	} else {
		ecR, ecS, rsaSig = nil, nil, nil
	}

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !wantECDSA {
			return errors.New("alg does not match the AIK key type")
		}
		if ecR != nil {
			if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(ecR), new(big.Int).SetBytes(ecS)) {
				return errors.New("attestation signature is invalid")
			}
			return nil
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("attestation signature is invalid")
		}
		return nil
	case *rsa.PublicKey:
		if wantECDSA {
			return errors.New("alg does not match the AIK key type")
		}
		if rsaSig == nil {
			rsaSig = sig
		}
		if err := rsa.VerifyPKCS1v15(k, hash, digest, rsaSig); err != nil {
			return errors.New("attestation signature is invalid")
		}
		return nil
	}
	return errors.New("AIK key type is not supported")
}

// verifyTPMStatement runs the WebAuthn tpm verification steps that need no
// trust anchor: the AIK signature over certInfo, certInfo's fields, the
// extraData binding, and the name-of-pubArea check. It returns the attested
// credential public key. extraWant is the digest of attToBeSigned.
func verifyTPMStatement(aikPub crypto.PublicKey, alg int64, certInfo, pubArea, sig, extraWant []byte) (crypto.PublicKey, error) {
	if err := verifyTPMSignature(aikPub, alg, certInfo, sig); err != nil {
		return nil, err
	}
	ci, err := parseTPMCertInfo(certInfo)
	if err != nil {
		return nil, fmt.Errorf("certInfo: %w", err)
	}
	if subtle.ConstantTimeCompare(ci.ExtraData, extraWant) != 1 {
		return nil, errors.New("certInfo extraData does not match the key authorization")
	}
	pa, err := parseTPMPublic(pubArea)
	if err != nil {
		return nil, fmt.Errorf("pubArea: %w", err)
	}
	if err := checkTPMName(ci.Name, pubArea, pa.NameAlg); err != nil {
		return nil, err
	}
	return pa.Key, nil
}
