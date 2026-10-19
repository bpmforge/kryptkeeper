// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package attestation verifies hardware-key attestation statements.
package attestation

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	ErrNoAttestation      = errors.New("attestation missing")
	ErrUnsupportedFormat  = errors.New("attestation format unsupported")
	ErrInvalidAttestation = errors.New("attestation invalid")
	ErrKeyMismatch        = errors.New("attested key does not match the CSR key")
)

// FormatYubiKeyPIV is the wire format name.
const FormatYubiKeyPIV = "yubikey-piv"

const (
	maxPEMBytes      = 16 * 1024
	maxIntermediates = 3
	maxChainDepth    = 4
)

// Yubico attestation extension OIDs (1.3.6.1.4.1.41482.3.*).
var (
	oidFirmware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

// Result describes a verified attestation.
type Result struct {
	Format           string
	Serial           string
	Firmware         string
	VendorRootSHA256 string
	KeySPKISHA256    string
	PINPolicy        int
	TouchPolicy      int
	VerifiedAt       time.Time
}

// Verifier checks attestations against a set of vendor roots.
type Verifier struct {
	Roots []*x509.Certificate
	Now   func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidAttestation, fmt.Sprintf(format, a...))
}

func parseCertPEM(s string) (*x509.Certificate, error) {
	if len(s) == 0 || len(s) > maxPEMBytes {
		return nil, invalid("certificate PEM empty or over %d bytes", maxPEMBytes)
	}
	blk, _ := pem.Decode([]byte(s))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, invalid("not a CERTIFICATE PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, invalid("parse certificate: %v", err)
	}
	return c, nil
}

func hasExt(c *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

// VerifyYubiKeyPIV validates a YubiKey PIV slot attestation certificate chain
// and that it attests csrPub. The chain is walked by hand: real YubiKey
// intermediates lack CA basicConstraints, so x509.Verify would reject them.
func (v *Verifier) VerifyYubiKeyPIV(certPEM string, intermediatesPEM []string, csrPub crypto.PublicKey) (Result, error) {
	if len(v.Roots) == 0 {
		return Result{}, invalid("no vendor roots configured")
	}
	if len(intermediatesPEM) > maxIntermediates {
		return Result{}, invalid("more than %d intermediates", maxIntermediates)
	}
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		return Result{}, err
	}
	fw, ok := hasExt(leaf, oidFirmware)
	if !ok {
		return Result{}, invalid("certificate is not a YubiKey PIV attestation")
	}
	inter := make([]*x509.Certificate, 0, len(intermediatesPEM))
	for _, p := range intermediatesPEM {
		c, err := parseCertPEM(p)
		if err != nil {
			return Result{}, err
		}
		inter = append(inter, c)
	}
	now := v.now()
	root := v.walk(leaf, inter, 1, now)
	if root == nil {
		return Result{}, invalid("chain does not reach a trusted vendor root")
	}

	leafSPKI, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return Result{}, invalid("attested key: %v", err)
	}
	csrSPKI, err := x509.MarshalPKIXPublicKey(csrPub)
	if err != nil {
		return Result{}, fmt.Errorf("%w: CSR key: %v", ErrKeyMismatch, err)
	}
	if !bytes.Equal(leafSPKI, csrSPKI) {
		return Result{}, ErrKeyMismatch
	}

	res := Result{
		Format:           FormatYubiKeyPIV,
		VendorRootSHA256: sha256Hex(root.Raw),
		KeySPKISHA256:    sha256Hex(leafSPKI),
		VerifiedAt:       now.UTC(),
	}
	if len(fw) == 3 {
		res.Firmware = fmt.Sprintf("%d.%d.%d", fw[0], fw[1], fw[2])
	}
	if raw, ok := hasExt(leaf, oidSerial); ok {
		n := new(big.Int)
		if rest, err := asn1.Unmarshal(raw, &n); err == nil && len(rest) == 0 {
			res.Serial = n.String()
		}
	}
	if raw, ok := hasExt(leaf, oidPolicy); ok && len(raw) >= 2 {
		res.PINPolicy, res.TouchPolicy = int(raw[0]), int(raw[1])
	}
	return res, nil
}

// walk returns the trusted root reached from child, or nil. Every link is a
// raw signature check; every cert must be inside its validity window.
func (v *Verifier) walk(child *x509.Certificate, inter []*x509.Certificate, depth int, now time.Time) *x509.Certificate {
	if depth > maxChainDepth || now.Before(child.NotBefore) || now.After(child.NotAfter) {
		return nil
	}
	signedBy := func(p *x509.Certificate) bool {
		return bytes.Equal(child.RawIssuer, p.RawSubject) &&
			p.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
	}
	for _, r := range v.Roots {
		if signedBy(r) && !now.Before(r.NotBefore) && !now.After(r.NotAfter) {
			return r
		}
	}
	for i, p := range inter {
		if p == child || !signedBy(p) {
			continue
		}
		rest := make([]*x509.Certificate, 0, len(inter)-1)
		rest = append(rest, inter[:i]...)
		rest = append(rest, inter[i+1:]...)
		if r := v.walk(p, rest, depth+1, now); r != nil {
			return r
		}
	}
	return nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
