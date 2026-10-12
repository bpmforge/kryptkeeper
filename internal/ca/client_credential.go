// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"math/big"
	"time"
)

// RevocationChecker reports whether a certificate this hub issued is
// revoked; every RevocationStore satisfies it.
type RevocationChecker interface {
	IsRevoked(serial *big.Int, caID string) (bool, time.Time, int, error)
}

// ErrNotIssuedHere means the presented certificate is not signed by the
// issuer: it is not a credential for this CA at all, and a protocol may fall
// back to another authentication method rather than refuse.
var ErrNotIssuedHere = errors.New("certificate was not issued by this CA")

// CredentialRefusedError is a hub-issued certificate that may not be used as
// a credential. Reason is safe to show the client and to audit.
type CredentialRefusedError struct {
	Reason string
	Err    error // underlying cause, if any; for logs only
}

func (e *CredentialRefusedError) Error() string { return e.Reason }
func (e *CredentialRefusedError) Unwrap() error { return e.Err }

// CheckHubClientCertificate decides whether cert, presented by a client to
// renew (WSTEP) or re-enroll (EST), is a usable credential issued by the CA
// caID whose certificate is issuer. It must be signed by issuer (else
// ErrNotIssuedHere), within its validity at now, carry client-auth EKU, and
// be known unrevoked: an unknown revocation state refuses (fail closed).
// One implementation for every protocol, so the checks cannot drift.
func CheckHubClientCertificate(cert, issuer *x509.Certificate, caID string, now time.Time, rev RevocationChecker) error {
	if cert == nil || issuer == nil || cert.CheckSignatureFrom(issuer) != nil {
		return ErrNotIssuedHere
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return &CredentialRefusedError{Reason: "certificate is outside its validity period"}
	}
	clientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return &CredentialRefusedError{Reason: "certificate lacks client-auth EKU"}
	}
	if rev == nil {
		return &CredentialRefusedError{Reason: "revocation status unavailable", Err: errors.New("no revocation store")}
	}
	revoked, _, _, err := rev.IsRevoked(cert.SerialNumber, caID)
	if err != nil {
		return &CredentialRefusedError{Reason: "revocation status unavailable", Err: err}
	}
	if revoked {
		return &CredentialRefusedError{Reason: "certificate is revoked"}
	}
	return nil
}
