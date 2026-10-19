// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"context"
	"crypto/x509"
	"fmt"
)

// IssuedCertificateRecorder persists a certificate issued through a protocol
// server (ACME, EST, SCEP, CMP) into the hub's certificate inventory. It
// lives here rather than in any one protocol package because every protocol
// server already imports internal/ca, and none of them may import
// internal/bootstrap (bootstrap depends on ca and the protocol packages, so
// the reverse edge would be a cycle) -- this interface is the seam bootstrap
// implements on *caCertificateProvider so main.go can wire the two together
// without either side depending on the other's concrete types. W18-16
// introduced this for ACME; W18-18 promoted it here so EST, SCEP and CMP
// share the same definition instead of each declaring their own.
//
// source identifies which protocol issued the certificate ("acme", "est",
// "scep", "cmp") so the inventory can tell them apart. W19-15 added the
// parameter: the single shared implementation had hardcoded "acme" for
// every caller, so EST/SCEP/CMP issuances were mislabeled in inventory even
// once W18-18 wired the recorder in.
type IssuedCertificateRecorder interface {
	RecordIssuedCertificate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error
}

// TemplateIssuedCertificateRecorder is the optional extension for a protocol
// whose issuance a template governed (W20-15). Only WSTEP has templates, so
// the base interface stays as it is for ACME, EST, SCEP and CMP, and their
// test doubles need nothing new.
type TemplateIssuedCertificateRecorder interface {
	RecordIssuedCertificateWithTemplate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source, templateID string) error
}

// RetryOnSerialCollision runs attempt up to maxAttempts times (n is the
// zero-based attempt number). An error satisfying IsSerialCollision triggers
// another run, so attempt must re-generate the serial (call the engine
// again). Any other error is returned unchanged; exhaustion returns an error
// wrapping ErrSerialCollision. Fail closed: the caller stores nothing on error.
func RetryOnSerialCollision(maxAttempts int, attempt func(n int) error) error {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	for n := 0; n < maxAttempts; n++ {
		err := attempt(n)
		if err == nil {
			return nil
		}
		if !IsSerialCollision(err) {
			return err
		}
	}
	return fmt.Errorf("%w after %d attempts", ErrSerialCollision, maxAttempts)
}
