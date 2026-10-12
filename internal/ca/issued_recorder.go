// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"context"
	"crypto/x509"
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
