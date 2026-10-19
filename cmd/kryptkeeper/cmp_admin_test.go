// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math/big"
	"testing"

	"kryptkeeper/internal/bootstrap"
)

// scopedCerts serves one CMP-issued certificate and reports a fixed
// revocation scope; the embedded nil interface panics on anything else.
type scopedCerts struct {
	bootstrap.CertificateProvider
	revoked string
}

func (s *scopedCerts) ListCertificates(context.Context, bootstrap.CertificateListQuery) (bootstrap.CertificateListResult, error) {
	return bootstrap.CertificateListResult{
		Items: []bootstrap.CertificateItem{{SerialNumber: "26", Source: "cmp", FingerprintSHA256: "fp1"}},
		Total: 1,
	}, nil
}

func (s *scopedCerts) RevokeCertificate(_ context.Context, fp string, _ bootstrap.CertificateRevokeRequest) (bootstrap.CertificateRevokeResult, error) {
	s.revoked = fp
	return bootstrap.CertificateRevokeResult{RevocationScope: bootstrap.RevocationScopeInventoryOnly}, nil
}

// Rescan R-08: the revocation scope must reach the CMP audit detail instead of
// being discarded, so an inventory-only revocation is distinguishable.
func TestCMPRevokerReturnsRevocationScope(t *testing.T) {
	certs := &scopedCerts{}
	scope, err := cmpRevoker{certs: certs}.Revoke(context.Background(), big.NewInt(26), 1, "ref")
	if err != nil {
		t.Fatal(err)
	}
	if scope != bootstrap.RevocationScopeInventoryOnly || certs.revoked != "fp1" {
		t.Fatalf("scope=%q revoked=%q", scope, certs.revoked)
	}
}
