// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"testing"
)

// The stored public_key_algorithm is the family name "ML-DSA"; the detail
// response also carries the parameter set so the UI can say which one.
func TestCACertificateProvider_MLDSALeafExposesParameterSet(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "paramset.example.com", "paramset.example.com")
	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, TemplateID: "tpl-tls", CSRPEM: csrPEM, TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf: %v", err)
	}
	detail, ok, err := provider.GetCertificate(ctx, result.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("GetCertificate: ok=%v err=%v", ok, err)
	}
	if detail.KeyAlgorithmDisplay != "ML-DSA-65" {
		t.Errorf("KeyAlgorithmDisplay = %q, want ML-DSA-65", detail.KeyAlgorithmDisplay)
	}
	// The POST /certificates response is built from the issue result, not from
	// the stored copy, so it must carry the field itself.
	if result.KeyAlgorithmDisplay != "ML-DSA-65" {
		t.Errorf("issue result KeyAlgorithmDisplay = %q, want ML-DSA-65", result.KeyAlgorithmDisplay)
	}

	renewCSR, _ := generateTestMLDSACSRPEM(t, keys, "paramset-2.example.com", "paramset.example.com")
	renewed, err := provider.RenewCertificate(ctx, result.FingerprintSHA256, CertificateRenewRequest{CSRPEM: renewCSR})
	if err != nil {
		t.Fatalf("renew ML-DSA leaf: %v", err)
	}
	if renewed.KeyAlgorithmDisplay != "ML-DSA-65" {
		t.Errorf("renew result KeyAlgorithmDisplay = %q, want ML-DSA-65", renewed.KeyAlgorithmDisplay)
	}
}

func TestKeyAlgorithmDisplayNonMLDSA(t *testing.T) {
	if got := keyAlgorithmDisplay(nil); got != "" {
		t.Errorf("nil cert: got %q", got)
	}
	if got := keyAlgorithmDisplay(&x509.Certificate{}); got != "" {
		t.Errorf("empty SPKI: got %q", got)
	}
}
