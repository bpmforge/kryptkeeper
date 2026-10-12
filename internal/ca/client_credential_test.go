// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

type brokenRevs struct{}

func (brokenRevs) IsRevoked(*big.Int, string) (bool, time.Time, int, error) {
	return false, time.Time{}, 0, errors.New("db down")
}

func TestCheckHubClientCertificate(t *testing.T) {
	engine, rootID := identityRoot(t)
	root, _ := engine.GetCA(rootID)
	other, err := engine.CreateRootCA("Other", pkix.Name{CommonName: "Other"}, keystore.ECDSAP256, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(caID string, eku x509.ExtKeyUsage) *x509.Certificate {
		issued, err := engine.IssueCertificate(caID, IssuanceRequest{CSR: identityCSR(t), Validity: time.Hour,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}})
		if err != nil {
			t.Fatal(err)
		}
		return issued.Certificate
	}
	good := issue(rootID, x509.ExtKeyUsageClientAuth)
	serverOnly := issue(rootID, x509.ExtKeyUsageServerAuth)
	foreign := issue(other.ID, x509.ExtKeyUsageClientAuth)
	revs := NewMemRevocationStore()
	// Taken after every issuance: a slow runner can issue in a later second,
	// and a NotBefore after "now" would trip the validity check first.
	now := time.Now()

	if err := CheckHubClientCertificate(good, root.Certificate, rootID, now, revs); err != nil {
		t.Fatalf("good certificate refused: %v", err)
	}
	if err := CheckHubClientCertificate(foreign, root.Certificate, rootID, now, revs); !errors.Is(err, ErrNotIssuedHere) {
		t.Fatalf("other CA's certificate: %v", err)
	}
	for name, tc := range map[string]struct {
		cert *x509.Certificate
		at   time.Time
		rev  RevocationChecker
		want string
	}{
		"expired":           {good, good.NotAfter.Add(time.Second), revs, "certificate is outside its validity period"},
		"not yet valid":     {good, good.NotBefore.Add(-time.Second), revs, "certificate is outside its validity period"},
		"server-auth only":  {serverOnly, now, revs, "certificate lacks client-auth EKU"},
		"revocation broken": {good, now, brokenRevs{}, "revocation status unavailable"},
		"no revocation":     {good, now, nil, "revocation status unavailable"},
	} {
		var refused *CredentialRefusedError
		if err := CheckHubClientCertificate(tc.cert, root.Certificate, rootID, tc.at, tc.rev); !errors.As(err, &refused) || refused.Reason != tc.want {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	if err := revs.Revoke(good.SerialNumber, rootID, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckHubClientCertificate(good, root.Certificate, rootID, now, revs); err == nil || err.Error() != "certificate is revoked" {
		t.Fatalf("revoked: %v", err)
	}
}
