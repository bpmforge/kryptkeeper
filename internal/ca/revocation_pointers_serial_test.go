// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"math/big"
	"slices"
	"testing"
	"time"
)

func TestEngineUsesSerialAwarePointers(t *testing.T) {
	engine, rootID := identityRoot(t)
	plainCalls := 0
	engine.SetRevocationPointers(func(string) ([]string, []string) {
		plainCalls++
		return []string{"http://plain.example/x.crl"}, nil
	})
	engine.SetRevocationPointersForSerial(func(caID string, serial *big.Int) ([]string, []string) {
		return []string{"http://shard.example/" + serial.Text(16) + ".crl"}, []string{"http://shard.example/ocsp"}
	})
	issued, err := engine.IssueCertificate(rootID, IssuanceRequest{CSR: identityCSR(t), Validity: 90 * 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		t.Fatal(err)
	}
	c := issued.Certificate
	if want := []string{"http://shard.example/" + c.SerialNumber.Text(16) + ".crl"}; !slices.Equal(c.CRLDistributionPoints, want) {
		t.Fatalf("CRL DPs %v, want %v", c.CRLDistributionPoints, want)
	}
	if plainCalls != 0 {
		t.Fatal("plain resolver consulted although a serial-aware one is set")
	}
}
