// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestPublicKeyBits(t *testing.T) {
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		pub  any
		want int
	}{
		{"rsa-2048", &rsa2048.PublicKey, 2048},
		{"rsa-3072", &rsa3072.PublicKey, 3072},
		{"p256", &p256.PublicKey, 256},
		{"p384", &p384.PublicKey, 384},
		{"ed25519", edPub, 256},
		// A pure ML-DSA subject key is not parseable by crypto/x509, so the
		// cert carries a nil PublicKey; size is unknown, not invented.
		{"unparseable-pqc", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicKeyBits(&x509.Certificate{PublicKey: tc.pub}); got != tc.want {
				t.Errorf("publicKeyBits = %d, want %d", got, tc.want)
			}
		})
	}
}

// Score and flags must be driven by one rule ladder at one instant. The
// explicit expected scores pin the weights; the sum check pins the coupling.
func TestRiskScoreAndFlagsAgree(t *testing.T) {
	now := time.Date(2027, 4, 1, 12, 0, 0, 0, time.UTC) // after the 200-day cutoff
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	selfSigned := pkix.Name{CommonName: "self"}

	cases := []struct {
		name      string
		cert      *x509.Certificate
		wantScore int
		wantFlag  string
	}{
		{
			name: "expired p256 short-lived CA",
			cert: &x509.Certificate{
				PublicKey: &p256.PublicKey, PublicKeyAlgorithm: x509.ECDSA, IsCA: true,
				NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour),
			},
			wantScore: 40 + 10, // EXPIRED + PQC_VULNERABLE
			wantFlag:  "EXPIRED",
		},
		{
			name: "rsa2048 expiring in 20 days, 300-day validity",
			cert: &x509.Certificate{
				PublicKey: &rsa2048.PublicKey, PublicKeyAlgorithm: x509.RSA, IsCA: true,
				NotBefore: now.Add(-280 * 24 * time.Hour), NotAfter: now.Add(20 * 24 * time.Hour),
			},
			wantScore: 20 + 10 + 15, // EXPIRING_30 + PQC + >200d after 2027-03-15
			wantFlag:  "VALIDITY_EXCEEDS_200_DAYS",
		},
		{
			name: "self-signed rsa2048 outliving NIST sunset",
			cert: &x509.Certificate{
				PublicKey: &rsa2048.PublicKey, PublicKeyAlgorithm: x509.RSA, Subject: selfSigned, Issuer: selfSigned,
				NotBefore: now, NotAfter: time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC),
			},
			wantScore: 10 + 10 + 15 + 10 + 15 + 10 + 5, // PQC + 397d + 200d + OUTLIVES + SELF_SIGNED + NO_OCSP + NO_CRL
			wantFlag:  "OUTLIVES_NIST_SUNSET",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags := computeRiskFlags(tc.cert, false, now)
			score := computeRiskScore(tc.cert, now)
			if !containsFlag(flags, tc.wantFlag) {
				t.Errorf("flags %v missing %s", flags, tc.wantFlag)
			}
			sum := 0
			for _, f := range flags {
				sum += riskFlagWeights[f]
			}
			if sum > 100 {
				sum = 100
			}
			if score != sum {
				t.Errorf("score %d != sum of flag weights %d (flags %v)", score, sum, flags)
			}
			if score != tc.wantScore {
				t.Errorf("score = %d, want %d (flags %v)", score, tc.wantScore, flags)
			}
		})
	}
}

// The 200-day rule must follow the injected clock, not the wall clock.
func TestRiskFlags200DayRuleUsesInjectedNow(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{
		PublicKey: &key.PublicKey, PublicKeyAlgorithm: x509.ECDSA, IsCA: true,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
	before := time.Date(2027, 3, 14, 0, 0, 0, 0, time.UTC)
	after := time.Date(2027, 3, 16, 0, 0, 0, 0, time.UTC)
	if containsFlag(computeRiskFlags(cert, false, before), "VALIDITY_EXCEEDS_200_DAYS") {
		t.Error("200-day flag raised before 2027-03-15")
	}
	if !containsFlag(computeRiskFlags(cert, false, after), "VALIDITY_EXCEEDS_200_DAYS") {
		t.Error("200-day flag missing after 2027-03-15")
	}
}
