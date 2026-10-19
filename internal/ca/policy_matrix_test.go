// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func ed25519CSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ed.example.com"}}, priv)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr
}

func pqcCSRFor(t *testing.T, algo keystore.Algorithm) *PQCCertificateRequest {
	t.Helper()
	keys, keyID := newTestMLDSASigner(t, algo)
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "pqc.example.com"}, nil, nil, signer, algo)
	if err != nil {
		t.Fatalf("pqc csr: %v", err)
	}
	csr, err := ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("parse pqc csr: %v", err)
	}
	return csr
}

func hybridCSRFor(t *testing.T, algo keystore.Algorithm) *HybridCertificateRequest {
	t.Helper()
	pair := newTestHybridKeyPair(t, algo)
	der, err := CreateCertificateRequestHybrid(pkix.Name{CommonName: "hy.example.com"}, []string{"hy.example.com"}, nil, pair.Primary, pair.Secondary, algo)
	if err != nil {
		t.Fatalf("hybrid csr: %v", err)
	}
	csr, err := ParseCertificateRequestHybrid(der)
	if err != nil {
		t.Fatalf("parse hybrid csr: %v", err)
	}
	return csr
}

// TestPolicyRefusalMatrix drives 12 (rule x key class) refusals through the
// real Engine.IssueCertificate path (W22-14 acceptance 3). Each row installs
// its own allow-list so the cited rule is deterministic; a refusal must be a
// *PolicyViolationError naming that rule and must sign nothing.
func TestPolicyRefusalMatrix(t *testing.T) {
	day := 24 * time.Hour
	base := []string{"ECDSA-P256", "RSA-4096", "ML-DSA-65", "Hybrid-ECDSA-P256-ML-DSA-65"}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }

	type row struct {
		name     string
		allow    []string
		req      func(t *testing.T) IssuanceRequest
		wantRule string
	}
	leaf := func(csr func(t *testing.T) *x509.CertificateRequest, validity time.Duration, isCA bool) func(t *testing.T) IssuanceRequest {
		return func(t *testing.T) IssuanceRequest {
			return IssuanceRequest{CSR: csr(t), Validity: validity, KeyUsage: x509.KeyUsageDigitalSignature, IsCA: isCA}
		}
	}
	pqc := func(algo keystore.Algorithm, validity time.Duration, isCA bool) func(t *testing.T) IssuanceRequest {
		return func(t *testing.T) IssuanceRequest {
			return IssuanceRequest{PQCCSR: pqcCSRFor(t, algo), Validity: validity, KeyUsage: x509.KeyUsageDigitalSignature, IsCA: isCA}
		}
	}
	hybrid := func(algo keystore.Algorithm, validity time.Duration, isCA bool) func(t *testing.T) IssuanceRequest {
		return func(t *testing.T) IssuanceRequest {
			return IssuanceRequest{HybridCSR: hybridCSRFor(t, algo), Validity: validity, KeyUsage: x509.KeyUsageDigitalSignature, IsCA: isCA}
		}
	}
	p256 := func(t *testing.T) *x509.CertificateRequest { return ecdsaCSR(t) }
	rsa2048 := func(t *testing.T) *x509.CertificateRequest { return rsaCSR(t, 2048) }

	rows := []row{
		{"classic weak RSA", with("RSA-2048"), leaf(rsa2048, 30*day, false), "min_rsa_bits"},
		{"classic off-list algorithm", base, leaf(ed25519CSR, 30*day, false), "allowed_algorithms"},
		{"classic over-validity", base, leaf(p256, 399*day, false), "max_validity_days"},
		{"classic IsCA", base, leaf(p256, 30*day, true), "allow_ca_certs"},
		{"pqc lowest-strength off-list", base, pqc(keystore.MLDSA44, 30*day, false), "allowed_algorithms"},
		{"pqc off-list algorithm", base, pqc(keystore.MLDSA87, 30*day, false), "allowed_algorithms"},
		{"pqc over-validity", base, pqc(keystore.MLDSA65, 399*day, false), "max_validity_days"},
		{"pqc IsCA", base, pqc(keystore.MLDSA65, 30*day, true), "allow_ca_certs"},
		{"hybrid lowest-strength off-list", []string{"ECDSA-P256", "RSA-4096", "ML-DSA-65"}, hybrid(keystore.HybridECDSAP256MLDSA65, 30*day, false), "allowed_algorithms"},
		{"hybrid off-list algorithm", base, hybrid(keystore.HybridECDSAP384MLDSA87, 30*day, false), "allowed_algorithms"},
		{"hybrid over-validity", base, hybrid(keystore.HybridECDSAP256MLDSA65, 399*day, false), "max_validity_days"},
		{"hybrid IsCA", base, hybrid(keystore.HybridECDSAP256MLDSA65, 30*day, true), "allow_ca_certs"},
	}
	if len(rows) != 12 {
		t.Fatalf("matrix must have 12 rows, has %d", len(rows))
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			engine, pe, caObj := newPolicyTestEngine(t)
			if _, err := pe.UpsertPolicy(IssuancePolicy{
				Name: "baseline-like", Enabled: true,
				Rules: PolicyRules{AllowedAlgorithms: tc.allow, MinRSABits: 3072, MaxValidityDays: 398},
			}); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			issued, err := engine.IssueCertificate(caObj.ID, tc.req(t))
			if err == nil {
				t.Fatalf("request must be refused, was issued: %v", issued)
			}
			var pv *PolicyViolationError
			if !errors.As(err, &pv) {
				t.Fatalf("want *PolicyViolationError, got %T: %v", err, err)
			}
			if pv.Rule != tc.wantRule {
				t.Fatalf("cited rule = %q, want %q (%v)", pv.Rule, tc.wantRule, err)
			}
			if !errors.Is(err, ErrPolicyViolation) {
				t.Fatalf("errors.Is(ErrPolicyViolation) must hold")
			}
			if issued != nil {
				t.Fatal("a refusal must not return a certificate")
			}
		})
	}
}
