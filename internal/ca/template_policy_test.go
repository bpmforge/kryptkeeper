// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"
)

// makeECDSACSR creates a P-256 CSR for use in policy tests.
func makeECDSACSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "policy-test.example.com"},
	}, k)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

// makeRSACSR creates an RSA CSR of the given bit size.
func makeRSACSR(t *testing.T, bits int) *x509.CertificateRequest {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA-%d key: %v", bits, err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "policy-rsa-test.example.com"},
	}, k)
	if err != nil {
		t.Fatalf("create RSA CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse RSA CSR: %v", err)
	}
	return csr
}

func TestValidateAgainstTemplate_AlgorithmViolation(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:                "tpl-algo",
		AllowedAlgorithms: []string{"ML-DSA-65", "ML-DSA-87"},
	}
	req := IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour}

	err := ValidateAgainstTemplate(req, policy)
	if err == nil {
		t.Fatal("expected policy violation, got nil")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

func TestValidateAgainstTemplate_AlgorithmAllowed(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:                "tpl-algo-ok",
		AllowedAlgorithms: []string{"ECDSA"},
	}
	req := IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour}

	if err := ValidateAgainstTemplate(req, policy); err != nil {
		t.Errorf("expected no violation, got %v", err)
	}
}

func TestValidateAgainstTemplate_ValidityViolation(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:          "tpl-validity",
		MaxValidity: 90 * 24 * time.Hour,
	}
	req := IssuanceRequest{CSR: csr, Validity: 200 * 24 * time.Hour}

	err := ValidateAgainstTemplate(req, policy)
	if err == nil {
		t.Fatal("expected policy violation for excess validity, got nil")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

func TestValidateAgainstTemplate_ValidityAtMax(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:          "tpl-validity-ok",
		MaxValidity: 90 * 24 * time.Hour,
	}
	req := IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour}

	if err := ValidateAgainstTemplate(req, policy); err != nil {
		t.Errorf("expected no violation at exact max validity, got %v", err)
	}
}

func TestValidateAgainstTemplate_EKUViolation(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:          "tpl-eku",
		AllowedEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	req := IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	err := ValidateAgainstTemplate(req, policy)
	if err == nil {
		t.Fatal("expected EKU policy violation, got nil")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

func TestValidateAgainstTemplate_EKUAllowed(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:          "tpl-eku-ok",
		AllowedEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	req := IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if err := ValidateAgainstTemplate(req, policy); err != nil {
		t.Errorf("expected no violation, got %v", err)
	}
}

func TestValidateAgainstTemplate_MinKeySizeViolation(t *testing.T) {
	csr := makeRSACSR(t, 2048)
	policy := TemplatePolicy{
		ID:         "tpl-keysize",
		MinKeySize: 4096,
	}
	req := IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour}

	err := ValidateAgainstTemplate(req, policy)
	if err == nil {
		t.Fatal("expected key size policy violation, got nil")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

func TestValidateAgainstTemplate_MinKeySizePasses(t *testing.T) {
	csr := makeRSACSR(t, 4096)
	policy := TemplatePolicy{
		ID:         "tpl-keysize-ok",
		MinKeySize: 2048,
	}
	req := IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour}

	if err := ValidateAgainstTemplate(req, policy); err != nil {
		t.Errorf("expected no violation for 4096-bit RSA with min 2048, got %v", err)
	}
}

func TestValidateAgainstTemplate_AllConstraintsPassing(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:                "tpl-full",
		AllowedAlgorithms: []string{"ECDSA"},
		MaxValidity:       90 * 24 * time.Hour,
		AllowedEKUs:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	req := IssuanceRequest{
		CSR:         csr,
		Validity:    30 * 24 * time.Hour,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if err := ValidateAgainstTemplate(req, policy); err != nil {
		t.Errorf("expected all constraints to pass, got %v", err)
	}
}

func TestIssueCertificate_PolicyEnforced(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Policy Root", pkix.Name{CommonName: "Policy Root CA"}, "ECDSA-P256", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	csr := makeECDSACSR(t)
	policy := &TemplatePolicy{
		ID:          "strict-server",
		MaxValidity: 30 * 24 * time.Hour,
	}

	// Validity exceeds policy max — must fail.
	_, err = engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:      csr,
		Validity: 90 * 24 * time.Hour,
		Policy:   policy,
	})
	if err == nil {
		t.Fatal("expected policy violation, got nil")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

func TestIssueCertificate_PolicyNilSkipsValidation(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("No-Policy Root", pkix.Name{CommonName: "No-Policy Root CA"}, "ECDSA-P256", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	csr := makeECDSACSR(t)

	// No policy — should issue regardless of validity.
	_, err = engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:      csr,
		Validity: 500 * 24 * time.Hour,
		Policy:   nil,
	})
	if err != nil {
		t.Errorf("expected issuance without policy to succeed, got %v", err)
	}
}

// TestValidateAgainstTemplate_ECDSASizeQualifiedAllowList reproduces the
// live defect (2026-09-10): a template with size-qualified entries
// ["ECDSA-P256","RSA-2048"] rejected an EC P-256 CSR because csrKeyAlgorithm
// returned the bare family "ECDSA" while the allow-list held "ECDSA-P256".
func TestValidateAgainstTemplate_ECDSASizeQualifiedAllowList(t *testing.T) {
	csr := makeECDSACSR(t)
	policy := TemplatePolicy{
		ID:                "tpl-ecdsa-p256",
		AllowedAlgorithms: []string{"ECDSA-P256", "RSA-2048"},
	}
	req := IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour}

	if err := ValidateAgainstTemplate(req, policy); err != nil {
		t.Errorf("expected P-256 CSR to satisfy ECDSA-P256 allow-list entry, got %v", err)
	}
}

func TestCsrKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		csr  *x509.CertificateRequest
		want string
	}{
		{"rsa-2048", makeRSACSR(t, 2048), "RSA-2048"},
		{"rsa-3072", makeRSACSR(t, 3072), "RSA-3072"},
		{"rsa-4096", makeRSACSR(t, 4096), "RSA-4096"},
		{"ecdsa-p256", makeECDSACSR(t), "ECDSA-P256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := csrKeyAlgorithm(tt.csr); got != tt.want {
				t.Errorf("csrKeyAlgorithm() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAlgorithmAllowed(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		csrAlgo string
		want    bool
	}{
		{"exact match", []string{"ECDSA-P256", "RSA-2048"}, "ECDSA-P256", true},
		{"bare family match", []string{"ECDSA", "RSA-2048"}, "ECDSA-P384", true},
		{"bare family case-insensitive", []string{"ecdsa"}, "ECDSA-P256", true},
		{"wrong family", []string{"RSA-2048"}, "ECDSA-P256", false},
		{"wrong size, exact entries only", []string{"RSA-4096"}, "RSA-2048", false},
		{"empty list allows everything", nil, "RSA-2048", true},
		{"ed25519 exact", []string{"Ed25519"}, "Ed25519", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := algorithmAllowed(tt.allowed, tt.csrAlgo); got != tt.want {
				t.Errorf("algorithmAllowed(%v, %q) = %v, want %v", tt.allowed, tt.csrAlgo, got, tt.want)
			}
		})
	}
}

func TestCheckEnrollment(t *testing.T) {
	ctx := context.Background()
	if err := CheckEnrollment(ctx, "t", nil); err != nil {
		t.Fatalf("empty list must allow: %v", err)
	}
	if err := CheckEnrollment(ctx, "t", []string{"a"}); !errors.Is(err, ErrEnrollmentDenied) {
		t.Fatalf("no role must deny, got %v", err)
	}
	if err := CheckEnrollment(WithCallerRole(ctx, "b"), "t", []string{"a"}); !errors.Is(err, ErrEnrollmentDenied) {
		t.Fatalf("unlisted role must deny, got %v", err)
	}
	if err := CheckEnrollment(WithCallerRole(ctx, "a"), "t", []string{"a"}); err != nil {
		t.Fatalf("listed role must pass: %v", err)
	}
}
