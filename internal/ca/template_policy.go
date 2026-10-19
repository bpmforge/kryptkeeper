// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// template_policy.go — policy enforcement at certificate issuance time.
//
// Templates define allowed algorithms, max validity, and EKU constraints.
// IssueCertificate calls ValidateAgainstTemplate when a TemplateID is set,
// returning ErrPolicyViolation with field-level detail on any constraint breach.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TemplatePolicy is the subset of TemplateItem fields needed for policy checks.
// Callers convert their TemplateItem into this struct before calling Validate.
type TemplatePolicy struct {
	ID                string
	AllowedAlgorithms []string      // empty = all allowed
	MinKeySize        int           // 0 = no minimum
	MaxValidity       time.Duration // 0 = no maximum
	AllowedEKUs       []x509.ExtKeyUsage
	Names             *NamePolicy // nil = names unrestricted (SUP-A04-3)
	EnrollRoles       []string    // empty = any role may enroll (W23-42)
}

// ErrEnrollmentDenied is returned when the caller's role is not listed in a
// template's enrollment_permissions (W23-42).
var ErrEnrollmentDenied = errors.New("role not permitted to enroll from this template")

type callerRoleKey struct{}

// WithCallerRole stamps the authenticated caller's role on ctx so the issuing
// provider can enforce a template's enrollment_permissions.
func WithCallerRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, callerRoleKey{}, role)
}

// CallerRoleFrom returns the role stamped by WithCallerRole; ok is false when
// none was set or it is blank.
func CallerRoleFrom(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(callerRoleKey{}).(string)
	return role, ok && role != ""
}

// CheckEnrollment enforces a template's enroll list. An empty list means
// unrestricted (the stored default is allow-all). A restricted template fails
// closed: a missing role in ctx is a denial, never a pass.
func CheckEnrollment(ctx context.Context, templateID string, enroll []string) error {
	if len(enroll) == 0 {
		return nil
	}
	role, ok := CallerRoleFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: template %s (no caller role)", ErrEnrollmentDenied, templateID)
	}
	for _, allowed := range enroll {
		if allowed == role {
			return nil
		}
	}
	return fmt.Errorf("%w: template %s", ErrEnrollmentDenied, templateID)
}

// PolicyViolation describes a single constraint breach.
type PolicyViolation struct {
	Field   string
	Message string
}

func (v PolicyViolation) Error() string {
	return fmt.Sprintf("policy violation [%s]: %s", v.Field, v.Message)
}

// ValidateAgainstTemplate checks whether an IssuanceRequest satisfies the policy.
// Returns the first violation found, wrapped in ErrPolicyViolation.
func ValidateAgainstTemplate(req IssuanceRequest, policy TemplatePolicy) error {
	// Algorithm check — only enforced when the CSR's public key algorithm is known.
	if len(policy.AllowedAlgorithms) > 0 && req.CSR != nil {
		csrAlgo := csrKeyAlgorithm(req.CSR)
		if csrAlgo != "" && !algorithmAllowed(policy.AllowedAlgorithms, csrAlgo) {
			return fmt.Errorf("%w: %s", ErrPolicyViolation,
				PolicyViolation{
					Field:   "algorithm",
					Message: fmt.Sprintf("key algorithm %q is not in the allowed list %v for template %s", csrAlgo, policy.AllowedAlgorithms, policy.ID),
				})
		}
	}

	// Validity check.
	if policy.MaxValidity > 0 && req.Validity > policy.MaxValidity {
		return fmt.Errorf("%w: %s", ErrPolicyViolation,
			PolicyViolation{
				Field:   "validity",
				Message: fmt.Sprintf("requested validity %v exceeds template maximum %v for template %s", req.Validity, policy.MaxValidity, policy.ID),
			})
	}

	// Extended key usage check — every requested EKU must be in the template allow-list.
	if len(policy.AllowedEKUs) > 0 && len(req.ExtKeyUsage) > 0 {
		for _, eku := range req.ExtKeyUsage {
			if !containsEKU(policy.AllowedEKUs, eku) {
				return fmt.Errorf("%w: %s", ErrPolicyViolation,
					PolicyViolation{
						Field:   "extended_key_usage",
						Message: fmt.Sprintf("EKU %v is not allowed by template %s", eku, policy.ID),
					})
			}
		}
	}

	// Min key size check (RSA only for now — ECDSA key size is set by curve choice).
	if policy.MinKeySize > 0 && req.CSR != nil {
		if bits := csrKeyBits(req.CSR); bits > 0 && bits < policy.MinKeySize {
			return fmt.Errorf("%w: %s", ErrPolicyViolation,
				PolicyViolation{
					Field:   "key_size",
					Message: fmt.Sprintf("key size %d bits is below template minimum %d for template %s", bits, policy.MinKeySize, policy.ID),
				})
		}
	}

	return nil
}

// csrKeyAlgorithm returns the canonical algorithm name for the CSR's public
// key (e.g. "RSA-2048", "ECDSA-P256", "Ed25519") — the same vocabulary
// AllowedAlgorithms is authored in (keystore.Algorithm), so callers can
// compare directly instead of stripping a shared prefix off a bare family
// name. Previously this returned the bare family "ECDSA" and a hardcoded
// "RSA-2048" for every RSA key regardless of actual size, which silently
// rejected any non-2048-bit RSA CSR and any EC CSR compared against a
// size-qualified allow-list entry (captured live 2026-09-10).
func csrKeyAlgorithm(csr *x509.CertificateRequest) string {
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return "ECDSA-P256"
		case elliptic.P384():
			return "ECDSA-P384"
		case elliptic.P521():
			return "ECDSA-P521"
		}
		return "ECDSA"
	}
	if csr.PublicKeyAlgorithm == x509.Ed25519 {
		return "Ed25519"
	}
	return ""
}

// csrKeyBits returns the key size in bits for RSA keys; 0 for other algorithms.
func csrKeyBits(csr *x509.CertificateRequest) int {
	// Only RSA has a meaningful "key size" for policy checks.
	// ECDSA curve selection already encodes the security level.
	if pub, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		return pub.N.BitLen()
	}
	return 0
}

// algorithmFamily returns the bare family name for a canonical algorithm
// string, e.g. "RSA-2048" -> "RSA", "ECDSA-P256" -> "ECDSA", "Ed25519" ->
// "Ed25519". Used so a template's bare-family allow-list entry (shipped
// templates and the UI's own examples use "RSA"/"ECDSA" without a size)
// still matches any size/curve of that family.
func algorithmFamily(algo string) string {
	if i := strings.Index(algo, "-"); i >= 0 {
		return algo[:i]
	}
	return algo
}

// algorithmAllowed reports whether csrAlgo (a canonical algorithm name from
// csrKeyAlgorithm) satisfies one of allowed's entries. An entry matches
// either by exact canonical value ("RSA-2048" == "RSA-2048") or by bare
// family, case-insensitively ("RSA" matches any RSA size, "ECDSA" matches
// any curve). An empty allow-list means all algorithms are allowed.
func algorithmAllowed(allowed []string, csrAlgo string) bool {
	if len(allowed) == 0 {
		return true
	}
	csrFamily := algorithmFamily(csrAlgo)
	for _, entry := range allowed {
		if entry == csrAlgo {
			return true
		}
		if strings.EqualFold(entry, csrFamily) {
			return true
		}
	}
	return false
}

func containsEKU(list []x509.ExtKeyUsage, eku x509.ExtKeyUsage) bool {
	for _, v := range list {
		if v == eku {
			return true
		}
	}
	return false
}
