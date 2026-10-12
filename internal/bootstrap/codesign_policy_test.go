// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// W17-02: code-signing policy enforcement, folded in from the deleted
// internal/codesign duplicate. Evaluated against the LIVE inventory, so
// there is exactly one risk model in the product.

func csCert(cn, algo string, bits int, from, until time.Time) CodeSigningCert {
	return CodeSigningCert{
		FingerprintSHA256:  "fp-" + cn,
		CommonName:         cn,
		PublicKeyAlgorithm: algo,
		KeySizeBits:        bits,
		ValidFrom:          from.Format(time.RFC3339),
		ValidUntil:         until.Format(time.RFC3339),
	}
}

func TestCodeSigningPolicyFlagsAlgorithmKeySizeAndValidity(t *testing.T) {
	now := time.Now().UTC()
	policy := CodeSigningPolicy{
		ID:                "corp-signing",
		Name:              "Corporate signing baseline",
		AllowedAlgorithms: []string{"ECDSA", "ML-DSA"},
		MinRSAKeySizeBits: 3072,
		MinECKeySizeBits:  256,
		MaxValidityDays:   365,
	}

	// Violates all three: wrong algorithm, RSA-2048 below the 3072 RSA
	// floor, and a 3-year validity.
	bad := csCert("legacy.example.com", "RSA", 2048, now.Add(-24*time.Hour), now.Add(3*365*24*time.Hour))
	v := evaluateCodeSigningPolicy(bad, policy)
	if len(v) != 3 {
		t.Fatalf("expected 3 violations, got %d: %v", len(v), v)
	}

	// Compliant on every axis.
	good := csCert("modern.example.com", "ECDSA", 384, now.Add(-24*time.Hour), now.Add(180*24*time.Hour))
	if v := evaluateCodeSigningPolicy(good, policy); len(v) != 0 {
		t.Fatalf("compliant cert must have no violations, got %v", v)
	}
}

// An empty policy must not manufacture violations — an unconfigured
// policy means "no constraint", never "everything fails".
func TestCodeSigningPolicyZeroValueConstrainsNothing(t *testing.T) {
	now := time.Now().UTC()
	cert := csCert("anything.example.com", "RSA", 1024, now, now.Add(10*365*24*time.Hour))
	if v := evaluateCodeSigningPolicy(cert, CodeSigningPolicy{ID: "empty"}); len(v) != 0 {
		t.Fatalf("a zero-value policy must constrain nothing, got %v", v)
	}
}

// An unparseable validity window must not silently pass the validity
// check — unknown is not compliant.
func TestCodeSigningPolicyUnparseableValidityIsReported(t *testing.T) {
	cert := CodeSigningCert{
		FingerprintSHA256: "fp-x", CommonName: "x", PublicKeyAlgorithm: "ECDSA",
		KeySizeBits: 384, ValidFrom: "not-a-date", ValidUntil: "also-not",
	}
	v := evaluateCodeSigningPolicy(cert, CodeSigningPolicy{ID: "p", MaxValidityDays: 90})
	if len(v) == 0 {
		t.Fatal("an unverifiable validity window must be reported, not silently passed")
	}
}

func TestCodeSigningPolicySummaryCountsViolatingCerts(t *testing.T) {
	now := time.Now().UTC()
	policy := CodeSigningPolicy{ID: "p", AllowedAlgorithms: []string{"ECDSA"}}
	certs := []CodeSigningCert{
		csCert("ok", "ECDSA", 256, now, now.Add(90*24*time.Hour)),
		csCert("bad1", "RSA", 2048, now, now.Add(90*24*time.Hour)),
		csCert("bad2", "RSA", 4096, now, now.Add(90*24*time.Hour)),
	}
	sum := summarizeCodeSigningPolicy(certs, policy)
	if sum.Evaluated != 3 || sum.Violating != 2 || sum.Compliant != 1 {
		t.Fatalf("summary wrong: %+v", sum)
	}
	if len(sum.Findings) != 2 {
		t.Fatalf("expected one finding per violating cert, got %d", len(sum.Findings))
	}
}

// A PQC algorithm has no comparable bit length, so the size floors must
// not fire on it — the allowlist is the control that applies there.
func TestCodeSigningPolicyKeySizeFloorsAreFamilyScoped(t *testing.T) {
	now := time.Now().UTC()
	policy := CodeSigningPolicy{ID: "p", MinRSAKeySizeBits: 3072, MinECKeySizeBits: 256}
	// EC-384 clears the EC floor and must NOT be judged against RSA's.
	if v := evaluateCodeSigningPolicy(csCert("ec", "ECDSA", 384, now, now.Add(24*time.Hour)), policy); len(v) != 0 {
		t.Fatalf("EC-384 must not be measured against the RSA floor: %v", v)
	}
	// ML-DSA carries no bit length: exempt from the size check entirely.
	if v := evaluateCodeSigningPolicy(csCert("pqc", "ML-DSA-65", 0, now, now.Add(24*time.Hour)), policy); len(v) != 0 {
		t.Fatalf("a PQC algorithm must be exempt from bit-length floors: %v", v)
	}
}

// The endpoint enforces auth and returns the evaluation over the live
// inventory — one risk model, one visibility path.
func TestCodeSigningPolicyCheckEndpoint(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerCodeSigningHandler(mux, auth, &reportCertProvider{items: []CertificateItem{{
		FingerprintSHA256: "aa", CommonName: "signer.example.com",
		PublicKeyAlgorithm: "RSA", KeySizeBits: 2048,
		ExtendedKeyUsage: []string{"Code Signing"},
		ValidFrom:        time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		ValidUntil:       time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}}}, stubAuditProvider{})

	body := []byte(`{"id":"p","allowed_algorithms":["ECDSA"],"min_rsa_key_size_bits":3072}`)

	// Unauthenticated is refused.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/inventory/code-signing/policy-check", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/inventory/code-signing/policy-check", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data CodeSigningPolicySummary }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Evaluated != 1 || resp.Data.Violating != 1 {
		t.Fatalf("RSA-2048 under an ECDSA-only, 3072-floor policy must violate: %+v", resp.Data)
	}
	if len(resp.Data.Findings[0].Violations) != 2 {
		t.Fatalf("expected algorithm + key-size violations: %v", resp.Data.Findings[0].Violations)
	}
}
