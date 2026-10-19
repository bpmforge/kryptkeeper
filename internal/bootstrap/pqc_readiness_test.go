// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// TestComputePQCReadiness_MLDSALeafClassicalCA proves G-70/D-104's core fix:
// a classical CA issuing an ML-DSA leaf (the realistic W4-03 migrate-wave
// scenario) is reported as the new quantum_safe_leaf_only category, not
// silently folded into full quantum_safe -- since the CA's own signature
// over the leaf remains classically forgeable.
func TestComputePQCReadiness_MLDSALeafClassicalCA(t *testing.T) {
	provider, engine := newTestCAProvider(t) // ECDSA-P256 root CA
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "leaf-only.example.com")

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf from classical CA: %v", err)
	}
	if result.PQCReadiness != pqcReadinessLeafOnly {
		t.Errorf("PQCReadiness = %q, want %q (leaf is PQC, issuing CA is classical)", result.PQCReadiness, pqcReadinessLeafOnly)
	}
}

// TestComputePQCReadiness_MLDSALeafMLDSACA proves the full quantum_safe
// category still fires correctly (unchanged behavior, acceptance criterion
// 3) when BOTH the leaf and the issuing CA are ML-DSA.
func TestComputePQCReadiness_MLDSALeafMLDSACA(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "full-quantum-safe.example.com")

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf from ML-DSA CA: %v", err)
	}
	if result.PQCReadiness != "quantum_safe" {
		t.Errorf("PQCReadiness = %q, want quantum_safe (leaf AND chain both PQC)", result.PQCReadiness)
	}
}

// TestComputePQCReadiness_HybridLeafClassicalCA proves a hybrid leaf issued
// by any CA is also leaf-only, not full quantum_safe -- per D-104, W4-08's
// hybrid leaf issuance deliberately carries no altSignatureValue, so the
// outer/primary signature is always classical regardless of the CA's type.
func TestComputePQCReadiness_HybridLeafClassicalCA(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	if _, err := engine.CreateRootCA("Hybrid Readiness Root", pkix.Name{
		CommonName: "Hybrid Readiness Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	provider := NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	if _, err := keys.GenerateKey("hybrid-readiness-leaf", keystore.HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("generate hybrid leaf key: %v", err)
	}
	pair, err := keys.LoadHybridKeyPair("hybrid-readiness-leaf")
	if err != nil {
		t.Fatalf("load hybrid key pair: %v", err)
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: "hybrid-readiness.example.com"}, nil, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: der}))

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue hybrid leaf: %v", err)
	}
	if result.PQCReadiness != pqcReadinessLeafOnly {
		t.Errorf("PQCReadiness = %q, want %q", result.PQCReadiness, pqcReadinessLeafOnly)
	}
}

// TestComputePQCReadiness_HybridLeafMLDSACA proves full quantum_safe still
// fires for the one case where a hybrid leaf's issuer signature really is
// ML-DSA (an ML-DSA-keyed CA issues the leaf, per engine.go's createCertDER
// dispatch, which routes ANY leaf pubkey through CreateCertificateMLDSA
// when the CA itself is ML-DSA-keyed) -- both the alt-key AND the chain are
// genuinely PQC here, unlike the classical-CA case above.
func TestComputePQCReadiness_HybridLeafMLDSACA(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	if _, err := keys.GenerateKey("hybrid-mldsa-ca-leaf", keystore.HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("generate hybrid leaf key: %v", err)
	}
	loader, ok := keys.(keystore.HybridKeyLoader)
	if !ok {
		t.Fatal("keystore does not implement HybridKeyLoader")
	}
	pair, err := loader.LoadHybridKeyPair("hybrid-mldsa-ca-leaf")
	if err != nil {
		t.Fatalf("load hybrid key pair: %v", err)
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: "hybrid-mldsa-ca.example.com"}, nil, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: der}))

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue hybrid leaf from ML-DSA CA: %v", err)
	}
	if result.PQCReadiness != "quantum_safe" {
		t.Errorf("PQCReadiness = %q, want quantum_safe (alt-key AND chain both PQC)", result.PQCReadiness)
	}
}

// TestIsPQCVulnerable_HybridLeafNotVulnerable proves the isPQCVulnerable
// hybrid fix (found while testing G-70/D-104, a distinct pre-existing bug
// in the OPPOSITE direction from G-70 -- undercounting real PQC protection
// instead of overclaiming it): a hybrid leaf's PublicKeyAlgorithm is always
// classical (its ML-DSA key lives in the alt extension, not the subject
// SPKI), so without HybridCertInfo awareness every hybrid cert would be
// PQCVulnerable=true and pay computeRiskScore's +10 PQC penalty despite
// carrying real ML-DSA leaf-key protection.
func TestIsPQCVulnerable_HybridLeafNotVulnerable(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	if _, err := engine.CreateRootCA("Vuln Check Root", pkix.Name{
		CommonName: "Vuln Check Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	provider := NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	if _, err := keys.GenerateKey("vuln-check-hybrid-leaf", keystore.HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("generate hybrid leaf key: %v", err)
	}
	pair, err := keys.LoadHybridKeyPair("vuln-check-hybrid-leaf")
	if err != nil {
		t.Fatalf("load hybrid key pair: %v", err)
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: "vuln-check.example.com"}, nil, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: der}))

	hybridResult, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, TemplateID: "tpl-tls", CSRPEM: csrPEM, TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("issue hybrid leaf: %v", err)
	}
	if hybridResult.PQCVulnerable {
		t.Error("hybrid leaf must not be PQCVulnerable=true -- it carries a real ML-DSA alt-key")
	}

	// A plain classical leaf (no alt-key) from the SAME CA must still pay
	// the PQC penalty -- proves the fix is HybridCertInfo-gated, not a
	// blanket change to isPQCVulnerable's ECDSA/RSA branch.
	classicalCSR := generateTestCSRPEM(t, "vuln-check-classical.example.com")
	classicalResult, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, TemplateID: "tpl-tls", CSRPEM: classicalCSR, TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("issue classical leaf: %v", err)
	}
	if !classicalResult.PQCVulnerable {
		t.Error("plain classical leaf must still be PQCVulnerable=true")
	}
	if classicalResult.RiskScore <= hybridResult.RiskScore {
		t.Errorf("classical leaf RiskScore (%d) should exceed hybrid leaf RiskScore (%d) due to the PQC penalty", classicalResult.RiskScore, hybridResult.RiskScore)
	}
}

// TestComputePQCReadiness_ClassicalUnaffected is a regression check: a
// plain classical leaf from a classical CA must keep classifying as
// vulnerable/migration_ready exactly as before this ticket.
func TestComputePQCReadiness_ClassicalUnaffected(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "classical.example.com", "classical.example.com")
	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue classical leaf: %v", err)
	}
	if result.PQCReadiness != "vulnerable" && result.PQCReadiness != "migration_ready" {
		t.Errorf("PQCReadiness = %q, want vulnerable or migration_ready (classical leaf, classical CA)", result.PQCReadiness)
	}
}

// TestComputeCryptoPosture_AggregatesLeafOnlyCategory proves acceptance
// criterion 2: the new category is surfaced through the shared
// computeCryptoPosture aggregation (crypto-posture report, and by
// extension pqc-countdown/executive-summary, which both derive from it),
// counted distinctly from quantum_safe, and included in PQCScorePercent.
func TestComputeCryptoPosture_AggregatesLeafOnlyCategory(t *testing.T) {
	certs := []CertificateItem{
		{FingerprintSHA256: "a", PQCReadiness: "quantum_safe"},
		{FingerprintSHA256: "b", PQCReadiness: pqcReadinessLeafOnly},
		{FingerprintSHA256: "c", PQCReadiness: pqcReadinessLeafOnly},
		{FingerprintSHA256: "d", PQCReadiness: "vulnerable"},
	}
	report := computeCryptoPosture(context.Background(), certs)

	if report.PQCReadiness.QuantumSafe != 1 {
		t.Errorf("QuantumSafe = %d, want 1", report.PQCReadiness.QuantumSafe)
	}
	if report.PQCReadiness.QuantumSafeLeafOnly != 2 {
		t.Errorf("QuantumSafeLeafOnly = %d, want 2", report.PQCReadiness.QuantumSafeLeafOnly)
	}
	if report.PQCReadiness.Vulnerable != 1 {
		t.Errorf("Vulnerable = %d, want 1", report.PQCReadiness.Vulnerable)
	}
	// pqcCovered = quantum_safe(1) + leaf_only(2) + migration_ready(0) = 3 of 4 = 75%.
	if report.PQCReadiness.PQCScorePercent != 75 {
		t.Errorf("PQCScorePercent = %d, want 75", report.PQCReadiness.PQCScorePercent)
	}
}

// TestComputePQCReadiness_MultiTierChainClassicalRootDemotesLeaf proves
// G-73's exact scenario: classical root -> ML-DSA intermediate -> ML-DSA
// leaf. The leaf's own immediate issuer (the ML-DSA intermediate) is
// non-classical, so isChainClassical(leaf) alone would misreport this as
// full quantum_safe -- resolveChainClassical must walk the full chain via
// engine.GetCAChain and find the classical root two hops up.
func TestComputePQCReadiness_MultiTierChainClassicalRootDemotesLeaf(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())

	root, err := engine.CreateRootCA("Classical Root", pkix.Name{CommonName: "Classical Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create classical root CA: %v", err)
	}
	intermediate, err := engine.CreateIntermediateCA("ML-DSA Intermediate", pkix.Name{CommonName: "ML-DSA Intermediate CA"}, keystore.MLDSA65, root.ID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create ML-DSA intermediate CA under classical root: %v", err)
	}

	provider := NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false)
	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "multi-tier-leaf.example.com")

	result, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       intermediate.ID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf from ML-DSA intermediate: %v", err)
	}
	if result.PQCReadiness != pqcReadinessLeafOnly {
		t.Errorf("PQCReadiness = %q, want %q (root two hops up is classical, so the chain is NOT fully quantum-safe even though the leaf's immediate issuer is ML-DSA)", result.PQCReadiness, pqcReadinessLeafOnly)
	}
}

// TestResolveChainClassical_UnresolvableCAFallsBackToSingleHop proves the
// error-handling half of G-73's fix as amended by W31-02: an unresolvable CA
// chain for a NON-EMPTY caID (matching e.g. a CA left inconsistent by an
// interrupted rotation -- S-16/G-78) degrades to the weaker label (true)
// instead of vouching for full quantum_safe. An empty caID still falls back
// to the single-hop check.
func TestResolveChainClassical_UnresolvableCAFallsBackToSingleHop(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())

	leafKeyID := "orphan-leaf-key"
	if _, err := keys.GenerateKey(leafKeyID, keystore.MLDSA65); err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	leaf, err := engine.IssueCertificate(root.ID, ca.IssuanceRequest{
		PQCCSR: mustPQCCSR(t, keys, leafKeyID, "orphan-leaf.example.com"),
	})
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}

	if got := resolveChainClassical(engine, "does-not-exist", leaf.Certificate); !got {
		t.Errorf("resolveChainClassical with an unresolvable non-empty caID = %v, want true (weaker label)", got)
	}
	if got := resolveChainClassical(engine, "", leaf.Certificate); got != isChainClassical(leaf.Certificate) {
		t.Errorf("resolveChainClassical with an empty caID = %v, want the single-hop result %v", got, isChainClassical(leaf.Certificate))
	}
}

func mustPQCCSR(t *testing.T, keys keystore.Store, keyID, cn string) *ca.PQCCertificateRequest {
	t.Helper()
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := ca.CreateCertificateRequestMLDSA(pkix.Name{CommonName: cn}, nil, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	pqcCSR, err := ca.ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
	}
	return pqcCSR
}

// TestIsChainClassical_PositiveMatch pins the classification to a positive
// list of classical algorithms. Go 1.27's x509 started naming ML-DSA
// signatures (SignatureAlgorithm 18..20) instead of returning
// UnknownSignatureAlgorithm, which silently broke a "known == classical"
// test and demoted every ML-DSA-signed leaf to quantum_safe_leaf_only.
func TestIsChainClassical_PositiveMatch(t *testing.T) {
	cases := []struct {
		name string
		alg  x509.SignatureAlgorithm
		want bool
	}{
		{"unknown stays non-classical", x509.UnknownSignatureAlgorithm, false},
		{"ECDSA-P256", x509.ECDSAWithSHA256, true},
		{"RSA-PSS", x509.SHA256WithRSAPSS, true},
		{"Ed25519", x509.PureEd25519, true},
		// Named by number rather than constant so this compiles on the
		// go.mod 1.25 floor, where x509 has no ML-DSA identifiers.
		{"ML-DSA-65 as Go 1.27 names it", x509.SignatureAlgorithm(18), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isChainClassical(&x509.Certificate{SignatureAlgorithm: tc.alg})
			if got != tc.want {
				t.Errorf("isChainClassical(%v) = %v, want %v", tc.alg, got, tc.want)
			}
		})
	}
}
