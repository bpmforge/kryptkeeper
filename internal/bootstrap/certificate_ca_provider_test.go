// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func newTestCAProvider(t *testing.T) (CertificateProvider, *ca.Engine) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())

	// Create a root CA for tests.
	_, err = engine.CreateRootCA("Test Root", pkix.Name{
		CommonName: "Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	return NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false), engine
}

func generateTestCSRPEM(t *testing.T, cn string, sans ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// generateTestCSRPEMWithIP builds a CSR carrying both a DNS SAN and an IP
// SAN, for W18-14: the engine issues the IP SAN correctly, but the bug this
// covers was in how the hub stores that fact afterwards, not in the CSR.
func generateTestCSRPEMWithIP(t *testing.T, cn, dnsName, ip string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    []string{dnsName},
		IPAddresses: []net.IP{net.ParseIP(ip)},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func getFirstCAID(t *testing.T, engine *ca.Engine) string {
	t.Helper()
	cas, err := engine.ListCAs()
	if err != nil || len(cas) == 0 {
		t.Fatalf("no CAs available: %v", err)
	}
	return cas[0].ID
}

func TestCACertificateProviderIssueAndQuery(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "test.example.com", "test.example.com", "www.test.example.com")

	// Issue certificate.
	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.FingerprintSHA256 == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if result.CommonName != "test.example.com" {
		t.Errorf("expected CN=test.example.com, got %s", result.CommonName)
	}
	if result.RenewalStatus != "active" {
		t.Errorf("expected active status, got %s", result.RenewalStatus)
	}
	if result.Source != "api" {
		t.Errorf("expected source=api, got %s", result.Source)
	}

	// Query by fingerprint.
	detail, found, err := provider.GetCertificate(ctx, result.FingerprintSHA256)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !found {
		t.Fatal("expected certificate to be found")
	}
	if detail.CommonName != "test.example.com" {
		t.Errorf("expected CN=test.example.com, got %s", detail.CommonName)
	}

	// List should contain the certificate.
	listResult, err := provider.ListCertificates(ctx, CertificateListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if listResult.Total != 1 {
		t.Errorf("expected 1 certificate, got %d", listResult.Total)
	}
}

// TestCACertificateProviderIssueKeepsIPSAN is W18-14: the CA engine issues
// the IP SAN correctly (internal/ca/engine.go passes CSR.IPAddresses
// through), but the stored CertificateItem.SubjectAltNames used to be built
// from issued.Certificate.DNSNames alone, silently dropping the IP SAN from
// the record renewal later rebuilds its CSR from.
func TestCACertificateProviderIssueKeepsIPSAN(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM := generateTestCSRPEMWithIP(t, "iis-lab.kk.local", "iis-lab.kk.local", "192.0.2.10")

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	detail, found, err := provider.GetCertificate(ctx, result.FingerprintSHA256)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !found {
		t.Fatal("expected certificate to be found")
	}

	wantDNS, wantIP := "iis-lab.kk.local", "192.0.2.10"
	var gotDNS, gotIP bool
	for _, san := range detail.SubjectAltNames {
		if san == wantDNS {
			gotDNS = true
		}
		if san == wantIP {
			gotIP = true
		}
	}
	if !gotDNS || !gotIP {
		t.Fatalf("SubjectAltNames = %v, want both %q and %q", detail.SubjectAltNames, wantDNS, wantIP)
	}
}

// TestCACertificateProviderRecordIssuedCertificate is W18-16: ACME-issued
// certificates never went through IssueCertificate (that's the API/dashboard
// path), so they need their own writer into the same inventory. This drives
// the CA engine directly -- as internal/acme/server.go's finalize handler
// does -- then calls RecordIssuedCertificate the way acme.Server would
// through the IssuedCertificateRecorder seam, and checks GetCertificate
// returns a row with SANs and CA id set, matching the API path's shape.
func TestCACertificateProviderRecordIssuedCertificate(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	recorder, ok := provider.(interface {
		RecordIssuedCertificate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error
	})
	if !ok {
		t.Fatal("caCertificateProvider does not implement RecordIssuedCertificate")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "acme-client.kk.local"},
		DNSNames:    []string{"acme-client.kk.local"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.9")},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	// Mirrors internal/acme/server.go's handleFinalize issuance request.
	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		DNSNames:    csrTmpl.DNSNames,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("issue via engine: %v", err)
	}

	if err := recorder.RecordIssuedCertificate(ctx, caID, issued.Certificate, issued.CertPEM, "acme"); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}

	detail, found, err := provider.GetCertificate(ctx, issued.Fingerprint)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !found {
		t.Fatal("expected recorded certificate to be found")
	}
	if detail.CAID != caID {
		t.Errorf("expected CAID=%s, got %s", caID, detail.CAID)
	}
	if detail.ManagementState != "managed" {
		t.Errorf("expected management_state=managed, got %s", detail.ManagementState)
	}
	if detail.Source != "acme" {
		t.Errorf("expected source=acme, got %s", detail.Source)
	}

	wantDNS, wantIP := "acme-client.kk.local", "10.0.0.9"
	var gotDNS, gotIP bool
	for _, san := range detail.SubjectAltNames {
		if san == wantDNS {
			gotDNS = true
		}
		if san == wantIP {
			gotIP = true
		}
	}
	if !gotDNS || !gotIP {
		t.Fatalf("SubjectAltNames = %v, want both %q and %q", detail.SubjectAltNames, wantDNS, wantIP)
	}
}

func TestCACertificateProviderRevokeFlow(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "revoke-me.example.com")
	issued, _ := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
	})

	// Revoke.
	revokeResult, err := provider.RevokeCertificate(ctx, issued.FingerprintSHA256, CertificateRevokeRequest{
		ReasonCode: 1,
		ReasonText: "key compromise",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revokeResult.RenewalStatus != "revoked" {
		t.Errorf("expected revoked status, got %s", revokeResult.RenewalStatus)
	}
	if revokeResult.RevocationReason != 1 {
		t.Errorf("expected reason 1, got %d", revokeResult.RevocationReason)
	}

	// Verify query reflects revocation.
	detail, _, _ := provider.GetCertificate(ctx, issued.FingerprintSHA256)
	if detail.RevokedAt == nil {
		t.Fatal("expected RevokedAt to be set")
	}
	if detail.RenewalStatus != "revoked" {
		t.Errorf("expected revoked, got %s", detail.RenewalStatus)
	}

	// Double-revoke should conflict.
	_, err = provider.RevokeCertificate(ctx, issued.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 0})
	if err != errCertificateConflict {
		t.Fatalf("expected conflict on double-revoke, got: %v", err)
	}
}

func TestCACertificateProviderRenewFlow(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "renew-me.example.com", "renew-me.example.com")
	original, _ := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})

	// Renew with new CSR.
	renewCSR := generateTestCSRPEM(t, "renew-me.example.com", "renew-me.example.com")
	renewed, err := provider.RenewCertificate(ctx, original.FingerprintSHA256, CertificateRenewRequest{
		CSRPEM: renewCSR,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.FingerprintSHA256 == original.FingerprintSHA256 {
		t.Error("renewed cert should have different fingerprint")
	}
	if renewed.PredecessorFP == nil || *renewed.PredecessorFP != original.FingerprintSHA256 {
		t.Error("renewed cert should link to predecessor")
	}

	// Original should now link to successor.
	origDetail, _, _ := provider.GetCertificate(ctx, original.FingerprintSHA256)
	if origDetail.SuccessorFP == nil || *origDetail.SuccessorFP != renewed.FingerprintSHA256 {
		t.Error("original should link to successor")
	}
	if origDetail.RenewalStatus != "renewed" {
		t.Errorf("expected original status=renewed, got %s", origDetail.RenewalStatus)
	}

	// Double-renew should conflict.
	_, err = provider.RenewCertificate(ctx, original.FingerprintSHA256, CertificateRenewRequest{CSRPEM: renewCSR})
	if err != errCertificateConflict {
		t.Fatalf("expected conflict on double-renew, got: %v", err)
	}

	// List should have 2 certs.
	list, _ := provider.ListCertificates(ctx, CertificateListQuery{Limit: 10})
	if list.Total != 2 {
		t.Errorf("expected 2 certificates after renewal, got %d", list.Total)
	}
}

func TestCACertificateProviderImportAndDownload(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	// Issue a cert to get a valid PEM for import testing.
	csrPEM := generateTestCSRPEM(t, "import-test.example.com")
	issued, _ := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
	})

	// Download as PEM.
	pemResult, err := provider.DownloadCertificate(ctx, issued.FingerprintSHA256, "pem", false)
	if err != nil {
		t.Fatalf("download pem: %v", err)
	}
	if pemResult.ContentType != "application/x-pem-file" {
		t.Errorf("expected pem content type, got %s", pemResult.ContentType)
	}
	if len(pemResult.Body) == 0 {
		t.Error("expected non-empty PEM body")
	}

	// Download as DER.
	derResult, err := provider.DownloadCertificate(ctx, issued.FingerprintSHA256, "der", false)
	if err != nil {
		t.Fatalf("download der: %v", err)
	}
	if derResult.ContentType != "application/x-x509-ca-cert" {
		t.Errorf("expected der content type, got %s", derResult.ContentType)
	}

	// Import a different certificate (use a self-signed one).
	selfKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	selfTemplate := &x509.Certificate{
		SerialNumber: mustSerialNumber(),
		Subject:      pkix.Name{CommonName: "imported.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	selfDER, _ := x509.CreateCertificate(rand.Reader, selfTemplate, selfTemplate, &selfKey.PublicKey, selfKey)
	selfPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfDER})

	imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
		CertificatePEM: string(selfPEM),
		TeamID:         "team-2",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.CommonName != "imported.example.com" {
		t.Errorf("expected CN=imported.example.com, got %s", imported.CommonName)
	}
	if imported.Source != "import" {
		t.Errorf("expected source=import, got %s", imported.Source)
	}

	// Duplicate import should conflict.
	_, err = provider.ImportCertificate(ctx, CertificateImportRequest{CertificatePEM: string(selfPEM)})
	if err != errCertificateConflict {
		t.Fatalf("expected conflict on duplicate import, got: %v", err)
	}
}

func TestCACertificateProviderNotFound(t *testing.T) {
	provider, _ := newTestCAProvider(t)
	ctx := context.Background()

	_, found, _ := provider.GetCertificate(ctx, "nonexistent-fingerprint")
	if found {
		t.Error("expected not found")
	}

	_, err := provider.RevokeCertificate(ctx, "nonexistent", CertificateRevokeRequest{})
	if err != errCertificateNotFound {
		t.Fatalf("expected not found, got: %v", err)
	}

	_, err = provider.DownloadCertificate(ctx, "nonexistent", "pem", false)
	if err != errCertificateNotFound {
		t.Fatalf("expected not found, got: %v", err)
	}
}

func TestCACertificateProviderInvalidCSR(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	_, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     "not-a-valid-csr",
	})
	if err == nil {
		t.Fatal("expected error for invalid CSR")
	}
}

func TestCACertificateProviderRiskScoring(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "risk.example.com")
	issued, _ := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
	})

	// ECDSA cert with 90-day validity should have low risk + PQC flag.
	// With expanded scoring, a cert without OCSP URL (+10) and CRL DP (+5) from a
	// test CA scores ~25 (PQC +10, no OCSP +10, no CRL +5) → Grade B, which is correct.
	if !issued.PQCVulnerable {
		t.Error("ECDSA cert should be PQC vulnerable")
	}
	if issued.RiskScore > 30 {
		t.Errorf("expected low risk score (≤30) for fresh cert, got %d (flags: %v)", issued.RiskScore, issued.RiskFlags)
	}
	if issued.Grade != "A" && issued.Grade != "B" {
		t.Errorf("expected grade A or B for fresh cert, got %s (score=%d, flags=%v)", issued.Grade, issued.RiskScore, issued.RiskFlags)
	}
	if len(issued.RiskFlags) == 0 {
		t.Error("expected at least PQC_VULNERABLE flag")
	}
}

func TestRiskScoringNISTSunsetForwardLooking(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// RSA-2048 cert whose lifetime extends past the 2031 NIST sunset.
	outlives := &x509.Certificate{
		PublicKey: &rsaKey.PublicKey,
		NotBefore: time.Now(),
		NotAfter:  time.Date(2032, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	flags := computeRiskFlags(outlives, false, time.Now())
	if !containsFlag(flags, "OUTLIVES_NIST_SUNSET") {
		t.Errorf("expected OUTLIVES_NIST_SUNSET for RSA-2048 cert expiring 2032, got %v", flags)
	}

	// Same key, expires before the sunset — no flag.
	expiresBefore := &x509.Certificate{
		PublicKey: &rsaKey.PublicKey,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
	}
	flags = computeRiskFlags(expiresBefore, false, time.Now())
	if containsFlag(flags, "OUTLIVES_NIST_SUNSET") {
		t.Errorf("did not expect OUTLIVES_NIST_SUNSET for short-lived RSA-2048 cert, got %v", flags)
	}

	// The outliving cert must score strictly higher than the compliant one,
	// after removing the expiry-window difference (both are unexpired).
	if computeRiskScore(outlives, time.Now()) <= computeRiskScore(expiresBefore, time.Now()) {
		t.Errorf("cert outliving NIST sunset should score higher: outlives=%d before=%d",
			computeRiskScore(outlives, time.Now()), computeRiskScore(expiresBefore, time.Now()))
	}
}

func TestRiskScoringSANSprawl(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	names := make([]string, sanSprawlThreshold+1)
	for i := range names {
		names[i] = "host" + big.NewInt(int64(i)).String() + ".example.com"
	}
	sprawl := &x509.Certificate{
		PublicKey: &key.PublicKey,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
		DNSNames:  names,
	}
	if !containsFlag(computeRiskFlags(sprawl, false, time.Now()), "SAN_SPRAWL") {
		t.Errorf("expected SAN_SPRAWL with %d DNS names", len(names))
	}

	modest := &x509.Certificate{
		PublicKey: &key.PublicKey,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
		DNSNames:  names[:5],
	}
	if containsFlag(computeRiskFlags(modest, false, time.Now()), "SAN_SPRAWL") {
		t.Error("did not expect SAN_SPRAWL with 5 DNS names")
	}
	if computeRiskScore(sprawl, time.Now()) <= computeRiskScore(modest, time.Now()) {
		t.Errorf("SAN sprawl should raise the score: sprawl=%d modest=%d",
			computeRiskScore(sprawl, time.Now()), computeRiskScore(modest, time.Now()))
	}
}

func containsFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

func mustSerialNumber() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, max)
	return serial
}

// W20-15: a protocol issuance governed by a template keeps that template on
// its inventory row, like an API issuance; the plain method leaves it empty.
func TestCACertificateProviderRecordIssuedCertificateWithTemplate(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	recorder, ok := provider.(ca.TemplateIssuedCertificateRecorder)
	if !ok {
		t.Fatal("caCertificateProvider does not implement ca.TemplateIssuedCertificateRecorder")
	}
	plain := provider.(ca.IssuedCertificateRecorder)

	issue := func(cn string) ca.IssuedCertificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
			CSR: csr, Validity: 24 * time.Hour,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			t.Fatal(err)
		}
		return *issued
	}

	templated, untemplated := issue("templated"), issue("untemplated")
	if err := recorder.RecordIssuedCertificateWithTemplate(ctx, caID, templated.Certificate, templated.CertPEM, "wstep", "tpl-machine"); err != nil {
		t.Fatal(err)
	}
	if err := plain.RecordIssuedCertificate(ctx, caID, untemplated.Certificate, untemplated.CertPEM, "wstep"); err != nil {
		t.Fatal(err)
	}
	for fp, want := range map[string]string{templated.Fingerprint: "tpl-machine", untemplated.Fingerprint: ""} {
		detail, found, err := provider.GetCertificate(ctx, fp)
		if err != nil || !found {
			t.Fatalf("get %s: found=%v err=%v", fp, found, err)
		}
		if detail.TemplateID != want || detail.Source != "wstep" {
			t.Errorf("%s: template_id=%q source=%q, want %q and wstep", fp, detail.TemplateID, detail.Source, want)
		}
	}
}

// TestCACertificateProviderDownloadIncludeChain pins the fullchain semantics:
// leaf + intermediates, root excluded. A root-issued leaf is a single
// certificate; an intermediate-issued leaf gets the intermediate appended.
func TestCACertificateProviderDownloadIncludeChain(t *testing.T) {
	provider, engine := newTestCAProvider(t)
	rootID := getFirstCAID(t, engine)
	ctx := context.Background()

	subjectsOf := func(body []byte) []string {
		var out []string
		for rest := body; ; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				return out
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatalf("parse chain member: %v", err)
			}
			out = append(out, c.Subject.CommonName)
		}
	}

	rootLeaf, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: rootID, TemplateID: "tpl-tls", CSRPEM: generateTestCSRPEM(t, "root-leaf.example.com"),
	})
	if err != nil {
		t.Fatalf("issue root leaf: %v", err)
	}
	dl, err := provider.DownloadCertificate(ctx, rootLeaf.FingerprintSHA256, "pem", true)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got := subjectsOf(dl.Body); len(got) != 1 {
		t.Fatalf("root-issued leaf with include_chain: want 1 cert (root excluded), got %v", got)
	}

	inter, err := engine.CreateIntermediateCA("Test Intermediate", pkix.Name{CommonName: "Test Intermediate CA"},
		keystore.ECDSAP256, rootID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	leaf, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: inter.ID, TemplateID: "tpl-tls", CSRPEM: generateTestCSRPEM(t, "inter-leaf.example.com"),
	})
	if err != nil {
		t.Fatalf("issue intermediate leaf: %v", err)
	}
	bare, _ := provider.DownloadCertificate(ctx, leaf.FingerprintSHA256, "pem", false)
	if got := subjectsOf(bare.Body); len(got) != 1 {
		t.Fatalf("include_chain=false: want 1 cert, got %v", got)
	}
	full, err := provider.DownloadCertificate(ctx, leaf.FingerprintSHA256, "pem", true)
	if err != nil {
		t.Fatalf("download fullchain: %v", err)
	}
	got := subjectsOf(full.Body)
	if len(got) != 2 || got[0] != "inter-leaf.example.com" || got[1] != "Test Intermediate CA" {
		t.Fatalf("want leaf then intermediate, got %v", got)
	}
	// Serving the chain must not corrupt the stored leaf PEM.
	again, _ := provider.DownloadCertificate(ctx, leaf.FingerprintSHA256, "pem", false)
	if !bytes.Equal(again.Body, bare.Body) {
		t.Fatal("include_chain download mutated the stored leaf PEM")
	}
}
