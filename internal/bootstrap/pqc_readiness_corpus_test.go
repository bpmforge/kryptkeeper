// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W31-01: one seeded 500-cert inventory pinned across the classifier, the
// three PQC report surfaces and the MCP report paths.

type pqcCorpusClass struct {
	name           string
	n              int
	base           *x509.Certificate
	chainClassical bool
	validity       time.Duration
	want           string
}

type pqcCorpus struct {
	items []CertificateItem
	// wantByFingerprint is the table's expectation, kept apart from the
	// classifier output so a mismatch cannot hide behind a shared value.
	wantByFingerprint map[string]string
}

func selfSignedCorpusCert(t *testing.T, cn string, pub crypto.PublicKey, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.Add(400 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create %s cert: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s cert: %v", cn, err)
	}
	return cert
}

func corpusMLDSACSR(t *testing.T, keys keystore.Store, algo keystore.Algorithm, cn string) *ca.PQCCertificateRequest {
	t.Helper()
	keyID := "corpus-" + cn
	if _, err := keys.GenerateKey(keyID, algo); err != nil {
		t.Fatalf("generate %s key: %v", algo, err)
	}
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := ca.CreateCertificateRequestMLDSA(pkix.Name{CommonName: cn}, nil, nil, signer, algo)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA(%s): %v", algo, err)
	}
	csr, err := ca.ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA(%s): %v", algo, err)
	}
	return csr
}

func corpusIssueMLDSA(t *testing.T, engine *ca.Engine, keys keystore.Store, caID string, algo keystore.Algorithm, cn string) *x509.Certificate {
	t.Helper()
	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{PQCCSR: corpusMLDSACSR(t, keys, algo, cn)})
	if err != nil {
		t.Fatalf("issue %s leaf: %v", algo, err)
	}
	return issued.Certificate
}

func corpusIssueHybrid(t *testing.T, engine *ca.Engine, keys keystore.Store, caID string) *x509.Certificate {
	t.Helper()
	const keyID = "corpus-hybrid-leaf"
	if _, err := keys.GenerateKey(keyID, keystore.HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("generate hybrid key: %v", err)
	}
	loader, ok := keys.(keystore.HybridKeyLoader)
	if !ok {
		t.Fatal("keystore does not implement HybridKeyLoader")
	}
	pair, err := loader.LoadHybridKeyPair(keyID)
	if err != nil {
		t.Fatalf("load hybrid key pair: %v", err)
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: "corpus-hybrid.example.com"}, nil, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	csr, err := ca.ParseCertificateRequestHybrid(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestHybrid: %v", err)
	}
	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{HybridCSR: csr})
	if err != nil {
		t.Fatalf("issue hybrid leaf: %v", err)
	}
	return issued.Certificate
}

// corpusUnknownOIDCert rewrites the ML-DSA-65 OID (2.16.840.1.101.3.4.3.18)
// to a same-length unassigned arc, so the SPKI parses but no algorithm
// resolves: the real shape of an unclassifiable key.
func corpusUnknownOIDCert(t *testing.T, mldsa65 *x509.Certificate) *x509.Certificate {
	t.Helper()
	oldOID := []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	newOID := []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x63}
	if !bytes.Contains(mldsa65.Raw, oldOID) {
		t.Fatal("ML-DSA-65 OID not found in leaf DER")
	}
	cert, err := x509.ParseCertificate(bytes.ReplaceAll(mldsa65.Raw, oldOID, newOID))
	if err != nil {
		t.Fatalf("parse unknown-OID cert: %v", err)
	}
	return cert
}

func corpusClasses(t *testing.T) []pqcCorpusClass {
	t.Helper()
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa4096, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048Cert := selfSignedCorpusCert(t, "rsa2048", &rsa2048.PublicKey, rsa2048)
	rsa4096Cert := selfSignedCorpusCert(t, "rsa4096", &rsa4096.PublicKey, rsa4096)
	p256Cert := selfSignedCorpusCert(t, "p256", &p256.PublicKey, p256)
	p384Cert := selfSignedCorpusCert(t, "p384", &p384.PublicKey, p384)
	edCert := selfSignedCorpusCert(t, "ed25519", edPub, edPriv)

	// ML-DSA root: full-chain PQC leaves.
	_, pqcEngine, pqcKeys := newTestMLDSACAProvider(t)
	pqcCAID := getFirstCAID(t, pqcEngine)
	mldsa44 := corpusIssueMLDSA(t, pqcEngine, pqcKeys, pqcCAID, keystore.MLDSA44, "mldsa44")
	mldsa65 := corpusIssueMLDSA(t, pqcEngine, pqcKeys, pqcCAID, keystore.MLDSA65, "mldsa65")
	mldsa87 := corpusIssueMLDSA(t, pqcEngine, pqcKeys, pqcCAID, keystore.MLDSA87, "mldsa87")

	// ECDSA root: ML-DSA and hybrid leaves under a classical chain.
	ecKeys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	ecEngine := ca.NewEngine(ecKeys, ca.NewMemStore())
	if _, err := ecEngine.CreateRootCA("Corpus ECDSA Root", pkix.Name{CommonName: "Corpus ECDSA Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("create ECDSA root: %v", err)
	}
	ecCAID := getFirstCAID(t, ecEngine)
	leafOnly := corpusIssueMLDSA(t, ecEngine, ecKeys, ecCAID, keystore.MLDSA65, "mldsa65-ecdsa-ca")
	hybrid := corpusIssueHybrid(t, ecEngine, ecKeys, ecCAID)

	const long, short, pqcValidity = 400 * 24 * time.Hour, 30 * 24 * time.Hour, 90 * 24 * time.Hour
	return []pqcCorpusClass{
		{"rsa2048-long", 80, rsa2048Cert, true, long, "vulnerable"},
		{"rsa2048-short", 30, rsa2048Cert, true, short, "migration_ready"},
		{"rsa4096-long", 60, rsa4096Cert, true, long, "vulnerable"},
		{"p256-long", 40, p256Cert, true, long, "vulnerable"},
		{"p256-short", 40, p256Cert, true, short, "migration_ready"},
		{"p384-long", 50, p384Cert, true, long, "vulnerable"},
		{"ed25519-long", 30, edCert, true, long, "vulnerable"},
		{"mldsa44", 30, mldsa44, false, pqcValidity, "quantum_safe"},
		{"mldsa65", 30, mldsa65, false, pqcValidity, "quantum_safe"},
		{"mldsa87", 30, mldsa87, false, pqcValidity, "quantum_safe"},
		{"mldsa65-ecdsa-ca", 20, leafOnly, true, pqcValidity, pqcReadinessLeafOnly},
		{"hybrid", 40, hybrid, true, pqcValidity, pqcReadinessLeafOnly},
		{"unknown-oid", 20, corpusUnknownOIDCert(t, mldsa65), false, pqcValidity, "not_applicable"},
	}
}

func buildPQCCorpus(t *testing.T) pqcCorpus {
	t.Helper()
	corpus := pqcCorpus{wantByFingerprint: map[string]string{}}
	notBefore := time.Now().UTC().Add(-time.Hour)
	for _, cl := range corpusClasses(t) {
		for i := 0; i < cl.n; i++ {
			c := *cl.base
			c.NotBefore = notBefore
			c.NotAfter = notBefore.Add(cl.validity)
			fp := fmt.Sprintf("%s-%d", cl.name, i)
			corpus.wantByFingerprint[fp] = cl.want
			corpus.items = append(corpus.items, CertificateItem{
				FingerprintSHA256:  fp,
				CommonName:         fp,
				PQCReadiness:       computePQCReadiness(&c, cl.chainClassical),
				PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(&c),
				PQCVulnerable:      isPQCVulnerable(&c),
				ValidFrom:          c.NotBefore.Format(time.RFC3339),
				ValidUntil:         c.NotAfter.Format(time.RFC3339),
			})
		}
	}
	return corpus
}

type pqcTotals struct {
	TotalCerts          int
	QuantumSafe         int
	QuantumSafeLeafOnly int
	MigrationReady      int
	Vulnerable          int
	PQCScorePercent     int
	QuantumSafePercent  int
}

var wantCorpusTotals = pqcTotals{
	TotalCerts: 500, QuantumSafe: 90, QuantumSafeLeafOnly: 60, MigrationReady: 70,
	Vulnerable: 260, PQCScorePercent: 44, QuantumSafePercent: 18,
}

// corpusEndpointTotals fetches the three report paths (the same ones the
// crypto_posture, pqc_migration and pqc_countdown MCP tools proxy) and
// returns each report's shared totals plus the roadmap's not_applicable.
func corpusEndpointTotals(t *testing.T, base string) (posture, migration, countdown pqcTotals, migrationNA, postureNA int) {
	t.Helper()
	get := func(path string, out any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer reports-test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}

	var p struct {
		Data CryptoPostureReport `json:"data"`
	}
	get("/api/v1/reports/crypto-posture", &p)
	r := p.Data.PQCReadiness
	posture = pqcTotals{p.Data.TotalCerts, r.QuantumSafe, r.QuantumSafeLeafOnly, r.MigrationReady, r.Vulnerable, r.PQCScorePercent, r.QuantumSafePercent}
	postureNA = r.NotApplicable

	var m struct {
		Data struct {
			TotalCerts          int `json:"total_certs"`
			Vulnerable          int `json:"vulnerable"`
			MigrationReady      int `json:"migration_ready"`
			QuantumSafe         int `json:"quantum_safe"`
			QuantumSafeLeafOnly int `json:"quantum_safe_leaf_only"`
			NotApplicable       int `json:"not_applicable"`
			PQCScorePercent     int `json:"pqc_score_percent"`
			QuantumSafePercent  int `json:"quantum_safe_percent"`
		} `json:"data"`
	}
	get("/api/v1/reports/pqc-migration", &m)
	md := m.Data
	migration = pqcTotals{md.TotalCerts, md.QuantumSafe, md.QuantumSafeLeafOnly, md.MigrationReady, md.Vulnerable, md.PQCScorePercent, md.QuantumSafePercent}
	migrationNA = md.NotApplicable

	var c struct {
		Data PQCCountdownReport `json:"data"`
	}
	get("/api/v1/reports/pqc-countdown", &c)
	cd := c.Data
	countdown = pqcTotals{cd.TotalCerts, cd.QuantumSafe, cd.QuantumSafeLeafOnly, cd.MigrationReady, cd.Vulnerable, cd.PQCScorePercent, cd.QuantumSafePercent}
	return posture, migration, countdown, migrationNA, postureNA
}

func corpusServer(t *testing.T, items []CertificateItem) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerReportsHandlers(mux, newReportsTestAuth(t), &reportCertProvider{items: items}, &reportCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestPQCCorpus_ExpectedBucketsZeroMismatch(t *testing.T) {
	corpus := buildPQCCorpus(t)
	if len(corpus.items) != 500 {
		t.Fatalf("corpus size = %d, want 500", len(corpus.items))
	}

	var mismatches []string
	got := map[string]int{}
	for _, it := range corpus.items {
		got[it.PQCReadiness]++
		if want := corpus.wantByFingerprint[it.FingerprintSHA256]; it.PQCReadiness != want {
			mismatches = append(mismatches, fmt.Sprintf("%s: got %q want %q", it.FingerprintSHA256, it.PQCReadiness, want))
		}
	}
	if len(mismatches) > 0 {
		t.Fatalf("%d classification mismatches, first: %v", len(mismatches), mismatches[:min(5, len(mismatches))])
	}

	want := map[string]int{"vulnerable": 260, "migration_ready": 70, "quantum_safe": 90, pqcReadinessLeafOnly: 60, "not_applicable": 20}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bucket counts = %v, want %v", got, want)
	}

	p := computeCryptoPostureReport(corpus.items, nil).PQCReadiness
	if p.NotApplicable != 20 || p.QuantumSafePercent != 18 || p.PQCScorePercent != 44 {
		t.Errorf("posture: %+v", p)
	}
}

func TestPQCCorpus_ThreeReportsAgree(t *testing.T) {
	corpus := buildPQCCorpus(t)
	srv := corpusServer(t, corpus.items)

	posture, migration, countdown, migrationNA, postureNA := corpusEndpointTotals(t, srv.URL)
	for name, got := range map[string]pqcTotals{"crypto-posture": posture, "pqc-migration": migration, "pqc-countdown": countdown} {
		if got != wantCorpusTotals {
			t.Errorf("%s totals = %+v, want %+v", name, got, wantCorpusTotals)
		}
	}
	if migrationNA != 20 || postureNA != 20 {
		t.Errorf("not_applicable: roadmap %d posture %d, want 20", migrationNA, postureNA)
	}
}

// The MCP crypto_posture / pqc_migration / pqc_countdown tools are thin
// hub.get proxies over these exact paths (internal/mcpserver cannot be
// imported from bootstrap tests: depguard no-mcpserver-reimport), so the
// MCP leg is the bearer-authenticated GET the HubClient issues, repeated
// independently of the in-process comparison above.
func TestPQCCorpus_MCPToolPathsMatchEndpoints(t *testing.T) {
	corpus := buildPQCCorpus(t)
	srv := corpusServer(t, corpus.items)

	fetch := func(path string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/reports/"+path, nil)
		req.Header.Set("Authorization", "Bearer reports-test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if data, ok := out["data"].(map[string]any); ok {
			delete(data, "generated_at")
		}
		return out
	}

	for _, tool := range []struct{ name, path string }{
		{"crypto_posture", "crypto-posture"},
		{"pqc_migration", "pqc-migration"},
		{"pqc_countdown", "pqc-countdown"},
	} {
		first, second := fetch(tool.path), fetch(tool.path)
		if !reflect.DeepEqual(first, second) {
			t.Errorf("%s (%s): two fetches differ", tool.name, tool.path)
		}
	}

	posture, migration, countdown, _, _ := corpusEndpointTotals(t, srv.URL)
	for _, got := range []pqcTotals{posture, migration, countdown} {
		if got != wantCorpusTotals {
			t.Errorf("MCP-path totals = %+v, want %+v", got, wantCorpusTotals)
		}
	}
}

func TestPQCCorpus_CAIssuedMLDSAIsNotPQCVulnerable(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "corpus-not-vulnerable.example.com")

	result, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: csrPEM, TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf: %v", err)
	}
	if result.PQCVulnerable {
		t.Error("ML-DSA leaf issued by the Kryptkeeper CA must have PQCVulnerable=false")
	}
	if slices.Contains(result.RiskFlags, "PQC_VULNERABLE") {
		t.Errorf("RiskFlags %v must not contain PQC_VULNERABLE", result.RiskFlags)
	}
}

func TestPQCCorpus_EmptyInventory(t *testing.T) {
	p := computeCryptoPostureReport(nil, nil).PQCReadiness
	if p.QuantumSafePercent != 0 || p.PQCScorePercent != 0 {
		t.Errorf("empty posture: %+v", p)
	}
	cd := computePQCCountdown(context.Background(), nil, nil, nil, time.Now().UTC(), nil)
	if cd.TotalCerts != 0 || cd.QuantumSafePercent != 0 || cd.PQCScorePercent != 0 {
		t.Errorf("empty countdown: %+v", cd)
	}
}

func TestPQCCorpus_100kReportsUnder3s(t *testing.T) {
	if testing.Short() {
		t.Skip("100k timing guard skipped in -short")
	}
	base := buildPQCCorpus(t).items
	items := make([]CertificateItem, 0, 100_000)
	for r := 0; r < 200; r++ {
		for _, it := range base {
			it.FingerprintSHA256 = fmt.Sprintf("%s-r%d", it.FingerprintSHA256, r)
			items = append(items, it)
		}
	}

	start := time.Now()
	report := computeCryptoPostureReport(items, nil)
	elapsed := time.Since(start)
	t.Logf("computeCryptoPostureReport over %d certs: %s", len(items), elapsed)

	if report.TotalCerts != 100_000 || report.PQCReadiness.Vulnerable != 52_000 {
		t.Errorf("100k report: total %d, %+v", report.TotalCerts, report.PQCReadiness)
	}
	if elapsed > 3*time.Second {
		t.Errorf("100k crypto-posture report took %s, budget 3s", elapsed)
	}
}
