// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestEveryControlHasRuleAndArtifact(t *testing.T) {
	now := time.Now().UTC()
	report := computeComplianceEvidenceAt(buildTestCerts(), []CAListItem{{ID: "ca-1", Status: "active"}}, "all", now)
	if len(report.Controls) == 0 {
		t.Fatal("no controls")
	}
	for _, c := range report.Controls {
		if _, ok := controlIndex[c.ID]; !ok {
			t.Errorf("control %s fell through to the fallback index", c.ID)
		}
		if c.Rule == "" || len(c.Artifacts) < 1 {
			t.Errorf("control %s: rule=%q artifacts=%d", c.ID, c.Rule, len(c.Artifacts))
		}
		for _, a := range c.Artifacts {
			if a.Kind == "" || a.ID == "" || !strings.HasPrefix(a.URL, "/api/v1/") {
				t.Errorf("control %s: bad artifact %+v", c.ID, a)
			}
		}
	}
	var unknown ComplianceControl
	unknown.ID = "NOT-INDEXED"
	applyControlArtifactIndex(&unknown)
	if unknown.Rule != "see control evidence" || len(unknown.Artifacts) != 1 || unknown.Artifacts[0].Kind != "inventory_export" {
		t.Errorf("fallback wrong: %+v", unknown)
	}
}

type countingCertProvider struct {
	reportCertProvider
	calls int
}

func (p *countingCertProvider) ListCertificates(ctx context.Context, q CertificateListQuery) (CertificateListResult, error) {
	p.calls++
	return p.reportCertProvider.ListCertificates(ctx, q)
}

func TestComplianceEvidenceFedrampWiredAndFrameworkValidated(t *testing.T) {
	certs := &countingCertProvider{reportCertProvider: reportCertProvider{items: buildTestCerts()}}
	mux := http.NewServeMux()
	registerReportsHandlers(mux, newReportsTestAuth(t), certs, exceptionCAs{ids: map[string]bool{"ca-1": true}}, stubTemplateProvider{}, nil, stubAuditProvider{})

	get := func(q string) (*httptest.ResponseRecorder, ComplianceEvidenceReport) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/compliance-evidence"+q, nil)
		req.Header.Set("Authorization", "Bearer reports-test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var resp struct {
			Data ComplianceEvidenceReport `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec, resp.Data
	}
	fedIDs := func(r ComplianceEvidenceReport) int {
		n := 0
		for _, c := range r.Controls {
			if strings.HasPrefix(c.ID, "FEDRAMP-") {
				n++
			}
		}
		return n
	}

	rec, r := get("?framework=fedramp")
	if rec.Code != http.StatusOK || fedIDs(r) != 6 || len(r.Controls) != 6 {
		t.Fatalf("fedramp: code=%d controls=%d fed=%d", rec.Code, len(r.Controls), fedIDs(r))
	}
	if r.KeyCustody != nil || r.KeyCustodyNote != "no keystore is configured" {
		t.Errorf("nil store must explain itself: %+v %q", r.KeyCustody, r.KeyCustodyNote)
	}
	if _, r = get("?framework=all"); fedIDs(r) != 6 {
		t.Errorf("all must include fedramp, got %d", fedIDs(r))
	}
	if _, r = get(""); fedIDs(r) != 6 || r.Framework != "all" {
		t.Errorf("empty framework must behave as all: %q %d", r.Framework, fedIDs(r))
	}

	before := certs.calls
	rec, _ = get("?framework=bogus")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus framework: %d", rec.Code)
	}
	if certs.calls != before {
		t.Error("cert provider must not be called for an unknown framework")
	}
}

func TestComplianceEvidencePDFShowsRuleArtifactsAndCustody(t *testing.T) {
	pdfCompression = false
	t.Cleanup(func() { pdfCompression = true })
	at := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	store := &fakeKeystore{metas: []keystore.KeyMetadata{{ID: "custody-seed-key", Algorithm: "ecdsa-p256", CreatedAt: "2026-01-01T00:00:00Z"}}}
	kc, note := packKeyCustody(context.Background(), AuthPrincipal{Role: "pki-admin"}, store, &custodyAudit{})
	if kc == nil || note != "" {
		t.Fatalf("custody: %v %q", kc, note)
	}
	rep := computeComplianceEvidenceAt(buildTestCerts(), []CAListItem{{ID: "ca-1", Status: "active"}}, "fedramp", at)
	rep.KeyCustody = kc
	b, err := renderComplianceEvidencePDF(rep, 3, at)
	if err != nil {
		t.Fatal(err)
	}
	txt := pdfText(b)
	for _, want := range []string{"Rule:", "Artifacts:", "Key custody", "custody-seed-key", "FedRAMP Moderate (mapping)", "not an assessor attestation"} {
		if !strings.Contains(txt, want) {
			t.Errorf("PDF missing %q", want)
		}
	}

	rep.KeyCustody, rep.KeyCustodyNote = packKeyCustody(context.Background(), AuthPrincipal{Role: "pki-admin"}, nil, nil)
	b, _ = renderComplianceEvidencePDF(rep, 3, at)
	if !strings.Contains(pdfText(b), "no keystore is configured") {
		t.Error("nil-store note missing from PDF")
	}
}

func TestPackKeyCustodyTenantScopedListsNoForeignKeys(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	store := &fakeKeystore{metas: []keystore.KeyMetadata{{ID: "k1", Algorithm: "ecdsa-p256"}, {ID: "k2", Algorithm: "ecdsa-p256"}}}
	ctx := context.Background()

	scoped := AuthPrincipal{ID: "u", Role: "pki-admin", Tenant: "t1", TenantScoped: true}
	kc, note := packKeyCustody(ctx, scoped, store, &custodyAudit{})
	if kc == nil || note != "" {
		t.Fatalf("scoped admin: %v %q", kc, note)
	}
	if len(kc.Keys) != 0 {
		t.Fatalf("unresolvable/foreign keys must be denied, got %d", len(kc.Keys))
	}

	super := AuthPrincipal{ID: "root", Role: "pki-admin", SuperAdmin: true}
	kc, _ = packKeyCustody(ctx, super, store, &custodyAudit{})
	if kc == nil || len(kc.Keys) != 2 {
		t.Fatalf("unscoped super-admin must see all keys: %+v", kc)
	}

	kc, note = packKeyCustody(ctx, AuthPrincipal{ID: "a", Role: "auditor"}, store, &custodyAudit{})
	if kc != nil || !strings.Contains(note, "restricted to administrators") {
		t.Fatalf("non-admin: %v %q", kc, note)
	}
}

func TestEvidencePacksRenderWithin30sOn10kEstate(t *testing.T) {
	if testing.Short() {
		t.Skip("10k-cert timing test skipped in -short")
	}
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	certs := make([]CertificateItem, 10000)
	for i := range certs {
		certs[i] = CertificateItem{
			FingerprintSHA256:  fmt.Sprintf("fp-%05d", i),
			CommonName:         fmt.Sprintf("host-%05d.example.com", i),
			PublicKeyAlgorithm: "RSA",
			KeySizeBits:        2048,
			SignatureAlgorithm: "SHA256-RSA",
			ValidFrom:          now.Add(-24 * time.Hour).Format(time.RFC3339),
			ValidUntil:         now.Add(time.Duration(i%400+1) * 24 * time.Hour).Format(time.RFC3339),
			OwnerEmail:         "owner@example.com",
		}
		if i%50 == 0 {
			certs[i].RiskFlags = []string{"WEAK_RSA_KEY"}
		}
	}
	cas := []CAListItem{{ID: "ca-1", Status: "active"}}
	for _, fw := range []string{"pci", "soc2", "nist", "dora", "nis2", "fedramp"} {
		start := time.Now()
		rep := computeComplianceEvidenceAt(certs, cas, fw, now)
		if _, err := renderComplianceEvidencePDF(rep, len(certs), now); err != nil {
			t.Fatalf("%s: %v", fw, err)
		}
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("%s took %s (>30s)", fw, d)
		}
	}

	pdfCompression = false
	t.Cleanup(func() { pdfCompression = true })
	t.Setenv("KRYPTKEEPER_ORG_NAME", "Acme Audit Org")
	rep := computeComplianceEvidenceAt(certs, cas, "pci", now)
	b, err := renderComplianceEvidencePDF(rep, len(certs), now)
	if err != nil {
		t.Fatal(err)
	}
	txt := pdfText(b)
	if !strings.Contains(txt, orgName()) || !strings.Contains(txt, "Generated ") {
		t.Error("PDF must carry org name and generated stamp")
	}
}

func TestCryptoPostureCSVHardened(t *testing.T) {
	rec := httptest.NewRecorder()
	writeCryptoPostureCSV(rec, []CertificateItem{{FingerprintSHA256: "fp", CommonName: "=cmd", RiskScore: 5}})
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv: %v rows=%d", err, len(rows))
	}
	if rows[1][1] != "'=cmd" {
		t.Errorf("common_name = %q, want '=cmd", rows[1][1])
	}
	if rows[1][10] != "5" {
		t.Errorf("risk_score = %q, numeric must be untouched", rows[1][10])
	}
}
