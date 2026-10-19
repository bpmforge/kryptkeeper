// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// W24-36: estate board report.

// estateFixture100 builds 100 deterministic certs: every one of the 12
// origin x state cells is non-zero, 5 are revoked, 3 have an empty state.
func estateFixture100() []CertificateItem {
	pqc := []string{"vulnerable", "migration_ready", "quantum_safe", "not_applicable"}
	// Weighted so all three states appear in every origin.
	stateCycle := []string{"managed", "managed", "external", "unmanaged", "managed", "unmanaged", "external"}
	revokedAt := "2026-01-01T00:00:00Z"
	items := make([]CertificateItem, 100)
	for i := range items {
		items[i] = CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp%03d", i),
			Origin:            estateOrigins[i%4],
			ManagementState:   stateCycle[(i/4)%len(stateCycle)],
			PQCReadiness:      pqc[i%4],
			RiskScore:         5 + (i*7)%86,
			RenewalStatus:     "active",
		}
	}
	for _, i := range []int{3, 17, 40, 58, 91} {
		items[i].RevokedAt = &revokedAt
	}
	for _, i := range []int{0, 1, 2} { // internal origin, empty state => managed
		items[i].ManagementState = ""
	}
	return items
}

func TestComputeEstateReport_MatrixAndTotals(t *testing.T) {
	r := computeEstateReport(estateFixture100())
	if len(r.Matrix) != 12 {
		t.Fatalf("matrix cells: %d", len(r.Matrix))
	}
	sum := 0
	for _, c := range r.Matrix {
		sum += c.Count
		if c.Count == 0 {
			t.Fatalf("fixture should fill every cell, %s/%s is 0", c.Origin, c.ManagementState)
		}
	}
	if sum != 95 || r.Total != 95 {
		t.Fatalf("sum=%d total=%d, want 95", sum, r.Total)
	}
	for _, o := range estateOrigins {
		n := 0
		for _, c := range r.Matrix {
			if c.Origin == o {
				n += c.Count
			}
		}
		if r.ByOrigin[o] != n {
			t.Fatalf("by_origin[%s]=%d marginal=%d", o, r.ByOrigin[o], n)
		}
	}
	for _, st := range estateStates {
		n := 0
		for _, c := range r.Matrix {
			if c.ManagementState == st {
				n += c.Count
			}
		}
		if r.ByState[st] != n {
			t.Fatalf("by_state[%s]=%d marginal=%d", st, r.ByState[st], n)
		}
	}
	// Empty state counted as managed: items 0,1,2 are internal/active.
	items := estateFixture100()
	for i := 0; i < 3; i++ {
		items[i].ManagementState = "managed"
	}
	if explicit := computeEstateReport(items); explicit.ByState["managed"] != r.ByState["managed"] {
		t.Fatalf("empty state not counted as managed: %d vs %d", r.ByState["managed"], explicit.ByState["managed"])
	}
}

func TestComputeEstateReport_UnknownBucketsIgnored(t *testing.T) {
	r := computeEstateReport([]CertificateItem{
		{Origin: "internal", ManagementState: "managed"},
		{Origin: "weird", ManagementState: "managed"},
		{Origin: "internal", ManagementState: "weird"},
	})
	if r.Total != 1 {
		t.Fatalf("unknown buckets must be ignored, total=%d", r.Total)
	}
}

// TestEstateReport_CountsEqualDashboard re-states the dashboard rule
// (certs_summary_db_provider.go: activeCertSQL + COALESCE(management_state,
// 'managed')) over the same fixture; no existing helper inserts certificate
// rows in <20 lines, so the spec's default (rule re-statement) applies.
func TestEstateReport_CountsEqualDashboard(t *testing.T) {
	items := estateFixture100()
	managed, external, unmanaged := 0, 0, 0
	for _, c := range items {
		if c.RevokedAt != nil || c.RenewalStatus == "revoked" || c.RenewalStatus == "renewed" {
			continue
		}
		switch c.ManagementState {
		case "", "managed":
			managed++
		case "external":
			external++
		case "unmanaged":
			unmanaged++
		}
	}
	r := computeEstateReport(items)
	if r.ByState["managed"] != managed || r.ByState["external"] != external || r.ByState["unmanaged"] != unmanaged {
		t.Fatalf("report %v != dashboard %d/%d/%d", r.ByState, managed, external, unmanaged)
	}
	if r.Total != managed+external+unmanaged || r.Total != 95 {
		t.Fatalf("total %d", r.Total)
	}
	// PQC split and risk equal the crypto-posture report on the same set.
	cp := computeCryptoPostureReport(items, nil)
	if r.PQC != cp.PQCReadiness || r.Risk != cp.RiskBreakdown {
		t.Fatalf("pqc/risk diverge from crypto-posture: %+v %+v", r.PQC, r.Risk)
	}
	if r.PQC.QuantumSafe+r.PQC.QuantumSafeLeafOnly+r.PQC.MigrationReady+r.PQC.Vulnerable+r.PQC.NotApplicable != 95 {
		t.Fatalf("pqc split does not cover 95: %+v", r.PQC)
	}
}

func estateReportMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerReportsHandlers(mux, newReportsTestAuth(t), &reportCertProvider{items: estateFixture100()}, &reportCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})
	return mux
}

func TestEstateReportHandler_PDF(t *testing.T) {
	mux := estateReportMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/estate?format=pdf", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	b := rec.Body.Bytes()
	if !bytes.HasPrefix(b, []byte("%PDF-")) || !bytes.Contains(b, []byte("%%EOF")) || len(b) <= 1500 {
		t.Fatalf("not a plausible PDF (%d bytes)", len(b))
	}
}

func TestEstateReportHandler_JSONAndAuth(t *testing.T) {
	mux := estateReportMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/estate", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("json: %d", rec.Code)
	}
	var resp struct {
		Data EstateReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Total != 95 || len(resp.Data.Matrix) != 12 {
		t.Fatalf("report: total=%d cells=%d", resp.Data.Total, len(resp.Data.Matrix))
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/estate", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", rec.Code)
	}
}

// pdfContentStreams returns the decompressed page content streams of a PDF
// with fpdf's random font tags normalised. The PDF file as a whole is not
// byte-stable (fpdf emits font objects in map order and tags them randomly,
// and evidence_pdf.go is out of scope), but what is drawn on the page must be
// a pure function of the report.
func pdfContentStreams(t *testing.T, pdf []byte) []string {
	t.Helper()
	tag := regexp.MustCompile(`/F[0-9a-f]{32}`)
	var out []string
	for _, m := range regexp.MustCompile(`(?s)stream\r?\n(.*?)endstream`).FindAllSubmatch(pdf, -1) {
		zr, err := zlib.NewReader(bytes.NewReader(m[1]))
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(zr)
		if err != nil || !bytes.Contains(raw, []byte("BT")) {
			continue
		}
		out = append(out, string(tag.ReplaceAll(raw, []byte("/F"))))
	}
	if len(out) == 0 {
		t.Fatal("no page content stream found")
	}
	return out
}

func TestRenderEstateReportPDF_Deterministic(t *testing.T) {
	r := computeEstateReport(estateFixture100())
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	a, err := renderEstateReportPDF(r, at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderEstateReportPDF(r, at)
	if err != nil {
		t.Fatal(err)
	}
	ca, cb := pdfContentStreams(t, a), pdfContentStreams(t, b)
	if strings.Join(ca, "\n") != strings.Join(cb, "\n") {
		t.Fatal("page content differs between renders of the same report")
	}
}
