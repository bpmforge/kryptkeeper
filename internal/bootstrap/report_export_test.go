// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// W7-05: CSV/XLSX export — pinned column sets, findings flattening,
// formula-injection hardening, and working endpoints.

func TestInventoryExportColumnSetIsPinned(t *testing.T) {
	want := "fingerprint_sha256,serial_number,common_name,subject_dn,subject_alt_names,issuer_cn,ca_id,team_id,valid_from,valid_until,public_key_algorithm,key_size_bits,signature_algorithm,chain_complete,chain_trusted,pqc_readiness,risk_score,risk_flags,grade,renewal_status,source"
	if got := strings.Join(inventoryExportColumns, ","); got != want {
		t.Fatalf("documented inventory column set changed:\n got %s\nwant %s", got, want)
	}
	if len(inventoryExportRow(CertificateItem{})) != len(inventoryExportColumns) {
		t.Fatal("row width must match the documented column set")
	}
	want = "fingerprint_sha256,common_name,finding,risk_score,grade,valid_until,team_id"
	if got := strings.Join(findingsExportColumns, ","); got != want {
		t.Fatalf("documented findings column set changed: %s", got)
	}
}

func TestFindingsFlattenOneRowPerFlag(t *testing.T) {
	items := []CertificateItem{
		{FingerprintSHA256: "aa", CommonName: "two.example.com", RiskFlags: []string{"expired", "weak_key"}},
		{FingerprintSHA256: "bb", CommonName: "clean.example.com"}, // no flags → no rows
	}
	rows := findingsExportRows(items)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (one per flag), got %d", len(rows))
	}
	if rows[0][2] != "expired" || rows[1][2] != "weak_key" {
		t.Fatalf("finding column wrong: %v", rows)
	}
}

func TestCSVFormulaInjectionHardened(t *testing.T) {
	var buf bytes.Buffer
	err := writeCSV(&buf, []string{"common_name"}, [][]string{
		{`=HYPERLINK("http://evil.example/","click")`},
		{"+1234"},
		{"safe.example.com"},
	})
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	recs, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse back: %v", err)
	}
	if !strings.HasPrefix(recs[1][0], "'=") {
		t.Fatalf("formula cell must be neutralized, got %q", recs[1][0])
	}
	if !strings.HasPrefix(recs[2][0], "'+") {
		t.Fatalf("plus cell must be neutralized, got %q", recs[2][0])
	}
	if recs[3][0] != "safe.example.com" {
		t.Fatalf("safe cell must be untouched, got %q", recs[3][0])
	}
}

func TestXLSXStructureAndContent(t *testing.T) {
	var buf bytes.Buffer
	err := writeXLSX(&buf, "inventory", []string{"common_name", "risk_score"}, [][]string{
		{"web.example.com", "42"},
		{`<script>&"'</script>`, "7"}, // XML-hostile content must be escaped
	})
	if err != nil {
		t.Fatalf("xlsx: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("output is not a zip: %v", err)
	}
	parts := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		raw, _ := io.ReadAll(rc)
		_ = rc.Close()
		parts[f.Name] = string(raw)
	}
	for _, required := range []string{"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/worksheets/sheet1.xml"} {
		if _, ok := parts[required]; !ok {
			t.Fatalf("missing OOXML part %s (have %v)", required, len(parts))
		}
	}
	sheet := parts["xl/worksheets/sheet1.xml"]
	if !strings.Contains(sheet, "web.example.com") || !strings.Contains(sheet, "common_name") {
		t.Fatal("sheet must contain header and data cells")
	}
	if strings.Contains(sheet, "<script>") {
		t.Fatal("XML-hostile content must be escaped in the sheet")
	}
	if !strings.Contains(parts["xl/workbook.xml"], `name="inventory"`) {
		t.Fatal("workbook must name the sheet")
	}
}

func exportTestMux(t *testing.T, items []CertificateItem) *http.ServeMux {
	t.Helper()
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerReportExportHandlers(mux, auth, &reportCertProvider{items: items}, stubAuditProvider{})
	return mux
}

func TestExportEndpoints(t *testing.T) {
	items := []CertificateItem{
		{FingerprintSHA256: "aa", CommonName: "web.example.com", RiskFlags: []string{"expiring_soon"}, RiskScore: 20},
	}
	mux := exportTestMux(t, items)

	// Unauthenticated: refused.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/export/inventory", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// CSV inventory.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/export/inventory?format=csv", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("csv: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "kryptkeeper-inventory") || !strings.Contains(cd, ".csv") {
		t.Fatalf("disposition %q", cd)
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || len(recs) != 2 {
		t.Fatalf("csv rows: %v %v", recs, err)
	}
	if recs[1][2] != "web.example.com" {
		t.Fatalf("common_name column: %v", recs[1])
	}

	// XLSX findings.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/export/findings?format=xlsx", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("xlsx: expected 200, got %d", rec.Code)
	}
	if _, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len())); err != nil {
		t.Fatalf("xlsx body is not a zip: %v", err)
	}

	// Unknown format refused.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/export/inventory?format=pdf", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown format: expected 400, got %d", rec.Code)
	}
}

// Review fix (security challenger #3): a leading TAB or CR is an OWASP
// formula-injection prefix and must be neutralized too.
func TestCSVFormulaInjectionHardensTabAndCR(t *testing.T) {
	for _, bad := range []string{"\t=cmd", "\r=cmd"} {
		if got := hardenSpreadsheetCell(bad); got[0] != '\'' {
			t.Fatalf("leading control-char formula %q must be neutralized, got %q", bad, got)
		}
	}
}
