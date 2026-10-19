// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// W28-07 ---------------------------------------------------------------

func TestHardenRowForKeepsNumericColumns(t *testing.T) {
	header := []string{"risk_score", "key_size_bits", "risk_score", "risk_score", "common_name"}
	row := []string{"-5", "2048", "=1+1", "-5x", "-5"}
	got := hardenRowFor(header, row)
	if got[0] != "-5" || got[1] != "2048" {
		t.Fatalf("plain integers in numeric columns must be unchanged: %q", got)
	}
	if got[2] != "'=1+1" || got[3] != "'-5x" {
		t.Fatalf("non-integer values in numeric columns must be prefixed: %q", got)
	}
	if got[4] != "'-5" {
		t.Fatalf("non-numeric column must be prefixed: %q", got[4])
	}
	if h := hardenRow([]string{"-5"}); h[0] != "'-5" {
		t.Fatalf("hardenRow has no numeric exemption: %q", h)
	}
}

// xlsxCells returns every <t> text of sheet1, row by row.
func xlsxCells(t *testing.T, body []byte) [][]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != "xl/worksheets/sheet1.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open sheet: %v", err)
		}
		defer func() { _ = rc.Close() }()
		dec := xml.NewDecoder(rc)
		var rows [][]string
		var inT bool
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("sheet xml: %v", err)
			}
			switch e := tok.(type) {
			case xml.StartElement:
				switch e.Name.Local {
				case "row":
					rows = append(rows, nil)
				case "t":
					inT = true
					rows[len(rows)-1] = append(rows[len(rows)-1], "") // empty cells emit no CharData
				}
			case xml.EndElement:
				if e.Name.Local == "t" {
					inT = false
				}
			case xml.CharData:
				if inT {
					last := rows[len(rows)-1]
					last[len(last)-1] += string(e)
				}
			}
		}
		return rows
	}
	t.Fatal("xl/worksheets/sheet1.xml missing")
	return nil
}

func exportBody(t *testing.T, mux *http.ServeMux, kind, format string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/export/"+kind+"?format="+format, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: status %d", kind, format, rec.Code)
	}
	return rec.Body.Bytes()
}

func exportRows(t *testing.T, mux *http.ServeMux, kind, format string) [][]string {
	t.Helper()
	body := exportBody(t, mux, kind, format)
	if format == "xlsx" {
		return xlsxCells(t, body)
	}
	recs, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	return recs
}

func hostileCerts() []CertificateItem {
	var items []CertificateItem
	for i, p := range []string{"=", "+", "-", "@", "\t", "\r"} {
		items = append(items, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp%d", i),
			CommonName:        p + `HYPERLINK("http://evil.example","x")`,
			SubjectDN:         p + "2+3",
			IssuerCN:          p + "cmd|' /C calc'!A0",
			SubjectAltNames:   []string{p + "SUM(1+1)"},
			TeamID:            p + "team",
			CAID:              p + "ca",
			RiskFlags:         []string{p + "flag"},
			RiskScore:         -1, // impossible in prod; proves the numeric exemption
			KeySizeBits:       2048,
		})
	}
	return items
}

func TestFormulaInjectionCorpusCSVAndXLSX(t *testing.T) {
	mux := exportTestMux(t, hostileCerts())
	hits := 0
	for _, kind := range []string{"inventory", "findings"} {
		for _, format := range []string{"csv", "xlsx"} {
			rows := exportRows(t, mux, kind, format)
			if len(rows) < 2 {
				t.Fatalf("%s/%s: no data rows", kind, format)
			}
			header := rows[0]
			for _, row := range rows[1:] {
				for i, cell := range row {
					if cell == "" {
						continue
					}
					if numericExportColumns[header[i]] && isPlainInteger(cell) {
						continue
					}
					if strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
						hits++
						t.Errorf("%s/%s col %s: unescaped %q", kind, format, header[i], cell)
					}
				}
			}
			// numeric columns untouched
			for _, row := range rows[1:] {
				for i, cell := range row {
					if header[i] == "risk_score" && cell != "-1" {
						t.Errorf("%s/%s risk_score altered: %q", kind, format, cell)
					}
				}
			}
		}
	}
	t.Logf("formula-injection hits: %d", hits)
	if hits != 0 {
		t.Fatalf("formula-injection hits: %d", hits)
	}
}

func TestExport50kRowsInventoryCSVUnder30s(t *testing.T) {
	if testing.Short() {
		t.Skip("50k-row export timing test skipped in -short")
	}
	const n = 50000
	items := make([]CertificateItem, n)
	for i := range items {
		items[i] = CertificateItem{
			FingerprintSHA256: fmt.Sprintf("%064x", i),
			SerialNumber:      fmt.Sprintf("%x", i),
			CommonName:        fmt.Sprintf("host-%d.example.com", i),
			KeySizeBits:       2048,
			RiskScore:         i % 100,
		}
	}
	mux := exportTestMux(t, items)
	start := time.Now()
	body := exportBody(t, mux, "inventory", "csv")
	elapsed := time.Since(start)
	t.Logf("50,000-row inventory CSV export took %s", elapsed)
	if elapsed >= 30*time.Second {
		t.Fatalf("export took %s, want < 30s", elapsed)
	}
	recs, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) != n+1 {
		t.Fatalf("records = %d, want %d", len(recs), n+1)
	}
	seen := map[string]bool{recs[1][2]: true, recs[n][2]: true}
	if !seen["host-0.example.com"] || !seen["host-49999.example.com"] {
		t.Fatalf("first/last common names wrong: %q %q", recs[1][2], recs[n][2])
	}
}

func TestExportNonASCIIRoundTrips(t *testing.T) {
	names := []string{"münchen.example", "日本語.example.jp", "пример.рф", "🔒.example"}
	var items []CertificateItem
	for i, n := range names {
		items = append(items, CertificateItem{FingerprintSHA256: fmt.Sprintf("fp%d", i), CommonName: n})
	}
	mux := exportTestMux(t, items)
	csvRows := exportRows(t, mux, "inventory", "csv")
	xlsxRows := exportRows(t, mux, "inventory", "xlsx")
	for i, n := range names {
		if csvRows[i+1][2] != n {
			t.Errorf("csv row %d = %q, want %q", i, csvRows[i+1][2], n)
		}
		if xlsxRows[i+1][2] != n {
			t.Errorf("xlsx row %d = %q, want %q", i, xlsxRows[i+1][2], n)
		}
	}
}

// TestExportXLSXFixtures emits real-handler workbooks for the nightly
// LibreOffice check (W28-08, scripts/test/xlsx-libreoffice.sh).
func TestExportXLSXFixtures(t *testing.T) {
	dir := os.Getenv("KK_XLSX_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set KK_XLSX_FIXTURE_DIR to emit fixtures")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hostile := []string{"=HYPERLINK(\"http://evil.example\",\"x\")", "@SUM(1+1)", "+cmd|' /C calc'!A0", "-2+3"}
	unicode := []string{"münchen.example", "日本語.example.jp", "пример.рф", "🔒.example"}
	items := make([]CertificateItem, 500)
	for i := range items {
		cn := fmt.Sprintf("host-%d.example.com", i)
		switch i % 3 {
		case 0:
			cn = hostile[i/3%len(hostile)]
		case 1:
			cn = unicode[i/3%len(unicode)]
		}
		items[i] = CertificateItem{
			FingerprintSHA256: fmt.Sprintf("%064x", i), CommonName: cn,
			SubjectDN: "CN=" + cn, KeySizeBits: 2048, RiskScore: i % 100,
			RiskFlags: []string{"expiring_soon", "weak_key", "wildcard"}, Grade: "B",
		}
	}
	mux := exportTestMux(t, items)
	for _, kind := range []string{"inventory", "findings"} {
		body := exportBody(t, mux, kind, "xlsx")
		if err := os.WriteFile(filepath.Join(dir, "kryptkeeper-"+kind+".xlsx"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
