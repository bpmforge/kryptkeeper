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
	"net/http"
	"strconv"
	"strings"
	"time"
)

// W7-05 (PE-11/D-059): inventory + findings as CSV/XLSX, complementing
// the JSON APIs and PDF reports. Stdlib only: CSV via encoding/csv,
// XLSX as the minimal OOXML part set with inline strings — no
// spreadsheet dependency.

// inventoryExportColumns is the documented inventory column set — the
// header row IS the documentation, and tests pin it.
var inventoryExportColumns = []string{
	"fingerprint_sha256", "serial_number", "common_name", "subject_dn",
	"subject_alt_names", "issuer_cn", "ca_id", "team_id",
	"valid_from", "valid_until", "public_key_algorithm", "key_size_bits",
	"signature_algorithm", "chain_complete", "chain_trusted",
	"pqc_readiness", "risk_score", "risk_flags", "grade",
	"renewal_status", "source",
}

// findingsExportColumns: one row per risk flag per certificate — the
// flat shape analysts filter on.
var findingsExportColumns = []string{
	"fingerprint_sha256", "common_name", "finding", "risk_score",
	"grade", "valid_until", "team_id",
}

func inventoryExportRow(c CertificateItem) []string {
	return []string{
		c.FingerprintSHA256, c.SerialNumber, c.CommonName, c.SubjectDN,
		strings.Join(c.SubjectAltNames, ";"), c.IssuerCN, c.CAID, c.TeamID,
		c.ValidFrom, c.ValidUntil, c.PublicKeyAlgorithm, strconv.Itoa(c.KeySizeBits),
		c.SignatureAlgorithm, optBool(c.ChainComplete), optBool(c.ChainTrusted),
		c.PQCReadiness, strconv.Itoa(c.RiskScore), strings.Join(c.RiskFlags, ";"), c.Grade,
		c.RenewalStatus, c.Source,
	}
}

func findingsExportRows(items []CertificateItem) [][]string {
	var rows [][]string
	for _, c := range items {
		for _, flag := range c.RiskFlags {
			rows = append(rows, []string{
				c.FingerprintSHA256, c.CommonName, flag,
				strconv.Itoa(c.RiskScore), c.Grade, c.ValidUntil, c.TeamID,
			})
		}
	}
	return rows
}

// hardenSpreadsheetCell neutralizes formula injection: certificate
// CNs/SANs are attacker-influenced input landing in spreadsheets, and
// a leading =, +, -, or @ executes in Excel. Standard OWASP
// mitigation: prefix with a single quote.
func hardenSpreadsheetCell(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

func hardenRow(row []string) []string {
	out := make([]string, len(row))
	for i, v := range row {
		out[i] = hardenSpreadsheetCell(v)
	}
	return out
}

// writeCSV writes a header + hardened rows.
func writeCSV(buf *bytes.Buffer, header []string, rows [][]string) error {
	w := csv.NewWriter(buf)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write(hardenRow(row)); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// xmlEscape escapes a string for XML text content.
func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // bytes.Buffer writes cannot fail
	return b.String()
}

// writeXLSX writes the minimal OOXML workbook: one sheet, inline
// strings — readable by Excel, LibreOffice, and Sheets without any
// shared-strings table.
func writeXLSX(buf *bytes.Buffer, sheetName string, header []string, rows [][]string) error {
	zw := zip.NewWriter(buf)
	add := func(name, content string) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write([]byte(content))
		return err
	}

	if err := add("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`); err != nil {
		return err
	}
	if err := add("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`); err != nil {
		return err
	}
	if err := add("xl/workbook.xml", fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="%s" sheetId="1" r:id="rId1"/></sheets>
</workbook>`, xmlEscape(sheetName))); err != nil {
		return err
	}
	if err := add("xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`); err != nil {
		return err
	}

	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeRow := func(cells []string) {
		sheet.WriteString("<row>")
		for _, cell := range cells {
			sheet.WriteString(`<c t="inlineStr"><is><t xml:space="preserve">`)
			sheet.WriteString(xmlEscape(cell))
			sheet.WriteString(`</t></is></c>`)
		}
		sheet.WriteString("</row>")
	}
	writeRow(header)
	for _, row := range rows {
		writeRow(hardenRow(row))
	}
	sheet.WriteString(`</sheetData></worksheet>`)
	if err := add("xl/worksheets/sheet1.xml", sheet.String()); err != nil {
		return err
	}
	return zw.Close()
}

// serveExport renders the rows in the requested format with a dated
// attachment filename.
func serveExport(w http.ResponseWriter, r *http.Request, base string, header []string, rows [][]string) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	stamp := time.Now().UTC().Format("2006-01-02")
	var buf bytes.Buffer
	switch format {
	case "csv":
		if err := writeCSV(&buf, header, rows); err != nil {
			writeServiceUnavailable(w, "csv render failed")
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.csv"`, base, stamp))
	case "xlsx":
		if err := writeXLSX(&buf, base, header, rows); err != nil {
			writeServiceUnavailable(w, "xlsx render failed")
			return
		}
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.xlsx"`, base, stamp))
	default:
		writeBadRequest(w, "format must be csv or xlsx")
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// registerReportExportHandlers mounts the export endpoints. Rows come
// from the SAME reportVisibleCertificates path every other report
// uses, so tenant/team visibility applies identically — an export can
// never show more than the report screens do.
func registerReportExportHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, auditProvider AuditProvider) {
	handle := func(base string, render func(items []CertificateItem) [][]string, header []string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "report.export", "report", base, AuditOutcomeDenied)
				writeUnauthorized(w)
				return
			}
			// Reject an unknown format BEFORE auditing success, so a
			// 400 never records a false "success".
			if f := r.URL.Query().Get("format"); f != "" && f != "csv" && f != "xlsx" {
				writeBadRequest(w, "format must be csv or xlsx")
				return
			}
			items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
			if err != nil {
				writeServiceUnavailable(w, "inventory unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "report.export", "report", base, AuditOutcomeSuccess)
			serveExport(w, r, base, header, render(items))
		}
	}
	mux.HandleFunc("/api/v1/reports/export/inventory", handle("kryptkeeper-inventory", func(items []CertificateItem) [][]string {
		rows := make([][]string, 0, len(items))
		for _, c := range items {
			rows = append(rows, inventoryExportRow(c))
		}
		return rows
	}, inventoryExportColumns))
	mux.HandleFunc("/api/v1/reports/export/findings", handle("kryptkeeper-findings", findingsExportRows, findingsExportColumns))
}

// optBool renders a nullable verdict; blank = not judged at certificate level
// (discovered certificates: see CertificateItem.ChainComplete).
func optBool(p *bool) string {
	if p == nil {
		return ""
	}
	return strconv.FormatBool(*p)
}
