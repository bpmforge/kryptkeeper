// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"sort"
	"strconv"
	"time"
)

// scheduledReportInputs is the fleet-wide data a scheduled report renders
// from. Schedules carry no principal, so nothing here is tenant-scoped; the
// schedule API is super-admin-only for the same reason (D-102).
type scheduledReportInputs struct {
	certs      []CertificateItem
	cas        []CAListItem
	exceptions []FindingException
}

// scheduledReportDef describes one report a schedule may deliver. table
// reuses the same compute function as the report's HTTP handler, so an
// emailed sheet and the on-screen report cannot disagree.
type scheduledReportDef struct {
	Title   string
	Formats []string
	// needsCAs makes the scheduler load the CA list before rendering.
	needsCAs bool
	table    func(in scheduledReportInputs) (header []string, rows [][]string)
	// pdf is nil for reports whose PDF is rendered by the scheduler itself
	// (executive-summary needs the posture trend and key counts).
	pdf func(in scheduledReportInputs, now time.Time) ([]byte, error)
}

// reportScheduleCatalog lists every report the schedule API accepts. Reports
// the HTTP API serves that are not here (pqc-migration, renewal-slo,
// key-custody, revocation-activity, issuance-velocity, change-audit,
// compliance-evidence, pqc-countdown, anomalies) need a flat-table shape of
// their own first; they are tracked on docs/ROADMAP.md.
var reportScheduleCatalog = map[string]scheduledReportDef{
	reportExecutiveSummary: {Title: "Executive summary", Formats: []string{"pdf"}},
	reportInventory: {Title: "Certificate inventory", Formats: []string{"csv", "xlsx"},
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			rows := make([][]string, 0, len(in.certs))
			for _, c := range in.certs {
				rows = append(rows, inventoryExportRow(c))
			}
			return inventoryExportColumns, rows
		}},
	reportFindings: {Title: "Findings", Formats: []string{"csv", "xlsx"},
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			return findingsExportColumns, findingsExportRows(in.certs)
		}},
	"estate": {Title: "Certificate estate (origin by management state)", Formats: []string{"csv", "xlsx", "pdf"},
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			rep := computeEstateReport(in.certs)
			rows := make([][]string, 0, len(rep.Matrix))
			for _, c := range rep.Matrix {
				rows = append(rows, []string{c.Origin, c.ManagementState, strconv.Itoa(c.Count)})
			}
			return []string{"origin", "management_state", "count"}, rows
		},
		pdf: func(in scheduledReportInputs, now time.Time) ([]byte, error) {
			return renderEstateReportPDF(computeEstateReport(in.certs), now)
		}},
	"crypto-posture": {Title: "Crypto posture", Formats: []string{"csv", "xlsx"},
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			r := computeCryptoPostureReport(in.certs, in.exceptions)
			rows := [][]string{{"total", "certificates", strconv.Itoa(r.TotalCerts)}}
			add := func(section, key string, n int) { rows = append(rows, []string{section, key, strconv.Itoa(n)}) }
			for _, k := range sortedKeys(r.AlgorithmBreakdown) {
				add("algorithm", k, r.AlgorithmBreakdown[k])
			}
			for _, k := range sortedKeys(r.GradeDistribution) {
				add("grade", k, r.GradeDistribution[k])
			}
			p := r.PQCReadiness
			add("pqc", "quantum_safe", p.QuantumSafe)
			add("pqc", "quantum_safe_leaf_only", p.QuantumSafeLeafOnly)
			add("pqc", "migration_ready", p.MigrationReady)
			add("pqc", "vulnerable", p.Vulnerable)
			add("pqc", "not_applicable", p.NotApplicable)
			add("pqc", "pqc_score_percent", p.PQCScorePercent)
			add("pqc", "quantum_safe_percent", p.QuantumSafePercent)
			e := r.ExpiryBuckets
			add("expiry", "expired", e.Expired)
			add("expiry", "expiring_47d", e.Expiring47d)
			add("expiry", "expiring_90d", e.Expiring90d)
			add("expiry", "expiring_200d", e.Expiring200d)
			add("expiry", "expiring_1yr", e.Expiring1yr)
			add("expiry", "unknown", e.Unknown)
			add("automation", "automated", r.AutomationCoverage.Automated)
			add("automation", "manual", r.AutomationCoverage.Manual)
			add("risk", "critical", r.RiskBreakdown.Critical)
			add("risk", "high", r.RiskBreakdown.High)
			add("risk", "medium", r.RiskBreakdown.Medium)
			add("risk", "low", r.RiskBreakdown.Low)
			add("findings", "raw", r.Findings.Raw)
			add("findings", "effective", r.Findings.Effective)
			add("findings", "suppressed", r.Findings.Suppressed)
			return []string{"section", "metric", "value"}, rows
		}},
	"expiry-timeline": {Title: "Expiry timeline", Formats: []string{"csv", "xlsx"},
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			r := computeExpiryTimeline(in.certs)
			rows := make([][]string, 0, len(r.Buckets)+1)
			for _, b := range r.Buckets {
				rows = append(rows, []string{b.Label, strconv.Itoa(b.DaysFrom), strconv.Itoa(b.DaysTo), strconv.Itoa(b.Count)})
			}
			rows = append(rows, []string{"unknown", "", "", strconv.Itoa(r.UnknownExpiry)})
			return []string{"bucket", "days_from", "days_to", "count"}, rows
		}},
	"ca-health": {Title: "CA health", Formats: []string{"csv", "xlsx"}, needsCAs: true,
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			r := computeCAHealth(in.cas)
			rows := make([][]string, 0, len(r.Items))
			for _, c := range r.Items {
				rows = append(rows, []string{c.ID, c.Name, c.Status, c.Algorithm, c.ExpiresAt,
					strconv.Itoa(c.DaysUntilExpiry), strconv.Itoa(c.ChainDepth), c.AlgorithmStrength})
			}
			return []string{"id", "name", "status", "algorithm", "expires_at", "days_until_expiry", "chain_depth", "algorithm_strength"}, rows
		}},
	"algorithm-sunset": {Title: "Algorithm sunset", Formats: []string{"csv", "xlsx"},
		table: func(in scheduledReportInputs) ([]string, [][]string) {
			r := computeAlgorithmSunset(in.certs)
			rows := make([][]string, 0, len(r.Groups))
			for _, g := range r.Groups {
				rows = append(rows, []string{g.ID, g.Algorithm, g.Deadline, g.Standard, g.Status, g.Urgency,
					strconv.Itoa(g.Count), g.Recommended})
			}
			return []string{"group", "algorithm", "deadline", "standard", "status", "urgency", "count", "recommended_replacement"}, rows
		}},
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scheduledReportNames returns the catalog keys in a stable order.
func scheduledReportNames() []string {
	out := make([]string, 0, len(reportScheduleCatalog))
	for k := range reportScheduleCatalog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func scheduledReportNameList() string {
	names := scheduledReportNames()
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}
