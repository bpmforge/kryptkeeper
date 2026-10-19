// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// PQCDeadline is a regulatory PQC milestone with time remaining.
type PQCDeadline struct {
	Name          string `json:"name"`
	Date          string `json:"date"`
	DaysRemaining int    `json:"days_remaining"`
	Passed        bool   `json:"passed"`
}

// PQCTrendPoint is one daily PQC-readiness sample for the progress chart.
type PQCTrendPoint struct {
	CapturedAt      string `json:"captured_at"`
	PQCScorePercent int    `json:"pqc_score_percent"`
}

// PQCCountdownReport is the "proof of progress" artifact: where PQC readiness
// stands against the CNSA 2.0 / NIST 800-131A deadlines, trending over time.
type PQCCountdownReport struct {
	GeneratedAt         string               `json:"generated_at"`
	Org                 string               `json:"org"`
	TotalCerts          int                  `json:"total_certs"`
	Vulnerable          int                  `json:"vulnerable"`
	MigrationReady      int                  `json:"migration_ready"`
	QuantumSafe         int                  `json:"quantum_safe"`
	QuantumSafeLeafOnly int                  `json:"quantum_safe_leaf_only"` // G-70/D-104: leaf key is PQC, issuing chain is still classical
	PQCScorePercent     int                  `json:"pqc_score_percent"`
	QuantumSafePercent  int                  `json:"quantum_safe_percent"`
	Status              string               `json:"status"` // complete | on_track | at_risk | behind
	Deadlines           []PQCDeadline        `json:"deadlines"`
	Trend               []PQCTrendPoint      `json:"trend"`
	Waves               []WaveProgress       `json:"waves"`
	Findings            FindingFunnelSummary `json:"findings"`
}

// pqcDeadlines returns the regulatory PQC milestones relative to now.
func pqcDeadlines(now time.Time) []PQCDeadline {
	defs := []struct {
		name string
		date time.Time
	}{
		{"CNSA 2.0 — software/firmware signing", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"NIST SP 800-131A — RSA-2048/ECC-224 disallowed", time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"CNSA 2.0 — all national security systems", time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	out := make([]PQCDeadline, 0, len(defs))
	for _, d := range defs {
		days := int(d.date.Sub(now).Hours() / 24)
		out = append(out, PQCDeadline{
			Name:          d.name,
			Date:          d.date.Format("2006-01-02"),
			DaysRemaining: days,
			Passed:        days < 0,
		})
	}
	return out
}

// pqcStatus assesses migration health from readiness. "complete" is
// reserved for a fleet with zero classical exposure anywhere -- not just
// zero fully-vulnerable certs, but zero quantum_safe_leaf_only certs
// either. A leaf-only cert's chain remains classically forgeable (G-70/
// D-104); reporting "complete" while any exist would be the same
// false-safety-record class D-104 was resolved to prevent, one layer above
// the per-cert PQCReadiness field -- PQCScorePercent still gives leaf-only
// certs partial credit as real progress, but the strongest headline claim
// stays reserved for actual chain-level safety.
func pqcStatus(vulnerable, leafOnly, pqcScore int) string {
	switch {
	case vulnerable == 0 && leafOnly == 0:
		return "complete"
	case pqcScore >= 80:
		return "on_track"
	case pqcScore >= 40:
		return "at_risk"
	default:
		return "behind"
	}
}

// computePQCCountdown assembles the countdown report from posture, snapshots,
// waves. activeExceptions (W2-12) is the same bulk active-exception read the
// crypto-posture report uses — threading it through computeCryptoPostureReport
// keeps the countdown's Findings funnel effective/suppressed rather than
// raw==effective.
func computePQCCountdown(ctx context.Context, certs []CertificateItem, snapshots []PostureSnapshot, waves []WaveProgress, now time.Time, activeExceptions []FindingException) PQCCountdownReport {
	posture := computeCryptoPostureReport(certs, activeExceptions)
	report := PQCCountdownReport{
		GeneratedAt:         now.Format(time.RFC3339),
		Org:                 orgName(),
		TotalCerts:          posture.TotalCerts,
		Vulnerable:          posture.PQCReadiness.Vulnerable,
		MigrationReady:      posture.PQCReadiness.MigrationReady,
		QuantumSafe:         posture.PQCReadiness.QuantumSafe,
		QuantumSafeLeafOnly: posture.PQCReadiness.QuantumSafeLeafOnly,
		PQCScorePercent:     posture.PQCReadiness.PQCScorePercent,
		QuantumSafePercent:  posture.PQCReadiness.QuantumSafePercent,
		Deadlines:           pqcDeadlines(now),
		Waves:               waves,
		Trend:               []PQCTrendPoint{},
		Findings:            posture.Findings,
	}
	report.Status = pqcStatus(report.Vulnerable, report.QuantumSafeLeafOnly, report.PQCScorePercent)
	for _, s := range snapshots {
		report.Trend = append(report.Trend, PQCTrendPoint{
			CapturedAt:      s.CapturedAt,
			PQCScorePercent: s.PQCScorePercent,
		})
	}
	return report
}

// registerPQCCountdownHandler mounts GET /api/v1/reports/pqc-countdown
// (?format=pdf for the branded proof artifact, JSON otherwise).
func registerPQCCountdownHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, snapshotStore PostureSnapshotStore, waveStore MigrationWaveStore, findingExceptionStore FindingExceptionStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/pqc-countdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.pqc_countdown", "report", "pqc-countdown", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// W2-03/D-102: the countdown mixes cert-derived counts with fleet-wide
		// posture-snapshot trend + migration-wave series that have no
		// per-tenant breakdown — scoping only the cert half would produce a
		// self-contradictory report (tenant-scoped totals next to fleet-wide
		// trend/waves), so the whole artifact is aggregate-super-admin-only.
		if denyAggregateReportForTenantScoped(w, pd) {
			emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_countdown", "report", "pqc-countdown", AuditOutcomeDenied)
			return
		}
		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_countdown", "report", "pqc-countdown", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		now := time.Now().UTC()

		var snapshots []PostureSnapshot
		if snapshotStore != nil {
			since := now.AddDate(0, 0, -180).Format(time.RFC3339)
			snapshots, _ = snapshotStore.List(r.Context(), since, 365)
		}
		var waves []WaveProgress
		if waveStore != nil {
			if list, err := waveStore.ListWaves(r.Context()); err == nil {
				waves = computeWaveProgress(list, waveCurrentReadiness(result.Items))
			}
		}

		report := computePQCCountdown(r.Context(), result.Items, snapshots, waves, now, activeFindingExceptions(r.Context(), findingExceptionStore))

		if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) == "pdf" {
			pdfBytes, perr := renderPQCCountdownPDF(report, now)
			if perr != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_countdown", "report", "pqc-countdown", AuditOutcomeFailure)
				logging.Infof("pqc countdown pdf: %v", perr)
				writeServiceUnavailable(w, "pdf unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_countdown_pdf", "report", "pqc-countdown", AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="pqc-countdown-%s.pdf"`, now.Format("2006-01-02")))
			_, _ = w.Write(pdfBytes)
			return
		}

		emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_countdown", "report", "pqc-countdown", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data PQCCountdownReport `json:"data"`
		}{Data: report}); err != nil {
			logging.Warnf("failed to encode pqc countdown: %v", err)
		}
	})
}
