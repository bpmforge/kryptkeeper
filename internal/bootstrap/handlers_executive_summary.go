// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// ExecutiveSummary is a one-page, board-readable snapshot of certificate
// posture, compliance, automation, and risk — composed from the existing
// crypto-posture and compliance-evidence computes.
type ExecutiveSummary struct {
	GeneratedAt           string               `json:"generated_at"`
	Org                   string               `json:"org"`
	TotalCerts            int                  `json:"total_certs"`
	PQCScorePercent       int                  `json:"pqc_score_percent"`
	QuantumSafePercent    int                  `json:"quantum_safe_percent"`
	AutomationPercent     int                  `json:"automation_percent"`
	CompliancePassPercent int                  `json:"compliance_pass_percent"`
	Compliance            ComplianceSummary    `json:"compliance"`
	Expired               int                  `json:"expired"`
	Expiring47d           int                  `json:"expiring_47d"`
	ExpiryUnknown         int                  `json:"expiry_unknown"`
	RiskCritical          int                  `json:"risk_critical"`
	RiskHigh              int                  `json:"risk_high"`
	TopRisks              []string             `json:"top_risks"`
	Findings              FindingFunnelSummary `json:"findings"`
}

// computeExecutiveSummary aggregates posture + compliance into a one-pager.
// activeExceptions (W2-12) is the same bulk active-exception read the
// crypto-posture report uses — threading it through computeCryptoPostureReport
// keeps the one-pager's Findings funnel effective/suppressed rather than
// raw==effective.
func computeExecutiveSummary(ctx context.Context, certs []CertificateItem, cas []CAListItem, activeExceptions []FindingException) ExecutiveSummary {
	posture := computeCryptoPostureReport(certs, activeExceptions)
	compliance := computeComplianceEvidence(certs, cas, "all")

	total := compliance.Summary.Pass + compliance.Summary.Warn + compliance.Summary.Fail
	passPct := 0
	if total > 0 {
		passPct = compliance.Summary.Pass * 100 / total
	}

	sum := ExecutiveSummary{
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
		Org:                   orgName(),
		TotalCerts:            posture.TotalCerts,
		PQCScorePercent:       posture.PQCReadiness.PQCScorePercent,
		QuantumSafePercent:    posture.PQCReadiness.QuantumSafePercent,
		AutomationPercent:     posture.AutomationCoverage.AutomationPercent,
		CompliancePassPercent: passPct,
		Compliance:            compliance.Summary,
		Expired:               posture.ExpiryBuckets.Expired,
		Expiring47d:           posture.ExpiryBuckets.Expiring47d,
		ExpiryUnknown:         posture.ExpiryBuckets.Unknown,
		RiskCritical:          posture.RiskBreakdown.Critical,
		RiskHigh:              posture.RiskBreakdown.High,
		Findings:              posture.Findings,
	}
	sum.TopRisks = executiveTopRisks(sum)
	return sum
}

// executiveTopRisks produces the headline risk statements for the one-pager.
func executiveTopRisks(s ExecutiveSummary) []string {
	var risks []string
	if s.Expired > 0 {
		risks = append(risks, fmt.Sprintf("%d certificate(s) have already expired and need immediate renewal.", s.Expired))
	}
	if s.Expiring47d > 0 {
		risks = append(risks, fmt.Sprintf("%d certificate(s) expire within 47 days (the new CA/B Forum cliff).", s.Expiring47d))
	}
	if s.ExpiryUnknown > 0 {
		risks = append(risks, fmt.Sprintf("%d certificate(s) have no readable expiry date and cannot be monitored.", s.ExpiryUnknown))
	}
	if s.Compliance.Fail > 0 {
		risks = append(risks, fmt.Sprintf("%d compliance control(s) are failing and require remediation.", s.Compliance.Fail))
	}
	if s.RiskCritical > 0 {
		risks = append(risks, fmt.Sprintf("%d certificate(s) carry a critical risk score.", s.RiskCritical))
	}
	if s.PQCScorePercent < 50 {
		risks = append(risks, fmt.Sprintf("Post-quantum readiness is %d%% — below the halfway mark to the 2030 deadline.", s.PQCScorePercent))
	}
	if s.AutomationPercent < 80 {
		risks = append(risks, fmt.Sprintf("Renewal automation covers %d%% of the fleet; manual certs are the top outage risk.", s.AutomationPercent))
	}
	if len(risks) == 0 {
		risks = append(risks, "No material certificate risks detected. Posture is healthy.")
	}
	return risks
}

// registerExecutiveSummaryHandler mounts GET /api/v1/reports/executive-summary
// (?format=pdf for the branded one-pager, JSON otherwise for the dashboard tile).
func registerExecutiveSummaryHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, caProvider CAProvider, findingExceptionStore FindingExceptionStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/executive-summary", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.executive_summary", "report", "executive-summary", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.executive_summary", "report", "executive-summary", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		certs := reportScopeCertificates(r.Context(), pd, result.Items)
		cas, err := caProvider.ListCAs(r.Context(), CAListQuery{Limit: 1000})
		if err != nil {
			// The compliance block embeds CA-health controls; a summary built
			// without the CA list would present them as complete.
			emitAuditEvent(r, auditProvider, pd.ID, "report.executive_summary", "report", "executive-summary", AuditOutcomeFailure)
			log.Printf("executive summary: list CAs: %v", err)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		summary := computeExecutiveSummary(r.Context(), certs, reportScopeCAs(r.Context(), pd, cas.Items), activeFindingExceptions(r.Context(), findingExceptionStore))

		if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) == "pdf" {
			pdfBytes, perr := renderExecutiveSummaryPDF(summary, time.Now().UTC())
			if perr != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "report.executive_summary", "report", "executive-summary", AuditOutcomeFailure)
				log.Printf("executive summary pdf: %v", perr)
				writeServiceUnavailable(w, "pdf unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "report.executive_summary_pdf", "report", "executive-summary", AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="executive-summary-%s.pdf"`, time.Now().UTC().Format("2006-01-02")))
			_, _ = w.Write(pdfBytes)
			return
		}

		emitAuditEvent(r, auditProvider, pd.ID, "report.executive_summary", "report", "executive-summary", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data ExecutiveSummary `json:"data"`
		}{Data: summary})
	})
}
