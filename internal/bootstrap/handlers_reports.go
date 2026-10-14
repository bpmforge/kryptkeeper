// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/pqc"
)

// CryptoPostureReport is the response body for GET /api/v1/reports/crypto-posture.
type CryptoPostureReport struct {
	GeneratedAt        string                    `json:"generated_at"`
	TotalCerts         int                       `json:"total_certs"`
	AlgorithmBreakdown map[string]int            `json:"algorithm_breakdown"`
	PQCReadiness       PQCReadinessSummary       `json:"pqc_readiness"`
	ExpiryBuckets      ExpiryBucketSummary       `json:"expiry_buckets"`
	GradeDistribution  map[string]int            `json:"grade_distribution"`
	AutomationCoverage AutomationCoverageSummary `json:"automation_coverage"`
	RiskBreakdown      RiskBreakdownSummary      `json:"risk_breakdown"`
	Findings           FindingFunnelSummary      `json:"findings"`
}

// FindingFunnelSummary is raw/effective/suppressed finding counts for a
// report surface — see docs/design/FINDING_ECONOMICS.md. This is NOT the
// full five-stage funnel (raw → dedup → scope → applicability → effective →
// suppressed) that doc describes: persisted dedup identity, tenant scope
// filtering, and applicability re-checks are explicitly out of scope for
// this ticket (W2-11) and remain future work. Raw is every finding the
// source layer produces on every read, with no dedup or identity. Effective
// is raw minus every finding that currently carries an active accepted-risk
// exception (FindingException/W2-06). Suppressed is that subtracted count,
// reported alongside raw and effective rather than hidden behind them —
// raw is never replaced or omitted.
//
// GET /api/v1/reports/crypto-posture (computeCryptoPostureReport), the
// executive summary, the PQC countdown, and every persisted GET
// /reports/crypto-posture/trend snapshot are all exception-aware as of
// W2-12 — each surface threads its own active-exception read into
// computeCryptoPostureReport rather than the exception-blind
// computeCryptoPosture wrapper. See computeCryptoPosture's doc comment for
// why that wrapper still exists (other callers outside bootstrap's report
// surfaces still use it, always raw==effective by design there).
type FindingFunnelSummary struct {
	Raw        int `json:"raw"`
	Effective  int `json:"effective"`
	Suppressed int `json:"suppressed"`
}

type PQCReadinessSummary struct {
	QuantumSafe         int `json:"quantum_safe"`
	QuantumSafeLeafOnly int `json:"quantum_safe_leaf_only"` // G-70/D-104: leaf key is PQC, issuing chain is still classical
	MigrationReady      int `json:"migration_ready"`
	Vulnerable          int `json:"vulnerable"`
	NotApplicable       int `json:"not_applicable"`
	// Definitions live on pqc.ReadinessTally: PQCScorePercent ("PQC
	// readiness") = (quantum_safe + leaf_only + migration_ready) / total;
	// QuantumSafePercent = full-chain quantum_safe / total. A leaf-only cert
	// is progress but not quantum-safe (its chain is still classically
	// forgeable), and an all-ECDSA estate can read 100% readiness, so both
	// numbers are always shown together.
	PQCScorePercent    int `json:"pqc_score_percent"`
	QuantumSafePercent int `json:"quantum_safe_percent"`
}

type ExpiryBucketSummary struct {
	Expired      int `json:"expired"`
	Expiring47d  int `json:"expiring_47d"`
	Expiring90d  int `json:"expiring_90d"`
	Expiring200d int `json:"expiring_200d"`
	Expiring1yr  int `json:"expiring_1yr"`
	// Unknown counts certs whose ValidUntil is empty or unparseable, so they
	// are visible instead of vanishing from every bucket (same rule as
	// tallyExpiry for compliance).
	Unknown int `json:"unknown"`
}

type AutomationCoverageSummary struct {
	Automated         int `json:"automated"`
	Manual            int `json:"manual"`
	AutomationPercent int `json:"automation_percent"`
}

type RiskBreakdownSummary struct {
	Critical int `json:"critical"` // risk_score > 70
	High     int `json:"high"`     // risk_score 40-70
	Medium   int `json:"medium"`   // risk_score 20-40
	Low      int `json:"low"`      // risk_score <= 20
}

// reportCertificateCeiling bounds how many certificates one report will hold
// in memory. It is far above the stated scale (50k) so it never shapes a real
// report; reaching it is logged by reportVisibleCertificates.
const reportCertificateCeiling = 1_000_000

// reportVisibleCertificates fetches up to limit certificates and narrows
// them to exactly what this principal's own GET /api/v1/certificates would
// show: the same TeamID ownership rule non-admin principals go through
// there (authorizeCertificateListQuery, handlers_certificates.go), then the
// existing tenant scope (reportScopeCertificates). Every certificate-based
// report call site used to fetch the whole fleet and apply only the tenant
// filter, so a non-admin principal's reports counted certificates their own
// inventory view refuses to display (S-45) — e.g. crypto-posture and
// expiry-timeline both counting a certificate GET /api/v1/certificates never
// lists for that caller. Routing through authorizeCertificateListQuery
// itself (rather than re-deriving the same TeamID comparison here) means the
// two paths agree by construction: they can't drift independently.
//
// ListCertificates is the HTTP page API and clamps to 100 rows, so it cannot
// back a report; this walks the whole inventory with ForEachCertificate
// instead (H2/H3), a single pass rather than one copy+sort per page.
func reportVisibleCertificates(ctx context.Context, pd AuthPrincipal, certProvider CertificateProvider, limit int) ([]CertificateItem, error) {
	query := CertificateListQuery{Limit: limit}
	// S-63: a forbidden verdict must reject the query — the helper returns
	// errCertificateForbidden WITHOUT clearing TeamID, so a discarded error
	// here would aggregate another team's certificates the moment a caller
	// threads a team filter through.
	if err := authorizeCertificateListQuery(&query, pd); err != nil {
		return nil, err
	}

	result, err := listAllCertificates(ctx, certProvider, query)
	if err != nil {
		return nil, err
	}
	items := result.Items
	if len(items) > limit {
		// A ceiling is a memory guard, not a report scope: say so loudly so a
		// truncated report is never mistaken for a complete one.
		log.Printf("report: inventory has %d certificates, truncating to the %d-row ceiling", len(items), limit)
		items = items[:limit]
	}
	return reportScopeCertificates(ctx, pd, items), nil
}

func registerReportsHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, caProvider CAProvider, templateProvider TemplateProvider, keys keystore.Store, auditProvider AuditProvider) {
	// W2-11: constructed here (not threaded through this function's
	// signature) to match the pqcWaveStore/pqcSnapshotStore precedent
	// below — RegisterHandlers/registerReportsHandlers' call sites live
	// outside this ticket's write_scope, so the store is self-constructed
	// from env like every other *FromEnv store in this file. A nil store
	// (env misconfigured) degrades to an empty active-exception set rather
	// than failing the whole report.
	findingExceptionStore, _ := newFindingExceptionStoreFromEnv()

	mux.HandleFunc("/api/v1/reports/crypto-posture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.crypto_posture", "report", "crypto-posture", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		// Aggregate over the whole visible inventory, up to reportCertificateCeiling.
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.crypto_posture", "report", "crypto-posture", AuditOutcomeFailure)
			log.Printf("crypto posture report: list certs: %v", err)
			writeServiceUnavailable(w, "report unavailable")
			return
		}

		format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
		if format == "csv" {
			emitAuditEvent(r, auditProvider, pd.ID, "report.crypto_posture", "report", "crypto-posture", AuditOutcomeSuccess)
			writeCryptoPostureCSV(w, items)
			return
		}

		report := computeCryptoPostureReport(items, activeFindingExceptions(r.Context(), findingExceptionStore))
		emitAuditEvent(r, auditProvider, pd.ID, "report.crypto_posture", "report", "crypto-posture", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data CryptoPostureReport `json:"data"`
		}{Data: report}); err != nil {
			log.Printf("failed to encode crypto posture report: %v", err)
		}
	})

	// S5-07: CA Health Report
	mux.HandleFunc("/api/v1/reports/ca-health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.ca_health", "report", "ca-health", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		cas, err := caProvider.ListCAs(r.Context(), CAListQuery{Limit: 1000})
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.ca_health", "report", "ca-health", AuditOutcomeFailure)
			log.Printf("ca health report: list CAs: %v", err)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		report := computeCAHealth(reportScopeCAs(r.Context(), pd, cas.Items))
		emitAuditEvent(r, auditProvider, pd.ID, "report.ca_health", "report", "ca-health", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data CAHealthReport `json:"data"`
		}{Data: report})
	})

	// S5-08: Expiry Timeline Report
	mux.HandleFunc("/api/v1/reports/expiry-timeline", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.expiry_timeline", "report", "expiry-timeline", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.expiry_timeline", "report", "expiry-timeline", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		report := computeExpiryTimeline(items)
		emitAuditEvent(r, auditProvider, pd.ID, "report.expiry_timeline", "report", "expiry-timeline", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data ExpiryTimelineReport `json:"data"`
		}{Data: report})
	})

	// S5-09: Revocation Activity Report
	mux.HandleFunc("/api/v1/reports/revocation-activity", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.revocation_activity", "report", "revocation-activity", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.revocation_activity", "report", "revocation-activity", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		// Parse optional time window from query params (defaults to 30 days).
		days := 30
		if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
			if n, err2 := strconv.Atoi(raw); err2 == nil && n > 0 && n <= 365 {
				days = n
			}
		}
		report := computeRevocationActivity(items, days)
		emitAuditEvent(r, auditProvider, pd.ID, "report.revocation_activity", "report", "revocation-activity", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data RevocationActivityReport `json:"data"`
		}{Data: report})
	})

	// Task 27: Issuance Velocity Report
	mux.HandleFunc("/api/v1/reports/issuance-velocity", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.issuance_velocity", "report", "issuance-velocity", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.issuance_velocity", "report", "issuance-velocity", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		report := computeIssuanceVelocity(items)
		emitAuditEvent(r, auditProvider, pd.ID, "report.issuance_velocity", "report", "issuance-velocity", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data IssuanceVelocityReport `json:"data"`
		}{Data: report})
	})

	// Task 28: Change Audit Report
	mux.HandleFunc("/api/v1/reports/change-audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.change_audit", "report", "change-audit", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		days := 30
		if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
			if n, err2 := strconv.Atoi(raw); err2 == nil && n > 0 && n <= 365 {
				days = n
			}
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
		fp := strings.TrimSpace(r.URL.Query().Get("fingerprint"))

		query := AuditListQuery{
			Limit: 1000,
			Order: "desc",
			After: cutoff,
		}
		if fp != "" {
			query.ResourceID = fp
		}
		auditResult, err := auditProvider.ListEntries(r.Context(), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.change_audit", "report", "change-audit", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		report := computeChangeAudit(reportScopeAuditEntries(pd, auditResult.Entries), days, fp)
		emitAuditEvent(r, auditProvider, pd.ID, "report.change_audit", "report", "change-audit", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data ChangeAuditReport `json:"data"`
		}{Data: report})
	})

	// Task 29: Compliance Evidence Report
	mux.HandleFunc("/api/v1/reports/compliance-evidence", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.compliance_evidence", "report", "compliance-evidence", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		framework := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("framework")))
		if framework == "" {
			framework = "all"
		}
		certs, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.compliance_evidence", "report", "compliance-evidence", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		cas, err := caProvider.ListCAs(r.Context(), CAListQuery{Limit: 1000})
		if err != nil {
			// Controls such as INTERNAL-CA-HEALTH are computed from the CA
			// list; building the report without it would present "no active
			// CAs" or a pass as if it were evidence.
			emitAuditEvent(r, auditProvider, pd.ID, "report.compliance_evidence", "report", "compliance-evidence", AuditOutcomeFailure)
			log.Printf("compliance evidence: list CAs: %v", err)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		cas.Items = reportScopeCAs(r.Context(), pd, cas.Items)
		report := computeComplianceEvidence(certs, cas.Items, framework)

		// PDF evidence pack (v1.4): branded, auditor-ready.
		if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) == "pdf" {
			pdfBytes, perr := renderComplianceEvidencePDF(report, len(certs), time.Now().UTC())
			if perr != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "report.compliance_evidence", "report", "compliance-evidence", AuditOutcomeFailure)
				log.Printf("compliance evidence pdf: %v", perr)
				writeServiceUnavailable(w, "pdf unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "report.compliance_evidence_pdf", "report", "compliance-evidence", AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="compliance-%s-%s.pdf"`, framework, time.Now().UTC().Format("2006-01-02")))
			_, _ = w.Write(pdfBytes)
			return
		}

		emitAuditEvent(r, auditProvider, pd.ID, "report.compliance_evidence", "report", "compliance-evidence", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data ComplianceEvidenceReport `json:"data"`
		}{Data: report})
	})

	// Task 34: Algorithm Sunset Report
	mux.HandleFunc("/api/v1/reports/algorithm-sunset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.algorithm_sunset", "report", "algorithm-sunset", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.algorithm_sunset", "report", "algorithm-sunset", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		report := computeAlgorithmSunset(items)
		emitAuditEvent(r, auditProvider, pd.ID, "report.algorithm_sunset", "report", "algorithm-sunset", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data AlgorithmSunsetReport `json:"data"`
		}{Data: report})
	})

	// v1.4: executive one-pager (JSON tile + branded PDF).
	registerExecutiveSummaryHandler(mux, auth, certProvider, caProvider, findingExceptionStore, auditProvider)

	// v1.5: PQC migration roadmap + migration waves + countdown/proof.
	registerPQCMigrationHandler(mux, auth, certProvider, auditProvider)
	pqcWaveStore := NewMigrationWaveStoreFromEnv()
	registerPQCWaveHandlers(mux, auth, certProvider, templateProvider, pqcWaveStore, keys, auditProvider)
	pqcSnapshotStore, _ := NewPostureSnapshotStoreFromEnv()
	registerPQCCountdownHandler(mux, auth, certProvider, pqcSnapshotStore, pqcWaveStore, findingExceptionStore, auditProvider)
}

// activeFindingExceptions fetches the bulk active-exception set a finding
// funnel needs. A nil store (env misconfigured) or a read error yields an
// empty set — a report degrades to raw==effective rather than failing.
func activeFindingExceptions(ctx context.Context, store FindingExceptionStore) []FindingException {
	if store == nil {
		return nil
	}
	active, err := store.ListActive(ctx, time.Now())
	if err != nil {
		log.Printf("finding exceptions unavailable, funnel will report raw==effective: %v", err)
		return nil
	}
	return active
}

// computeCryptoPosture is the exception-blind convenience wrapper: always
// raw==effective, for callers that have no active-exception set to pass
// (tests, and any future posture-shaped surface that hasn't been wired to a
// FindingExceptionStore yet). Every report surface that ships in the
// product — crypto-posture, executive summary, PQC countdown, and posture
// snapshots (posture_scheduler.go, persisted and served back by
// GET /reports/crypto-posture/trend) — calls computeCryptoPostureReport
// directly with its own active-exception read instead, as of W2-12.
func computeCryptoPosture(_ context.Context, certs []CertificateItem) CryptoPostureReport {
	return computeCryptoPostureReport(certs, nil)
}

func computeCryptoPostureReport(certs []CertificateItem, activeExceptions []FindingException) CryptoPostureReport {
	now := time.Now().UTC()

	report := CryptoPostureReport{
		GeneratedAt:        now.Format(time.RFC3339),
		TotalCerts:         len(certs),
		AlgorithmBreakdown: make(map[string]int),
		GradeDistribution:  make(map[string]int),
	}

	exceptionIdx := findingExceptionIndex(activeExceptions)

	var pqcTally pqc.ReadinessTally
	for _, cert := range certs {
		// Algorithm breakdown.
		algo := cert.PublicKeyAlgorithm
		if algo == "" {
			algo = "Unknown"
		}
		report.AlgorithmBreakdown[algo]++

		pqcTally.Add(cert.PQCReadiness)

		// Expiry buckets.
		if t, err := time.Parse(time.RFC3339, cert.ValidUntil); err != nil {
			report.ExpiryBuckets.Unknown++
		} else {
			remaining := t.Sub(now)
			switch {
			case remaining <= 0:
				report.ExpiryBuckets.Expired++
			case remaining <= 47*24*time.Hour:
				report.ExpiryBuckets.Expiring47d++
			case remaining <= 90*24*time.Hour:
				report.ExpiryBuckets.Expiring90d++
			case remaining <= 200*24*time.Hour:
				report.ExpiryBuckets.Expiring200d++
			case remaining <= 365*24*time.Hour:
				report.ExpiryBuckets.Expiring1yr++
			}
		}

		// Grade distribution.
		grade := cert.Grade
		if grade == "" {
			grade = "Unknown"
		}
		report.GradeDistribution[grade]++

		// Automation coverage.
		if cert.RenewalMethod == "acme" || cert.RenewalMethod == "est" || cert.RenewalMethod == "scep" {
			report.AutomationCoverage.Automated++
		} else {
			report.AutomationCoverage.Manual++
		}

		// Risk breakdown.
		switch {
		case cert.RiskScore > 70:
			report.RiskBreakdown.Critical++
		case cert.RiskScore > 40:
			report.RiskBreakdown.High++
		case cert.RiskScore > 20:
			report.RiskBreakdown.Medium++
		default:
			report.RiskBreakdown.Low++
		}

		// Finding funnel (W2-11): raw is every computeRiskFlags flag this
		// certificate carries today, no dedup — see FindingFunnelSummary's
		// doc comment for why this isn't the full five-stage funnel.
		for _, flag := range cert.RiskFlags {
			report.Findings.Raw++
			if exceptionIdx[findingExceptionKey(FindingExceptionTargetCertificate, cert.FingerprintSHA256, flag)] {
				report.Findings.Suppressed++
			}
		}
	}
	report.Findings.Effective = report.Findings.Raw - report.Findings.Suppressed

	pqcTally.Finalize(report.TotalCerts)
	report.PQCReadiness.QuantumSafe = pqcTally.QuantumSafe
	report.PQCReadiness.QuantumSafeLeafOnly = pqcTally.QuantumSafeLeafOnly
	report.PQCReadiness.MigrationReady = pqcTally.MigrationReady
	report.PQCReadiness.Vulnerable = pqcTally.Vulnerable
	report.PQCReadiness.NotApplicable = pqcTally.NotApplicable
	report.PQCReadiness.PQCScorePercent = pqcTally.PQCScorePercent
	report.PQCReadiness.QuantumSafePercent = pqcTally.QuantumSafePercent

	if report.TotalCerts > 0 {
		automated := report.AutomationCoverage.Automated
		report.AutomationCoverage.AutomationPercent = automated * 100 / report.TotalCerts
	}

	return report
}

func writeCryptoPostureCSV(w http.ResponseWriter, certs []CertificateItem) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="crypto-posture-%s.csv"`, time.Now().UTC().Format("2006-01-02")))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"fingerprint_sha256", "common_name", "ca_id", "template_id",
		"public_key_algorithm", "key_size_bits", "signature_algorithm",
		"valid_from", "valid_until", "pqc_readiness", "risk_score", "grade",
		"renewal_method", "renewal_status", "revoked_at",
	})
	for _, c := range certs {
		revokedAt := ""
		if c.RevokedAt != nil {
			revokedAt = *c.RevokedAt
		}
		_ = cw.Write([]string{
			c.FingerprintSHA256,
			c.CommonName,
			c.CAID,
			c.TemplateID,
			c.PublicKeyAlgorithm,
			strconv.Itoa(c.KeySizeBits),
			c.SignatureAlgorithm,
			c.ValidFrom,
			c.ValidUntil,
			c.PQCReadiness,
			strconv.Itoa(c.RiskScore),
			c.Grade,
			c.RenewalMethod,
			c.RenewalStatus,
			revokedAt,
		})
	}
	cw.Flush()
}

// --- S5-07: CA Health Report ---

// CAHealthReport is the response body for GET /api/v1/reports/ca-health.
type CAHealthReport struct {
	GeneratedAt string          `json:"generated_at"`
	TotalCAs    int             `json:"total_cas"`
	Items       []CAHealthEntry `json:"items"`
	Summary     CAHealthSummary `json:"summary"`
}

type CAHealthEntry struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Status            string `json:"status"`
	Algorithm         string `json:"algorithm"`
	ExpiresAt         string `json:"expires_at"`
	DaysUntilExpiry   int    `json:"days_until_expiry"`
	ChainDepth        int    `json:"chain_depth"`
	AlgorithmStrength string `json:"algorithm_strength"` // strong, acceptable, weak, sunset
}

type CAHealthSummary struct {
	Active          int `json:"active"`
	Expiring90d     int `json:"expiring_90d"`
	Expiring1yr     int `json:"expiring_1yr"`
	WeakAlgorithm   int `json:"weak_algorithm"`
	SunsetAlgorithm int `json:"sunset_algorithm"`
}

func computeCAHealth(cas []CAListItem) CAHealthReport {
	now := time.Now().UTC()
	report := CAHealthReport{
		GeneratedAt: now.Format(time.RFC3339),
		TotalCAs:    len(cas),
		Items:       make([]CAHealthEntry, 0, len(cas)),
	}

	for _, caItem := range cas {
		algo := ""
		validUntil := ""
		if caItem.Certificate != nil {
			algo = caItem.Certificate.PublicKeyAlg
			validUntil = caItem.Certificate.ValidUntil
		}
		status := caEffectiveStatus(caItem, now)
		entry := CAHealthEntry{
			ID:        caItem.ID,
			Name:      caItem.Name,
			Status:    status,
			Algorithm: algo,
		}

		// Parse expiry from nested cert.
		if validUntil != "" {
			if t, err := time.Parse(time.RFC3339, validUntil); err == nil {
				entry.ExpiresAt = validUntil
				days := int(t.Sub(now).Hours() / 24)
				entry.DaysUntilExpiry = days
				if days < 90 {
					report.Summary.Expiring90d++
				} else if days < 365 {
					report.Summary.Expiring1yr++
				}
			}
		}

		// Algorithm strength classification.
		switch {
		case strings.Contains(algo, "ML-DSA") || strings.Contains(algo, "Ed25519"):
			entry.AlgorithmStrength = "strong"
		case strings.Contains(algo, "P-384") || strings.Contains(algo, "P384") ||
			strings.Contains(algo, "RSA-4096") || strings.Contains(algo, "rsa4096"):
			entry.AlgorithmStrength = "acceptable"
		case strings.Contains(algo, "SHA1") || strings.Contains(algo, "MD5"):
			entry.AlgorithmStrength = "weak"
			report.Summary.WeakAlgorithm++
		default:
			entry.AlgorithmStrength = "acceptable"
		}
		if strings.Contains(algo, "RSA-2048") || strings.Contains(algo, "rsa2048") ||
			(strings.Contains(algo, "P-256") && now.After(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))) {
			entry.AlgorithmStrength = "sunset"
			report.Summary.SunsetAlgorithm++
		}

		if status == "active" {
			report.Summary.Active++
		}
		report.Items = append(report.Items, entry)
	}
	return report
}

// --- S5-08: Expiry Timeline Report ---

// ExpiryTimelineReport is the response body for GET /api/v1/reports/expiry-timeline.
type ExpiryTimelineReport struct {
	GeneratedAt string              `json:"generated_at"`
	TotalCerts  int                 `json:"total_certs"`
	Buckets     []ExpiryBucketEntry `json:"buckets"`
	// UnknownExpiry counts certs with an empty or unparseable ValidUntil;
	// they fall in no bucket and are excluded from by_ca / by_owner_team.
	UnknownExpiry int            `json:"unknown_expiry"`
	ByCA          map[string]int `json:"by_ca"`
	ByOwnerTeam   map[string]int `json:"by_owner_team"`
}

type ExpiryBucketEntry struct {
	Label    string `json:"label"`
	DaysFrom int    `json:"days_from"`
	DaysTo   int    `json:"days_to"`
	Count    int    `json:"count"`
}

func computeExpiryTimeline(certs []CertificateItem) ExpiryTimelineReport {
	now := time.Now().UTC()
	report := ExpiryTimelineReport{
		GeneratedAt: now.Format(time.RFC3339),
		TotalCerts:  len(certs),
		ByCA:        make(map[string]int),
		ByOwnerTeam: make(map[string]int),
	}

	bucketDefs := []struct {
		label string
		from  int
		to    int
	}{
		{"Expired", -9999, 0},
		{"0–7 days", 0, 7},
		{"7–30 days", 7, 30},
		{"30–47 days", 30, 47},
		{"47–90 days", 47, 90},
		{"90–200 days", 90, 200},
		{"200–397 days", 200, 397},
		{"397+ days", 397, 9999},
	}

	buckets := make([]ExpiryBucketEntry, len(bucketDefs))
	for i, d := range bucketDefs {
		buckets[i] = ExpiryBucketEntry{Label: d.label, DaysFrom: d.from, DaysTo: d.to}
	}

	for _, cert := range certs {
		t, err := time.Parse(time.RFC3339, cert.ValidUntil)
		if err != nil {
			report.UnknownExpiry++
			continue
		}
		days := int(t.Sub(now).Hours() / 24)

		for i, d := range bucketDefs {
			if days >= d.from && days < d.to {
				buckets[i].Count++
				break
			}
		}

		caKey := cert.CAID
		if caKey == "" {
			caKey = "unknown"
		}
		report.ByCA[caKey]++

		team := cert.OwnerTeam
		if team == "" {
			team = "unassigned"
		}
		report.ByOwnerTeam[team]++
	}

	report.Buckets = buckets
	return report
}

// --- S5-09: Revocation Activity Report ---

// RevocationActivityReport is the response body for GET /api/v1/reports/revocation-activity.
type RevocationActivityReport struct {
	GeneratedAt       string             `json:"generated_at"`
	WindowDays        int                `json:"window_days"`
	TotalRevoked      int                `json:"total_revoked"`
	ByReasonCode      map[string]int     `json:"by_reason_code"`
	ByCA              map[string]int     `json:"by_ca"`
	RecentRevocations []RevokedCertEntry `json:"recent_revocations"`
}

type RevokedCertEntry struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	CommonName        string `json:"common_name"`
	CAID              string `json:"ca_id"`
	RevokedAt         string `json:"revoked_at"`
	ReasonCode        int    `json:"reason_code"`
	ReasonLabel       string `json:"reason_label"`
	OwnerEmail        string `json:"owner_email,omitempty"`
	OwnerTeam         string `json:"owner_team,omitempty"`
}

var revocationReasonLabels = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "caCompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	6:  "certificateHold",
	9:  "privilegeWithdrawn",
	10: "aACompromise",
}

func computeRevocationActivity(certs []CertificateItem, windowDays int) RevocationActivityReport {
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -windowDays)

	report := RevocationActivityReport{
		GeneratedAt:       now.Format(time.RFC3339),
		WindowDays:        windowDays,
		ByReasonCode:      make(map[string]int),
		ByCA:              make(map[string]int),
		RecentRevocations: make([]RevokedCertEntry, 0),
	}

	for _, cert := range certs {
		if cert.RevokedAt == nil {
			continue
		}
		revokedTime, err := time.Parse(time.RFC3339, *cert.RevokedAt)
		if err != nil {
			continue
		}
		if revokedTime.Before(cutoff) {
			continue
		}
		report.TotalRevoked++

		reasonCode := 0
		if cert.RevocationReason != nil {
			reasonCode = *cert.RevocationReason
		}
		label, ok := revocationReasonLabels[reasonCode]
		if !ok {
			label = fmt.Sprintf("reason_%d", reasonCode)
		}
		report.ByReasonCode[label]++

		caKey := cert.CAID
		if caKey == "" {
			caKey = "unknown"
		}
		report.ByCA[caKey]++

		if len(report.RecentRevocations) < 100 {
			report.RecentRevocations = append(report.RecentRevocations, RevokedCertEntry{
				FingerprintSHA256: cert.FingerprintSHA256,
				CommonName:        cert.CommonName,
				CAID:              cert.CAID,
				RevokedAt:         *cert.RevokedAt,
				ReasonCode:        reasonCode,
				ReasonLabel:       label,
				OwnerEmail:        cert.OwnerEmail,
				OwnerTeam:         cert.OwnerTeam,
			})
		}
	}

	return report
}

// --- Task 27: Issuance Velocity Report ---

// IssuanceVelocityReport is the response body for GET /api/v1/reports/issuance-velocity.
type IssuanceVelocityReport struct {
	GeneratedAt          string                  `json:"generated_at"`
	TotalIssued          int                     `json:"total_issued"`
	Windows              IssuanceVelocityWindows `json:"windows"`
	DailyBuckets         []IssuanceDailyBucket   `json:"daily_buckets"`
	ByCA                 map[string]int          `json:"by_ca"`
	ByTeam               map[string]int          `json:"by_team"`
	ByTemplate           map[string]int          `json:"by_template"`
	AnomalyDays          []string                `json:"anomaly_days"` // days where count > 2× 30d average, only if sample >= min threshold
	AnomalyMinimumSample int                     `json:"anomaly_minimum_sample"`
	AnomalyThresholdNote string                  `json:"anomaly_threshold_note"`
}

type IssuanceVelocityWindows struct {
	Last7d  int `json:"last_7d"`
	Last30d int `json:"last_30d"`
	Last90d int `json:"last_90d"`
}

type IssuanceDailyBucket struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

func computeIssuanceVelocity(certs []CertificateItem) IssuanceVelocityReport {
	now := time.Now().UTC()
	report := IssuanceVelocityReport{
		GeneratedAt: now.Format(time.RFC3339),
		ByCA:        make(map[string]int),
		ByTeam:      make(map[string]int),
		ByTemplate:  make(map[string]int),
		AnomalyDays: make([]string, 0),
	}

	// Rolling window cutoffs.
	cut7 := now.AddDate(0, 0, -7)
	cut30 := now.AddDate(0, 0, -30)
	cut90 := now.AddDate(0, 0, -90)

	// Daily bucket map: date string (YYYY-MM-DD) → count.
	daily := make(map[string]int)

	for _, cert := range certs {
		ts := cert.CreatedAt
		if ts == "" {
			ts = cert.ValidFrom
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		report.TotalIssued++

		if t.After(cut7) {
			report.Windows.Last7d++
		}
		if t.After(cut30) {
			report.Windows.Last30d++
		}
		if t.After(cut90) {
			report.Windows.Last90d++
		}

		day := t.Format("2006-01-02")
		daily[day]++

		caKey := cert.CAID
		if caKey == "" {
			caKey = "unknown"
		}
		report.ByCA[caKey]++

		team := cert.TeamID
		if team == "" {
			team = "unassigned"
		}
		report.ByTeam[team]++

		tpl := cert.TemplateID
		if tpl == "" {
			tpl = "none"
		}
		report.ByTemplate[tpl]++
	}

	// Build sorted daily buckets for the last 90 days.
	for i := 89; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		report.DailyBuckets = append(report.DailyBuckets, IssuanceDailyBucket{Date: day, Count: daily[day]})
	}

	// Anomaly detection: only fire if sample size is sufficient.
	// Minimum sample of 5 certificates prevents false positives on small deployments.
	const anomalyMinSample = 5
	report.AnomalyMinimumSample = anomalyMinSample

	if report.Windows.Last30d >= anomalyMinSample {
		// Detect anomaly days: count > 2× 30d daily average.
		dailyAvg30 := float64(report.Windows.Last30d) / 30.0
		if dailyAvg30 > 0 {
			for day, count := range daily {
				if float64(count) > 2*dailyAvg30 {
					t, _ := time.Parse("2006-01-02", day)
					if t.After(cut30) {
						report.AnomalyDays = append(report.AnomalyDays, day)
					}
				}
			}
		}
		report.AnomalyThresholdNote = fmt.Sprintf("Anomalies detected when daily issuance > 2× the 30-day average (%.1f certs/day). Minimum sample of %d certs in 30-day window required.", dailyAvg30, anomalyMinSample)
	} else {
		report.AnomalyThresholdNote = fmt.Sprintf("Anomaly detection requires a minimum sample of %d certificates in the last 30 days (currently %d). No anomalies reported below this threshold.", anomalyMinSample, report.Windows.Last30d)
	}

	return report
}

// --- Task 28: Change Audit Report ---

// ChangeAuditReport is the response body for GET /api/v1/reports/change-audit.
type ChangeAuditReport struct {
	GeneratedAt string             `json:"generated_at"`
	WindowDays  int                `json:"window_days"`
	Fingerprint string             `json:"fingerprint,omitempty"`
	TotalEvents int                `json:"total_events"`
	ByAction    map[string]int     `json:"by_action"`
	ByActor     map[string]int     `json:"by_actor"`
	ByOutcome   map[string]int     `json:"by_outcome"`
	Events      []ChangeAuditEntry `json:"events"`
}

type ChangeAuditEntry struct {
	Timestamp     string `json:"timestamp"`
	Action        string `json:"action"`
	ActorID       string `json:"actor_id"`
	ActorType     string `json:"actor_type"`
	ResourceID    string `json:"resource_id"`
	Outcome       string `json:"outcome"`
	SourceIP      string `json:"source_ip,omitempty"`
	ChangeSummary string `json:"change_summary,omitempty"`
	TraceID       string `json:"trace_id,omitempty"`
}

// mutationActions are the audit actions that represent certificate/CA state changes.
var mutationActions = map[string]bool{
	"certificate.issue":            true,
	"certificate.revoke":           true,
	"certificate.renew":            true,
	"certificate.ownership_update": true,
	"ca.create":                    true,
	"ca.suspend":                   true,
	"ca.activate":                  true,
	"ca.delete":                    true,
}

func computeChangeAudit(entries []AuditEntry, days int, fingerprintFilter string) ChangeAuditReport {
	report := ChangeAuditReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowDays:  days,
		Fingerprint: fingerprintFilter,
		ByAction:    make(map[string]int),
		ByActor:     make(map[string]int),
		ByOutcome:   make(map[string]int),
		Events:      make([]ChangeAuditEntry, 0),
	}

	for _, e := range entries {
		// Only include mutation events unless a specific fingerprint is requested.
		if fingerprintFilter == "" && !mutationActions[e.Action] {
			continue
		}

		report.TotalEvents++
		report.ByAction[e.Action]++
		report.ByActor[e.ActorID]++
		report.ByOutcome[string(e.Outcome)]++

		if len(report.Events) < 500 {
			report.Events = append(report.Events, ChangeAuditEntry{
				Timestamp:     e.Timestamp,
				Action:        e.Action,
				ActorID:       e.ActorID,
				ActorType:     e.ActorType,
				ResourceID:    e.ResourceID,
				Outcome:       string(e.Outcome),
				SourceIP:      e.SourceIP,
				ChangeSummary: e.ChangeSummary,
				TraceID:       e.TraceID,
			})
		}
	}

	return report
}

// --- Task 29: Compliance Evidence Report ---

// ComplianceEvidenceReport is the response body for GET /api/v1/reports/compliance-evidence.
type ComplianceEvidenceReport struct {
	GeneratedAt string              `json:"generated_at"`
	Framework   string              `json:"framework"`
	Controls    []ComplianceControl `json:"controls"`
	Summary     ComplianceSummary   `json:"summary"`
}

type ComplianceControl struct {
	ID          string `json:"id"`
	Framework   string `json:"framework"`
	Title       string `json:"title"`
	Status      string `json:"status"` // pass, warn, fail
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation,omitempty"`
}

type ComplianceSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

func computeComplianceEvidence(certs []CertificateItem, cas []CAListItem, framework string) ComplianceEvidenceReport {
	return computeComplianceEvidenceAt(certs, cas, framework, time.Now().UTC())
}

// expiryTally buckets certificates by expiry as of one instant. unknown counts
// certs whose ValidUntil is empty or unparseable: they are neither expired nor
// expiring on the evidence we hold, so a control must not read them as healthy.
type expiryTally struct {
	expired, expiring30, unknown int
}

func tallyExpiry(certs []CertificateItem, now time.Time) expiryTally {
	var t expiryTally
	horizon := now.Add(30 * 24 * time.Hour)
	for _, c := range certs {
		until, err := time.Parse(time.RFC3339, c.ValidUntil)
		switch {
		case err != nil:
			t.unknown++
		case until.Before(now):
			t.expired++
		case until.Before(horizon):
			t.expiring30++
		}
	}
	return t
}

// soc2LifecycleControl evaluates SOC2-CC6.7. Unknown-expiry certs block a
// "pass" (the status vocabulary has no "insufficient data", so the strongest
// honest non-pass that does not overstate is "warn") but do not by themselves
// raise it to "fail".
func soc2LifecycleControl(certs []CertificateItem, now time.Time) ComplianceControl {
	total := len(certs)
	t := tallyExpiry(certs, now)
	automatedPct := 0
	if total > 0 {
		automated := 0
		for _, c := range certs {
			if c.RenewalMethod == "acme" || c.RenewalMethod == "est" || c.RenewalMethod == "scep" {
				automated++
			}
		}
		automatedPct = automated * 100 / total
	}
	status := "fail"
	switch {
	case t.expired == 0 && t.expiring30 == 0 && t.unknown == 0:
		status = "pass"
	case t.expired == 0 && t.expiring30 <= total/10:
		status = "warn"
	}
	evidence := fmt.Sprintf("Expired: %d. Expiring <30d: %d. Unknown expiry: %d. Automated renewal: %d%%. Total: %d.", t.expired, t.expiring30, t.unknown, automatedPct, total)
	var remediation []string
	if t.expired > 0 {
		remediation = append(remediation, fmt.Sprintf("Revoke or renew %d expired certificate(s) immediately.", t.expired))
	}
	if t.unknown > 0 {
		remediation = append(remediation, fmt.Sprintf("%d certificate(s) have a missing or unparseable expiry date; expiry compliance cannot be established for them. Re-scan or correct the inventory records.", t.unknown))
	}
	return ComplianceControl{
		ID:          "SOC2-CC6.7",
		Framework:   "SOC 2",
		Title:       "Certificate lifecycle management and timely renewal",
		Status:      status,
		Evidence:    evidence,
		Remediation: strings.Join(remediation, " "),
	}
}

// computeComplianceEvidenceAt is computeComplianceEvidence with an injected
// clock so expiry-dependent controls are testable.
func computeComplianceEvidenceAt(certs []CertificateItem, cas []CAListItem, framework string, now time.Time) ComplianceEvidenceReport {
	report := ComplianceEvidenceReport{
		GeneratedAt: now.Format(time.RFC3339),
		Framework:   framework,
		Controls:    make([]ComplianceControl, 0),
	}

	total := len(certs)

	// Helper: count certs matching predicate.
	count := func(fn func(CertificateItem) bool) int {
		n := 0
		for _, c := range certs {
			if fn(c) {
				n++
			}
		}
		return n
	}

	statusOf := func(passing, warning bool) string {
		if passing {
			return "pass"
		}
		if warning {
			return "warn"
		}
		return "fail"
	}

	pct := func(n, d int) string {
		if d == 0 {
			return "N/A (no certs)"
		}
		return fmt.Sprintf("%d/%d (%.0f%%)", n, d, float64(n)*100/float64(d))
	}

	// --- SOC 2 CC6.7: Logical access controls — cert expiry management ---
	if framework == "all" || framework == "soc2" {
		report.Controls = append(report.Controls, soc2LifecycleControl(certs, now))
	}

	// --- PCI DSS 4.2.1.1: Certificate inventory with key strength and expiry ---
	if framework == "all" || framework == "pci" {
		withOwner := count(func(c CertificateItem) bool { return c.OwnerEmail != "" || c.OwnerTeam != "" })
		weakKey := count(func(c CertificateItem) bool {
			for _, f := range c.RiskFlags {
				if f == "WEAK_RSA_KEY" || f == "WEAK_EC_KEY" {
					return true
				}
			}
			return false
		})
		report.Controls = append(report.Controls, ComplianceControl{
			ID:        "PCI-DSS-4.2.1.1",
			Framework: "PCI DSS 4.0.1",
			Title:     "Certificate inventory with key strength, algorithm, and expiry tracking",
			Status:    statusOf(weakKey == 0, weakKey <= total/20),
			Evidence:  fmt.Sprintf("Total certs inventoried: %d. With owner assigned: %s. Weak key algorithm: %d.", total, pct(withOwner, total), weakKey),
			Remediation: func() string {
				if weakKey > 0 {
					return fmt.Sprintf("Replace %d certificate(s) with weak key algorithms.", weakKey)
				}
				return ""
			}(),
		})
	}

	// --- NIST SP 800-57: Key algorithm strength and lifetime limits ---
	if framework == "all" || framework == "nist" {
		sha1Certs := count(func(c CertificateItem) bool {
			for _, f := range c.RiskFlags {
				if f == "WEAK_SIGNATURE" {
					return true
				}
			}
			return false
		})
		longValidity := count(func(c CertificateItem) bool {
			for _, f := range c.RiskFlags {
				if f == "VALIDITY_EXCEEDS_397_DAYS" {
					return true
				}
			}
			return false
		})
		pqcVulnerable := count(func(c CertificateItem) bool { return c.PQCVulnerable })
		report.Controls = append(report.Controls, ComplianceControl{
			ID:        "NIST-800-57-3.6",
			Framework: "NIST SP 800-57",
			Title:     "Cryptoperiod limits and algorithm deprecation",
			Status:    statusOf(sha1Certs == 0 && longValidity == 0, sha1Certs == 0),
			Evidence:  fmt.Sprintf("SHA-1/MD5 certs: %d. Validity >397d: %s. PQC-vulnerable: %s.", sha1Certs, pct(longValidity, total), pct(pqcVulnerable, total)),
			Remediation: func() string {
				if sha1Certs > 0 {
					return fmt.Sprintf("Replace %d SHA-1/MD5 signed certificate(s) before 2030 NIST deadline.", sha1Certs)
				}
				return ""
			}(),
		})

		// NIST 800-131A: Algorithm transitions
		nistSunset := count(func(c CertificateItem) bool {
			for _, f := range c.RiskFlags {
				if f == "NIST_SUNSET_RSA2048" || f == "NIST_SUNSET_ECC224" {
					return true
				}
			}
			return false
		})
		report.Controls = append(report.Controls, ComplianceControl{
			ID:        "NIST-800-131A",
			Framework: "NIST SP 800-131A Rev.3",
			Title:     "Algorithm transition — RSA-2048 and ECC-224 disallowed after Dec 2030",
			Status:    statusOf(nistSunset == 0, true),
			Evidence:  fmt.Sprintf("Certs using sunset algorithms (post-2030 deadline): %d.", nistSunset),
			Remediation: func() string {
				if nistSunset > 0 {
					return fmt.Sprintf("Migrate %d certificate(s) to RSA-3072+, P-384+, or ML-DSA before Jan 2031.", nistSunset)
				}
				return ""
			}(),
		})
	}

	// W16-05: DORA / NIS2 EU control mappings (framework "dora"/"nis2"/"all").
	report.Controls = append(report.Controls, doraNIS2Controls(certs, cas, framework, now)...)

	// --- CA health cross-cut: used for both SOC2 and PCI ---
	if framework == "all" {
		activeCAs := 0
		for _, ca := range cas {
			if caEffectiveStatus(ca, now) == "active" {
				activeCAs++
			}
		}
		report.Controls = append(report.Controls, ComplianceControl{
			ID:        "INTERNAL-CA-HEALTH",
			Framework: "Internal",
			Title:     "Active CA count and chain integrity",
			Status:    statusOf(activeCAs > 0, true),
			Evidence:  fmt.Sprintf("Active CAs: %d of %d total.", activeCAs, len(cas)),
		})
	}

	// Tally summary.
	for _, ctrl := range report.Controls {
		switch ctrl.Status {
		case "pass":
			report.Summary.Pass++
		case "warn":
			report.Summary.Warn++
		case "fail":
			report.Summary.Fail++
		}
	}

	return report
}

// --- Task 34: Algorithm Sunset Report ---

// AlgorithmSunsetReport is the response body for GET /api/v1/reports/algorithm-sunset.
type AlgorithmSunsetReport struct {
	GeneratedAt   string            `json:"generated_at"`
	TotalCerts    int               `json:"total_certs"`
	Groups        []SunsetAlgoGroup `json:"groups"`
	SunsetSummary SunsetAlgoSummary `json:"summary"`
}

type SunsetAlgoGroup struct {
	Algorithm    string   `json:"algorithm"`
	Deadline     string   `json:"deadline"` // RFC 3339 date of ban
	Standard     string   `json:"standard"`
	Status       string   `json:"status"`  // banned, sunset_2030, sunset_2026, current
	Urgency      string   `json:"urgency"` // immediate, high, medium, low
	Count        int      `json:"count"`
	Recommended  string   `json:"recommended_replacement"`
	Fingerprints []string `json:"fingerprints"` // up to 20 examples
}

type SunsetAlgoSummary struct {
	Banned     int `json:"banned_now"`
	Sunset2030 int `json:"sunset_2030"`
	Compliant  int `json:"compliant"`
}

func computeAlgorithmSunset(certs []CertificateItem) AlgorithmSunsetReport {
	now := time.Now().UTC()
	report := AlgorithmSunsetReport{
		GeneratedAt: now.Format(time.RFC3339),
		TotalCerts:  len(certs),
	}

	type algoRule struct {
		match       func(CertificateItem) bool
		algorithm   string
		deadline    string
		standard    string
		status      string
		urgency     string
		recommended string
	}

	rules := []algoRule{
		{
			algorithm:   "SHA-1 / MD5 signature",
			deadline:    "2016-01-01T00:00:00Z",
			standard:    "CA/B Forum BR 1.5.6",
			status:      "banned",
			urgency:     "immediate",
			recommended: "SHA-256 or SHA-384",
			match: func(c CertificateItem) bool {
				for _, f := range c.RiskFlags {
					if f == "WEAK_SIGNATURE" {
						return true
					}
				}
				return false
			},
		},
		{
			algorithm:   "RSA < 2048-bit",
			deadline:    "2014-01-01T00:00:00Z",
			standard:    "NIST SP 800-131A",
			status:      "banned",
			urgency:     "immediate",
			recommended: "RSA-3072 or ECDSA P-256",
			match: func(c CertificateItem) bool {
				for _, f := range c.RiskFlags {
					if f == "WEAK_RSA_KEY" {
						return true
					}
				}
				return false
			},
		},
		{
			algorithm:   "RSA-2048 (post-2030)",
			deadline:    "2031-01-01T00:00:00Z",
			standard:    "NIST SP 800-131A Rev.3",
			status:      "sunset_2030",
			urgency:     "high",
			recommended: "RSA-3072, RSA-4096, or ECDSA P-256+",
			match: func(c CertificateItem) bool {
				for _, f := range c.RiskFlags {
					if f == "NIST_SUNSET_RSA2048" {
						return true
					}
				}
				return false
			},
		},
		{
			algorithm:   "ECC-224 / P-224 (post-2030)",
			deadline:    "2031-01-01T00:00:00Z",
			standard:    "NIST SP 800-131A Rev.3",
			status:      "sunset_2030",
			urgency:     "high",
			recommended: "ECDSA P-256 or P-384",
			match: func(c CertificateItem) bool {
				for _, f := range c.RiskFlags {
					if f == "NIST_SUNSET_ECC224" {
						return true
					}
				}
				return false
			},
		},
		{
			algorithm:   "Validity > 397 days",
			deadline:    "2020-09-01T00:00:00Z",
			standard:    "CA/B Forum SC-31",
			status:      "banned",
			urgency:     "immediate",
			recommended: "≤397 day validity (47 days by March 2029)",
			match: func(c CertificateItem) bool {
				for _, f := range c.RiskFlags {
					if f == "VALIDITY_EXCEEDS_397_DAYS" {
						return true
					}
				}
				return false
			},
		},
		{
			algorithm:   "Classical algorithms (PQC-vulnerable)",
			deadline:    "2030-01-01T00:00:00Z",
			standard:    "CNSA 2.0 / NIST IR 8413",
			status:      "sunset_2030",
			urgency:     "medium",
			recommended: "ML-DSA-65, ML-DSA-87, or Hybrid ECDSA+ML-DSA",
			match:       func(c CertificateItem) bool { return c.PQCVulnerable },
		},
	}

	groupMap := make(map[string]*SunsetAlgoGroup)
	for _, rule := range rules {
		g := &SunsetAlgoGroup{
			Algorithm:    rule.algorithm,
			Deadline:     rule.deadline,
			Standard:     rule.standard,
			Status:       rule.status,
			Urgency:      rule.urgency,
			Recommended:  rule.recommended,
			Fingerprints: make([]string, 0),
		}
		groupMap[rule.algorithm] = g
	}

	for _, cert := range certs {
		for _, rule := range rules {
			if !rule.match(cert) {
				continue
			}
			g := groupMap[rule.algorithm]
			g.Count++
			if len(g.Fingerprints) < 20 {
				g.Fingerprints = append(g.Fingerprints, cert.FingerprintSHA256)
			}
		}
	}

	for _, rule := range rules {
		g := groupMap[rule.algorithm]
		if g.Count == 0 {
			continue
		}
		switch g.Status {
		case "banned":
			report.SunsetSummary.Banned += g.Count
		case "sunset_2030":
			report.SunsetSummary.Sunset2030 += g.Count
		}
		report.Groups = append(report.Groups, *g)
	}
	report.SunsetSummary.Compliant = len(certs) - report.SunsetSummary.Banned - report.SunsetSummary.Sunset2030
	if report.SunsetSummary.Compliant < 0 {
		report.SunsetSummary.Compliant = 0
	}

	_ = now
	return report
}
