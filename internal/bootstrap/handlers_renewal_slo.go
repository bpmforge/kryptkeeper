// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// RenewalSLOReport summarizes Renewal Autopilot health for the dashboard.
type RenewalSLOReport struct {
	GeneratedAt         string          `json:"generated_at"`
	AgentsTotal         int             `json:"agents_total"`
	AgentsActive        int             `json:"agents_active"`
	EndpointsManaged    int             `json:"endpoints_managed"`
	Outcomes            map[string]int  `json:"outcomes"`
	TotalRenewals       int             `json:"total_renewals"`
	SuccessRatePercent  int             `json:"success_rate_percent"`    // installed_verified / total with an outcome
	MeanTimeToRenewSecs int             `json:"mean_time_to_renew_secs"` // mean over measurable samples
	MTTRSamples         int             `json:"mttr_samples"`
	FailedRenewals      []FailedRenewal `json:"failed_renewals"`
}

// FailedRenewal is one entry in the failed-renewal queue.
type FailedRenewal struct {
	AgentID           string `json:"agent_id"`
	TaskID            string `json:"task_id"`
	Fingerprint       string `json:"fingerprint"`
	Outcome           string `json:"outcome"`
	RolledBack        bool   `json:"rolled_back"`
	Detail            string `json:"detail,omitempty"`
	ServedFingerprint string `json:"served_fingerprint,omitempty"`
	ReportedAt        string `json:"reported_at"`
}

// isLaterResult reports whether candidate is at least as recent as current
// (by ReportedAt). An empty current is always superseded.
func isLaterResult(candidate, current AgentRenewalResult) bool {
	if current.ReportedAt == "" {
		return true
	}
	ct, err1 := time.Parse(time.RFC3339, candidate.ReportedAt)
	pt, err2 := time.Parse(time.RFC3339, current.ReportedAt)
	if err1 != nil || err2 != nil {
		return true // can't compare — prefer the candidate (later in iteration)
	}
	return !ct.Before(pt)
}

// isSuccessOutcome reports whether an outcome counts as a healthy renewal.
func isSuccessOutcome(outcome string, rolledBack bool) bool {
	if rolledBack {
		return false
	}
	return outcome == "installed_verified" || outcome == "installed"
}

// registerRenewalSLOHandler mounts GET /api/v1/reports/renewal-slo. It
// aggregates agent-reported renewal results into an autopilot health summary.
// MTTR is computed for results whose cert can be matched to the inventory
// (renewed cert ValidFrom → result ReportedAt); unmatched results are skipped.
func registerRenewalSLOHandler(mux *http.ServeMux, auth *Authenticator, store AgentStore, certProvider CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/renewal-slo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.renewal_slo", "report", "renewal-slo", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// W2-07/D-102: renewal-SLO composes fleet-wide agent counts and
		// agent-reported outcomes — agent-token auth has no tenant concept at
		// all (G-50), so there is no coherent per-tenant breakdown to filter
		// down to. Aggregate-super-admin-only, same treatment as dashboard/
		// pqc-waves.
		if denyAggregateReportForTenantScoped(w, principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "report.renewal_slo", "report", "renewal-slo", AuditOutcomeDenied)
			return
		}

		total, active := store.agentCounts()
		// S-63: a failed endpoint count is a failed report, not "0 managed".
		endpoints, err := store.endpointCount()
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "report.renewal_slo", "report", "renewal-slo", AuditOutcomeFailure)
			log.Printf("renewal-slo: endpoint count unavailable: %v", err)
			writeServiceUnavailable(w, "renewal SLO report unavailable")
			return
		}
		report := RenewalSLOReport{
			GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
			AgentsTotal:      total,
			AgentsActive:     active,
			EndpointsManaged: endpoints,
			Outcomes:         map[string]int{},
			FailedRenewals:   []FailedRenewal{},
		}

		entries := store.allResults()
		// latestByFP tracks the most recent result per fingerprint so the
		// failed-renewal queue reflects CURRENT state, not stale failures that
		// later auto-retried to success.
		latestByFP := make(map[string]AgentResultEntry)
		var successes, mttrTotalSecs, mttrSamples int
		for _, e := range entries {
			res := e.Result
			report.TotalRenewals++ // historical activity count
			if res.Outcome != "" {
				report.Outcomes[res.Outcome]++
			}
			if isSuccessOutcome(res.Outcome, res.RolledBack) {
				successes++
				if secs, ok := timeToRenewSeconds(r, certProvider, res); ok {
					mttrTotalSecs += secs
					mttrSamples++
				}
			}
			if res.Fingerprint != "" && isLaterResult(res, latestByFP[res.Fingerprint].Result) {
				latestByFP[res.Fingerprint] = e
			}
		}
		// Failed queue = certs whose LATEST result is a failure (still actionable).
		for _, e := range latestByFP {
			res := e.Result
			if isSuccessOutcome(res.Outcome, res.RolledBack) {
				continue
			}
			report.FailedRenewals = append(report.FailedRenewals, FailedRenewal{
				AgentID:           e.AgentID,
				TaskID:            res.TaskID,
				Fingerprint:       res.Fingerprint,
				Outcome:           res.Outcome,
				RolledBack:        res.RolledBack,
				Detail:            res.Detail,
				ServedFingerprint: res.ServedFingerprint,
				ReportedAt:        res.ReportedAt,
			})
		}
		// W2-07: the scheduler's own renewal-notification trigger failures
		// (dead-lettered after renewalTriggerMaxAttempts consecutive
		// attempts) are a distinct failure domain from agent-reported
		// renewal outcomes above — surface both in the same queue so an
		// operator has one place to look, not logs for one and this report
		// for the other.
		report.FailedRenewals = append(report.FailedRenewals, renewalDeadLetterSnapshot()...)
		if report.TotalRenewals > 0 {
			report.SuccessRatePercent = successes * 100 / report.TotalRenewals
		}
		report.MTTRSamples = mttrSamples
		if mttrSamples > 0 {
			report.MeanTimeToRenewSecs = mttrTotalSecs / mttrSamples
		}

		emitAuditEvent(r, auditProvider, principal.ID, "report.renewal_slo", "report", "renewal-slo", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data RenewalSLOReport `json:"data"`
		}{Data: report}); err != nil {
			log.Printf("failed to encode renewal SLO report: %v", err)
		}
	})
}

// timeToRenewSeconds returns the seconds between the renewed cert becoming valid
// and the agent reporting a verified install, when both timestamps are known.
func timeToRenewSeconds(r *http.Request, certProvider CertificateProvider, res AgentRenewalResult) (int, bool) {
	if res.Fingerprint == "" || res.ReportedAt == "" || certProvider == nil {
		return 0, false
	}
	reported, err := time.Parse(time.RFC3339, res.ReportedAt)
	if err != nil {
		return 0, false
	}
	detail, ok, err := certProvider.GetCertificate(r.Context(), res.Fingerprint)
	if err != nil || !ok || detail.ValidFrom == "" {
		return 0, false
	}
	validFrom, err := time.Parse(time.RFC3339, detail.ValidFrom)
	if err != nil {
		return 0, false
	}
	d := reported.Sub(validFrom)
	if d < 0 {
		return 0, false
	}
	return int(d.Seconds()), true
}
