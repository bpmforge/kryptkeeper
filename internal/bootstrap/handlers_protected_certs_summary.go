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

func registerProtectedCertsSummaryHandler(auth *Authenticator, certSummaryProvider CertSummaryProvider, auditProvider AuditProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		principal, err := auth.AuthenticatePrincipal(r, now)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protected.certs.summary.read", "protected_resource", "certs_summary", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}

		summary, err := certSummaryProvider.LoadSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "protected.certs.summary.read", "protected_resource", "certs_summary", AuditOutcomeFailure)
			log.Printf("cert summary unavailable: %v", err)
			writeServiceUnavailable(w, "certificate summary unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, principal, "protected.certs.summary.read", "protected_resource", "certs_summary", AuditOutcomeSuccess)
		resp := struct {
			Service     string `json:"service"`
			Resource    string `json:"resource"`
			GeneratedAt string `json:"generated_at"`
			Principal   string `json:"principal"`
			Source      string `json:"source"`
			Summary     struct {
				Total          int `json:"total"`
				Expiring30Days int `json:"expiring_30_days"`
				Expired        int `json:"expired"`
			} `json:"summary"`
		}{
			Service:     "kryptkeeper",
			Resource:    "protected-certs-summary",
			GeneratedAt: now.Format(time.RFC3339),
			Principal:   principal,
			Source:      summary.Source,
		}
		resp.Summary.Total = summary.Total
		resp.Summary.Expiring30Days = summary.Expiring30Days
		resp.Summary.Expired = summary.Expired

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protected/certs/summary response: %v", err)
		}
	}
}
