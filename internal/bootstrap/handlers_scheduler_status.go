// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"time"

	"kryptkeeper/internal/logging"
)

// registerSchedulerStatusHandler mounts the renewal-scheduler status endpoint.
// It reports the most recent scan result published by the running scheduler.
func registerSchedulerStatusHandler(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/scheduler/renewal/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "scheduler.renewal_status", "scheduler", "renewal", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		status, hasRun := LatestRenewalStatus()
		emitAuditEvent(r, auditProvider, principal, "scheduler.renewal_status", "scheduler", "renewal", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data struct {
				HasRun bool                   `json:"has_run"`
				Status RenewalSchedulerStatus `json:"status"`
			} `json:"data"`
		}{Data: struct {
			HasRun bool                   `json:"has_run"`
			Status RenewalSchedulerStatus `json:"status"`
		}{HasRun: hasRun, Status: status}}); err != nil {
			logging.Warnf("failed to encode scheduler status: %v", err)
		}
	})
}
