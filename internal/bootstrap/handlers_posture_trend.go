// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PostureTrendResponse is the response body for
// GET /api/v1/reports/crypto-posture/trend.
type PostureTrendResponse struct {
	Snapshots []PostureSnapshot `json:"snapshots"`
}

// registerPostureTrendHandler mounts the posture-trend endpoint. The handler
// tolerates a nil store (DB unavailable) by returning an empty series rather
// than failing, so the dashboard degrades gracefully.
func registerPostureTrendHandler(mux *http.ServeMux, auth *Authenticator, store PostureSnapshotStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/crypto-posture/trend", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.crypto_posture_trend", "report", "crypto-posture-trend", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// W2-03/D-102: posture snapshots are captured fleet-wide with no
		// per-tenant breakdown (PostureSnapshotStore has no tenant dimension)
		// — aggregate-super-admin-only rather than mixing tenants' data.
		if denyAggregateReportForTenantScoped(w, pd) {
			emitAuditEvent(r, auditProvider, pd.ID, "report.crypto_posture_trend", "report", "crypto-posture-trend", AuditOutcomeDenied)
			return
		}

		// since: default 90 days ago. limit: default 365.
		since := strings.TrimSpace(r.URL.Query().Get("since"))
		if since == "" {
			since = time.Now().UTC().AddDate(0, 0, -90).Format(time.RFC3339)
		}
		limit := 365
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		}

		snapshots := []PostureSnapshot{}
		if store != nil {
			snapshots, err = store.List(r.Context(), since, limit)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "report.crypto_posture_trend", "report", "crypto-posture-trend", AuditOutcomeFailure)
				log.Printf("crypto posture trend: list snapshots: %v", err)
				writeServiceUnavailable(w, "trend unavailable")
				return
			}
		}

		emitAuditEvent(r, auditProvider, pd.ID, "report.crypto_posture_trend", "report", "crypto-posture-trend", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data PostureTrendResponse `json:"data"`
		}{Data: PostureTrendResponse{Snapshots: snapshots}}); err != nil {
			log.Printf("failed to encode crypto posture trend: %v", err)
		}
	})
}
