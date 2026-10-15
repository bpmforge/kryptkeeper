// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

func registerDashboardHandlers(mux *http.ServeMux, auth *Authenticator, certSummaryProvider CertSummaryProvider, discoveryProvider DiscoveryProvider, notificationProvider NotificationProvider, dashboardActionProvider DashboardActionProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/dashboard/summary", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "dashboard.summary", "dashboard", "summary", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.summary", "dashboard", "summary", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		// W2-03/D-102: the dashboard composes fleet-wide summary providers
		// (cert/discovery/notification) with no per-tenant breakdown —
		// aggregate-super-admin-only.
		if denyAggregateReportForTenantScoped(w, principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.summary", "dashboard", "summary", AuditOutcomeDenied)
			return
		}

		certSummary, err := certSummaryProvider.LoadSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.summary", "dashboard", "summary", AuditOutcomeFailure)
			log.Printf("dashboard summary unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard summary unavailable")
			return
		}

		discoverySummary, err := discoveryProvider.GetSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.summary", "dashboard", "summary", AuditOutcomeFailure)
			log.Printf("dashboard discovery summary unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard summary unavailable")
			return
		}

		notifSummary, err := notificationProvider.GetSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.summary", "dashboard", "summary", AuditOutcomeFailure)
			log.Printf("dashboard notification summary unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard summary unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "dashboard.summary", "dashboard", "summary", AuditOutcomeSuccess)

		resp := struct {
			Data struct {
				Resource     string `json:"resource"`
				Principal    string `json:"principal"`
				Certificates struct {
					Total          int `json:"total"`
					Revoked        int `json:"revoked"`
					Expiring30Days int `json:"expiring_30_days"`
					Expired        int `json:"expired"`
					// W11-01 estate split by management_state; zeros on
					// file-backed summaries.
					Managed   int    `json:"managed"`
					External  int    `json:"external"`
					Unmanaged int    `json:"unmanaged"`
					Source    string `json:"source"`
				} `json:"certificates"`
				Discovery struct {
					DiscoveredEndpoints int                  `json:"discovered_endpoints"`
					RiskyEndpoints      int                  `json:"risky_endpoints"`
					ActiveScanJobs      int                  `json:"active_scan_jobs"`
					Findings            FindingFunnelSummary `json:"findings"`
					// Discovery-found leaf certificates by whose they are.
					TrustClasses TrustClassCounts `json:"trust_classes"`
				} `json:"discovery"`
				Notifications struct {
					PendingNotifications int `json:"pending_notifications"`
					Escalations          int `json:"escalations"`
				} `json:"notifications"`
			} `json:"data"`
		}{}

		resp.Data.Resource = "dashboard-summary"
		resp.Data.Principal = principal.ID
		resp.Data.Certificates.Total = certSummary.Total
		resp.Data.Certificates.Revoked = certSummary.Revoked
		resp.Data.Certificates.Expiring30Days = certSummary.Expiring30Days
		resp.Data.Certificates.Expired = certSummary.Expired
		resp.Data.Certificates.Managed = certSummary.Managed
		resp.Data.Certificates.External = certSummary.External
		resp.Data.Certificates.Unmanaged = certSummary.Unmanaged
		resp.Data.Certificates.Source = certSummary.Source
		resp.Data.Discovery.DiscoveredEndpoints = discoverySummary.DiscoveredEndpoints
		resp.Data.Discovery.RiskyEndpoints = discoverySummary.RiskyEndpoints
		resp.Data.Discovery.ActiveScanJobs = discoverySummary.ActiveScanJobs
		resp.Data.Discovery.Findings = discoverySummary.Findings
		resp.Data.Discovery.TrustClasses = discoverySummary.TrustClasses
		resp.Data.Notifications.PendingNotifications = notifSummary.PendingNotifications
		resp.Data.Notifications.Escalations = notifSummary.OwnershipEscalations

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/dashboard/summary response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/dashboard/actions", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "dashboard.actions", "dashboard", "actions", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions", "dashboard", "actions", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions", "dashboard", "actions", AuditOutcomeDenied)
			return
		}

		certSummary, err := certSummaryProvider.LoadSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions", "dashboard", "actions", AuditOutcomeFailure)
			log.Printf("dashboard actions unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard actions unavailable")
			return
		}

		discoverySummary, err := discoveryProvider.GetSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions", "dashboard", "actions", AuditOutcomeFailure)
			log.Printf("dashboard actions discovery unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard actions unavailable")
			return
		}

		notifSummary, err := notificationProvider.GetSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions", "dashboard", "actions", AuditOutcomeFailure)
			log.Printf("dashboard actions notifications unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard actions unavailable")
			return
		}

		actions := make([]map[string]any, 0, 4)
		if certSummary.Expiring30Days > 0 {
			actions = append(actions, map[string]any{
				"id":       "act-expiring-certs",
				"category": "certificate",
				"severity": "high",
				"title":    "Review expiring certificates",
				"count":    certSummary.Expiring30Days,
			})
		}
		if certSummary.Expired > 0 {
			actions = append(actions, map[string]any{
				"id":       "act-expired-certs",
				"category": "certificate",
				"severity": "critical",
				"title":    "Replace expired certificates",
				"count":    certSummary.Expired,
			})
		}
		if discoverySummary.RiskyEndpoints > 0 {
			actions = append(actions, map[string]any{
				"id":       "act-risky-endpoints",
				"category": "discovery",
				"severity": "high",
				"title":    "Investigate risky endpoints",
				"count":    discoverySummary.RiskyEndpoints,
			})
		}
		if notifSummary.DeliveryFailures24h > 0 {
			actions = append(actions, map[string]any{
				"id":       "act-notification-failures",
				"category": "notification",
				"severity": "medium",
				"title":    "Review notification delivery failures",
				"count":    notifSummary.DeliveryFailures24h,
			})
		}

		emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions", "dashboard", "actions", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string           `json:"resource"`
				Principal string           `json:"principal"`
				Actions   []map[string]any `json:"actions"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "dashboard-actions"
		resp.Data.Principal = principal.ID
		resp.Data.Actions = actions

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/dashboard/actions response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/dashboard/actions/history", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "dashboard.actions.history", "dashboard", "actions-history", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions.history", "dashboard", "actions-history", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions.history", "dashboard", "actions-history", AuditOutcomeDenied)
			return
		}

		statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
		if statusFilter != "" {
			switch statusFilter {
			case "open", "acknowledged", "resolved", "success":
			default:
				writeBadRequest(w, "invalid status value")
				return
			}
		}
		categoryFilter := strings.TrimSpace(r.URL.Query().Get("category"))
		if categoryFilter != "" {
			switch categoryFilter {
			case "certificate", "discovery", "notification", "dashboard":
			default:
				writeBadRequest(w, "invalid category value")
				return
			}
		}
		query := DashboardActionHistoryQuery{
			Status:   statusFilter,
			Category: categoryFilter,
			Limit:    parseLimit(r.URL.Query().Get("limit"), 25, 100),
			Cursor:   parseCursor(r.URL.Query().Get("cursor"), 0),
		}

		result, err := dashboardActionProvider.ListHistory(r.Context(), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions.history", "dashboard", "actions-history", AuditOutcomeFailure)
			log.Printf("dashboard actions history unavailable: %v", err)
			writeServiceUnavailable(w, "dashboard actions history unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "dashboard.actions.history", "dashboard", "actions-history", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string                         `json:"resource"`
				Principal string                         `json:"principal"`
				History   []DashboardActionHistoryRecord `json:"history"`
			} `json:"data"`
			Meta struct {
				Total      int  `json:"total"`
				Limit      int  `json:"limit"`
				NextCursor *int `json:"next_cursor"`
				PrevCursor *int `json:"prev_cursor"`
			} `json:"meta"`
		}{}
		resp.Data.Resource = "dashboard-actions-history"
		resp.Data.Principal = principal.ID
		resp.Data.History = result.History
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		resp.Meta.NextCursor = result.NextCursor
		resp.Meta.PrevCursor = result.PrevCursor

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/dashboard/actions/history response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/dashboard/actions/ack", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "dashboard.action.ack", "dashboard", "actions", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageDashboardActions(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.ack", "dashboard", "actions", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.ack", "dashboard", "actions", AuditOutcomeDenied)
			return
		}

		var req struct {
			ActionID string `json:"action_id"`
			Note     string `json:"note"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.ack", "dashboard", "actions", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		req.ActionID = strings.TrimSpace(req.ActionID)
		req.Note = strings.TrimSpace(req.Note)
		if req.ActionID == "" || tooLong(req.Note) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.ack", "dashboard", "actions", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := dashboardActionProvider.AckAction(r.Context(), req.ActionID, req.Note)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.ack", "dashboard", "actions", AuditOutcomeFailure)
			log.Printf("dashboard action ack failed: %v", err)
			writeServiceUnavailable(w, "dashboard action ack unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.ack", "dashboard", req.ActionID, AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource   string `json:"resource"`
				Principal  string `json:"principal"`
				ActionID   string `json:"action_id"`
				Status     string `json:"status"`
				Note       string `json:"note"`
				AckedAtUTC string `json:"acked_at_utc"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "dashboard-action-ack"
		resp.Data.Principal = principal.ID
		resp.Data.ActionID = result.ActionID
		resp.Data.Status = result.Status
		resp.Data.Note = result.Note
		resp.Data.AckedAtUTC = result.AckedAtUTC

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/dashboard/actions/ack response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/dashboard/actions/resolve", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "dashboard.action.resolve", "dashboard", "actions", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageDashboardActions(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.resolve", "dashboard", "actions", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.resolve", "dashboard", "actions", AuditOutcomeDenied)
			return
		}

		var req struct {
			ActionID string `json:"action_id"`
			Note     string `json:"note"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.resolve", "dashboard", "actions", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		req.ActionID = strings.TrimSpace(req.ActionID)
		req.Note = strings.TrimSpace(req.Note)
		if req.ActionID == "" || tooLong(req.Note) {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.resolve", "dashboard", "actions", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := dashboardActionProvider.ResolveAction(r.Context(), req.ActionID, req.Note)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.resolve", "dashboard", "actions", AuditOutcomeFailure)
			log.Printf("dashboard action resolve failed: %v", err)
			writeServiceUnavailable(w, "dashboard action resolve unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "dashboard.action.resolve", "dashboard", req.ActionID, AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource   string `json:"resource"`
				Principal  string `json:"principal"`
				ActionID   string `json:"action_id"`
				Status     string `json:"status"`
				Note       string `json:"note"`
				ResolvedAt string `json:"resolved_at"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "dashboard-action-resolve"
		resp.Data.Principal = principal.ID
		resp.Data.ActionID = result.ActionID
		resp.Data.Status = result.Status
		resp.Data.Note = result.Note
		resp.Data.ResolvedAt = result.ResolvedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/dashboard/actions/resolve response: %v", err)
		}
	})
}
