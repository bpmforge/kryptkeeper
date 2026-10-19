// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

func registerAuditHandlers(mux *http.ServeMux, auth *Authenticator, roles *CustomRoleStore, auditProvider AuditProvider, names auditNameSources) {
	mux.HandleFunc("/api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "audit.list", "audit_log", "audit", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		// LLM-001 / A01-004: the log names every actor, source IP and change.
		if !requireReadPermission(w, r, auditProvider, pd, roles, "audit.read", "audit.list", "audit_log", "audit") {
			return
		}
		principal := pd.ID

		outcome := AuditOutcome(strings.TrimSpace(r.URL.Query().Get("outcome")))
		if outcome != "" && !outcome.Valid() {
			writeBadRequest(w, "unknown outcome filter")
			return
		}

		query := AuditListQuery{
			Limit:        parseAuditLimit(r.URL.Query().Get("limit"), 25),
			Offset:       parseAuditOffset(r.URL.Query().Get("cursor")),
			Order:        parseAuditOrder(r.URL.Query().Get("order")),
			ActionPrefix: strings.TrimSpace(r.URL.Query().Get("action")),
			ActorType:    strings.TrimSpace(r.URL.Query().Get("actor_type")),
			ActorID:      strings.TrimSpace(r.URL.Query().Get("actor_id")),
			ResourceType: strings.TrimSpace(r.URL.Query().Get("resource_type")),
			ResourceID:   strings.TrimSpace(r.URL.Query().Get("resource_id")),
			TraceID:      strings.TrimSpace(r.URL.Query().Get("trace_id")),
			Outcome:      outcome,
			After:        parseAuditTimestamp(r.URL.Query().Get("after")),
			Before:       parseAuditTimestamp(r.URL.Query().Get("before")),
		}
		// Rows carry the tenant of the principal that produced them; only the
		// unscoped super-admin sees across tenants.
		if !tenantBypass(pd) {
			query.Tenant = pd.Tenant
		}

		result, err := auditProvider.ListEntries(r.Context(), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "audit.list", "audit_log", "audit", AuditOutcomeFailure)
			logging.Warnf("audit list unavailable: %v", err)
			writeServiceUnavailable(w, "audit unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, principal, "audit.list", "audit_log", "audit", AuditOutcomeSuccess)

		resp := struct {
			Data []auditEntryView `json:"data"`
			Meta struct {
				Total      int     `json:"total"`
				Limit      int     `json:"limit"`
				NextCursor *string `json:"next_cursor"`
				PrevCursor *string `json:"prev_cursor"`
			} `json:"meta"`
			Principal string `json:"principal"`
		}{
			Data:      names.resolveAuditNames(r.Context(), pd, result.Entries),
			Principal: principal,
		}
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		nextOffset := query.Offset + len(result.Entries)
		if nextOffset < result.Total {
			next := strconv.Itoa(nextOffset)
			resp.Meta.NextCursor = &next
		}
		if query.Offset > 0 {
			prevOffset := query.Offset - query.Limit
			if prevOffset < 0 {
				prevOffset = 0
			}
			prev := strconv.Itoa(prevOffset)
			resp.Meta.PrevCursor = &prev
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/audit response: %v", err)
		}
	})
}
