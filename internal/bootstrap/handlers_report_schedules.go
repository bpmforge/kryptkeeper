// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	reportSchedulesPath = "/api/v1/reports/schedules"

	auditReportScheduleCreate = "report.schedule_create"
	auditReportScheduleDelete = "report.schedule_delete"
	auditReportScheduleType   = "report-schedule"
)

// RegisterReportScheduleHandlers mounts schedule list/create/delete for the
// generic scheduled-report delivery (W28-06). Like evidence schedules these
// render fleet-wide data, so every tenant-scoped principal is refused
// (D-102) and can neither see nor delete another tenant's schedule.
func RegisterReportScheduleHandlers(mux *http.ServeMux, auth *Authenticator, store ReportScheduleStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/schedules", func(w http.ResponseWriter, r *http.Request) {
		action := auditReportScheduleCreate
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			if r.Method == http.MethodPost {
				emitAuditEvent(r, auditProvider, "", action, auditReportScheduleType, "-", AuditOutcomeDenied)
			}
			writeUnauthorized(w)
			return
		}
		if r.Method == http.MethodGet {
			if denyAggregateReportForTenantScoped(w, principal) {
				return
			}
			if store == nil {
				writeServiceUnavailable(w, "schedule store unavailable")
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Data []ReportSchedule `json:"data"`
			}{Data: list})
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, "GET, POST")
			return
		}
		if !tenantBypass(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeDenied)
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "schedule store unavailable")
			return
		}
		req := ReportSchedule{Enabled: true}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid JSON")
			return
		}
		if err := validateReportSchedule(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		created, err := store.Create(r.Context(), req)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "create failed")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, created.ID, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			Data ReportSchedule `json:"data"`
		}{Data: created})
	})

	mux.HandleFunc("/api/v1/reports/schedules/", func(w http.ResponseWriter, r *http.Request) {
		action := auditReportScheduleDelete
		id := strings.TrimPrefix(r.URL.Path, reportSchedulesPath+"/")
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			if r.Method == http.MethodDelete {
				emitAuditEvent(r, auditProvider, "", action, auditReportScheduleType, "-", AuditOutcomeDenied)
			}
			writeUnauthorized(w)
			return
		}
		if r.Method == http.MethodGet && id == "catalog" {
			if denyAggregateReportForTenantScoped(w, principal) {
				return
			}
			writeReportScheduleCatalog(w)
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if !tenantBypass(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeDenied)
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "schedule store unavailable")
			return
		}
		if id == "" || strings.Contains(id, "/") {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, "-", AuditOutcomeFailure)
			writeBadRequest(w, "schedule id required")
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, id, AuditOutcomeFailure)
			if errors.Is(err, errReportScheduleNotFound) {
				writeNotFound(w, "schedule not found")
				return
			}
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, action, auditReportScheduleType, id, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})
}

// ReportScheduleCatalogEntry is one schedulable report and its formats.
type ReportScheduleCatalogEntry struct {
	Report  string   `json:"report"`
	Title   string   `json:"title"`
	Formats []string `json:"formats"`
}

// writeReportScheduleCatalog lists what POST /reports/schedules accepts, so
// the UI never hard-codes the report/format matrix.
func writeReportScheduleCatalog(w http.ResponseWriter) {
	out := make([]ReportScheduleCatalogEntry, 0, len(reportScheduleCatalog))
	for _, name := range scheduledReportNames() {
		d := reportScheduleCatalog[name]
		out = append(out, ReportScheduleCatalogEntry{Report: name, Title: d.Title, Formats: d.Formats})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Data []ReportScheduleCatalogEntry `json:"data"`
	}{Data: out})
}
