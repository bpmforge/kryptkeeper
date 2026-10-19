// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W22-05: server-side streamed audit export. The Audit page used to build
// audit-evidence.csv in the browser from a capped client-side fetch; an
// auditor needs EVERY matching row, so the server pages the provider in
// fixed chunks and writes each straight to the response. Memory stays at
// one page regardless of log size.

// auditExportPageSize bounds rows held in memory per provider call. Do not
// raise it: offset paging recounts, and one page is the memory ceiling.
const auditExportPageSize = 1000

var auditExportCSVHeader = []string{
	"id", "timestamp", "action", "actor_type", "actor_id",
	"resource_type", "resource_id", "trace_id", "outcome", "tenant",
}

// RegisterAuditExportHandlers mounts GET /api/v1/audit/export.
func RegisterAuditExportHandlers(mux *http.ServeMux, auth *Authenticator, roles *CustomRoleStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/audit/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "audit.export", "audit_log", "audit", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !requireReadPermission(w, r, auditProvider, pd, roles, "audit.read", "audit.export", "audit_log", "audit") {
			return
		}

		qv := r.URL.Query()
		format := strings.ToLower(strings.TrimSpace(qv.Get("format")))
		if format == "" {
			format = "csv"
		}
		if format != "csv" && format != "json" {
			writeBadRequest(w, "format must be csv or json")
			return
		}
		outcome := AuditOutcome(strings.TrimSpace(qv.Get("outcome")))
		if outcome != "" && !outcome.Valid() {
			writeBadRequest(w, "unknown outcome filter")
			return
		}

		query := AuditListQuery{
			Limit:        auditExportPageSize,
			Order:        "asc", // chronological: an evidence file reads oldest-first
			ActionPrefix: strings.TrimSpace(qv.Get("action")),
			ActorType:    strings.TrimSpace(qv.Get("actor_type")),
			ActorID:      strings.TrimSpace(qv.Get("actor_id")),
			ResourceType: strings.TrimSpace(qv.Get("resource_type")),
			ResourceID:   strings.TrimSpace(qv.Get("resource_id")),
			TraceID:      strings.TrimSpace(qv.Get("trace_id")),
			Outcome:      outcome,
			After:        parseAuditTimestamp(qv.Get("after")),
			Before:       parseAuditTimestamp(qv.Get("before")),
		}
		// Same rule as GET /audit: tenants only ever export their own rows,
		// enforced in the provider query so page termination stays correct.
		if !tenantBypass(pd) {
			query.Tenant = pd.Tenant
		}

		// Fail before any byte is sent if the store is down; after the first
		// write the status can no longer change.
		first, err := auditProvider.ListEntries(r.Context(), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "audit.export", "audit_log", "audit", AuditOutcomeFailure)
			logging.Warnf("audit export unavailable: %v", err)
			writeServiceUnavailable(w, "audit unavailable")
			return
		}

		now := time.Now().UTC()
		h := w.Header()
		if format == "csv" {
			h.Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			h.Set("Content-Type", "application/json")
		}
		h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-evidence-%s.%s"`, now.Format("20060102T150405Z"), format))
		h.Set("Cache-Control", "no-store")
		// server.go sets a short WriteTimeout that would cut a large export.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{}) // unsupported ResponseWriter (tests) keeps the default

		sink := newAuditExportSink(w, format)
		rows, streamErr := streamAuditExport(r.Context(), auditProvider, query, first, sink, rc)
		if streamErr != nil {
			logging.Infof("audit export aborted after %d rows: %v", rows, streamErr)
		}
		outcomeOut := AuditOutcomeSuccess
		if streamErr != nil {
			outcomeOut = AuditOutcomeFailure
		}
		// Written AFTER the loop so the export never contains its own row.
		emitAuditEventDetail(r, auditProvider, pd.ID, "audit.export", "audit_log", "audit", outcomeOut,
			auditExportSummary(format, query, rows))
	})
}

// streamAuditExport writes first and every following page to sink and
// returns the number of rows written. A mid-stream error cannot change the
// status code, so the body is simply truncated (no closing bracket for
// JSON) and the caller records a failure row.
func streamAuditExport(ctx context.Context, p AuditProvider, q AuditListQuery, first AuditListResult, sink *auditExportSink, rc *http.ResponseController) (int, error) {
	rows := 0
	res := first
	for {
		for _, e := range res.Entries {
			if err := sink.write(e); err != nil {
				return rows, err
			}
			rows++
		}
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return rows, err
		}
		if len(res.Entries) < auditExportPageSize || q.Offset+len(res.Entries) >= res.Total {
			break
		}
		q.Offset += len(res.Entries)
		var err error
		if res, err = p.ListEntries(ctx, q); err != nil {
			return rows, err
		}
	}
	return rows, sink.close()
}

type auditExportSink struct {
	w      http.ResponseWriter
	csvw   *csv.Writer
	enc    *json.Encoder
	json   bool
	opened bool
	count  int
}

func newAuditExportSink(w http.ResponseWriter, format string) *auditExportSink {
	s := &auditExportSink{w: w, json: format == "json"}
	if s.json {
		s.enc = json.NewEncoder(w)
	} else {
		s.csvw = csv.NewWriter(w)
	}
	return s
}

func (s *auditExportSink) write(e AuditEntry) error {
	if s.json {
		prefix := ","
		if s.count == 0 {
			prefix = "["
		}
		if _, err := s.w.Write([]byte(prefix)); err != nil {
			return err
		}
		s.count++
		return s.enc.Encode(e)
	}
	if !s.opened {
		s.opened = true
		if err := s.csvw.Write(auditExportCSVHeader); err != nil {
			return err
		}
	}
	err := s.csvw.Write(hardenRowFor(auditExportCSVHeader, []string{
		strconv.FormatInt(e.ID, 10), e.Timestamp, e.Action, e.ActorType, e.ActorID,
		e.ResourceType, e.ResourceID, e.TraceID, string(e.Outcome), e.Tenant,
	}))
	if err != nil {
		return err
	}
	// csv.Writer buffers; push each row through so Flush sees it.
	s.csvw.Flush()
	return s.csvw.Error()
}

// close finishes the document, including the empty-result case where no
// row ever opened it (a header-only CSV and "[]" are both valid).
func (s *auditExportSink) close() error {
	if s.json {
		if s.count == 0 {
			_, err := s.w.Write([]byte("[]"))
			return err
		}
		_, err := s.w.Write([]byte("]"))
		return err
	}
	if !s.opened {
		s.opened = true
		if err := s.csvw.Write(auditExportCSVHeader); err != nil {
			return err
		}
	}
	s.csvw.Flush()
	return s.csvw.Error()
}

func auditExportSummary(format string, q AuditListQuery, rows int) string {
	parts := []string{"format=" + format}
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("action", q.ActionPrefix)
	add("actor_type", q.ActorType)
	add("actor", q.ActorID)
	add("resource_type", q.ResourceType)
	add("resource_id", q.ResourceID)
	add("trace_id", q.TraceID)
	add("outcome", string(q.Outcome))
	add("after", q.After)
	add("before", q.Before)
	parts = append(parts, "rows="+strconv.Itoa(rows))
	return strings.Join(parts, " ")
}
