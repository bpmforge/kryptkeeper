// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// renderEvidencePackForFramework builds the compliance evidence PDF for a
// framework, returning the bytes and a suggested filename. Shared by the manual
// send endpoint and the scheduler.
func renderEvidencePackForFramework(ctx context.Context, certProvider CertificateProvider, caProvider CAProvider, framework string, createdAt time.Time) ([]byte, string, error) {
	result, err := listAllCertificates(ctx, certProvider, CertificateListQuery{})
	if err != nil {
		return nil, "", err
	}
	var cas CAListResult
	if caProvider != nil {
		cas, err = caProvider.ListCAs(ctx, CAListQuery{Limit: 1000})
		if err != nil {
			// An evidence pack is audit material: a pack built without the CA
			// list would report CA-derived controls from missing data.
			return nil, "", fmt.Errorf("list CAs for evidence pack: %w", err)
		}
	}
	report := computeComplianceEvidence(result.Items, cas.Items, framework)
	pdfBytes, err := renderComplianceEvidencePDF(report, len(result.Items), createdAt)
	if err != nil {
		return nil, "", err
	}
	filename := fmt.Sprintf("compliance-%s-%s.pdf", framework, createdAt.Format("2006-01-02"))
	return pdfBytes, filename, nil
}

// evidenceEmailSubjectBody returns the subject and plain-text body for a pack.
func evidenceEmailSubjectBody(framework string, createdAt time.Time) (string, string) {
	fw := frameworkDisplayName(framework)
	subject := fmt.Sprintf("%s — %s Compliance Evidence Pack (%s)", orgName(), fw, createdAt.Format("2006-01-02"))
	body := fmt.Sprintf("Attached is the %s compliance evidence pack for %s, generated %s by Kryptkeeper.\n\nThis pack maps the framework's controls to your live certificate posture.",
		fw, orgName(), createdAt.Format("2006-01-02 15:04 MST"))
	return subject, body
}

// registerEvidenceHandlers mounts schedule CRUD and the manual-send endpoint.
func registerEvidenceHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, caProvider CAProvider, store EvidenceScheduleStore, mailer *EvidenceMailer, auditProvider AuditProvider) {
	// GET/POST /api/v1/reports/evidence/schedules
	mux.HandleFunc("/api/v1/reports/evidence/schedules", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		// W2-03/D-102: evidence schedules/packs are fleet-wide (no tenant field
		// on EvidenceSchedule, and the pack composes every CA/cert) —
		// aggregate-super-admin-only.
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "schedule store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := store.List(r.Context())
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Data []EvidenceSchedule `json:"data"`
			}{Data: list})
		case http.MethodPost:
			var req EvidenceSchedule
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			if req.Framework == "" || len(req.Recipients) == 0 {
				writeBadRequest(w, "framework and recipients are required")
				return
			}
			if req.Cadence == "" {
				req.Cadence = "monthly"
			}
			created, err := store.Create(r.Context(), req)
			if err != nil {
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_create", "evidence-schedule", created.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data EvidenceSchedule `json:"data"`
			}{Data: created})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	// DELETE /api/v1/reports/evidence/schedules/{id}
	mux.HandleFunc("/api/v1/reports/evidence/schedules/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "schedule store unavailable")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/evidence/schedules/")
		if id == "" {
			writeBadRequest(w, "schedule id required")
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_delete", "evidence-schedule", id, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})

	// POST /api/v1/reports/evidence/send — render + email now.
	mux.HandleFunc("/api/v1/reports/evidence/send", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			Framework  string   `json:"framework"`
			Recipients []string `json:"recipients"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON")
			return
		}
		if req.Framework == "" {
			req.Framework = "all"
		}
		if len(req.Recipients) == 0 {
			writeBadRequest(w, "recipients are required")
			return
		}
		if mailer == nil || !mailer.Enabled() {
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", req.Framework, AuditOutcomeFailure)
			writeBadRequest(w, "SMTP not configured (set SMTP_HOST and SMTP_FROM)")
			return
		}
		now := time.Now().UTC()
		pdfBytes, filename, err := renderEvidencePackForFramework(r.Context(), certProvider, caProvider, req.Framework, now)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", req.Framework, AuditOutcomeFailure)
			writeServiceUnavailable(w, "render failed")
			return
		}
		subject, body := evidenceEmailSubjectBody(req.Framework, now)
		if err := mailer.Send(req.Recipients, subject, body, pdfBytes, filename); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", req.Framework, AuditOutcomeFailure)
			writeServiceUnavailable(w, "send failed: "+err.Error())
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", req.Framework, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "sent", "recipients": len(req.Recipients)})
	})
}
