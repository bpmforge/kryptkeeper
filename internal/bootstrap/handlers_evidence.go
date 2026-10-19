// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"sort"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// AcceptedRisk is one active accepted-risk exception as the evidence pack
// shows it: what was excused, by whom, why, until when, and who owns the
// certificate (W22-32). Expired exceptions are not listed.
type AcceptedRisk struct {
	ID                string `json:"id"`
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	FindingCode       string `json:"finding_code"`
	JustificationCode string `json:"justification_code"`
	JustificationNote string `json:"justification_note,omitempty"`
	OwnerTeam         string `json:"owner_team"`
	OwnerEmail        string `json:"owner_email"`
	// TargetLabel names a target_file exception's file as host:path.
	TargetLabel string `json:"target_label,omitempty"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
}

// buildAcceptedRisks lists the active exceptions whose target is in the
// caller's visible certs or cas. Matching against the already tenant-scoped
// inventory is what keeps a tenant's pack from naming another tenant's
// exceptions. The result is never nil, so the JSON is [] rather than null.
func buildAcceptedRisks(ctx context.Context, store FindingExceptionStore, certs []CertificateItem, cas []CAListItem, now time.Time) []AcceptedRisk {
	out := []AcceptedRisk{}
	if store == nil {
		return out
	}
	active, err := store.ListActive(ctx, now)
	if err != nil {
		logging.Warnf("accepted risks unavailable, evidence pack lists none: %v", err)
		return out
	}
	byFP := make(map[string]CertificateItem, len(certs))
	for _, c := range certs {
		byFP[c.FingerprintSHA256] = c
	}
	caIDs := make(map[string]bool, len(cas))
	for _, c := range cas {
		caIDs[c.ID] = true
	}
	for _, e := range active {
		r := AcceptedRisk{
			ID: e.ID, TargetType: e.TargetType, TargetID: e.TargetID, FindingCode: e.FindingCode,
			JustificationCode: e.JustificationCode, JustificationNote: e.JustificationNote,
			CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt,
		}
		switch e.TargetType {
		case FindingExceptionTargetCertificate:
			c, ok := byFP[e.TargetID]
			if !ok {
				continue
			}
			r.OwnerTeam, r.OwnerEmail = c.OwnerTeam, c.OwnerEmail
		case FindingExceptionTargetCA:
			if !caIDs[e.TargetID] {
				continue
			}
		case FindingExceptionTargetFile:
			// A file is in the caller's scope when a certificate that lives in
			// it is: the inventory is already tenant-scoped, and the file's own
			// tenant column is not visible to this builder.
			files := exceptionFiles(store)
			if files == nil {
				continue
			}
			ref, found, err := files.LookupDiscoveredFile(ctx, e.TargetID)
			if err != nil || !found {
				continue
			}
			owner, ok := CertificateItem{}, false
			for _, fp := range ref.Fingerprints {
				if c, in := byFP[fp]; in {
					owner, ok = c, true
					break
				}
			}
			if !ok {
				continue
			}
			r.OwnerTeam, r.OwnerEmail, r.TargetLabel = owner.OwnerTeam, owner.OwnerEmail, ref.Host+":"+ref.Path
		default:
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExpiresAt != out[j].ExpiresAt {
			return out[i].ExpiresAt < out[j].ExpiresAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// renderEvidencePackForFramework builds the compliance evidence PDF for a
// framework, returning the bytes and a suggested filename. Shared by the manual
// send endpoint and the scheduler. The exception store soft-fails like every
// other finding surface: without it the pack lists no accepted risks.
func renderEvidencePackForFramework(ctx context.Context, certProvider CertificateProvider, caProvider CAProvider, framework string, createdAt time.Time) ([]byte, string, error) {
	store, _ := newFindingExceptionStoreFromEnv()
	return renderEvidencePackWithExceptions(ctx, certProvider, caProvider, store, framework, createdAt)
}

func renderEvidencePackWithExceptions(ctx context.Context, certProvider CertificateProvider, caProvider CAProvider, store FindingExceptionStore, framework string, createdAt time.Time) ([]byte, string, error) {
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
	attestStore := NewComplianceAttestationStoreFromEnv()
	applyManualControls(ctx, attestStore, &report, createdAt)
	closeAttestationStore(attestStore)
	report.AcceptedRisks = buildAcceptedRisks(ctx, store, result.Items, cas.Items, createdAt)
	report.KeyCustody, report.KeyCustodyNote = loadPackCustody(ctx)
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
			emitAuditEvent(r, auditProvider, "", "evidence.schedule_create", "evidence", "-", AuditOutcomeDenied)
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
			// An omitted "enabled" means enabled: the column defaults to 1 and a
			// 201 for a schedule that can never send is a silent failure (W28-13).
			req := EvidenceSchedule{Enabled: true}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_create", "evidence-schedule", "-", AuditOutcomeFailure)
				writeBadRequest(w, "invalid JSON")
				return
			}
			if req.Framework == "" || len(req.Recipients) == 0 {
				emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_create", "evidence-schedule", "-", AuditOutcomeFailure)
				writeBadRequest(w, "framework and recipients are required")
				return
			}
			if req.Cadence == "" {
				req.Cadence = "monthly"
			}
			created, err := store.Create(r.Context(), req)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_create", "evidence-schedule", "-", AuditOutcomeFailure)
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
			emitAuditEvent(r, auditProvider, "", "evidence.schedule_delete", "evidence", "-", AuditOutcomeDenied)
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
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_delete", "evidence-schedule", id, AuditOutcomeFailure)
			writeBadRequest(w, "schedule id required")
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.schedule_delete", "evidence-schedule", id, AuditOutcomeFailure)
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
			emitAuditEvent(r, auditProvider, "", "evidence.send", "evidence", "-", AuditOutcomeDenied)
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
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid JSON")
			return
		}
		if req.Framework == "" {
			req.Framework = "all"
		}
		if len(req.Recipients) == 0 {
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", "-", AuditOutcomeFailure)
			writeBadRequest(w, "recipients are required")
			return
		}
		if msg := validateEvidenceRecipients(req.Recipients); msg != "" {
			emitAuditEvent(r, auditProvider, principal.ID, "evidence.send", "evidence", "-", AuditOutcomeFailure)
			writeBadRequest(w, msg)
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

// maxEvidenceRecipients bounds one ad-hoc evidence send. The pack is a
// compliance artifact, so a request is meant for a handful of auditors, not a
// mailing list.
const maxEvidenceRecipients = 20

// validateEvidenceRecipients returns a client-facing reason when the list is
// too long or holds anything but a bare address. A display name or a second
// address smuggled into one entry would widen who receives the pack beyond
// what the audit row records.
func validateEvidenceRecipients(recipients []string) string {
	if len(recipients) > maxEvidenceRecipients {
		return fmt.Sprintf("at most %d recipients are allowed", maxEvidenceRecipients)
	}
	for _, rcpt := range recipients {
		addr, err := mail.ParseAddress(rcpt)
		if err != nil || addr.Name != "" || addr.Address != strings.TrimSpace(rcpt) {
			return "each recipient must be a plain email address"
		}
	}
	return ""
}
