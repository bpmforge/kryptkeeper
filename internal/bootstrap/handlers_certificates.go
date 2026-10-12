// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

const (
	maxCertificateIssueBodyBytes  int64 = 256 * 1024
	maxCertificateRenewBodyBytes  int64 = 256 * 1024
	maxCertificateImportBodyBytes int64 = 512 * 1024
	maxCertificateRevokeBodyBytes int64 = 16 * 1024
)

// S-37: a denied certificate mutation used to answer with the same bare
// {"error":"forbidden"} whether the caller's team didn't own the resource or
// their tenant couldn't see it, and wrote nothing to the server log either —
// so neither the caller nor an operator reading logs could tell which gate
// fired. These two messages, plus denyCertificateAccess below, keep the two
// reasons distinguishable without naming the tenant or team that actually
// owns the resource (that would leak cross-tenant data through the refusal
// itself).
const (
	certificateTeamScopeDeniedMessage      = "forbidden: certificate does not belong to your team"
	certificateCATenantDeniedMessage       = "forbidden: certificate authority is not visible in your tenant"
	certificateTemplateTenantDeniedMessage = "forbidden: template is not visible in your tenant"
)

var (
	errCertificateTeamScopeForbidden = errors.New("certificate team scope forbidden")
	errCertificateTenantForbidden    = errors.New("certificate tenant forbidden")
)

// maxLoggedDenialValueRunes bounds the offending field's value before it is
// written to the server log, so a single request cannot inflate one denial
// line beyond a few hundred bytes (a request body up to
// maxCertificateIssueBodyBytes could otherwise turn that field into a
// flooding vector).
const maxLoggedDenialValueRunes = 128

// truncateForLog bounds s to at most maxLoggedDenialValueRunes runes,
// appending a marker if it was cut.
func truncateForLog(s string) string {
	r := []rune(s)
	if len(r) <= maxLoggedDenialValueRunes {
		return s
	}
	return string(r[:maxLoggedDenialValueRunes]) + "...(truncated)"
}

// denyCertificateAccess logs the denial server-side with the principal, the
// field that failed, and why, audits it with the same detail (the audit
// event previously carried outcome "denied" with no reason at all), and
// writes the 403. value is the offending field's own value (e.g. the CA or
// team ID) -- safe to log since the operator reading server logs already has
// every tenant's data, but never included in the response body. principal,
// field and value are attacker-controlled (value in particular comes
// straight from the request body) so they are logged with %q: unescaped,
// a newline in any of them would let a caller forge a second, fully-formed
// denial line attributing a fabricated event to another principal.
func denyCertificateAccess(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, principal, action, resourceID, field, value, reason, message string) {
	log.Printf("certificate %s denied: principal=%q field=%q value=%q reason=%s", action, principal, field, truncateForLog(value), reason)
	emitAuditEventDetail(r, auditProvider, principal, action, "certificate", resourceID, AuditOutcomeDenied, fmt.Sprintf("field=%s reason=%s", field, reason))
	writeForbidden(w, message)
}

func registerCertificateHandlers(mux *http.ServeMux, auth *Authenticator, provider CertificateProvider, auditProvider AuditProvider, approvalStore ApprovalStore) {
	mux.HandleFunc("/api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			auditAction := "certificate.list"
			if r.Method == http.MethodPost {
				auditAction = "certificate.issue"
			}
			emitAuditEvent(r, auditProvider, "", auditAction, "certificate", "certificates", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		if r.Method == http.MethodPost {
			body := http.MaxBytesReader(w, r.Body, maxCertificateIssueBodyBytes)
			defer body.Close()
			raw, err := io.ReadAll(body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			req, err := parseCertificateIssueRequest(raw)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			if err := authorizeCertificateMutationRequest(pd, &req.TeamID); err != nil {
				denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.issue", "certificates", "team_id", req.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
				return
			}
			if !caVisibleToTenant(r.Context(), activeTenantStore, pd, req.CAID) {
				denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.issue", "certificates", "ca_id", req.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
				return
			}
			if !templateVisibleToTenant(r.Context(), activeTenantStore, pd, req.TemplateID) {
				denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.issue", "certificates", "template_id", req.TemplateID, "tenant_visibility", certificateTemplateTenantDeniedMessage)
				return
			}

			issued, err := provider.IssueCertificate(r.Context(), req)
			if err != nil {
				if errors.Is(err, errApprovalRequired) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomePendingApproval)
					if approvalStore == nil {
						writeServiceUnavailable(w, "approval store not configured")
						return
					}
					approvalID, aerr := newApprovalID()
					if aerr != nil {
						log.Printf("approval ID generation failed: %v", aerr)
						writeServiceUnavailable(w, "approval request failed")
						return
					}
					apr := ApprovalRequest{
						ID:          approvalID,
						TemplateID:  req.TemplateID,
						CAID:        req.CAID,
						Requester:   pd.ID,
						CSRPEM:      req.CSRPEM,
						TeamID:      req.TeamID,
						RequestedAt: time.Now().UTC().Format(time.RFC3339),
					}
					if aerr := approvalStore.Create(r.Context(), apr); aerr != nil {
						log.Printf("approval request creation failed: %v", aerr)
						writeServiceUnavailable(w, "approval request failed")
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Location", "/api/v1/approvals/"+approvalID)
					w.WriteHeader(http.StatusAccepted)
					body := fmt.Sprintf(`{"status":"pending_approval","approval_id":%q,"message":"issuance requires approval — check /api/v1/approvals/%s"}`, approvalID, approvalID)
					_, _ = w.Write([]byte(body))
					return
				}
				if errors.Is(err, errCertificateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"certificate with this fingerprint already exists"}`))
					return
				}
				if errors.Is(err, errCertificateInvalid) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}
				if errors.Is(err, ca.ErrPolicyViolation) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					body := fmt.Sprintf(`{"error":"policy_violation","message":%q}`, err.Error())
					_, _ = w.Write([]byte(body))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure)
				log.Printf("certificate issue unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}

			issueSummary := fmt.Sprintf(`{"cn":%q,"template_id":%q,"ca_id":%q,"algorithm":%q}`,
				issued.CommonName, issued.TemplateID, issued.CAID, issued.PublicKeyAlgorithm)
			if req.TemplateID == "" {
				// SUP-A04-3: no template means no name policy; the audit trail says so.
				issueSummary = fmt.Sprintf(`{"cn":%q,"template_id":"","ca_id":%q,"algorithm":%q,"name_policy":"none (no template)"}`,
					issued.CommonName, issued.CAID, issued.PublicKeyAlgorithm)
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.issue", "certificate", issued.FingerprintSHA256, AuditOutcomeSuccess, issueSummary)
			resp := struct {
				Data CertificateIssueResult `json:"data"`
			}{Data: issued}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "/api/v1/certificates/"+issued.FingerprintSHA256)
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/certificates issue response: %v", err)
			}
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, "GET, POST")
			return
		}

		query := CertificateListQuery{
			Limit:           parseCertificateLimit(r.URL.Query().Get("limit"), 25),
			Offset:          parseCertificateOffset(r.URL.Query().Get("cursor")),
			Q:               strings.TrimSpace(r.URL.Query().Get("q")),
			CAID:            strings.TrimSpace(r.URL.Query().Get("ca_id")),
			TemplateID:      strings.TrimSpace(r.URL.Query().Get("template_id")),
			TeamID:          strings.TrimSpace(r.URL.Query().Get("team_id")),
			Origin:          strings.TrimSpace(r.URL.Query().Get("origin")),
			ManagementState: strings.TrimSpace(r.URL.Query().Get("management_state")),
			Status:          strings.TrimSpace(r.URL.Query().Get("status")),
			Grades:          strings.Split(strings.TrimSpace(r.URL.Query().Get("grade")), ","),
			Order:           strings.TrimSpace(r.URL.Query().Get("order")),
		}
		if err := authorizeCertificateListQuery(&query, pd); err != nil {
			// S-57: the last bare denial in the file — list has exactly one
			// refusal reason (a non-admin asking for another team's list).
			denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.list", "certificates", "team_id", query.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
			return
		}

		// S-54: for a tenant-scoped principal the tenant filter must apply
		// BEFORE pagination — the provider paginates the unfiltered set, so
		// filtering its page rows post-hoc leaves Meta.Total as the global
		// cross-tenant count and advances the cursor against it (overlapping
		// pages and "2 of 5000" displays). Latent until S-36 let a
		// tenant-scoped pki-admin skip the team_id confinement that used to
		// mask this branch.
		tenantScoped := activeTenantStore != nil && !tenantBypass(pd)
		var result CertificateListResult
		if tenantScoped {
			visible, err := listCertificatesTenantFiltered(r.Context(), provider, activeTenantStore, pd, query)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.list", "certificate", "certificates", AuditOutcomeFailure)
				log.Printf("certificate list unavailable: %v", err)
				writeServiceUnavailable(w, "certificate list unavailable")
				return
			}
			limit := query.Limit
			if limit <= 0 {
				limit = 25
			}
			if limit > 100 {
				limit = 100
			}
			start := query.Offset
			if start < 0 {
				start = 0
			}
			if start > len(visible) {
				start = len(visible)
			}
			end := start + limit
			if end > len(visible) {
				end = len(visible)
			}
			result = CertificateListResult{Items: visible[start:end], Total: len(visible), Limit: limit}
		} else {
			var err error
			result, err = provider.ListCertificates(r.Context(), query)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.list", "certificate", "certificates", AuditOutcomeFailure)
				log.Printf("certificate list unavailable: %v", err)
				writeServiceUnavailable(w, "certificate list unavailable")
				return
			}
		}
		emitAuditEvent(r, auditProvider, pd.ID, "certificate.list", "certificate", "certificates", AuditOutcomeSuccess)

		resp := struct {
			Data []CertificateItem `json:"data"`
			Meta struct {
				Total      int     `json:"total"`
				Limit      int     `json:"limit"`
				NextCursor *string `json:"next_cursor"`
				PrevCursor *string `json:"prev_cursor"`
			} `json:"meta"`
		}{Data: result.Items}
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		nextOffset := query.Offset + len(result.Items)
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
			log.Printf("failed to encode /api/v1/certificates response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/certificates/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			auditAction := "certificate.get"
			if strings.HasSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/"), "/chain") {
				auditAction = "certificate.chain"
			}
			if strings.HasSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/"), "/revoke") {
				auditAction = "certificate.revoke"
			}
			emitAuditEvent(r, auditProvider, "", auditAction, "certificate", "fingerprint", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
		if tail == "import" {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}

			body := http.MaxBytesReader(w, r.Body, maxCertificateImportBodyBytes)
			defer body.Close()
			raw, err := io.ReadAll(body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.import", "certificate", "import", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			req, err := parseCertificateImportRequest(raw)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.import", "certificate", "import", AuditOutcomeFailure)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			if err := authorizeCertificateMutationRequest(pd, &req.TeamID); err != nil {
				denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.import", "import", "team_id", req.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
				return
			}

			imported, err := provider.ImportCertificate(r.Context(), req)
			if err != nil {
				if errors.Is(err, errCertificateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.import", "certificate", "import", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"certificate with this fingerprint already exists"}`))
					return
				}
				if errors.Is(err, errCertificateInvalid) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.import", "certificate", "import", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.import", "certificate", "import", AuditOutcomeFailure)
				log.Printf("certificate import unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}

			emitAuditEvent(r, auditProvider, pd.ID, "certificate.import", "certificate", imported.FingerprintSHA256, AuditOutcomeSuccess)
			resp := struct {
				Data CertificateIssueResult `json:"data"`
			}{Data: imported}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "/api/v1/certificates/"+imported.FingerprintSHA256)
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/certificates/import response: %v", err)
			}
			return
		}

		if tail == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.get", "certificate", "", AuditOutcomeFailure)
			writeNotFound(w, "certificate not found")
			return
		}

		if strings.HasSuffix(tail, "/chain") {
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			fp := strings.TrimSuffix(tail, "/chain")
			if fp == "" || strings.Contains(fp, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.chain", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
				return
			}
			item, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.chain", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateTeamScopeForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.chain", fp, "team_id", item.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
					return
				}
				if errors.Is(err, errCertificateTenantForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.chain", fp, "ca_id", item.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.chain", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate chain unavailable: %v", err)
				writeServiceUnavailable(w, "certificate chain unavailable")
				return
			}

			chain, found, err := provider.GetCertificateChain(r.Context(), fp)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.chain", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate chain unavailable: %v", err)
				writeServiceUnavailable(w, "certificate chain unavailable")
				return
			}
			if !found {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.chain", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
				return
			}

			emitAuditEvent(r, auditProvider, pd.ID, "certificate.chain", "certificate", fp, AuditOutcomeSuccess)
			resp := struct {
				Data CertificateChainResult `json:"data"`
			}{Data: chain}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/certificates/{fingerprint}/chain response: %v", err)
			}
			return
		}

		if strings.HasSuffix(tail, "/revoke") {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			fp := strings.TrimSuffix(tail, "/revoke")
			if fp == "" || strings.Contains(fp, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
				return
			}
			item, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateTeamScopeForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.revoke", fp, "team_id", item.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
					return
				}
				if errors.Is(err, errCertificateTenantForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.revoke", fp, "ca_id", item.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate revoke unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}

			body := http.MaxBytesReader(w, r.Body, maxCertificateRevokeBodyBytes)
			defer body.Close()
			req, err := parseCertificateRevokeRequest(body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}

			revoked, err := provider.RevokeCertificate(r.Context(), fp, req)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"certificate is already revoked or expired"}`))
					return
				}
				if errors.Is(err, errCertificateInvalid) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate revoke unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}

			revokeSummary := fmt.Sprintf(`{"fingerprint":%q,"reason":%d}`, fp, req.ReasonCode)
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.revoke", "certificate", fp, AuditOutcomeSuccess, revokeSummary)
			resp := struct {
				Data CertificateRevokeResult `json:"data"`
			}{Data: revoked}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/certificates/{fingerprint}/revoke response: %v", err)
			}
			return
		}

		if strings.HasSuffix(tail, "/renew") {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			fp := strings.TrimSuffix(tail, "/renew")
			if fp == "" || strings.Contains(fp, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
				return
			}
			item, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateTeamScopeForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.renew", fp, "team_id", item.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
					return
				}
				if errors.Is(err, errCertificateTenantForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.renew", fp, "ca_id", item.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate renew unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}

			body := http.MaxBytesReader(w, r.Body, maxCertificateRenewBodyBytes)
			defer body.Close()
			raw, err := io.ReadAll(body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			req, err := parseCertificateRenewRequest(raw)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}

			renewed, err := provider.RenewCertificate(r.Context(), fp, req)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"certificate already has an active successor"}`))
					return
				}
				if errors.Is(err, errCertificateInvalid) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate renew unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}

			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew", "certificate", fp, AuditOutcomeSuccess)
			resp := struct {
				Data CertificateIssueResult `json:"data"`
			}{Data: renewed}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "/api/v1/certificates/"+renewed.FingerprintSHA256)
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/certificates/{fingerprint}/renew response: %v", err)
			}
			return
		}

		if strings.HasSuffix(tail, "/ownership") {
			if r.Method != http.MethodPatch {
				writeMethodNotAllowed(w, http.MethodPatch)
				return
			}
			fp := strings.TrimSuffix(tail, "/ownership")
			if fp == "" || strings.Contains(fp, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
				return
			}
			item, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateTeamScopeForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.ownership_update", fp, "team_id", item.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
					return
				}
				if errors.Is(err, errCertificateTenantForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.ownership_update", fp, "ca_id", item.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeFailure)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}
			var req CertificateOwnershipRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}
			updated, err := provider.UpdateOwnership(r.Context(), fp, req)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeFailure)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}
			ownerSummary := fmt.Sprintf(`{"owner_email":%q,"owner_team":%q,"service_name":%q}`,
				req.OwnerEmail, req.OwnerTeam, req.ServiceName)
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.ownership_update", "certificate", fp, AuditOutcomeSuccess, ownerSummary)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Data CertificateItem `json:"data"`
			}{Data: updated})
			return
		}

		if strings.HasSuffix(tail, "/download") {
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			fp := strings.TrimSuffix(tail, "/download")
			if fp == "" || strings.Contains(fp, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
				return
			}
			item, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, fp)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateTeamScopeForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.download", fp, "team_id", item.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
					return
				}
				if errors.Is(err, errCertificateTenantForbidden) {
					denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.download", fp, "ca_id", item.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate download unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}
			format := strings.TrimSpace(r.URL.Query().Get("format"))
			includeChain := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("include_chain")), "true")
			download, err := provider.DownloadCertificate(r.Context(), fp, format, includeChain)
			if err != nil {
				if errors.Is(err, errCertificateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeFailure)
					writeNotFound(w, "certificate not found")
					return
				}
				if errors.Is(err, errCertificateInvalid) {
					emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid format parameter"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeFailure)
				log.Printf("certificate download unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.download", "certificate", fp, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", download.ContentType)
			w.Header().Set("Content-Disposition", attachmentDisposition(download.Filename))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(download.Body)
			return
		}

		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}

		fingerprint := tail
		if strings.Contains(fingerprint, "/") {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.get", "certificate", fingerprint, AuditOutcomeFailure)
			writeNotFound(w, "certificate not found")
			return
		}

		item, found, err := provider.GetCertificate(r.Context(), fingerprint)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.get", "certificate", fingerprint, AuditOutcomeFailure)
			log.Printf("certificate get unavailable: %v", err)
			writeServiceUnavailable(w, "certificate unavailable")
			return
		}
		if !found {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.get", "certificate", fingerprint, AuditOutcomeFailure)
			writeNotFound(w, "certificate not found")
			return
		}
		if !isCertificateAdmin(pd) && strings.TrimSpace(item.TeamID) != pd.ID {
			denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.get", fingerprint, "team_id", item.TeamID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
			return
		}
		if !caVisibleToTenant(r.Context(), activeTenantStore, pd, item.CAID) {
			denyCertificateAccess(w, r, auditProvider, pd.ID, "certificate.get", fingerprint, "ca_id", item.CAID, "tenant_visibility", certificateCATenantDeniedMessage)
			return
		}

		emitAuditEvent(r, auditProvider, pd.ID, "certificate.get", "certificate", fingerprint, AuditOutcomeSuccess)
		etag := strconv.Itoa(item.ETag)
		if etag == "0" {
			etag = "1"
		}
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		resp := struct {
			Data CertificateDetail `json:"data"`
		}{Data: item}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/certificates/{fingerprint} response: %v", err)
		}
	})
}

func parseCertificateRevokeRequest(body io.Reader) (CertificateRevokeRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		if isBodyTooLarge(err) {
			return CertificateRevokeRequest{}, errBodyTooLarge
		}
		return CertificateRevokeRequest{}, errCertificateInvalid
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return CertificateRevokeRequest{}, errCertificateInvalid
	}
	var req CertificateRevokeRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return CertificateRevokeRequest{}, errCertificateInvalid
	}
	if req.ReasonCode < 0 {
		return CertificateRevokeRequest{}, errCertificateInvalid
	}
	return req, nil
}

// listCertificatesTenantFiltered pages through the provider's UNFILTERED
// result and returns every row visible to the tenant-scoped principal —
// the caller paginates the filtered slice, so totals and cursors reflect
// what the caller may actually see (S-54). The loop advances by the rows
// each provider page actually returned and stops when a page comes back
// short or empty, so a provider whose Total disagrees with its rows
// cannot spin it (the S-62 lesson: paging loops written against Total
// alone reintroduce count mismatches).
func listCertificatesTenantFiltered(ctx context.Context, provider CertificateProvider, store TenantStore, pd AuthPrincipal, query CertificateListQuery) ([]CertificateItem, error) {
	// Tenant membership is resolved per chunk, not per row, so batch the
	// rows exactly as the paged version did.
	const batchSize = 100
	visible := make([]CertificateItem, 0)
	batch := make([]CertificateItem, 0, batchSize)
	flush := func() {
		visible = append(visible, filterCertificatesByTenant(ctx, store, pd, batch)...)
		batch = batch[:0]
	}
	err := ForEachCertificate(ctx, provider, query, func(item CertificateItem) error {
		batch = append(batch, item)
		if len(batch) == batchSize {
			flush()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	flush()
	return visible, nil
}

// isCertificateAdmin derives certificate-admin privilege from ROLE — the
// same role the rest of the product keys on (W8-08 nav, S-34 session
// claims). S-36: this replaced a principal == "bootstrap" literal that
// refused every real admin session; the bootstrap token still qualifies,
// but because authenticateBootstrap assigns it the pki-admin role, not
// because of its name. Deliberately not scope-based — wildcard scopes
// alone must not grant certificate admin (S-56).
func isCertificateAdmin(pd AuthPrincipal) bool {
	return isAdminRole(pd.Role)
}

func authorizeCertificateMutationRequest(pd AuthPrincipal, teamID *string) error {
	if isCertificateAdmin(pd) {
		return nil
	}
	if teamID == nil {
		return errCertificateForbidden
	}
	trimmed := strings.TrimSpace(*teamID)
	if trimmed == "" {
		*teamID = pd.ID
		return nil
	}
	if trimmed != pd.ID {
		return errCertificateForbidden
	}
	*teamID = trimmed
	return nil
}

func authorizeCertificateListQuery(query *CertificateListQuery, pd AuthPrincipal) error {
	if isCertificateAdmin(pd) {
		return nil
	}
	query.TeamID = strings.TrimSpace(query.TeamID)
	if query.TeamID == "" {
		query.TeamID = pd.ID
		return nil
	}
	if query.TeamID != pd.ID {
		return errCertificateForbidden
	}
	return nil
}

// authorizeCertificateResourceAccess checks both TeamID (intra-tenant grouping,
// D-022) and tenant (W2-01) access to a single certificate. TeamID admins
// bypass the TeamID check but are still tenant-scoped unless they are also a
// tenancy super-admin (tenantBypass). It returns errCertificateTeamScopeForbidden
// and errCertificateTenantForbidden as distinct sentinels (S-37) so callers can
// tell the two refusals apart; it also returns the fetched item so a caller can
// log which CA/team the denial was against without another provider round-trip.
func authorizeCertificateResourceAccess(ctx context.Context, provider CertificateProvider, pd AuthPrincipal, fingerprint string) (CertificateDetail, error) {
	item, found, err := provider.GetCertificate(ctx, fingerprint)
	if err != nil {
		return CertificateDetail{}, err
	}
	if !found {
		return CertificateDetail{}, errCertificateNotFound
	}
	if !isCertificateAdmin(pd) && strings.TrimSpace(item.TeamID) != pd.ID {
		return item, errCertificateTeamScopeForbidden
	}
	if !caVisibleToTenant(ctx, activeTenantStore, pd, item.CAID) {
		return item, errCertificateTenantForbidden
	}
	return item, nil
}
