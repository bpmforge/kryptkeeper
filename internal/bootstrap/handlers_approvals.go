// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// isApproverForTemplate returns true if the principal's role is allowed to approve
// requests for the given template. pki-admin can always approve.
func isApproverForTemplate(role string, approvalRoles []string) bool {
	if isAdminRole(role) {
		return true
	}
	for _, r := range approvalRoles {
		if strings.EqualFold(strings.TrimSpace(r), strings.TrimSpace(role)) {
			return true
		}
	}
	return false
}

func registerApprovalHandlers(
	mux *http.ServeMux,
	auth *Authenticator,
	store ApprovalStore,
	certProvider CertificateProvider,
	templateProvider TemplateProvider,
	auditProvider AuditProvider,
) {
	if store == nil {
		return
	}

	// GET  /api/v1/approvals         — list (filtered by ?status=pending|approved|rejected)
	// GET  /api/v1/approvals/{id}    — get one
	// POST /api/v1/approvals/{id}/approve — approve and issue cert
	// POST /api/v1/approvals/{id}/reject  — reject with reason

	mux.HandleFunc("/api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "approval.list", "approval", "approvals", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		// Any authenticated user can list their own requests; admins see all.
		status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err2 := strconv.Atoi(v); err2 == nil && n > 0 {
				limit = n
			}
		}
		offset := 0
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err2 := strconv.Atoi(v); err2 == nil && n >= 0 {
				offset = n
			}
		}

		items, total, err := store.List(r.Context(), status, limit, offset)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "approval.list", "approval", "approvals", AuditOutcomeFailure)
			writeServiceUnavailable(w, "approval store unavailable")
			return
		}
		// Non-admins see only their own requests.
		if !isAdminRole(pd.Role) {
			filtered := items[:0]
			for _, item := range items {
				if item.Requester == pd.ID {
					filtered = append(filtered, item)
				}
			}
			items = filtered
		}
		// Tenant isolation: scope approval requests by their CA's tenant.
		items = filterApprovalsByTenant(r.Context(), activeTenantStore, pd, items)
		emitAuditEvent(r, auditProvider, pd.ID, "approval.list", "approval", "approvals", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data []ApprovalRequest `json:"data"`
			Meta struct {
				Total  int `json:"total"`
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
			} `json:"meta"`
		}{
			Data: items,
			Meta: struct {
				Total  int `json:"total"`
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
			}{Total: total, Limit: limit, Offset: offset},
		})
	})

	mux.HandleFunc("/api/v1/approvals/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "approval.op", "approval", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/")

		if strings.HasSuffix(tail, "/approve") {
			id := strings.TrimSuffix(tail, "/approve")
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			handleApprove(w, r, auth, pd, id, store, certProvider, templateProvider, auditProvider)
			return
		}

		if strings.HasSuffix(tail, "/reject") {
			id := strings.TrimSuffix(tail, "/reject")
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			handleReject(w, r, pd, id, store, auditProvider)
			return
		}

		// GET /api/v1/approvals/{id}
		id := tail
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "approval request not found")
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		apr, err := store.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, errApprovalNotFound) {
				writeNotFound(w, "approval request not found")
				return
			}
			writeServiceUnavailable(w, "approval store unavailable")
			return
		}
		// Non-admins can only see their own requests.
		if !isAdminRole(pd.Role) && apr.Requester != pd.ID {
			writeForbidden(w, "forbidden")
			return
		}
		if !caVisibleToTenant(r.Context(), activeTenantStore, pd, apr.CAID) {
			writeForbidden(w, "forbidden")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Data ApprovalRequest `json:"data"`
		}{Data: apr})
	})
}

func handleApprove(
	w http.ResponseWriter, r *http.Request,
	auth *Authenticator,
	pd AuthPrincipal, id string,
	store ApprovalStore,
	certProvider CertificateProvider,
	templateProvider TemplateProvider,
	auditProvider AuditProvider,
) {
	apr, err := store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, errApprovalNotFound) {
			emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeFailure)
			writeNotFound(w, "approval request not found")
			return
		}
		writeServiceUnavailable(w, "approval store unavailable")
		return
	}
	if !caVisibleToTenant(r.Context(), activeTenantStore, pd, apr.CAID) {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}

	// Check role against template's approval_roles.
	tpl, found, terr := templateProvider.GetTemplate(r.Context(), apr.TemplateID)
	if terr != nil || !found {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "template lookup failed")
		return
	}
	if !isApproverForTemplate(pd.Role, tpl.ApprovalRoles) {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied)
		writeForbidden(w, "your role is not authorized to approve this template")
		return
	}
	// Proposer ≠ approver is structural in this product
	// (handlers_pending_actions.go enforces the same rule): the raiser of
	// a CSR must not be the one who approves it, regardless of role.
	// RC1-B-01: decided on the human behind the credential, and never by the
	// bootstrap token or a key minted with it.
	if msg := auth.approverRefusal(pd, apr.Requester); msg != "" {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied)
		writeForbidden(w, msg)
		return
	}

	if apr.Status != "pending" {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeFailure)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"conflict","message":"approval request is not pending"}`))
		return
	}

	// Mark approved before issuing so the record is consistent even if issuance fails.
	if err := store.Decide(r.Context(), id, pd.ID, "approved", ""); err != nil {
		if errors.Is(err, errApprovalDecided) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"conflict","message":"approval request already decided"}`))
			return
		}
		writeServiceUnavailable(w, "approval store unavailable")
		return
	}

	// Issue the certificate now.
	issueReq := CertificateIssueRequest{
		CSRPEM:     apr.CSRPEM,
		CAID:       apr.CAID,
		TemplateID: apr.TemplateID,
		TeamID:     apr.TeamID,
	}
	// Temporarily bypass approval check by using a context marker.
	issued, err := certProvider.IssueCertificate(
		context.WithValue(r.Context(), approvalBypassKey{}, true), issueReq)
	if err != nil {
		log.Printf("cert issuance after approval failed for %s: %v", id, err)
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeIssuanceFailed)
		writeServiceUnavailable(w, fmt.Sprintf("issuance failed after approval: %v", err))
		return
	}

	_ = store.SetIssued(r.Context(), id, issued.FingerprintSHA256) // cert already issued; store status update is best-effort bookkeeping
	emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeSuccess,
		fmt.Sprintf(`{"fingerprint":%q,"cn":%q}`, issued.FingerprintSHA256, issued.CommonName))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/certificates/"+issued.FingerprintSHA256)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Data CertificateIssueResult `json:"data"`
	}{Data: issued})
}

func handleReject(
	w http.ResponseWriter, r *http.Request,
	pd AuthPrincipal, id string,
	store ApprovalStore,
	auditProvider AuditProvider,
) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&body); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	apr, err := store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, errApprovalNotFound) {
			emitAuditEvent(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeFailure)
			writeNotFound(w, "approval request not found")
			return
		}
		writeServiceUnavailable(w, "approval store unavailable")
		return
	}
	if !caVisibleToTenant(r.Context(), activeTenantStore, pd, apr.CAID) {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	if apr.Status != "pending" {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeFailure)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"conflict","message":"approval request is not pending"}`))
		return
	}
	if err := store.Decide(r.Context(), id, pd.ID, "rejected", body.Reason); err != nil {
		if errors.Is(err, errApprovalDecided) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"conflict","message":"approval request already decided"}`))
			return
		}
		writeServiceUnavailable(w, "approval store unavailable")
		return
	}

	emitAuditEventDetail(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeSuccess,
		fmt.Sprintf(`{"reason":%q}`, body.Reason))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"rejected"}`))
}

// approvalBypassKey is a context key used to let the approval handler re-call
// IssueCertificate without triggering another approval check.
type approvalBypassKey struct{}
