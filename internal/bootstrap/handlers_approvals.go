// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// isApproverForTemplate returns true if the principal's role is allowed to approve
// requests for the given template. pki-admin can always approve.
// approvalsMaxListLimit caps GET /api/v1/approvals page size, matching the
// 100-row cap of the certificate and discovery list handlers.
const approvalsMaxListLimit = 100

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
	// W22-11: mounted before the nil-store return so the route does not
	// vanish when approvals are off (it then answers 503).
	registerApprovalDelegationHandlers(mux, auth, delegationStoreForApprovals(store), auditProvider)
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
				limit = min(n, approvalsMaxListLimit) // L-8: uncapped limit was a table-size read amplifier
			}
		}
		offset := 0
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err2 := strconv.Atoi(v); err2 == nil && n >= 0 {
				offset = n
			}
		}

		// L-20: a tenant-scoped caller gets total/offset over their own rows,
		// so read the whole set, filter, then window it.
		apprScoped := !tenantBypass(pd)
		var items []ApprovalRequest
		var total int
		if apprScoped {
			items, err = drainPages(func(o, l int) ([]ApprovalRequest, int, error) { return store.List(r.Context(), status, l, o) })
		} else {
			items, total, err = store.List(r.Context(), status, limit, offset)
		}
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "approval.list", "approval", "approvals", AuditOutcomeFailure)
			writeServiceUnavailable(w, "approval store unavailable")
			return
		}
		// Non-admins see their own requests plus those on templates whose
		// approval_roles name their role (the ones they can decide).
		items = newApprovalRoleScope(templateProvider).visibleTo(r.Context(), pd, items)
		// Tenant isolation: scope approval requests by their CA's tenant.
		items = filterApprovalsByTenant(r.Context(), activeTenantStore, pd, items)
		if apprScoped {
			total = len(items)
			items = pageSlice(items, offset, limit)
		}
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
		pd, err := authenticateDecider(auth, r, time.Now())
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
			handleReject(w, r, pd, id, store, templateProvider, auditProvider)
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
		// Non-admins can see their own requests and those their role may decide.
		if apr.Requester != pd.ID && !newApprovalRoleScope(templateProvider).mayDecide(r.Context(), pd.Role, apr.TemplateID) {
			writeForbidden(w, "forbidden")
			return
		}
		if !approvalVisibleToTenant(r.Context(), activeTenantStore, pd, apr) {
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
	if !approvalVisibleToTenant(r.Context(), activeTenantStore, pd, apr) {
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
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied, oboDecisionDetail(apr, pd.ID))
		writeForbidden(w, "your role is not authorized to approve this template")
		return
	}
	// Proposer ≠ approver is structural in this product
	// (handlers_pending_actions.go enforces the same rule): the raiser of
	// a CSR must not be the one who approves it, regardless of role.
	// RC1-B-01: decided on the human behind the credential, and never by the
	// bootstrap token or a key minted with it.
	if msg := auth.approverRefusal(pd, apr.Requester); msg != "" {
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied, oboDecisionDetail(apr, pd.ID))
		writeForbidden(w, msg)
		return
	}

	// W22-11: approving on behalf of a delegator. The delegate's own gates
	// above already ran; the delegation must live in the CA's tenant.
	onBehalfOf := onBehalfRequest(w, r)
	detail := delegationAuditDetail(onBehalfOf, pd.ID)
	if onBehalfOf != "" {
		if msg := authorizeOnBehalf(r.Context(), auth, delegationStoreForApprovals(store), pd, onBehalfOf, apr.Requester, approvalTenant(r.Context(), activeTenantStore, apr), time.Now()); msg != "" {
			emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied, detail)
			writeForbidden(w, msg)
			return
		}
	}

	if apr.Status != "pending" {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeFailure)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"conflict","message":"approval request is not pending"}`))
		return
	}

	// W33-21: the team policy may have tightened (or the template changed)
	// since filing. Refuse before deciding, so the request stays pending.
	if denial, perr := reevaluateTeamPolicyAtApproval(r.Context(), apr); perr != nil {
		logging.Warnf("team policy re-evaluation failed for approval %s: %v", id, perr)
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeFailure, "field=team_policy reason=enforcement_unavailable")
		writeServiceUnavailable(w, "team policy unavailable")
		return
	} else if denial != nil {
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeDenied, "field=team_policy reason="+denial.Code)
		writeForbiddenCode(w, denial.Code, denial.Message)
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

	if apr.Kind == approvalKindSSH {
		approveSSH(w, r, pd, id, apr, store, auditProvider, onBehalfOf, detail)
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
		logging.Warnf("cert issuance after approval failed for %s: %v", id, err)
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeIssuanceFailed, detail)
		writeServiceUnavailable(w, fmt.Sprintf("issuance failed after approval: %v", err))
		return
	}

	_ = store.SetIssued(r.Context(), id, issued.FingerprintSHA256) // cert already issued; store status update is best-effort bookkeeping
	approveDetail := fmt.Sprintf(`{"fingerprint":%q,"cn":%q}`, issued.FingerprintSHA256, issued.CommonName)
	if onBehalfOf != "" {
		approveDetail = fmt.Sprintf(`{"fingerprint":%q,"cn":%q,"on_behalf_of":%q,"delegate":%q}`, issued.FingerprintSHA256, issued.CommonName, onBehalfOf, pd.ID)
	}
	if apr.OnBehalfOf != "" {
		approveDetail = approvalDetailJSON(apr, pd.ID, issued.FingerprintSHA256, issued.CommonName, onBehalfOf) // W33-23
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeSuccess, approveDetail)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/certificates/"+issued.FingerprintSHA256)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Data CertificateIssueResult `json:"data"`
	}{Data: issued})
}

// approveSSH completes an approved kind="ssh" row through the hook published
// by RegisterSSHCertHandlers. Every gate (role, proposer != approver, tenant,
// pending) already ran in handleApprove, and the row is already Decided.
func approveSSH(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, id string, apr ApprovalRequest,
	store ApprovalStore, auditProvider AuditProvider, onBehalfOf, detail string) {
	issuer := sshApprovalIssuer.Load()
	if issuer == nil {
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeIssuanceFailed, detail)
		writeServiceUnavailable(w, "ssh certificate authority not available")
		return
	}
	rec, err := (*issuer)(r.Context(), apr)
	if err != nil {
		logging.Warnf("ssh cert issuance after approval failed for %s: %v", id, err)
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeIssuanceFailed, detail)
		writeServiceUnavailable(w, fmt.Sprintf("issuance failed after approval: %v", err))
		return
	}
	_ = store.SetIssued(r.Context(), id, rec.Serial) // cert already issued; store status update is best-effort bookkeeping
	approveDetail := fmt.Sprintf(`{"serial":%q,"key_id":%q}`, rec.Serial, rec.KeyID)
	if onBehalfOf != "" {
		approveDetail = fmt.Sprintf(`{"serial":%q,"key_id":%q,"on_behalf_of":%q,"delegate":%q}`, rec.Serial, rec.KeyID, onBehalfOf, pd.ID)
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, "approval.approve", "approval", id, AuditOutcomeSuccess, approveDetail)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/ssh/certificates?subject_fingerprint="+url.QueryEscape(rec.SubjectFingerprint))
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Data SSHCertRecord `json:"data"`
	}{Data: rec})
}

// approvalTenant is the tenant an approval row belongs to: stored on SSH rows,
// derived from the CA for X.509 rows.
func approvalTenant(ctx context.Context, store TenantStore, apr ApprovalRequest) string {
	if apr.Kind == approvalKindSSH {
		if apr.Tenant == "" {
			return DefaultTenant
		}
		return apr.Tenant
	}
	if store != nil {
		if t, err := store.CATenant(ctx, apr.CAID); err == nil {
			return t
		}
	}
	return DefaultTenant
}

// approvalVisibleToTenant is the per-row tenant gate for approve, reject and
// get. An SSH row has no CA, so its stored tenant decides; the store may be
// nil there and the row must still never cross tenants.
func approvalVisibleToTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, apr ApprovalRequest) bool {
	if apr.Kind == approvalKindSSH {
		return tenantBypass(pd) || approvalTenant(ctx, store, apr) == pd.Tenant
	}
	return caVisibleToTenant(ctx, store, pd, apr.CAID)
}

func handleReject(
	w http.ResponseWriter, r *http.Request,
	pd AuthPrincipal, id string,
	store ApprovalStore,
	templateProvider TemplateProvider,
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
	if !approvalVisibleToTenant(r.Context(), activeTenantStore, pd, apr) {
		emitAuditEvent(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	// F8: reject needs the same role approve needs. The write gate is the
	// only other guard and the ChatOps bridge dispatches below it, so without
	// this any identity-mapped user could reject any pending approval.
	// A missing or unreadable template leaves only the admin roles able to
	// reject, so a deleted template cannot strand its pending requests.
	tpl, tplFound, tplErr := templateProvider.GetTemplate(r.Context(), apr.TemplateID)
	if !isApproverForTemplate(pd.Role, tpl.ApprovalRoles) {
		emitAuditEventDetail(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeDenied, oboDecisionDetail(apr, pd.ID))
		writeForbidden(w, "your role is not authorized to reject this template")
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

	rejectDetail := fmt.Sprintf(`{"reason":%q}`, body.Reason)
	if apr.OnBehalfOf != "" {
		rejectDetail = oboRejectDetail(apr, pd.ID, body.Reason) // W33-23
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, "approval.reject", "approval", id, AuditOutcomeSuccess, rejectDetail)
	if tplErr == nil && tplFound {
		auditCodesignRejection(r, auditProvider, tpl, pd.ID, id)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"rejected"}`))
}

// approvalBypassKey is a context key used to let the approval handler re-call
// IssueCertificate without triggering another approval check.
type approvalBypassKey struct{}
