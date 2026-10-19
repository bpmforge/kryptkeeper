// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W33-23 (FR-P8, UC-M04): a delegate files a certificate request on behalf of
// another principal's team. The request always goes to approval, so the
// approver exists for the audit trail, and requester (the delegate),
// on_behalf_of (the delegator) and approver are all recorded.
//
// Delegation is the existing W22-11 table (approval_delegations): "may file
// for X" means an active, tenant-scoped delegation X -> caller. It is never
// inferred from team_id == caller. The request is enforced against, and
// consumes the quota of, the DELEGATOR's team (D-195 semantics apply: no
// policy row, an empty list, or a zero cap place no restriction).

const (
	oboAction           = "certificate.request_on_behalf"
	CodeOBONoDelegation = "obo_no_delegation"
	maxOBOBodyBytes     = 256 * 1024
)

type oboRequestBody struct {
	CAID       string `json:"ca_id"`
	TemplateID string `json:"template_id"`
	CSRPEM     string `json:"csr_pem"`
	OnBehalfOf string `json:"on_behalf_of"`
}

// oboAuditDetail is the JSON detail of a filing-side audit row. Requester and
// delegate are the same principal here; the approver is unknown until the
// request is decided (approval.approve / approval.reject rows carry it).
type oboAuditDetail struct {
	Requester  string `json:"requester"`
	Delegate   string `json:"delegate"`
	OnBehalfOf string `json:"on_behalf_of"`
	ApprovalID string `json:"approval_id,omitempty"`
	TemplateID string `json:"template_id,omitempty"`
	CAID       string `json:"ca_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Reused     bool   `json:"reused,omitempty"`
}

func oboDetailJSON(d oboAuditDetail) string {
	raw, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(raw)
}

// approvalAuditDetail is the decision-side audit detail for an approval.
// For an on-behalf-of request it names the requester (delegate), the
// delegator the request was filed for, and the approver. fingerprint and cn
// are omitted while empty (a denial has no certificate).
func approvalAuditDetail(apr ApprovalRequest, approver, fingerprint, cn string) string {
	return approvalDetailJSON(apr, approver, fingerprint, cn, "")
}

// approvalDetailJSON is approvalAuditDetail plus the W22-11 approver-side
// delegation: approvedOnBehalfOf is the approver the deciding delegate acted
// for (empty when the approver acted for themself).
func approvalDetailJSON(apr ApprovalRequest, approver, fingerprint, cn, approvedOnBehalfOf string) string {
	raw, err := json.Marshal(struct {
		Requester          string `json:"requester"`
		OnBehalfOf         string `json:"on_behalf_of"`
		Approver           string `json:"approver"`
		ApprovedOnBehalfOf string `json:"approved_on_behalf_of,omitempty"`
		Fingerprint        string `json:"fingerprint,omitempty"`
		CN                 string `json:"cn,omitempty"`
	}{apr.Requester, apr.OnBehalfOf, approver, approvedOnBehalfOf, fingerprint, cn})
	if err != nil {
		return ""
	}
	return string(raw)
}

func registerCertificateOBOHandlers(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider, approvalStore ApprovalStore) {
	mux.HandleFunc("POST /api/v1/certificate-requests", func(w http.ResponseWriter, r *http.Request) {
		handleCertificateOBO(w, r, auth, auditProvider, approvalStore)
	})
}

func handleCertificateOBO(w http.ResponseWriter, r *http.Request, auth *Authenticator, auditProvider AuditProvider, approvalStore ApprovalStore) {
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, "", oboAction, "approval", "approvals", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	// audit emits a filing-side row for this request; the detail always
	// carries requester and delegate (the caller) and the claimed delegator.
	var body oboRequestBody
	audit := func(outcome AuditOutcome, resourceID, reason string) {
		emitAuditEventDetail(r, auditProvider, pd.ID, oboAction, "approval", resourceID, outcome, oboDetailJSON(oboAuditDetail{
			Requester: pd.ID, Delegate: pd.ID, OnBehalfOf: truncateForLog(body.OnBehalfOf),
			TemplateID: truncateForLog(body.TemplateID), CAID: truncateForLog(body.CAID), Reason: reason,
		}))
	}
	denyCode := func(code, msg string) {
		audit(AuditOutcomeDenied, "approvals", code)
		writeForbiddenCode(w, code, msg)
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOBOBodyBytes))
	if err != nil {
		audit(AuditOutcomeFailure, "approvals", "unreadable_body")
		if rejectOversizeBody(w, err) {
			return
		}
		writeBadRequest(w, "invalid request body")
		return
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		audit(AuditOutcomeFailure, "approvals", "invalid_body")
		writeBadRequest(w, "invalid request body")
		return
	}
	body.OnBehalfOf = strings.TrimSpace(body.OnBehalfOf)
	if strings.TrimSpace(body.CAID) == "" || strings.TrimSpace(body.TemplateID) == "" || strings.TrimSpace(body.CSRPEM) == "" {
		audit(AuditOutcomeFailure, "approvals", "missing_field")
		writeBadRequest(w, "ca_id, template_id and csr_pem are required")
		return
	}
	if body.OnBehalfOf == "" {
		audit(AuditOutcomeFailure, "approvals", "on_behalf_of_required")
		writeBadRequest(w, "on_behalf_of is required")
		return
	}
	// A request for yourself is the ordinary certificate flow, and filing "for"
	// the same human through another credential would launder a self-request.
	if body.OnBehalfOf == pd.ID || auth.sameHuman(pd, body.OnBehalfOf) {
		audit(AuditOutcomeFailure, "approvals", "on_behalf_of_self")
		writeBadRequest(w, "on_behalf_of must name a different principal than the caller")
		return
	}

	// Delegation: an active delegation from the delegator to this caller, in
	// the caller's tenant. Never inferred from team_id.
	ds := delegationStoreForApprovals(approvalStore)
	if ds == nil {
		denyCode(CodeOBONoDelegation, "no active delegation from "+body.OnBehalfOf+" to you")
		return
	}
	d, ok, derr := ds.Active(r.Context(), body.OnBehalfOf, delegationScopeTenant(delegationTenant(pd)), time.Now())
	if derr != nil {
		logging.Warnf("on-behalf-of delegation lookup failed: principal=%q: %v", pd.ID, derr)
		audit(AuditOutcomeFailure, "approvals", "delegation_lookup_unavailable")
		writeServiceUnavailable(w, "delegation lookup unavailable")
		return
	}
	if !ok || (d.Delegate != pd.ID && d.Delegate != auth.canonicalHuman(pd)) {
		denyCode(CodeOBONoDelegation, "no active delegation from "+body.OnBehalfOf+" to you")
		return
	}

	if !caVisibleToTenant(r.Context(), activeTenantStore, pd, body.CAID) {
		audit(AuditOutcomeDenied, "approvals", "tenant_visibility_ca")
		writeForbiddenCode(w, "tenant_visibility", certificateCATenantDeniedMessage)
		return
	}
	if !templateVisibleToTenant(r.Context(), activeTenantStore, pd, body.TemplateID) {
		audit(AuditOutcomeDenied, "approvals", "tenant_visibility_template")
		writeForbiddenCode(w, "tenant_visibility", certificateTemplateTenantDeniedMessage)
		return
	}

	if approvalStore == nil {
		audit(AuditOutcomeFailure, "approvals", "approval_store_unavailable")
		writeServiceUnavailable(w, "approval store not configured")
		return
	}

	// An identical pending on-behalf-of request files nothing new.
	req := CertificateIssueRequest{CAID: body.CAID, TemplateID: body.TemplateID, CSRPEM: body.CSRPEM, TeamID: body.OnBehalfOf}
	if existing, found := findPendingOBO(r.Context(), approvalStore, req, pd.ID); found {
		emitAuditEventDetail(r, auditProvider, pd.ID, oboAction, "approval", existing.ID, AuditOutcomePendingApproval, oboDetailJSON(oboAuditDetail{
			Requester: pd.ID, Delegate: pd.ID, OnBehalfOf: body.OnBehalfOf, ApprovalID: existing.ID,
			TemplateID: body.TemplateID, CAID: body.CAID, Reused: true,
		}))
		writePendingApproval(w, existing.ID)
		return
	}

	// Team policy and quota are the delegator's (W33-21, D-195).
	release, allowed := enforceOBOTeamPolicy(w, r, auditProvider, pd, req, audit)
	if !allowed {
		return
	}

	approvalID, aerr := newApprovalID()
	if aerr != nil {
		release(r.Context())
		logging.Warnf("approval ID generation failed: %v", aerr)
		audit(AuditOutcomeFailure, "approvals", "approval_id_unavailable")
		writeServiceUnavailable(w, "approval request failed")
		return
	}
	apr := ApprovalRequest{
		ID: approvalID, TemplateID: body.TemplateID, CAID: body.CAID,
		Requester: pd.ID, TeamID: body.OnBehalfOf, OnBehalfOf: body.OnBehalfOf, CSRPEM: body.CSRPEM,
		RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if cerr := approvalStore.Create(r.Context(), apr); cerr != nil {
		release(r.Context())
		logging.Warnf("on-behalf-of approval request creation failed: %v", cerr)
		audit(AuditOutcomeFailure, "approvals", "approval_create_failed")
		writeServiceUnavailable(w, "approval request failed")
		return
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, oboAction, "approval", approvalID, AuditOutcomePendingApproval, oboDetailJSON(oboAuditDetail{
		Requester: pd.ID, Delegate: pd.ID, OnBehalfOf: body.OnBehalfOf, ApprovalID: approvalID,
		TemplateID: body.TemplateID, CAID: body.CAID,
	}))
	writePendingApproval(w, approvalID)
}

// findPendingOBO is findPendingApproval restricted to rows filed for the same
// delegator, so an ordinary pending request by the same caller is never
// mistaken for an on-behalf-of one.
func findPendingOBO(ctx context.Context, store ApprovalStore, req CertificateIssueRequest, requester string) (ApprovalRequest, bool) {
	wantSPKI := csrSPKIHash(csrFromPEM(req.CSRPEM))
	const page = 200
	for offset := 0; ; offset += page {
		rows, total, err := store.List(ctx, "pending", page, offset)
		if err != nil {
			return ApprovalRequest{}, false
		}
		for _, a := range rows {
			if a.Kind == approvalKindSSH || a.CAID != req.CAID || a.TemplateID != req.TemplateID || a.Requester != requester || a.OnBehalfOf != req.TeamID {
				continue
			}
			if wantSPKI != "" {
				if csrSPKIHash(csrFromPEM(a.CSRPEM)) == wantSPKI {
					return a, true
				}
			} else if a.CSRPEM == req.CSRPEM {
				return a, true
			}
		}
		if offset+page >= total || len(rows) == 0 {
			return ApprovalRequest{}, false
		}
	}
}

// enforceOBOTeamPolicy checks the delegator's team policy and reserves a slot
// of the delegator's monthly quota. It writes and audits any refusal (every
// row names requester, delegate and delegator) and fails closed on a store
// error. On ok the returned release gives the slot back if filing then fails.
func enforceOBOTeamPolicy(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, pd AuthPrincipal, req CertificateIssueRequest,
	audit func(AuditOutcome, string, string)) (release func(context.Context), ok bool) {
	e := activeTeamEnforcer
	if e == nil {
		return func(context.Context) {}, true
	}
	fail := func(msg string, err error) {
		logging.Warnf("team policy enforcement unavailable: principal=%q team=%q: %v", pd.ID, truncateForLog(req.TeamID), err)
		audit(AuditOutcomeFailure, "approvals", "enforcement_unavailable")
		writeServiceUnavailable(w, msg)
	}
	tenant, err := teamTenantForRequest(r.Context(), pd, req.CAID)
	if err != nil {
		fail("team policy unavailable", err)
		return nil, false
	}
	denial, err := e.Check(r.Context(), tenant, req.TeamID, req)
	if err != nil {
		fail("team policy unavailable", err)
		return nil, false
	}
	if denial != nil {
		audit(AuditOutcomeDenied, "approvals", denial.Code)
		writeForbiddenCode(w, denial.Code, denial.Message)
		return nil, false
	}
	res, denial, err := e.Reserve(r.Context(), tenant, req.TeamID)
	if err != nil {
		fail("team quota unavailable", err)
		return nil, false
	}
	if denial != nil {
		if denial.Code == CodeTeamQuotaExceeded {
			emitAuditEventDetail(r, auditProvider, pd.ID, "request.quota_exceeded", "team", req.TeamID, AuditOutcomeDenied,
				fmt.Sprintf(`{"error_code":%q,"limit":%d,"period":%q,"requester":%q,"delegate":%q,"on_behalf_of":%q}`,
					denial.Code, quotaLimitOf(r.Context(), e, tenant, req.TeamID), quotaPeriod(e.clock()), pd.ID, pd.ID, req.TeamID))
		} else {
			audit(AuditOutcomeDenied, "approvals", denial.Code)
		}
		writeForbiddenCode(w, denial.Code, denial.Message)
		return nil, false
	}
	return func(ctx context.Context) { e.Release(ctx, res) }, true
}

// oboDecisionDetail is the audit detail of a refused decision on an
// on-behalf-of row ("" for an ordinary row, which keeps its bare event).
func oboDecisionDetail(apr ApprovalRequest, approver string) string {
	if apr.OnBehalfOf == "" {
		return ""
	}
	return approvalAuditDetail(apr, approver, "", "")
}

func oboRejectDetail(apr ApprovalRequest, approver, reason string) string {
	raw, err := json.Marshal(struct {
		Requester  string `json:"requester"`
		OnBehalfOf string `json:"on_behalf_of"`
		Approver   string `json:"approver"`
		Reason     string `json:"reason"`
	}{apr.Requester, apr.OnBehalfOf, approver, reason})
	if err != nil {
		return ""
	}
	return string(raw)
}
