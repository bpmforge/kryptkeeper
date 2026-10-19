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
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// ActionCARevoke is the pending-action type for revoking a CA (W23-34). A CA
// revocation is irreversible, so it is always dual-controlled: unlike the key
// ops there is no KRYPTKEEPER_KEY_DUAL_CONTROL=false bypass.
const ActionCARevoke = "ca_revoke"

const caRevokeReason = "cACompromise"

func caRevokeSummary(certs, descendants int) string {
	return fmt.Sprintf(`{"reason":%q,"blast_radius":{"affected_certs":%d,"descendant_cas":%d}}`, caRevokeReason, certs, descendants)
}

// handleCARevoke serves POST /api/v1/cas/{id}/revoke: it only files the
// proposal; the revocation runs when a different admin approves it.
func handleCARevoke(w http.ResponseWriter, r *http.Request, caProvider CAProvider, tenantStore TenantStore, auditProvider AuditProvider, dc *KeyDualControl, pd AuthPrincipal, id string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if id == "" || strings.Contains(id, "/") {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeNotFound(w, "ca not found")
		return
	}
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "admin role required to revoke a CA")
		return
	}
	if !caVisibleToTenant(r.Context(), tenantStore, pd, id) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024))
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeBadRequest(w, "invalid request body")
		return
	}
	var req struct {
		Reason    string `json:"reason"`
		Rationale string `json:"rationale"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
	}
	if req.Reason != "" && req.Reason != caRevokeReason {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeBadRequest(w, "reason must be "+caRevokeReason+": a CA revocation is irreversible and always a compromise")
		return
	}
	item, found, err := caProvider.GetCA(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		logging.Warnf("ca revoke lookup failed: %v", err)
		writeServiceUnavailable(w, "ca unavailable")
		return
	}
	if !found {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeNotFound(w, "ca not found")
		return
	}
	if item.Status == "revoked" {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeConflict(w, "ca is already revoked")
		return
	}
	revoker, ok := caProvider.(CARevoker)
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "ca revocation not supported by this provider")
		return
	}
	if dc == nil || dc.store == nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "the approval queue is unavailable, so this CA cannot be revoked")
		return
	}
	certs, descendants, err := revoker.CARevokeBlastRadius(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		logging.Warnf("ca revoke blast radius failed: %v", err)
		writeServiceUnavailable(w, "ca unavailable")
		return
	}
	params, _ := json.Marshal(map[string]string{"ca_id": id, "reason": caRevokeReason}) // static map: cannot fail
	rationale := strings.TrimSpace(req.Rationale)
	if rationale == "" {
		rationale = fmt.Sprintf("revoke CA %s (%s): %d active certificates, %d descendant CAs", id, caRevokeReason, certs, descendants)
	}
	act, err := dc.store.Create(r.Context(), PendingAction{
		ActionType: ActionCARevoke, Params: params, ProposedBy: pd.ID, Tenant: pd.Tenant, Rationale: rationale,
	})
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeFailure)
		logging.Warnf("ca revoke proposal failed: %v", err)
		writeServiceUnavailable(w, "approval queue unavailable")
		return
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, "ca.revoke", "ca", id, AuditOutcomeProposed, caRevokeSummary(certs, descendants))
	writeDualControlProposed(w, act.ID, "CA revocation is irreversible - a different admin must approve it")
}

// NewCARevokeExecutor carries out an approved ActionCARevoke. The queue has
// already refused self-approval; revoking a CA additionally needs a pki-admin.
func NewCARevokeExecutor(p CAProvider, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		if !isAdminRole(approver.Role) {
			return nil, errors.New("revoking a CA needs a pki-admin approver")
		}
		revoker, ok := p.(CARevoker)
		if !ok {
			return nil, errors.New("ca revocation not supported by this provider")
		}
		var params struct {
			CAID   string `json:"ca_id"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(action.Params, &params); err != nil || params.CAID == "" {
			return nil, errors.New("bad params")
		}
		if params.Reason != caRevokeReason {
			return nil, errors.New("unsupported revocation reason")
		}
		res, err := revoker.RevokeCA(ctx, params.CAID)
		if err != nil {
			if errors.Is(err, ca.ErrCAAlreadyRevoked) {
				return nil, errors.New("ca is already revoked")
			}
			if errors.Is(err, errCANotFound) {
				return nil, errors.New("ca not found")
			}
			logging.Warnf("ca revoke failed for %s: %v", params.CAID, err)
			return nil, errors.New("ca revocation failed")
		}
		if audit != nil {
			entry := AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "ca.revoke", ActorType: "user", ActorID: approver.ID,
				ResourceType: "ca", ResourceID: params.CAID, Outcome: AuditOutcomeExecuted,
				ChangeSummary: caRevokeSummary(res.AffectedCerts, res.DescendantCAs), Tenant: action.Tenant,
			}
			// The CA is already revoked and that cannot be undone, so a lost
			// audit row is logged loudly rather than failing the action.
			if err := audit.AppendEntry(ctx, entry); err != nil {
				logging.Errorf("ca.revoke for %s executed but its audit row was not written: %v", params.CAID, err)
			}
		}
		return json.Marshal(res)
	}
}
