// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// maxProposalBodyBytes bounds one proposal (action params plus rationale).
const maxProposalBodyBytes = 64 << 10

// canApproveActions reports whether a role may approve AI-proposed actions.
// D-029/R-C1: RoleMCPAgent is checked first and unconditionally denied — the
// identity provisioned for MCP server integration must never be capable of
// approving actions, structurally, independent of whatever the allowlist
// below grows to include (see mcp_role.go).
func canApproveActions(role string) bool {
	if role == RoleMCPAgent {
		return false
	}
	switch role {
	case "pki-admin", "pki-operator":
		return true
	default:
		return false
	}
}

// registerPendingActionHandlers mounts the generalized approval queue:
// list/create proposals, and approve (execute) / reject. Approval is gated to
// approver roles and forbids self-approval (proposer must differ from approver).
// keys is a variadic tail (W9-10) so existing callers compile unchanged;
// at most one store is meaningful — it executes approved key_* actions.
func registerPendingActionHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, store PendingActionStore, auditProvider AuditProvider, executors map[string]ActionExecutor, keys ...keystore.Store) {
	var keyStore keystore.Store
	if len(keys) > 0 {
		keyStore = keys[0]
	}
	if ds := delegationStoreForActions(store); ds != nil {
		_ = ds.EnsureSchema(context.Background()) // self-heal like the other stores; a failure denies delegated approvals (fail closed)
	}
	mux.HandleFunc("/api/v1/pending-actions", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "action.propose", "pending-action", "", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "pending-action store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := store.List(r.Context(), strings.TrimSpace(r.URL.Query().Get("status")))
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			list = filterPendingActionsByTenant(pd, list)
			writeJSONData(w, list)
		case http.MethodPost:
			// LLM-005: params and rationale are stored verbatim and shown to
			// approvers, so an unbounded body is unbounded storage.
			var req PendingAction
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProposalBodyBytes)).Decode(&req); err != nil {
				if rejectOversizeBody(w, err) {
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "action.propose", "pending-action", "", AuditOutcomeFailure)
				writeBadRequest(w, "invalid JSON")
				return
			}
			if !validActionType(req.ActionType) {
				emitAuditEvent(r, auditProvider, pd.ID, "action.propose", "pending-action", "", AuditOutcomeFailure)
				writeBadRequest(w, "unsupported action_type (revoke, bulk_revoke)")
				return
			}
			// L-03: the proposer may only queue actions against targets
			// visible to their own tenant.
			if !tenantBypass(pd) {
				if err := checkPendingActionTargets(r.Context(), certProvider, activeTenantStore, pd.Tenant, req); err != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "action.propose", "pending-action", "", AuditOutcomeDenied)
					writeForbidden(w, "action target is not visible in your tenant")
					return
				}
			}
			// A bypass principal's own tenant says nothing about where the
			// action will run; stamp the target's tenant so the execution-time
			// re-check (which compares against this stamp) passes for a
			// legitimate super-admin action on a tenant's resources.
			actionTenant := pd.Tenant
			if tenantBypass(pd) && multiTenancyEnabled() {
				if t, ok := resolvePendingActionTenant(r.Context(), certProvider, activeTenantStore, req); ok {
					actionTenant = t
				}
			}
			created, err := store.Create(r.Context(), PendingAction{
				ActionType: req.ActionType,
				Params:     req.Params,
				Rationale:  req.Rationale,
				ProposedBy: pd.ID,
				Tenant:     actionTenant,
			})
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "action.propose", "pending-action", "", AuditOutcomeFailure)
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "action.propose", "pending-action", created.ID, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusCreated)
			writeJSONData(w, created)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/pending-actions/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := authenticateDecider(auth, r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "action.decide", "pending-action", "", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "pending-action store unavailable")
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/pending-actions/")
		parts := strings.Split(tail, "/")
		if len(parts) != 2 || parts[0] == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "action.decide", "pending-action", "", AuditOutcomeFailure)
			writeBadRequest(w, "expected /pending-actions/{id}/{approve|reject|override}")
			return
		}
		id, verb := parts[0], parts[1]
		// W22-38: break-glass override. Handled before the lookup below so a
		// caller outside the live two-holder window learns nothing about which
		// actions exist.
		if verb == "override" {
			breakGlassOverride(w, r, pd, overrideDeps{auth: auth, store: store, certProvider: certProvider, keyStore: keyStore, executors: executors,
				audit: auditProvider, users: accessReviewUsers(auth), roles: accessReviewRoles(auth)}, id)
			return
		}

		action, ok, err := store.Get(r.Context(), id)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "action.decide", "pending-action", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "lookup failed")
			return
		}
		if !ok {
			emitAuditEvent(r, auditProvider, pd.ID, "action.decide", "pending-action", id, AuditOutcomeFailure)
			writeNotFound(w, "action not found")
			return
		}
		// Tenant isolation: an action is only decidable within its own tenant
		// (or by a super-admin). Hide cross-tenant actions as not-found.
		actionTenant := action.Tenant
		if actionTenant == "" {
			actionTenant = DefaultTenant
		}
		if !tenantVisible(pd, actionTenant) {
			emitAuditEvent(r, auditProvider, pd.ID, "action.decide", "pending-action", id, AuditOutcomeFailure)
			writeNotFound(w, "action not found")
			return
		}
		if action.Status != "pending" {
			writeConflict(w, "action is not pending")
			return
		}

		switch verb {
		case "reject":
			if !auth.mayDecide(pd) {
				emitAuditEvent(r, auditProvider, pd.ID, "action.reject", "pending-action", id, AuditOutcomeDenied)
				writeForbidden(w, approveDeniedMessage(auth, pd, "decide"))
				return
			}
			var body struct {
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body) // reject body is optional; absent/invalid = empty reason
			result, _ := json.Marshal(map[string]string{"reason": body.Reason})
			if err := store.Decide(r.Context(), id, "rejected", pd.ID, result); err != nil {
				// Not-pending races and DB faults both land here; the raw
				// error (SQL text) stays server-side.
				logging.Infof("pending action %s: reject decision not recorded: %v", id, err)
				writeConflict(w, "action is not pending")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "action.reject", "pending-action", id, AuditOutcomeSuccess)
			if strings.HasPrefix(action.ActionType, anomalyActionPrefix) {
				emitAuditEventDetail(r, auditProvider, pd.ID, anomalyAuditRejectAction, "pending-action", id, AuditOutcomeSuccess, "reason="+body.Reason)
			}
			writeJSONData(w, map[string]string{"status": "rejected"})

		case "approve":
			if !auth.mayDecide(pd) {
				emitAuditEvent(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeDenied)
				writeForbidden(w, approveDeniedMessage(auth, pd, "approve"))
				return
			}
			// The proposer's human must not approve their own action (esp. an
			// AI proposer), however many credentials they hold.
			if msg := auth.approverRefusal(pd, action.ProposedBy); msg != "" {
				emitAuditEvent(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeDenied)
				writeForbidden(w, msg)
				return
			}
			// W22-11: an approval on behalf of a delegator. The caller's own
			// gates above already ran; the delegation adds no capability.
			onBehalfOf := onBehalfRequest(w, r)
			detail := delegationAuditDetail(onBehalfOf, pd.ID)
			if onBehalfOf != "" {
				if msg := authorizeOnBehalf(r.Context(), auth, delegationStoreForActions(store), pd, onBehalfOf, action.ProposedBy, actionTenant, time.Now()); msg != "" {
					emitAuditEventDetail(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeDenied, detail)
					writeForbidden(w, msg)
					return
				}
			}
			// W22-10: n-of-m. Record this human's approval before the CAS; only
			// an approval that reaches n goes on to claim execution.
			if action.QuorumN > 1 {
				qs, ok := store.(quorumStore)
				if !ok {
					writeServiceUnavailable(w, "quorum approvals unsupported by this store")
					return
				}
				n, qerr := qs.RecordApproval(r.Context(), id, approvalHuman(auth, pd, onBehalfOf), auth.canonicalHuman(pd))
				if errors.Is(qerr, errAlreadyApproved) {
					emitAuditEventDetail(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeDenied, detail)
					writeConflict(w, "you have already approved this action")
					return
				}
				if qerr != nil {
					logging.Warnf("pending action %s: recording approval failed: %v", id, qerr)
					writeServiceUnavailable(w, "approval could not be recorded")
					return
				}
				if n < action.QuorumN {
					emitAuditEventDetail(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomePendingApproval,
						strings.TrimSpace(fmt.Sprintf("approvals=%d/%d %s", n, action.QuorumN, detail)))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusAccepted)
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "pending", "approvals": n, "required": action.QuorumN}})
					return
				}
			}
			// A01-003: win the compare-and-set BEFORE executing, so N racing
			// approvals run the action once; losers get 409 untouched.
			if err := store.Decide(r.Context(), id, statusExecuting, pd.ID, nil); err != nil {
				writeConflict(w, "action is not pending")
				return
			}
			result, execErr := dispatchPendingAction(r.Context(), certProvider, keyStore, executors, action, pd)
			if execErr != nil {
				failResult, _ := json.Marshal(map[string]string{"error": execErr.Error()}) // static map: cannot fail
				emitAuditEventDetail(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeFailure, detail)
				// S-63: a failed Decide after a failed action must be
				// surfaced - otherwise the caller is told "failed" while
				// the queue still shows the action unfinished.
				if derr := decideDetached(r, store, id, "failed", pd.ID, failResult); derr != nil {
					logging.Warnf("pending action %s: execution failed AND the failure could not be recorded - action still shows executing: exec=%v decide=%v", id, execErr, derr)
					writeServiceUnavailable(w, "action failed: "+execErr.Error()+" - and recording the failure also failed; the action may still show as executing")
					return
				}
				writeServiceUnavailable(w, "action failed: "+execErr.Error())
				return
			}
			if err := decideDetached(r, store, id, "approved", pd.ID, result); err != nil {
				// FB-05: the action already ran. Record that truth in the
				// audit log BEFORE answering, or the executed operation
				// is unreconstructable and the row sticks in "executing".
				logging.Errorf("pending action %s (%s): EXECUTED but decision could not be recorded - row left in executing: %v", id, action.ActionType, err)
				if aerr := emitAuditEventDetailErr(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeExecuted,
					"action executed; recording the approved decision failed - queue row left in executing"); aerr != nil {
					logging.Errorf("pending action %s: executed action has NO audit row and no decision record - reconcile manually", id)
				}
				writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error",
					"the action was executed but its approval record could not be saved; contact an administrator")
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "action.approve", "pending-action", id, AuditOutcomeSuccess, detail)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Data struct {
					Status string          `json:"status"`
					Result json.RawMessage `json:"result"`
				} `json:"data"`
			}{Data: struct {
				Status string          `json:"status"`
				Result json.RawMessage `json:"result"`
			}{Status: "approved", Result: result}})

		default:
			writeBadRequest(w, "expected approve or reject")
		}
	})
}

// decideDetached records a decision after the action has already executed.
// The write is detached from the request context (a client disconnect must
// not strand the row in "executing") and retried once, since a transient
// busy/locked DB is the likeliest failure.
func decideDetached(r *http.Request, store PendingActionStore, id, status, approvedBy string, result json.RawMessage) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditAppendTimeout)
		err = store.Decide(ctx, id, status, approvedBy, result)
		cancel()
		if err == nil {
			return nil
		}
		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return err
}

// approveDeniedMessage explains a failed mayDecide: the bootstrap
// token gets its own message so the operator knows to sign in by name.
func approveDeniedMessage(auth *Authenticator, pd AuthPrincipal, verb string) string {
	if auth.isBootstrapHuman(pd) {
		return msgBootstrapCannotApprove
	}
	return "your role is not authorized to " + verb + " actions"
}

// dispatchPendingAction runs an approved action: registered executors first
// (W20-20, e.g. enabling a delivery plugin), then destructive key ops (W9-10,
// which run under the queue's second-approver and no-self-approval gates), then
// certificate actions. Shared by approve and the break-glass override so the
// two cannot drift in what they execute.
func dispatchPendingAction(ctx context.Context, certProvider CertificateProvider, keyStore keystore.Store, executors map[string]ActionExecutor, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
	if exec, ok := executors[action.ActionType]; ok {
		return exec(ctx, action, approver)
	}
	if isKeyAction(action.ActionType) {
		return executeKeyAction(ctx, keyStore, action)
	}
	return executePendingAction(ctx, certProvider, action)
}
