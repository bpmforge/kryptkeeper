// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// W22-38: the two ways break-glass is consumed. (A) A local login for exactly
// one flagged account that never touches the IdP, so an operator can get in
// while SSO is down, and always alerts. (B) An override that executes a
// pending action whose approval quorum can no longer be met, under a live
// two-holder window. Neither relaxes proposer != approver or tenant scope:
// the override still refuses the proposer's own action and an action outside
// the caller's tenant.

// envBreakGlassEmail names the break-glass local account. It must equal the
// configured local login user: this route can only ever authenticate that one
// credential, never an arbitrary user.
const envBreakGlassEmail = "APP_AUTH_BREAKGLASS_EMAIL"

func init() {
	// Append, never assign: other tickets hook the same list.
	breakGlassRouteHooks = append(breakGlassRouteHooks, mountBreakGlassLogin)
}

// breakGlassLoginEmail returns the flagged account when break-glass login is
// configured: the env var is set and matches the local login user.
func breakGlassLoginEmail(auth *Authenticator) (string, bool) {
	flagged := strings.TrimSpace(os.Getenv(envBreakGlassEmail))
	local := strings.TrimSpace(auth.config.loginUser.Email)
	if flagged == "" || local == "" || !strings.EqualFold(flagged, local) {
		return "", false
	}
	return local, true
}

func mountBreakGlassLogin(mux *http.ServeMux, b *BreakGlass, auth *Authenticator) {
	mux.HandleFunc("/api/v1/auth/breakglass/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		flagged, configured := breakGlassLoginEmail(auth)
		if !configured {
			writeServiceUnavailable(w, "break-glass login is not configured")
			return
		}
		now := time.Now()
		// Its own limiter key: a flood against /auth/login must not lock the
		// break-glass path, and guessing here is held to 5 a minute.
		if !auth.allowRateLimit("breakglass-login:"+clientIP(r), 5, time.Minute, now) {
			emitAuditEvent(r, b.audit, "", "auth.breakglass_login", "auth", "breakglass-login", AuditOutcomeDenied)
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAuthBodyBytes, "invalid request body") {
			return
		}
		email := strings.TrimSpace(req.Email)
		if !strings.EqualFold(email, flagged) {
			emitAuditEvent(r, b.audit, "", "auth.breakglass_login", "auth", "breakglass-login", AuditOutcomeDenied)
			writeForbidden(w, "this account is not the break-glass account")
			return
		}
		// LoginContext checks the local verifier only; it never calls the IdP.
		accessToken, accessTTL, refreshToken, refreshTTL, principal, err := auth.LoginContext(r.Context(), email, req.Password, now)
		if err != nil {
			if r.Context().Err() != nil {
				return // client left while queued for a KDF slot
			}
			switch {
			case errors.Is(err, errInvalidCredentials):
				emitAuditEvent(r, b.audit, "", "auth.breakglass_login", "auth", "breakglass-login", AuditOutcomeDenied)
				writeInvalidLoginCredentials(w)
			case errors.Is(err, errAccountInactive):
				emitAuditEvent(r, b.audit, "", "auth.breakglass_login", "auth", "breakglass-login", AuditOutcomeDenied)
				writeForbidden(w, "account inactive")
			default:
				emitAuditEvent(r, b.audit, "", "auth.breakglass_login", "auth", "breakglass-login", AuditOutcomeFailure)
				writeServiceUnavailable(w, "auth unavailable")
			}
			return
		}
		emitAuditEvent(r, b.audit, principal.ID, "auth.breakglass_login", "auth", "breakglass-login", AuditOutcomeSuccess)
		// R-04, accepted: this path must keep working with the break-glass DB
		// down (it exists for outages), so it is deliberately not behind the
		// D-290-A gate. The compensating controls are the audit row and the
		// alert, which recordUse emits before the review row is written, so a
		// review-store fault cannot silence them. The login already succeeded;
		// the lost review row is logged at error level so it can be recreated.
		if _, rerr := b.recordUse(r.Context(), r, breakGlassLocalLoginScope, principal.ID, "auth.breakglass_login", clientIP(r), false); rerr != nil {
			logging.Errorf("break-glass login by %s (elevation %s): use audited and alerted but review row not written: %v", principal.ID, breakGlassLocalLoginScope, rerr)
		}
		setSessionCookie(w, r, accessToken, accessTTL)

		resp := struct {
			Data struct {
				AccessToken      string `json:"access_token"`
				TokenType        string `json:"token_type"`
				ExpiresIn        int64  `json:"expires_in"`
				RefreshToken     string `json:"refresh_token"`
				RefreshExpiresIn int64  `json:"refresh_expires_in"`
				Principal        struct {
					UserID string `json:"user_id"`
					Role   string `json:"role"`
				} `json:"principal"`
			} `json:"data"`
		}{}
		resp.Data.AccessToken = accessToken
		resp.Data.TokenType = "Bearer"
		resp.Data.ExpiresIn = accessTTL
		resp.Data.RefreshToken = refreshToken
		resp.Data.RefreshExpiresIn = refreshTTL
		resp.Data.Principal.UserID = principal.ID
		resp.Data.Principal.Role = principal.Role
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/auth/breakglass/login response: %v", err)
		}
	})
}

// ---- override --------------------------------------------------------------

// pendingQuorumRequired is how many distinct humans must approve: the n
// stamped at proposal time (W22-10), never less than one.
func pendingQuorumRequired(a PendingAction) int {
	if a.QuorumN < 1 {
		return 1
	}
	return a.QuorumN
}

// approvalLister is the optional PendingActionStore capability that names the
// humans who have already approved an action. Without it the override cannot
// tell how many approvals remain, so it refuses.
type approvalLister interface {
	ListApprovalHumans(ctx context.Context, actionID string) ([]string, error)
}

func (s *dbPendingActionStore) ListApprovalHumans(ctx context.Context, actionID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT human FROM pending_action_approvals WHERE action_id = `+s.ph(1), actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// pendingQuorumApproved returns the distinct humans who already approved.
func pendingQuorumApproved(ctx context.Context, store PendingActionStore, a PendingAction) ([]string, error) {
	if a.ApprovalsCount == 0 {
		return nil, nil
	}
	l, ok := store.(approvalLister)
	if !ok {
		return nil, errors.New("pending-action store cannot list approvals")
	}
	return l.ListApprovalHumans(ctx, a.ID)
}

// quorumUnreachable reports whether the action can no longer collect enough
// approvals: fewer eligible humans remain than approvals still needed.
// Eligible means an active user who may approve, in the action's tenant when
// multi-tenancy is on, other than the proposer's human, the bootstrap
// identity, and anyone who already approved. Over-counting only ever refuses
// an override, so every doubt resolves toward "still reachable".
func quorumUnreachable(ctx context.Context, auth *Authenticator, users UserProvider, roles *CustomRoleStore, store PendingActionStore, a PendingAction) (bool, error) {
	have, err := pendingQuorumApproved(ctx, store, a)
	if err != nil {
		return false, err
	}
	need := pendingQuorumRequired(a) - len(have)
	if need <= 0 {
		return false, nil
	}
	all, err := users.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	excluded := auth.humansBehind(a.ProposedBy)
	excluded[bootstrapHuman] = true
	for _, h := range have {
		excluded[h] = true
	}
	tenant := a.Tenant
	if tenant == "" {
		tenant = DefaultTenant
	}
	eligible := 0
	for _, u := range all {
		if u.Status != "active" || excluded[u.ID] {
			continue
		}
		if multiTenancyEnabled() && userTenant(u) != tenant {
			continue
		}
		if canApproveActions(u.Role) || roleHoldsPermission(roles, u.Role, "action.approve") {
			eligible++
		}
	}
	return eligible < need, nil
}

// overrideDeps are the collaborators the pending-actions handler already holds.
type overrideDeps struct {
	auth         *Authenticator
	store        PendingActionStore
	certProvider CertificateProvider
	keyStore     keystore.Store
	executors    map[string]ActionExecutor
	audit        AuditProvider
	users        UserProvider
	roles        *CustomRoleStore
}

// breakGlassOverride handles POST /pending-actions/{id}/override. Every check
// runs before the action is looked up, so a caller outside the live
// two-holder window learns nothing about which actions exist.
func breakGlassOverride(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, d overrideDeps, id string) {
	deny := func(msg, detail string) {
		emitAuditEventDetail(r, d.audit, pd.ID, "approval.override", "pending-action", id, AuditOutcomeDenied, detail)
		writeForbidden(w, msg)
	}
	if d.auth.isBootstrapHuman(pd) {
		deny(msgBootstrapCannotApprove, "bootstrap")
		return
	}
	if pd.AuthType == AuthTypeAPIKey {
		deny(errBreakGlassNamedOnly.Error(), "api-key")
		return
	}
	b := activeBreakGlass()
	if b == nil {
		deny("no active break-glass window", "break-glass not configured")
		return
	}
	act, live := b.Active(r.Context())
	if !live {
		deny("no active break-glass window", "no active window")
		return
	}
	human := d.auth.canonicalHuman(pd)
	if human != act.RequestedBy && human != act.ConfirmedBy {
		deny("only the two holders who opened the break-glass window may override", "not a holder of "+act.ID)
		return
	}
	// Live record too: a holder demoted or deactivated mid-window is out.
	if err := b.IsHolder(r.Context(), pd); err != nil {
		deny(err.Error(), "holder check")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeJSONBodyOrReject(w, r, &req, maxBreakGlassBody, "invalid request body") {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > maxBreakGlassReason {
		writeBadRequest(w, "reason is required (1..500 characters)")
		return
	}

	action, found, err := d.store.Get(r.Context(), id)
	if err != nil {
		writeServiceUnavailable(w, "lookup failed")
		return
	}
	actionTenant := action.Tenant
	if actionTenant == "" {
		actionTenant = DefaultTenant
	}
	// Tenant scope is not relaxed: a holder overrides only what they could see.
	if !found || !tenantVisible(pd, actionTenant) {
		writeNotFound(w, "action not found")
		return
	}
	if d.auth.sameHuman(pd, action.ProposedBy) {
		deny(msgSelfApproval, "own proposal")
		return
	}
	if action.Status != "pending" {
		writeConflict(w, "action is not pending")
		return
	}
	unreachable, err := quorumUnreachable(r.Context(), d.auth, d.users, d.roles, d.store, action)
	if err != nil {
		logging.Warnf("break-glass override %s: cannot decide quorum reachability: %v", id, err)
		writeServiceUnavailable(w, "cannot determine whether the quorum is reachable")
		return
	}
	if !unreachable {
		writeConflict(w, "quorum is still reachable; use the normal approval flow")
		return
	}

	// Alert and open the review before any effect: if this cannot be recorded
	// the override must not run.
	if _, err := b.RecordUse(r.Context(), r, pd.ID, "approval.override", id); err != nil {
		logging.Warnf("break-glass override %s: use could not be recorded: %v", id, err)
		if errors.Is(err, errBreakGlassNotActive) {
			deny("no active break-glass window", "window closed")
			return
		}
		writeServiceUnavailable(w, "break-glass use could not be recorded; nothing was executed")
		return
	}
	detail := "holders=" + act.RequestedBy + "," + act.ConfirmedBy + ";reason=" + req.Reason

	// Same claim-then-execute as approve: racing overrides run the action once.
	if err := d.store.Decide(r.Context(), id, statusExecuting, pd.ID, nil); err != nil {
		writeConflict(w, "action is not pending")
		return
	}
	result, execErr := dispatchPendingAction(r.Context(), d.certProvider, d.keyStore, d.executors, action, pd)
	if execErr != nil {
		failResult, _ := json.Marshal(map[string]string{"error": execErr.Error()}) // static map: cannot fail
		emitAuditEventDetail(r, d.audit, pd.ID, "approval.override", "pending-action", id, AuditOutcomeFailure, detail)
		if derr := decideDetached(r, d.store, id, "failed", pd.ID, failResult); derr != nil {
			logging.Warnf("pending action %s: override execution failed AND the failure could not be recorded: exec=%v decide=%v", id, execErr, derr)
			writeServiceUnavailable(w, "action failed: "+execErr.Error()+" - and recording the failure also failed; the action may still show as executing")
			return
		}
		writeServiceUnavailable(w, "action failed: "+execErr.Error())
		return
	}
	if err := decideDetached(r, d.store, id, "approved", pd.ID, result); err != nil {
		logging.Errorf("pending action %s (%s): OVERRIDDEN and executed but decision could not be recorded - row left in executing: %v", id, action.ActionType, err)
		if aerr := emitAuditEventDetailErr(r, d.audit, pd.ID, "approval.override", "pending-action", id, AuditOutcomeExecuted,
			detail+";executed; recording the approved decision failed - queue row left in executing"); aerr != nil {
			logging.Errorf("pending action %s: overridden action has NO audit row and no decision record - reconcile manually", id)
		}
		writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error",
			"the action was executed but its approval record could not be saved; contact an administrator")
		return
	}
	emitAuditEventDetail(r, d.audit, pd.ID, "approval.override", "pending-action", id, AuditOutcomeSuccess, detail)
	writeJSONData(w, map[string]any{"status": "approved", "overridden": true, "result": result})
}
