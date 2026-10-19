// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"

	"kryptkeeper/internal/keystore"
)

// authorizeKeyOp enforces the per-key owner/ACL (W9-09) on a mutating key
// operation. A nil manager keeps the global admin gate only.
func authorizeKeyOp(w http.ResponseWriter, r *http.Request, audit AuditProvider, pd AuthPrincipal, keyID string) bool {
	m := activeKeyLifecycle
	if m == nil {
		return true
	}
	if err := m.Authorize(keyID, pd.ID, isAdminRole(pd.Role)); err != nil {
		var unavailable *keyPolicyUnavailableError
		if errors.As(err, &unavailable) {
			// Fail closed, but an outage is not an authz denial. The raw
			// error can carry DB host/user, so the client gets a uniform body.
			logging.Warnf("key policy load failed for %s: %v", keyID, err)
			emitAuditEvent(r, audit, pd.ID, "key.op", "key", keyID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "key policy unavailable")
			return false
		}
		emitAuditEvent(r, audit, pd.ID, "key.op", "key", keyID, AuditOutcomeDenied)
		writeForbidden(w, err.Error())
		return false
	}
	return true
}

func handleKeyPolicy(w http.ResponseWriter, r *http.Request, store keystore.Store, audit AuditProvider, principal, id string) {
	m := activeKeyLifecycle
	if id == "" || strings.Contains(id, "/") {
		writeNotFound(w, "key not found")
		return
	}
	if m == nil {
		if r.Method != http.MethodGet {
			emitAuditEvent(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeFailure)
		}
		writeServiceUnavailable(w, "key lifecycle policy is not enabled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		policy, found, err := m.GetPolicy(id)
		if err != nil {
			logging.Warnf("key policy load failed: %v", err)
			writeServiceUnavailable(w, "key policy unavailable")
			return
		}
		if !found {
			writeNotFound(w, "no policy for this key")
			return
		}
		writeJSONData(w, policy)
	case http.MethodPut:
		var req struct {
			Owner      string   `json:"owner"`
			ACL        []string `json:"acl"`
			MaxAgeDays int      `json:"max_age_days"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
			emitAuditEvent(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid request body")
			return
		}
		req.Owner = strings.TrimSpace(req.Owner)
		if req.Owner == "" {
			emitAuditEvent(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeFailure)
			writeBadRequest(w, "owner is required")
			return
		}
		if req.MaxAgeDays < 0 {
			emitAuditEvent(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeFailure)
			writeBadRequest(w, "max_age_days must be >= 0")
			return
		}
		if _, err := store.Metadata(id); err != nil {
			emitAuditEvent(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeFailure)
			if errors.Is(err, keystore.ErrKeyNotFound) {
				writeNotFound(w, "key not found")
				return
			}
			writeServiceUnavailable(w, "key unavailable")
			return
		}
		if err := m.SetPolicy(id, req.Owner, req.ACL, req.MaxAgeDays); err != nil {
			emitAuditEvent(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeFailure)
			logging.Warnf("key policy set failed: %v", err)
			writeServiceUnavailable(w, "key policy not saved")
			return
		}
		detail, _ := json.Marshal(map[string]any{"owner": req.Owner, "acl": req.ACL, "max_age_days": req.MaxAgeDays})
		emitAuditEventDetail(r, audit, principal, "key.policy_set", "key", id, AuditOutcomeSuccess, string(detail))
		policy, _, err := m.GetPolicy(id)
		if err != nil {
			writeServiceUnavailable(w, "key policy unavailable")
			return
		}
		writeJSONData(w, policy)
	default:
		writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

// handleKeyCompromise only files the proposal; the rotate/flag/revoke/reissue
// run happens when a different admin approves it. There is no
// KRYPTKEEPER_KEY_DUAL_CONTROL=false bypass: it revokes certificates.
func handleKeyCompromise(w http.ResponseWriter, r *http.Request, store keystore.Store, dc *KeyDualControl, audit AuditProvider, pd AuthPrincipal, id string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	m := activeKeyLifecycle
	if id == "" || strings.Contains(id, "/") {
		writeNotFound(w, "key not found")
		return
	}
	if m == nil {
		emitAuditEvent(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "key lifecycle is not enabled")
		return
	}
	if !authorizeKeyOp(w, r, audit, pd, id) {
		return
	}
	if _, err := store.Metadata(id); err != nil {
		emitAuditEvent(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeFailure)
		if errors.Is(err, keystore.ErrKeyNotFound) {
			writeNotFound(w, "key not found")
			return
		}
		writeServiceUnavailable(w, "key unavailable")
		return
	}
	if _, found, err := m.GetPolicy(id); err != nil {
		emitAuditEvent(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "key policy unavailable")
		return
	} else if !found {
		emitAuditEvent(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeFailure)
		writeConflict(w, "set a policy first: the compromise flow needs a key policy")
		return
	}
	if dc == nil || dc.store == nil {
		emitAuditEvent(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "the approval queue is unavailable, so the compromise flow cannot start")
		return
	}
	params, _ := json.Marshal(map[string]string{"key_id": id}) // static map: cannot fail
	act, err := dc.store.Create(r.Context(), PendingAction{
		ActionType: ActionKeyCompromise, Params: params, ProposedBy: pd.ID, Tenant: pd.Tenant,
		Rationale: fmt.Sprintf("key %s compromised: rotate, flag, revoke affected certificates, re-issue", id),
	})
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeFailure)
		logging.Warnf("key compromise proposal failed: %v", err)
		writeServiceUnavailable(w, "approval queue unavailable")
		return
	}
	emitAuditEventDetail(r, audit, pd.ID, "key.compromise", "key", id, AuditOutcomeProposed, fmt.Sprintf(`{"action_id":%q}`, act.ID))
	writeDualControlProposed(w, act.ID, "the compromise flow revokes certificates - a different admin must approve it")
}
