// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// W17-08: the W15-03 leaf-escrow ceremonies, wired.
//
// EscrowLeafKey/RecoverLeafKey shipped complete with zero non-test
// callers — the ceremony existed but no operator could perform it. These
// handlers expose it WITHOUT weakening any guarantee it depends on:
//   - leaf custody stays per-tenant opt-in and off by default
//   - every path stays dual-control gated and audited
//   - no key or custodian material is ever echoed back
//
// BYOK export (W15-04) is NOT here: it needs a keystore primitive that
// recovers plaintext to memory plus real cloud-KMS import adapters, both
// security-sensitive and larger than this wiring. Filed as W17-12 rather
// than half-implemented behind a route that looks finished.
//
// Mirrors the W9-12 escrow endpoints' posture exactly: admin role, exact
// -match routes, encrypted bundle as an attachment.

// leafEscrowPolicyFromEnv builds the per-tenant opt-in policy.
//
// Custody is OFF unless a tenant is named in KRYPTKEEPER_LEAF_ESCROW_TENANTS.
// The zero-value policy escrows nothing, which is the W15-03 decision:
// holding leaf private keys conflicts with the key-boundary law unless a
// tenant explicitly adopts it.
var leafEscrowPolicyFromEnv = func() *keystore.LeafEscrowPolicy {
	policy := keystore.NewLeafEscrowPolicy()
	for _, tenant := range strings.Split(os.Getenv("KRYPTKEEPER_LEAF_ESCROW_TENANTS"), ",") {
		if t := strings.TrimSpace(tenant); t != "" {
			policy.OptIn(t)
		}
	}
	return policy
}

// leafEscrowAuditSink forwards custody events into the append-only trail.
type leafEscrowAuditSink struct {
	r        *http.Request
	provider AuditProvider
	actor    string
}

func (s leafEscrowAuditSink) Record(ev keystore.LeafEscrowEvent) {
	emitAuditEventDetail(s.r, s.provider, s.actor, ev.Action, "key", ev.KeyID, AuditOutcome(ev.Outcome),
		fmt.Sprintf(`{"tenant":%q}`, ev.Tenant))
}

func registerKeyCustodyOpsHandlers(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider) {
	if store == nil {
		return
	}

	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())

	authorize := func(w http.ResponseWriter, r *http.Request, action string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "key", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "key", "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key custody operations")
			return AuthPrincipal{}, false
		}
		if denyTenantPrincipalKeyOp(w, r, auditProvider, pd, action, "key", "-") {
			return AuthPrincipal{}, false
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	// POST /api/v1/keys/leaf-escrow — deposit an endpoint key under dual
	// control. Refused unless the tenant opted in.
	mux.HandleFunc("/api/v1/keys/leaf-escrow", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authorize(w, r, "leaf_escrow.deposit")
		if !ok {
			return
		}
		var req struct {
			KeyID                string `json:"key_id"`
			CustodianAPassphrase string `json:"custodian_a_passphrase"`
			CustodianBPassphrase string `json:"custodian_b_passphrase"`
			ApprovedActionID     string `json:"approved_action_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "leaf_escrow.deposit", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if dualControl.Enabled() && strings.TrimSpace(req.KeyID) == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "leaf_escrow.deposit", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, "key_id is required")
			return
		}
		if !dualControl.gate(w, r, auth, auditProvider, pd, egressGate{
			actionType: keyActionLeafEscrow, keyID: req.KeyID, approvedID: req.ApprovedActionID,
			auditAction: "leaf_escrow.deposit",
			message:     "dual control is on - after approval, retry with approved_action_id",
		}) {
			return
		}
		tenant := auditRequestTenant(r)
		bundle, err := keystore.EscrowLeafKey(store, leafEscrowPolicyFromEnv(),
			leafEscrowAuditSink{r: r, provider: auditProvider, actor: pd.ID},
			tenant, req.KeyID,
			[]byte(req.CustodianAPassphrase), []byte(req.CustodianBPassphrase), time.Now())
		if err != nil {
			// The refusal reason (not opted in / single control) is safe to
			// surface: it names policy, never key or custodian material.
			emitAuditEvent(r, auditProvider, pd.ID, "leaf_escrow.deposit", "key", req.KeyID, AuditOutcomeDenied)
			writeForbidden(w, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", attachmentDisposition("leaf-"+req.KeyID+"-escrow.json"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	})

	// POST /api/v1/keys/leaf-escrow/recover — same dual-control ceremony.
	mux.HandleFunc("/api/v1/keys/leaf-escrow/recover", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authorize(w, r, "leaf_escrow.recover")
		if !ok {
			return
		}
		var req struct {
			Bundle               json.RawMessage `json:"bundle"`
			CustodianAPassphrase string          `json:"custodian_a_passphrase"`
			CustodianBPassphrase string          `json:"custodian_b_passphrase"`
			ApprovedActionID     string          `json:"approved_action_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil || len(req.Bundle) == 0 {
			emitAuditEvent(r, auditProvider, pd.ID, "leaf_escrow.recover", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, "bundle and both custodian passphrases are required")
			return
		}
		bundleKeyID, bundleSHA := bundleDigest(req.Bundle)
		if !dualControl.gate(w, r, auth, auditProvider, pd, egressGate{
			actionType: keyActionLeafEscrowRecover, keyID: bundleKeyID, bundleSHA256: bundleSHA,
			approvedID: req.ApprovedActionID, auditAction: "leaf_escrow.recover",
			message: "dual control is on - after approval, retry with approved_action_id",
		}) {
			return
		}
		id, err := keystore.RecoverLeafKey(store, leafEscrowPolicyFromEnv(),
			leafEscrowAuditSink{r: r, provider: auditProvider, actor: pd.ID},
			auditRequestTenant(r), req.Bundle,
			[]byte(req.CustodianAPassphrase), []byte(req.CustodianBPassphrase), time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "leaf_escrow.recover", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		writeJSONData(w, map[string]any{"key_id": id, "recovered": true})
	})
}
