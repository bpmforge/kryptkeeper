// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// W9-12 (D-051/FR-P13): key escrow under dual control. Exact-match routes —
// they win over the /api/v1/keys/ prefix handler, so that handler stays
// untouched. The bundle returned here is the sanctioned encrypted-escrow
// artifact: dual-custody ciphertext, never plaintext key bytes.
func registerKeyEscrowHandlers(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider) {
	if store == nil {
		return
	}

	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())

	authorize := func(w http.ResponseWriter, r *http.Request, action string) (AuthPrincipal, bool) {
		principalDetails, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "key", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !isAdminRole(principalDetails.Role) {
			emitAuditEvent(r, auditProvider, principalDetails.ID, action, "key", "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key escrow")
			return AuthPrincipal{}, false
		}
		if denyTenantPrincipalKeyOp(w, r, auditProvider, principalDetails, action, "key", "-") {
			return AuthPrincipal{}, false
		}
		return principalDetails, true
	}

	// POST /api/v1/keys/escrow — escrow a key under two custodians.
	mux.HandleFunc("/api/v1/keys/escrow", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authorize(w, r, "key.escrow")
		if !ok {
			return
		}
		principal := pd.ID
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			KeyID                string `json:"key_id"`
			CustodianAPassphrase string `json:"custodian_a_passphrase"`
			CustodianBPassphrase string `json:"custodian_b_passphrase"`
			ApprovedActionID     string `json:"approved_action_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal, "key.escrow", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if dualControl.Enabled() && strings.TrimSpace(req.KeyID) == "" {
			emitAuditEvent(r, auditProvider, principal, "key.escrow", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, "key_id is required")
			return
		}
		if !dualControl.gate(w, r, auth, auditProvider, pd, egressGate{
			actionType: keyActionEscrow, keyID: req.KeyID, approvedID: req.ApprovedActionID,
			auditAction: "key.escrow",
			message:     "dual control is on - after approval, retry with approved_action_id",
		}) {
			return
		}
		bundle, err := keystore.EscrowKey(store, req.KeyID, []byte(req.CustodianAPassphrase), []byte(req.CustodianBPassphrase))
		if err != nil {
			if errors.Is(err, keystore.ErrKeyNotFound) {
				emitAuditEvent(r, auditProvider, principal, "key.escrow", "key", req.KeyID, AuditOutcomeFailure)
				writeNotFound(w, "key not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal, "key.escrow", "key", req.KeyID, AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		emitAuditEventDetail(r, auditProvider, principal, "key.escrow", "key", req.KeyID, AuditOutcomeSuccess,
			fmt.Sprintf(`{"id":%q,"custodians":2}`, req.KeyID))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", attachmentDisposition("key-"+req.KeyID+"-escrow.json"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	})

	// POST /api/v1/keys/escrow/recover — recover an escrowed key; both
	// custodian passphrases required.
	mux.HandleFunc("/api/v1/keys/escrow/recover", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authorize(w, r, "key.escrow_recover")
		if !ok {
			return
		}
		principal := pd.ID
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			Bundle               json.RawMessage `json:"bundle"`
			CustodianAPassphrase string          `json:"custodian_a_passphrase"`
			CustodianBPassphrase string          `json:"custodian_b_passphrase"`
			ApprovedActionID     string          `json:"approved_action_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512*1024)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal, "key.escrow_recover", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		bundleKeyID, bundleSHA := bundleDigest(req.Bundle)
		if !dualControl.gate(w, r, auth, auditProvider, pd, egressGate{
			actionType: keyActionEscrowRecover, keyID: bundleKeyID, bundleSHA256: bundleSHA,
			approvedID: req.ApprovedActionID, auditAction: "key.escrow_recover",
			message: "dual control is on - after approval, retry with approved_action_id",
		}) {
			return
		}
		id, err := keystore.RecoverEscrowedKey(store, req.Bundle, []byte(req.CustodianAPassphrase), []byte(req.CustodianBPassphrase))
		if err != nil {
			if errors.Is(err, keystore.ErrKeyExists) {
				emitAuditEvent(r, auditProvider, principal, "key.escrow_recover", "key", id, AuditOutcomeFailure)
				writeErrorEnvelope(w, http.StatusConflict, "conflict", "key already exists")
				return
			}
			// A wrong custodian passphrase is the interesting audit case —
			// a recovery attempt that did not satisfy dual control.
			emitAuditEvent(r, auditProvider, principal, "key.escrow_recover", "key", "-", AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		emitAuditEventDetail(r, auditProvider, principal, "key.escrow_recover", "key", id, AuditOutcomeSuccess,
			fmt.Sprintf(`{"id":%q}`, id))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"recovered","id":%q}}`, id)))
	})
}
