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
	"kryptkeeper/internal/keystore"
)

// keyBackend identifies which keystore.Store backend `store` is (e.g.
// "software", "pkcs11", "vault", "cloudkms") -- injected by the caller
// (cmd/kryptkeeper/main.go, via RunWithProtocols/Run/RegisterKeyHandlers)
// rather than held as package state, since keystore.Store itself has no
// such accessor. Empty means "software" (keystore.CheckHSMPQCSupport
// treats an unrecognized/empty backend as non-hardware and passes
// through), matching ca.Engine.keyBackendLabel's same default.
func registerKeyHandlers(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider, keyBackend string) {
	if store == nil {
		return
	}
	// W9-05: the generation policy, resolved once from env at registration.
	keygenPolicy := keystore.KeygenPolicyFromEnv()
	// W9-10: dual control for destructive key ops, resolved from env once.
	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())

	// GET  /api/v1/keys           — list all keys
	// POST /api/v1/keys           — generate new key
	mux.HandleFunc("/api/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		principalDetails, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "key."+r.Method, "key", "keys", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := principalDetails.ID
		if !isAdminRole(principalDetails.Role) {
			emitAuditEvent(r, auditProvider, principal, "key."+r.Method, "key", "keys", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key management")
			return
		}

		switch r.Method {
		case http.MethodGet:
			metas, err := store.List()
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.list", "key", "keys", AuditOutcomeFailure)
				writeServiceUnavailable(w, "key list unavailable")
				return
			}
			// W23-23: keys inside a provider recovery window are listed (flagged
			// pending_deletion) so they can be seen and cancelled.
			if pl, ok := store.(keystore.PendingDeletionLister); ok {
				metas = append(metas, pl.PendingDeletions(time.Now())...)
			}
			metas = filterKeyMetasByTenant(r.Context(), activeTenantStore, principalDetails, metas)
			emitAuditEvent(r, auditProvider, principal, "key.list", "key", "keys", AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Data []keystore.KeyMetadata `json:"data"`
			}{Data: metas})

		case http.MethodPost:
			if denyTenantPrincipalKeyOp(w, r, auditProvider, principalDetails, "key.generate", "key", "keys") {
				return
			}
			var req struct {
				ID        string `json:"id"`
				Algorithm string `json:"algorithm"`
				// Purpose selects the policy floor (W9-05): "general"
				// (default) or "ca" (stricter RSA floor).
				Purpose string `json:"purpose"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.generate", "key", "keys", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			if strings.TrimSpace(req.ID) == "" {
				emitAuditEvent(r, auditProvider, principal, "key.generate", "key", "keys", AuditOutcomeFailure)
				writeBadRequest(w, "id is required")
				return
			}
			algo := keystore.Algorithm(strings.TrimSpace(req.Algorithm))
			// W9-05: policy first — before this, any algorithm passed
			// straight through (an RSA-2048 CA key with no floor anywhere).
			if err := keygenPolicy.Check(algo, strings.TrimSpace(req.Purpose)); err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.generate", "key", req.ID, AuditOutcomeDenied)
				writeBadRequest(w, err.Error())
				return
			}
			// W9-11: in FIPS mode, non-approved algorithms are refused
			// with the reason (no-op outside FIPS mode).
			if err := keystore.CheckFIPSAlgorithm(algo); err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.generate", "key", req.ID, AuditOutcomeDenied)
				writeBadRequest(w, err.Error())
				return
			}
			// W19-19: ML-DSA/hybrid on a hardware/remote backend must be
			// refused here, before store.GenerateKey ever runs, so no
			// token object is created and the caller gets the ADR's
			// reasoning instead of a generic 503 (observed live against
			// SoftHSM2 in W19-08 UAT).
			if err := keystore.CheckHSMPQCSupport(keyBackend, algo); err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.generate", "key", req.ID, AuditOutcomeDenied)
				writeErrorEnvelope(w, http.StatusUnprocessableEntity, "unprocessable_entity",
					fmt.Sprintf("%s -- PQC keys are software-keystore-only; see docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md", err.Error()))
				return
			}
			meta, err := store.GenerateKey(req.ID, algo)
			if err != nil {
				if errors.Is(err, keystore.ErrKeyExists) {
					emitAuditEvent(r, auditProvider, principal, "key.generate", "key", req.ID, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"key already exists"}`))
					return
				}
				if errors.Is(err, keystore.ErrUnsupportedAlgo) {
					emitAuditEvent(r, auditProvider, principal, "key.generate", "key", req.ID, AuditOutcomeFailure)
					writeBadRequest(w, "unsupported algorithm")
					return
				}
				logging.Warnf("key generate failed: %v", err)
				emitAuditEvent(r, auditProvider, principal, "key.generate", "key", req.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "key generation failed")
				return
			}
			genSummary := fmt.Sprintf(`{"id":%q,"algorithm":%q}`, meta.ID, meta.Algorithm)
			emitAuditEventDetail(r, auditProvider, principal, "key.generate", "key", meta.ID, AuditOutcomeSuccess, genSummary)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data keystore.KeyMetadata `json:"data"`
			}{Data: meta})

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	// GET    /api/v1/keys/{id}         — get key metadata
	// DELETE /api/v1/keys/{id}         — delete key
	// POST   /api/v1/keys/{id}/rotate  — rotate key
	// POST   /api/v1/keys/{id}/export  — export encrypted backup
	// POST   /api/v1/keys/import       — import backup
	mux.HandleFunc("/api/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		principalDetails, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "key.op", "key", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := principalDetails.ID
		if !isAdminRole(principalDetails.Role) {
			emitAuditEvent(r, auditProvider, principal, "key.op", "key", "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key management")
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")

		// POST /api/v1/keys/import
		if tail == "import" {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			if denyTenantPrincipalKeyOp(w, r, auditProvider, principalDetails, "key.import", "key", "-") {
				return
			}
			var req struct {
				ID         string `json:"id"`
				BackupPEM  string `json:"backup_pem"`
				Passphrase string `json:"passphrase"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.import", "key", "-", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			if err := store.ImportEncryptedKey(req.ID, []byte(req.BackupPEM), []byte(req.Passphrase)); err != nil {
				if errors.Is(err, keystore.ErrKeyExists) {
					emitAuditEvent(r, auditProvider, principal, "key.import", "key", req.ID, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"key already exists"}`))
					return
				}
				if errors.Is(err, keystore.ErrDecryptionFailed) {
					emitAuditEvent(r, auditProvider, principal, "key.import", "key", req.ID, AuditOutcomeFailure)
					writeBadRequest(w, "decryption failed — wrong passphrase or corrupt data")
					return
				}
				emitAuditEvent(r, auditProvider, principal, "key.import", "key", req.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "key import failed")
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "key.import", "key", req.ID, AuditOutcomeSuccess,
				fmt.Sprintf(`{"id":%q}`, req.ID))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"status":"imported"}}`))
			return
		}

		// W23 per-key routes (policy, compromise, cancel-deletion) are tenant
		// scoped like rotate/export: a key outside the caller's tenant is 404.
		for _, suffix := range []string{"/policy", "/compromise", "/cancel-deletion"} {
			if !strings.HasSuffix(tail, suffix) {
				continue
			}
			if id := strings.TrimSuffix(tail, suffix); !keyVisibleToTenant(r.Context(), activeTenantStore, principalDetails, id) {
				emitAuditEvent(r, auditProvider, principal, "key"+strings.ReplaceAll(suffix, "/", "."), "key", id, AuditOutcomeDenied)
				writeNotFound(w, "key not found")
				return
			}
		}

		// GET/PUT /api/v1/keys/{id}/policy (W23-38). Admin-only but not
		// ACL-gated: a lost owner must not brick a key.
		if strings.HasSuffix(tail, "/policy") {
			handleKeyPolicy(w, r, store, auditProvider, principal, strings.TrimSuffix(tail, "/policy"))
			return
		}

		// POST /api/v1/keys/{id}/compromise (W23-38). Always dual-controlled.
		if strings.HasSuffix(tail, "/compromise") {
			handleKeyCompromise(w, r, store, dualControl, auditProvider, principalDetails, strings.TrimSuffix(tail, "/compromise"))
			return
		}

		// POST /api/v1/keys/{id}/cancel-deletion (W23-22)
		if strings.HasSuffix(tail, "/cancel-deletion") {
			id := strings.TrimSuffix(tail, "/cancel-deletion")
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			if id == "" || strings.Contains(id, "/") {
				writeNotFound(w, "key not found")
				return
			}
			handleCancelKeyDeletion(w, r, store, dualControl, auditProvider, principal, id)
			return
		}

		// Routes: /api/v1/keys/{id} or /api/v1/keys/{id}/...
		if strings.HasSuffix(tail, "/rotate") {
			id := strings.TrimSuffix(tail, "/rotate")
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			if !keyVisibleToTenant(r.Context(), activeTenantStore, principalDetails, id) {
				emitAuditEvent(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeDenied)
				writeNotFound(w, "key not found")
				return
			}
			if !authorizeKeyOp(w, r, auditProvider, principalDetails, id) {
				return
			}
			var req struct {
				Algorithm string `json:"algorithm"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			// W9-04/G-35: raw keystore rotation on a key that backs a CA
			// silently breaks the CA -- its certificate still embeds the
			// old public key/SKI, with nothing re-issuing it. Refuse and
			// point the caller at the real CA re-key flow instead.
			if activeCAStore != nil {
				if backingCAID, found, err := ca.KeyInUseByCA(activeCAStore, id); err == nil && found {
					emitAuditEvent(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeDenied)
					writeErrorEnvelope(w, http.StatusConflict, "conflict",
						fmt.Sprintf("key %s backs CA %s; use CA re-key (POST /api/v1/cas/%s/rotate-key), not raw key rotation", id, backingCAID, backingCAID))
					return
				}
			}

			// W9-10: with dual control on, rotation is proposed, not done.
			if dualControl.Enabled() {
				action, err := dualControl.Propose(r.Context(), keyActionRotate, id, principal)
				if err != nil {
					emitAuditEvent(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeFailure)
					writeServiceUnavailable(w, "dual-control proposal failed")
					return
				}
				emitAuditEventDetail(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeProposed,
					fmt.Sprintf(`{"action_id":%q}`, action.ID))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"proposed","action_id":%q,"message":"dual control is on — a second approver must approve this rotation"}}`, action.ID)))
				return
			}

			algo := keystore.Algorithm(strings.TrimSpace(req.Algorithm))
			result, err := store.RotateKey(id, algo)
			if err != nil {
				if errors.Is(err, keystore.ErrKeyNotFound) {
					emitAuditEvent(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeFailure)
					writeNotFound(w, "key not found")
					return
				}
				logging.Warnf("key rotate failed: %v", err)
				emitAuditEvent(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "key rotation failed")
				return
			}
			rotateSummary := fmt.Sprintf(`{"id":%q,"algorithm":%q,"previous_id":%q}`, id, result.New.Algorithm, result.PreviousID)
			emitAuditEventDetail(r, auditProvider, principal, "key.rotate", "key", id, AuditOutcomeSuccess, rotateSummary)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Data keystore.KeyRotateResult `json:"data"`
			}{Data: result})
			return
		}

		if strings.HasSuffix(tail, "/export") {
			id := strings.TrimSuffix(tail, "/export")
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			if !keyVisibleToTenant(r.Context(), activeTenantStore, principalDetails, id) {
				emitAuditEvent(r, auditProvider, principal, "key.export", "key", id, AuditOutcomeDenied)
				writeNotFound(w, "key not found")
				return
			}
			if !authorizeKeyOp(w, r, auditProvider, principalDetails, id) {
				return
			}
			var req struct {
				Passphrase string `json:"passphrase"`
				// W9-10: an approved key_export grant id, redeemed here by
				// its proposer. The passphrase never touches the queue.
				ApprovedActionID string `json:"approved_action_id"`
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024))
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "key.export", "key", id, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Passphrase) == "" {
				emitAuditEvent(r, auditProvider, principal, "key.export", "key", id, AuditOutcomeFailure)
				writeBadRequest(w, "passphrase is required")
				return
			}
			// W9-10: with dual control on, export needs an approved grant.
			if !dualControl.gate(w, r, auth, auditProvider, principalDetails, egressGate{
				actionType: keyActionExport, keyID: id, approvedID: req.ApprovedActionID,
				auditAction: "key.export",
				message:     "dual control is on - after approval, retry with approved_action_id",
			}) {
				return
			}
			pemBytes, err := store.ExportEncryptedKey(id, []byte(req.Passphrase))
			if err != nil {
				if errors.Is(err, keystore.ErrKeyNotFound) {
					emitAuditEvent(r, auditProvider, principal, "key.export", "key", id, AuditOutcomeFailure)
					writeNotFound(w, "key not found")
					return
				}
				emitAuditEvent(r, auditProvider, principal, "key.export", "key", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "export failed")
				return
			}
			// Every export is audited regardless of outcome.
			emitAuditEventDetail(r, auditProvider, principal, "key.export", "key", id, AuditOutcomeSuccess,
				fmt.Sprintf(`{"id":%q,"purpose":"backup"}`, id))
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="key-%s-backup.pem"`, id))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(pemBytes)
			return
		}

		// GET/DELETE /api/v1/keys/{id}
		id := tail
		if strings.Contains(id, "/") {
			writeNotFound(w, "key not found")
			return
		}
		if !keyVisibleToTenant(r.Context(), activeTenantStore, principalDetails, id) {
			emitAuditEvent(r, auditProvider, principal, "key.op", "key", id, AuditOutcomeDenied)
			writeNotFound(w, "key not found")
			return
		}

		switch r.Method {
		case http.MethodGet:
			meta, err := store.Metadata(id)
			if err != nil {
				if errors.Is(err, keystore.ErrKeyNotFound) {
					emitAuditEvent(r, auditProvider, principal, "key.get", "key", id, AuditOutcomeFailure)
					writeNotFound(w, "key not found")
					return
				}
				emitAuditEvent(r, auditProvider, principal, "key.get", "key", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "key unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal, "key.get", "key", id, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Data keystore.KeyMetadata `json:"data"`
			}{Data: meta})

		case http.MethodDelete:
			if !authorizeKeyOp(w, r, auditProvider, principalDetails, id) {
				return
			}
			// W19-19: same in-use guard /rotate applies (W9-04/G-35) --
			// deleting a key that backs a CA would orphan it just as
			// silently as rotating it out from under the CA would.
			if activeCAStore != nil {
				if backingCAID, found, err := ca.KeyInUseByCA(activeCAStore, id); err == nil && found {
					emitAuditEvent(r, auditProvider, principal, "key.delete", "key", id, AuditOutcomeDenied)
					writeErrorEnvelope(w, http.StatusConflict, "conflict",
						fmt.Sprintf("key %s backs CA %s; delete or migrate the CA before deleting its key", id, backingCAID))
					return
				}
			}
			// W9-10: with dual control on, deletion is proposed, not done.
			if dualControl.Enabled() {
				action, err := dualControl.Propose(r.Context(), keyActionDelete, id, principal)
				if err != nil {
					emitAuditEvent(r, auditProvider, principal, "key.delete", "key", id, AuditOutcomeFailure)
					writeServiceUnavailable(w, "dual-control proposal failed")
					return
				}
				emitAuditEventDetail(r, auditProvider, principal, "key.delete", "key", id, AuditOutcomeProposed,
					fmt.Sprintf(`{"action_id":%q}`, action.ID))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"proposed","action_id":%q,"message":"dual control is on — a second approver must approve this deletion"}}`, action.ID)))
				return
			}
			if err := store.Delete(id); err != nil {
				if errors.Is(err, keystore.ErrKeyNotFound) {
					emitAuditEvent(r, auditProvider, principal, "key.delete", "key", id, AuditOutcomeFailure)
					writeNotFound(w, "key not found")
					return
				}
				emitAuditEvent(r, auditProvider, principal, "key.delete", "key", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "key delete failed")
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "key.delete", "key", id, AuditOutcomeSuccess,
				fmt.Sprintf(`{"id":%q}`, id))
			w.WriteHeader(http.StatusNoContent)

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodDelete)
		}
	})
}

// handleCancelKeyDeletion un-schedules a provider-side key deletion. Refusals
// are audited too: an attempt to cancel is itself a security-relevant event.
func handleCancelKeyDeletion(w http.ResponseWriter, r *http.Request, store keystore.Store, dualControl *KeyDualControl, auditProvider AuditProvider, principal, id string) {
	const auditAction = "key.destroy_cancel"
	c, ok := store.(keystore.DeletionCanceller)
	if !ok {
		emitAuditEvent(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeDenied)
		writeErrorEnvelope(w, http.StatusConflict, "conflict", "this keystore backend has no scheduled deletions to cancel")
		return
	}
	can, err := c.CanCancelDeletion(id, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "key deletion status unavailable")
		return
	}
	if !can {
		emitAuditEvent(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeDenied)
		writeErrorEnvelope(w, http.StatusConflict, "conflict", "key is not in a cancellable pending-deletion window")
		return
	}
	if dualControl.Enabled() {
		action, err := dualControl.Propose(r.Context(), keyActionCancelDelete, id, principal)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "dual-control proposal failed")
			return
		}
		emitAuditEventDetail(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeProposed,
			fmt.Sprintf(`{"action_id":%q}`, action.ID))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"proposed","action_id":%q,"message":"dual control is on — a second approver must approve this cancellation"}}`, action.ID)))
		return
	}
	if err := c.CancelDeletion(r.Context(), id); err != nil {
		emitAuditEvent(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeFailure)
		if errors.Is(err, keystore.ErrNotCancellable) {
			writeErrorEnvelope(w, http.StatusConflict, "conflict", "key is not in a cancellable pending-deletion window")
			return
		}
		logging.Warnf("key deletion cancel failed: %v", err)
		writeServiceUnavailable(w, "key deletion cancel failed")
		return
	}
	emitAuditEventDetail(r, auditProvider, principal, auditAction, "key", id, AuditOutcomeSuccess,
		fmt.Sprintf(`{"id":%q}`, id))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"cancelled","id":%q}}`, id)))
}

// keyOwnerTenant maps a keystore key to the tenant of the CA it backs. Keys the
// CA store cannot attribute to a CA (ssh-ca, escrow material, standalone keys)
// have no owner, so only an unscoped super-admin may touch them.
func keyOwnerTenant(ctx context.Context, ts TenantStore, keyID string) (string, bool) {
	if activeCAStore == nil || ts == nil {
		return "", false
	}
	caID, found, err := ca.KeyInUseByCA(activeCAStore, keyID)
	if err != nil || !found {
		return "", false
	}
	t, err := ts.CATenant(ctx, caID)
	if err != nil {
		return "", false // deny by default on lookup failure
	}
	return t, true
}

// keyVisibleToTenant reports whether pd may see/operate on keyID.
func keyVisibleToTenant(ctx context.Context, ts TenantStore, pd AuthPrincipal, keyID string) bool {
	if tenantBypass(pd) {
		return true
	}
	t, ok := keyOwnerTenant(ctx, ts, keyID)
	return ok && t == pd.Tenant
}

// denyTenantPrincipalKeyOp refuses key operations that are not attributable to a
// single tenant (backup, restore, escrow, generate, import) unless the caller is
// an unscoped super-admin. Returns true when it has written the 403.
func denyTenantPrincipalKeyOp(w http.ResponseWriter, r *http.Request, audit AuditProvider, pd AuthPrincipal, action, resType, resID string) bool {
	if tenantBypass(pd) {
		return false
	}
	emitAuditEventDetail(r, audit, pd.ID, action, resType, resID, AuditOutcomeDenied, `{"reason":"super-admin only when multi-tenancy is on"}`)
	writeForbidden(w, "this key operation is restricted to the platform super-admin when multi-tenancy is on")
	return true
}

func filterKeyMetasByTenant(ctx context.Context, ts TenantStore, pd AuthPrincipal, metas []keystore.KeyMetadata) []keystore.KeyMetadata {
	if tenantBypass(pd) {
		return metas
	}
	out := make([]keystore.KeyMetadata, 0, len(metas))
	for _, m := range metas {
		if keyVisibleToTenant(ctx, ts, pd, m.ID) {
			out = append(out, m)
		}
	}
	return out
}
