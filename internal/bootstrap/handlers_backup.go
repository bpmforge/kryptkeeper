// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// maxRestoreBundleBytes bounds a restore request body. A backup bundle holds
// every key in the store as PEM text (a few KB each even for the largest
// ML-DSA keys) — 16MB comfortably covers a store with thousands of keys
// while still rejecting a runaway/malicious body.
const maxRestoreBundleBytes = 16 * 1024 * 1024

// registerBackupHandlers wires the whole-keystore backup/restore endpoints
// (W10-03/G-36) if a keystore is available. Kept separate from
// registerKeyHandlers because it operates on every key in the store at once
// — a materially larger blast radius than the single-key export/import
// endpoints, worth its own audit event names and its own file to review.
func registerBackupHandlers(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider) {
	if store == nil {
		return
	}

	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())

	// POST /api/v1/admin/backup — export every key in the store, encrypted
	// under the caller-supplied backup passphrase, as a single JSON bundle.
	mux.HandleFunc("/api/v1/admin/backup", func(w http.ResponseWriter, r *http.Request) {
		principalDetails, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "backup.create", "backup", "all-keys", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := principalDetails.ID
		if !isAdminRole(principalDetails.Role) {
			emitAuditEvent(r, auditProvider, principal, "backup.create", "backup", "all-keys", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key backup")
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		var req struct {
			BackupPassphrase string `json:"backup_passphrase"`
			// FG-2: an approved key_backup grant id, redeemed by its proposer.
			ApprovedActionID string `json:"approved_action_id"`
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024))
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "backup.create", "backup", "all-keys", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.BackupPassphrase) == "" {
			emitAuditEvent(r, auditProvider, principal, "backup.create", "backup", "all-keys", AuditOutcomeFailure)
			writeBadRequest(w, "backup_passphrase is required")
			return
		}

		if !dualControl.gate(w, r, auth, auditProvider, principalDetails, egressGate{
			actionType: keyActionBackup, keyID: backupScope, approvedID: req.ApprovedActionID,
			auditAction: "backup.create",
			message:     "dual control is on - after approval, retry with approved_action_id",
		}) {
			return
		}

		bundle, err := keystore.BackupAll(store, []byte(req.BackupPassphrase))
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "backup.create", "backup", "all-keys", AuditOutcomeFailure)
			writeServiceUnavailable(w, "backup failed")
			return
		}

		exported, skipped, errored := countBundleOutcomes(bundle)
		emitAuditEventDetail(r, auditProvider, principal, "backup.create", "backup", "all-keys", AuditOutcomeSuccess,
			fmt.Sprintf(`{"exported":%d,"skipped_non_extractable":%d,"error":%d}`, exported, skipped, errored))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="kryptkeeper-keys-backup-%s.json"`, time.Now().UTC().Format("20060102T150405Z")))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	})

	// POST /api/v1/admin/restore — re-import every exported key from a
	// bundle produced by /api/v1/admin/backup into this store.
	mux.HandleFunc("/api/v1/admin/restore", func(w http.ResponseWriter, r *http.Request) {
		principalDetails, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "backup.restore", "backup", "all-keys", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := principalDetails.ID
		if !isAdminRole(principalDetails.Role) {
			emitAuditEvent(r, auditProvider, principal, "backup.restore", "backup", "all-keys", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key restore")
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		var req struct {
			BackupPassphrase string          `json:"backup_passphrase"`
			Bundle           json.RawMessage `json:"bundle"`
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRestoreBundleBytes))
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "backup.restore", "backup", "all-keys", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.BackupPassphrase) == "" || len(req.Bundle) == 0 {
			emitAuditEvent(r, auditProvider, principal, "backup.restore", "backup", "all-keys", AuditOutcomeFailure)
			writeBadRequest(w, "backup_passphrase and bundle are required")
			return
		}

		imported, restoreErr := keystore.RestoreAll(store, req.Bundle, []byte(req.BackupPassphrase))
		if restoreErr != nil {
			// RestoreAll is best-effort — some keys may have imported even
			// though others failed (e.g. a duplicate ID already present).
			// Report both counts and the failure detail rather than only a
			// generic 500, since a partial restore is actionable, not fatal.
			// audit_log's outcome column only accepts success/failure/denied
			// (schema CHECK constraint) — a partial restore is recorded as
			// "failure" with the imported count in the detail, not a fourth
			// outcome value the DB-mode audit provider would reject outright.
			emitAuditEventDetail(r, auditProvider, principal, "backup.restore", "backup", "all-keys", AuditOutcomeFailure,
				fmt.Sprintf(`{"imported":%d,"error":%q}`, imported, restoreErr.Error()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMultiStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"imported": imported,
					"error":    restoreErr.Error(),
				},
			})
			return
		}

		emitAuditEventDetail(r, auditProvider, principal, "backup.restore", "backup", "all-keys", AuditOutcomeSuccess,
			fmt.Sprintf(`{"imported":%d}`, imported))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"imported": imported},
		})
	})
}

// countBundleOutcomes is a lightweight, tolerant re-parse of a bundle purely
// for the audit-log summary — a parse failure here must never fail the
// backup response itself (the bundle was already built successfully by
// keystore.BackupAll), so errors are swallowed and counts default to 0.
func countBundleOutcomes(bundle []byte) (exported, skipped, errored int) {
	var parsed struct {
		Keys []struct {
			Status string `json:"status"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return 0, 0, 0
	}
	for _, k := range parsed.Keys {
		switch keystore.BackupKeyStatus(k.Status) {
		case keystore.BackupKeyExported:
			exported++
		case keystore.BackupKeySkippedNonExtractable:
			skipped++
		case keystore.BackupKeyError:
			errored++
		}
	}
	return exported, skipped, errored
}

// RegisterBackupHandlers wires the backup/restore API if a keystore is
// available. Mirrors RegisterKeyHandlers's pattern: called separately from
// RegisterHandlers so the keystore dependency stays optional.
func RegisterBackupHandlers(mux *http.ServeMux, auth *Authenticator, store keystore.Store, auditProvider AuditProvider) {
	registerBackupHandlers(mux, auth, store, auditProvider)
}
