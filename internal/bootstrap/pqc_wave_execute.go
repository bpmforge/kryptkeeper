// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/pqc"
)

// migrateWaveExecutionParams is the propose-time payload for a
// "pqc_migrate_wave" pending action.
type migrateWaveExecutionParams struct {
	WaveID     string `json:"wave_id"`
	TemplateID string `json:"template_id"`
}

// migrateWaveMemberResult is one member's migration outcome -- always
// recorded, never silently dropped (W4-03 acceptance #2).
type migrateWaveMemberResult struct {
	Fingerprint    string `json:"fingerprint"`
	Status         string `json:"status"` // "migrated" | "failed"
	NewFingerprint string `json:"new_fingerprint,omitempty"`
	Error          string `json:"error,omitempty"`
}

// migrateWaveExecutionResult is a full migrate-wave EXECUTE run's outcome.
type migrateWaveExecutionResult struct {
	Results  []migrateWaveMemberResult `json:"results"`
	Migrated int                       `json:"migrated"`
	Failed   int                       `json:"failed"`
}

// templateHasPQCAlgorithm reports whether tpl's AllowedAlgorithms contains
// at least one ML-DSA or hybrid algorithm, returning the first one found.
// Acceptance #1 requires migrate-wave to use "existing issuance" -- reusing
// the template's own algorithm allowlist (rather than hardcoding a target
// algorithm) is what makes this true; a template with no PQC entry is not
// a valid migrate-wave target.
func templateHasPQCAlgorithm(tpl TemplateItem) (keystore.Algorithm, bool) {
	for _, a := range tpl.AllowedAlgorithms {
		algo := keystore.Algorithm(a)
		if keystore.IsMLDSA(algo) || keystore.IsHybrid(algo) {
			return algo, true
		}
	}
	return "", false
}

// handleWaveExecutePropose creates a "pqc_migrate_wave" pending action for
// waveID. Called from registerPQCWaveHandlers's existing .../pqc-waves/
// prefix handler (not separately mux-registered) since this endpoint is a
// sub-path of that already-owned prefix.
func handleWaveExecutePropose(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, waveID string, waveStore MigrationWaveStore, templateProvider TemplateProvider, pendingStore PendingActionStore, auditProvider AuditProvider) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if pendingStore == nil {
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}
	var req migrateWaveExecutionParams
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON")
		return
	}
	req.WaveID = waveID

	waves, err := waveStore.ListWaves(r.Context())
	if err != nil {
		writeServiceUnavailable(w, "list waves failed")
		return
	}
	found := false
	for _, wv := range waves {
		if wv.ID == waveID {
			found = true
			break
		}
	}
	if !found {
		writeNotFound(w, "wave not found")
		return
	}

	tpl, ok, err := templateProvider.GetTemplate(r.Context(), req.TemplateID)
	if err != nil {
		writeServiceUnavailable(w, "template lookup failed")
		return
	}
	if !ok {
		writeBadRequest(w, "template not found")
		return
	}
	if _, ok := templateHasPQCAlgorithm(tpl); !ok {
		writeBadRequest(w, "template has no ML-DSA/hybrid algorithm in its allowed_algorithms")
		return
	}

	paramsJSON, err := json.Marshal(req)
	if err != nil {
		writeServiceUnavailable(w, "encode params failed")
		return
	}
	created, err := pendingStore.Create(r.Context(), PendingAction{
		ActionType: "pqc_migrate_wave",
		Params:     paramsJSON,
		ProposedBy: pd.ID,
		Tenant:     pd.Tenant,
	})
	if err != nil {
		writeServiceUnavailable(w, "propose failed")
		return
	}
	emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeSuccess)
	w.WriteHeader(http.StatusCreated)
	writeJSONData(w, created)
}

// handleWaveExecuteApprove decides a "pqc_migrate_wave" pending action and,
// on approval, runs the migration. Deliberately self-contained (does NOT
// route through executePendingAction's generic action-type switch, which
// is out of this ticket's write_scope) but duplicates that endpoint's
// proposer-cannot-approve-own-action and role-gate checks intentionally --
// same security properties, independent dispatch path.
func handleWaveExecuteApprove(w http.ResponseWriter, r *http.Request, auth *Authenticator, pd AuthPrincipal, waveID, actionID string, waveStore MigrationWaveStore, templateProvider TemplateProvider, certProvider CertificateProvider, keys keystore.Store, pendingStore PendingActionStore, auditProvider AuditProvider) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if pendingStore == nil {
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}
	action, ok, err := pendingStore.Get(r.Context(), actionID)
	if err != nil {
		writeServiceUnavailable(w, "lookup failed")
		return
	}
	if !ok || action.ActionType != "pqc_migrate_wave" {
		writeNotFound(w, "action not found")
		return
	}
	actionTenant := action.Tenant
	if actionTenant == "" {
		actionTenant = DefaultTenant
	}
	if !tenantVisible(pd, actionTenant) {
		writeNotFound(w, "action not found")
		return
	}
	if action.Status != "pending" {
		writeConflict(w, "action is not pending")
		return
	}
	var params migrateWaveExecutionParams
	if err := json.Unmarshal(action.Params, &params); err != nil {
		writeServiceUnavailable(w, "corrupt action params")
		return
	}
	if params.WaveID != waveID {
		writeNotFound(w, "action not found")
		return
	}

	if !auth.mayDecide(pd) {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeDenied)
		writeForbidden(w, approveDeniedMessage(auth, pd, "approve"))
		return
	}
	if msg := auth.approverRefusal(pd, action.ProposedBy); msg != "" {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeDenied)
		writeForbidden(w, msg)
		return
	}
	if keys == nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "no keystore configured")
		return
	}

	waves, err := waveStore.ListWaves(r.Context())
	if err != nil {
		writeServiceUnavailable(w, "list waves failed")
		return
	}
	var wave *MigrationWave
	for i := range waves {
		if waves[i].ID == waveID {
			wave = &waves[i]
			break
		}
	}
	if wave == nil {
		writeNotFound(w, "wave not found")
		return
	}

	tpl, ok, err := templateProvider.GetTemplate(r.Context(), params.TemplateID)
	if err != nil || !ok {
		writeServiceUnavailable(w, "template lookup failed")
		return
	}
	algo, ok := templateHasPQCAlgorithm(tpl)
	if !ok {
		writeServiceUnavailable(w, "template no longer has an ML-DSA/hybrid algorithm")
		return
	}

	// A01-003: claim the action (compare-and-set) before running the
	// migration so racing approvals re-issue each member once.
	if err := pendingStore.Decide(r.Context(), actionID, statusExecuting, pd.ID, nil); err != nil {
		writeConflict(w, "action is not pending")
		return
	}
	execResult := runWaveMigration(r.Context(), certProvider, keys, *wave, algo)

	resultJSON, err := json.Marshal(execResult)
	if err != nil {
		writeServiceUnavailable(w, "encode result failed")
		return
	}
	// Deciding "approved" reflects that the approval was processed and
	// results recorded, independent of whether individual members
	// succeeded -- per-member outcome is in execResult, matching
	// bulk_revoke's existing {revoked, failed} convention rather than
	// treating any per-item failure as an overall action failure.
	if err := pendingStore.Decide(r.Context(), actionID, "approved", pd.ID, resultJSON); err != nil {
		writeConflict(w, err.Error())
		return
	}
	emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeSuccess)
	writeJSONData(w, execResult)
}

// runWaveMigration re-issues every member of wave to algo via
// CertificateProvider.RenewCertificate -- NOT IssueCertificate -- so the
// result carries the same PredecessorFP/SuccessorFP chaining every other
// renewal in the product already establishes (RenewalStatus flips to
// "renewed" on the old cert). This is required for acceptance #1's
// "advances tracked progress" half, not just cosmetic: wave progress
// (vulnerableFingerprints, handlers_pqc_waves.go) is computed from live
// PQCReadiness, and a plain IssueCertificate call leaves the member's
// original fingerprint completely unlinked from its replacement -- the
// member would stay "not migrated" forever even after a real, successful
// re-issuance (found and fixed during closeout, confirmed empirically with
// a real long-lived vulnerable cert before this fix). "Migrated" means "a
// PQC-capable replacement was generated" -- the same meaning "renewed"
// already has for every cert in the product (D-103: generate-without-
// auto-deploy is the accepted migrate-wave scope; nothing in this codebase
// confirms a cert is actually live on the service using it).
//
// One member's failure never aborts the run (acceptance #2): a member
// whose fingerprint no longer resolves (cert deleted/rotated since the
// wave was built) is recorded failed and skipped, not fatal. A member
// already superseded (RenewCertificate's own errCertificateConflict) is
// likewise recorded failed, not fatal -- re-running EXECUTE on an
// already-migrated wave doesn't abort the rest of the run.
//
// The propose-time target template (already verified PQC-capable at
// propose/approve time, see templateHasPQCAlgorithm) is not threaded into
// this function -- RenewCertificate inherits the PREDECESSOR's own
// TemplateID for lineage, matching every other renewal's existing
// behavior; RenewCertificate does not enforce template algorithm policy on
// any renewal today (a pre-existing characteristic, not introduced here).
//
// Known limitation: CertificateItem tracks DNS SANs (SubjectAltNames) but
// not IP SANs separately, so a re-issued cert's IP SANs (if the original
// had any) are not preserved -- out of this ticket's scope to add IP-SAN
// tracking to the certificate store.
func runWaveMigration(ctx context.Context, certProvider CertificateProvider, keys keystore.Store, wave MigrationWave, algo keystore.Algorithm) migrateWaveExecutionResult {
	result := migrateWaveExecutionResult{Results: make([]migrateWaveMemberResult, 0, len(wave.Members))}
	for _, m := range wave.Members {
		detail, ok, err := certProvider.GetCertificate(ctx, m.Fingerprint)
		if err != nil || !ok {
			result.Results = append(result.Results, migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: "failed", Error: "certificate not found"})
			result.Failed++
			continue
		}
		item := detail.CertificateItem

		keyID := fmt.Sprintf("pqc-migrate-%s-%d", item.FingerprintSHA256, time.Now().UnixNano())
		subject := pkix.Name{CommonName: item.CommonName}
		migrated, err := pqc.BuildMigrationCSR(keys, keyID, algo, subject, item.SubjectAltNames, nil)
		if err != nil {
			result.Results = append(result.Results, migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: "failed", Error: err.Error()})
			result.Failed++
			continue
		}

		renewed, err := certProvider.RenewCertificate(ctx, m.Fingerprint, CertificateRenewRequest{CSRPEM: migrated.CSRPEM})
		if err != nil {
			result.Results = append(result.Results, migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: "failed", Error: err.Error()})
			result.Failed++
			continue
		}

		result.Results = append(result.Results, migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: "migrated", NewFingerprint: renewed.FingerprintSHA256})
		result.Migrated++
	}
	return result
}
