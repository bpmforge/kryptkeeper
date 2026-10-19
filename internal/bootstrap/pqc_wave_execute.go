// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/pqc"
)

// migrateWaveExecutionParams is the propose-time payload for a
// "pqc_migrate_wave" pending action.
type migrateWaveExecutionParams struct {
	WaveID     string `json:"wave_id"`
	TemplateID string `json:"template_id"`
	// TargetAlgorithm selects a classical (or explicit PQC) re-issue target
	// from the template's allowed algorithms; empty keeps the PQC-only pick.
	TargetAlgorithm string `json:"target_algorithm,omitempty"`
}

// migrateWaveMemberResult is one member's migration outcome -- always
// recorded, never silently dropped (W4-03 acceptance #2).
type migrateWaveMemberResult struct {
	Fingerprint    string `json:"fingerprint"`
	Status         string `json:"status"` // pqc.Member*
	NewFingerprint string `json:"new_fingerprint,omitempty"`
	// Error mirrors Reason for pre-W31-08 consumers.
	Error  string `json:"error,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Delivery is none|verified|failed|unsupported.
	Delivery string `json:"delivery,omitempty"`
	// OldSerialServed is set only when delivery was attempted and the verifier
	// confirmed the previous certificate is still what the target serves.
	OldSerialServed *bool `json:"old_serial_served,omitempty"`
}

// migrateWaveExecutionResult is a full migrate-wave EXECUTE run's outcome.
type migrateWaveExecutionResult struct {
	Results     []migrateWaveMemberResult `json:"results"`
	Migrated    int                       `json:"migrated"`
	Failed      int                       `json:"failed"`
	Skipped     int                       `json:"skipped"`
	Unsupported int                       `json:"unsupported"`
	Regressed   bool                      `json:"regressed"`
	WaveStatus  string                    `json:"wave_status,omitempty"`
}

// Delivery outcomes a waveDeliverer reports.
const (
	waveDeliveryOK         = "ok"
	waveDeliveryRolledBack = "rolled_back"
	waveDeliveryFailed     = "failed"
)

// waveDelivery is one install attempt's outcome. Verified means the target was
// observed serving the new fingerprint.
type waveDelivery struct {
	Outcome  string
	Detail   string
	Verified bool
}

// waveDeliverer is the UC-D01 install/verify/rollback seam for wave members.
type waveDeliverer interface {
	Supports(t ManagedTarget) (ok bool, reason string)
	// Deliver installs the member's new cert, verifies the served fingerprint
	// equals newFP and, on mismatch, restores the previous files. A non-nil
	// error means the install was not attempted.
	Deliver(ctx context.Context, t ManagedTarget, oldFP, newFP string) (waveDelivery, error)
}

// unsupportedWaveDeliverer is the production deliverer until ML-DSA private
// key export exists (D-103 generate-without-deliver): RenewalExecutor generates
// its own ECDSA/RSA key and cannot carry a hub-held ML-DSA key, so every bound
// target is reported rather than silently skipped.
type unsupportedWaveDeliverer struct{}

const waveDeliveryUnsupportedReason = "PQC key material cannot be installed yet (D-103 generate-without-deliver); manual install"

func (unsupportedWaveDeliverer) Supports(ManagedTarget) (bool, string) {
	return false, waveDeliveryUnsupportedReason
}

func (unsupportedWaveDeliverer) Deliver(context.Context, ManagedTarget, string, string) (waveDelivery, error) {
	return waveDelivery{}, errors.New(waveDeliveryUnsupportedReason)
}

// waveHooks are optional observation/veto points (W31-09 plugs in); the zero
// value is a no-op.
type waveHooks struct {
	// PreApprove runs after the proposer/role/status checks and before the
	// action is claimed; a non-empty return refuses the approval with a 409.
	PreApprove   func(a PendingAction) string
	MemberResult func(waveID string, r migrateWaveMemberResult)
	WaveOutcome  func(waveID string, res migrateWaveExecutionResult)
}

// waveDeps are runWaveMigration's collaborators.
type waveDeps struct {
	certs   CertificateProvider
	keys    keystore.Store
	targets ManagedTargetStore
	deliver waveDeliverer
	// waves persists the regressed mark; nil skips persistence (the result
	// still reports Regressed).
	waves MigrationWaveStore
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
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}
	var req migrateWaveExecutionParams
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
		writeBadRequest(w, "invalid JSON")
		return
	}
	req.WaveID = waveID

	waves, err := waveStore.ListWaves(r.Context())
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
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
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
		writeNotFound(w, "wave not found")
		return
	}

	tpl, ok, err := templateProvider.GetTemplate(r.Context(), req.TemplateID)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "template lookup failed")
		return
	}
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
		writeBadRequest(w, "template not found")
		return
	}
	if _, ok := resolveWaveTargetAlgorithm(tpl, req.TargetAlgorithm); !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
		writeBadRequest(w, "template has no allowed algorithm usable as the wave target")
		return
	}

	paramsJSON, err := json.Marshal(req)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
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
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_propose", "migration-wave", waveID, AuditOutcomeFailure)
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
func handleWaveExecuteApprove(w http.ResponseWriter, r *http.Request, auth *Authenticator, pd AuthPrincipal, waveID, actionID string, waveStore MigrationWaveStore, templateProvider TemplateProvider, certProvider CertificateProvider, keys keystore.Store, pendingStore PendingActionStore, auditProvider AuditProvider, targets ManagedTargetStore, deliver waveDeliverer, hooks waveHooks) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if pendingStore == nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}
	action, ok, err := pendingStore.Get(r.Context(), actionID)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "lookup failed")
		return
	}
	if !ok || action.ActionType != "pqc_migrate_wave" {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeNotFound(w, "action not found")
		return
	}
	actionTenant := action.Tenant
	if actionTenant == "" {
		actionTenant = DefaultTenant
	}
	if !tenantVisible(pd, actionTenant) {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeNotFound(w, "action not found")
		return
	}
	if action.Status != "pending" {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeConflict(w, "action is not pending")
		return
	}
	var params migrateWaveExecutionParams
	if err := json.Unmarshal(action.Params, &params); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "corrupt action params")
		return
	}
	if params.WaveID != waveID {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
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
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
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
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeNotFound(w, "wave not found")
		return
	}

	tpl, ok, err := templateProvider.GetTemplate(r.Context(), params.TemplateID)
	if err != nil || !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "template lookup failed")
		return
	}
	algo, ok := resolveWaveTargetAlgorithm(tpl, params.TargetAlgorithm)
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "template has no allowed algorithm usable as the wave target")
		return
	}

	if hooks.PreApprove != nil {
		if msg := hooks.PreApprove(action); msg != "" {
			emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeDenied)
			writeConflict(w, msg)
			return
		}
	}

	// A01-003: claim the action (compare-and-set) before running the
	// migration so racing approvals re-issue each member once.
	if err := pendingStore.Decide(r.Context(), actionID, statusExecuting, pd.ID, nil); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeConflict(w, "action is not pending")
		return
	}
	publishMigrateWaveEvent(pd.Tenant, waveID, "running", "")
	execResult := runWaveMigration(r.Context(), waveDeps{certs: certProvider, keys: keys, targets: targets, deliver: deliver, waves: waveStore}, *wave, algo, hooks)
	if execResult.Failed == 0 {
		publishMigrateWaveEvent(pd.Tenant, waveID, "completed", "migrated")
	} else {
		publishMigrateWaveEvent(pd.Tenant, waveID, "failed", fmt.Sprintf("%d of %d members failed", execResult.Failed, len(execResult.Results)))
	}

	resultJSON, err := json.Marshal(execResult)
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "encode result failed")
		return
	}
	// Deciding "approved" reflects that the approval was processed and
	// results recorded, independent of whether individual members
	// succeeded -- per-member outcome is in execResult, matching
	// bulk_revoke's existing {revoked, failed} convention rather than
	// treating any per-item failure as an overall action failure.
	if err := pendingStore.Decide(r.Context(), actionID, "approved", pd.ID, resultJSON); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "pqc.wave_execute_approve", "migration-wave", waveID, AuditOutcomeFailure)
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
func runWaveMigration(ctx context.Context, d waveDeps, wave MigrationWave, algo keystore.Algorithm, hooks waveHooks) migrateWaveExecutionResult {
	result := migrateWaveExecutionResult{Results: make([]migrateWaveMemberResult, 0, len(wave.Members))}
	var targets []ManagedTarget
	var targetsErr error
	if d.targets != nil {
		targets, targetsErr = d.targets.List(ctx)
	}
	record := func(r migrateWaveMemberResult) {
		if r.Error == "" {
			r.Error = r.Reason
		}
		switch r.Status {
		case pqc.MemberMigrated:
			result.Migrated++
		case pqc.MemberSkipped:
			result.Skipped++
		case pqc.MemberDeliveryUnsupported:
			result.Unsupported++
		default:
			result.Failed++
		}
		result.Results = append(result.Results, r)
		d.recordMemberDelivery(ctx, wave.ID, r)
		if hooks.MemberResult != nil {
			hooks.MemberResult(wave.ID, r)
		}
	}
	fail := func(fp, reason string) {
		record(migrateWaveMemberResult{Fingerprint: fp, Status: pqc.MemberFailed, Reason: reason})
	}

	for _, m := range wave.Members {
		if targetsErr != nil {
			// Delivery state is unknowable; issuing now would strand an
			// undeliverable successor, so refuse before touching the member.
			fail(m.Fingerprint, "managed targets unavailable; nothing issued")
			continue
		}
		detail, ok, err := d.certs.GetCertificate(ctx, m.Fingerprint)
		if err != nil || !ok {
			fail(m.Fingerprint, "certificate not found")
			continue
		}
		if detail.SuccessorFP != nil {
			record(migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: pqc.MemberSkipped,
				Reason: fmt.Sprintf("renewed by another path (successor %s) mid-wave", *detail.SuccessorFP)})
			continue
		}
		item := detail.CertificateItem

		keyID := fmt.Sprintf("pqc-migrate-%s-%d", item.FingerprintSHA256, time.Now().UnixNano())
		subject := pkix.Name{CommonName: item.CommonName}
		migrated, err := pqc.BuildTransitionCSR(d.keys, keyID, algo, subject, item.SubjectAltNames, nil)
		if err != nil {
			fail(m.Fingerprint, err.Error())
			continue
		}
		renewed, err := d.certs.RenewCertificate(ctx, m.Fingerprint, CertificateRenewRequest{CSRPEM: migrated.CSRPEM})
		if err != nil {
			fail(m.Fingerprint, err.Error())
			continue
		}
		newFP := renewed.FingerprintSHA256

		target, bound := matchWaveTarget(ctx, targets, detail)
		if !bound || d.deliver == nil {
			record(migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: pqc.MemberMigrated, NewFingerprint: newFP, Delivery: "none"})
			continue
		}
		if supported, why := d.deliver.Supports(target); !supported {
			record(migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: pqc.MemberDeliveryUnsupported, NewFingerprint: newFP, Delivery: "unsupported", Reason: why})
			continue
		}
		del, derr := d.deliver.Deliver(ctx, target, m.Fingerprint, newFP)
		switch {
		case derr != nil:
			result.Regressed = true
			record(migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: pqc.MemberFailed, NewFingerprint: newFP, Delivery: "failed",
				Reason: "delivery not attempted: " + derr.Error()})
		case del.Verified && del.Outcome == waveDeliveryOK:
			record(migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: pqc.MemberMigrated, NewFingerprint: newFP, Delivery: "verified"})
		default:
			// RenewCertificate already superseded the predecessor, so the
			// inventory now shows the PQC successor while the target keeps the
			// old cert; the wave is marked regressed rather than un-superseded.
			result.Regressed = true
			oldServed := del.Outcome == waveDeliveryRolledBack
			record(migrateWaveMemberResult{Fingerprint: m.Fingerprint, Status: pqc.MemberFailed, NewFingerprint: newFP, Delivery: "failed",
				Reason:          fmt.Sprintf("delivery %s: %s; rolled back", del.Outcome, del.Detail),
				OldSerialServed: &oldServed})
		}
	}

	if result.Regressed {
		result.WaveStatus = waveStatusRegressed
		if d.waves != nil {
			if err := d.waves.UpdateWaveStatus(ctx, wave.ID, waveStatusRegressed); err != nil {
				logging.Infof("pqc wave %s: persisting regressed status: %v", wave.ID, err)
			}
		}
	}
	if hooks.WaveOutcome != nil {
		hooks.WaveOutcome(wave.ID, result)
	}
	return result
}

// recordMemberDelivery persists a member's delivery outcome so wave progress
// does not count an issued-but-undelivered successor as migrated (W31-21). Only
// results that issued a successor touch the record: unsupported/failed delivery
// marks it, a migrated result clears it; skipped or pre-issuance failures leave
// any earlier mark alone.
func (d waveDeps) recordMemberDelivery(ctx context.Context, waveID string, r migrateWaveMemberResult) {
	if d.waves == nil || r.NewFingerprint == "" {
		return
	}
	status := ""
	switch r.Status {
	case pqc.MemberDeliveryUnsupported, pqc.MemberFailed:
		status = r.Status
	case pqc.MemberMigrated:
	default:
		return
	}
	if err := d.waves.SetMemberDelivery(ctx, waveID, r.Fingerprint, status); err != nil {
		logging.Infof("pqc wave %s: persisting delivery status for %s: %v", waveID, r.Fingerprint, err)
	}
}

// matchWaveTarget returns the first managed target whose host the certificate
// is seen on or names (CN/SANs) and whose tenant may see the certificate's CA.
func matchWaveTarget(ctx context.Context, targets []ManagedTarget, cert CertificateDetail) (ManagedTarget, bool) {
	for _, t := range targets {
		if strings.TrimSpace(t.Host) == "" || !targetMayReceiveCert(ctx, t, cert.CertificateItem) {
			continue
		}
		if targetHostsCert(t.Host, cert) {
			return t, true
		}
	}
	return ManagedTarget{}, false
}
