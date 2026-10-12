// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// WaveProgress is a migration wave plus live migration progress, computed from
// the current inventory: a member counts as migrated once its certificate is no
// longer a vulnerable classical cert (it became migration-ready/quantum-safe, or
// was renewed to a new fingerprint).
type WaveProgress struct {
	MigrationWave
	Total           int `json:"total"`
	Migrated        int `json:"migrated"`
	ProgressPercent int `json:"progress_percent"`
}

// vulnerableFingerprints returns the set of currently-vulnerable cert
// fingerprints. A cert with a SuccessorFP (renewed/migrated to a new
// fingerprint, e.g. via W4-03's migrate-wave EXECUTE or any ordinary
// renewal) is excluded regardless of its own now-stale PQCReadiness --
// its replacement is what matters going forward, matching this type's own
// doc comment ("...or was renewed to a new fingerprint") which predates
// this being actually implemented (found and fixed during W4-03 closeout:
// a member whose cert was genuinely re-issued to ML-DSA via
// IssueCertificate, with no successor link, stayed counted "vulnerable"
// forever -- confirmed empirically before switching runWaveMigration to
// RenewCertificate, which establishes the link this function now honors).
func vulnerableFingerprints(ctx context.Context, certProvider CertificateProvider) map[string]bool {
	out := map[string]bool{}
	result, err := listAllCertificates(ctx, certProvider, CertificateListQuery{})
	if err != nil {
		return out
	}
	for _, c := range result.Items {
		if c.PQCReadiness == "vulnerable" && c.SuccessorFP == nil {
			out[c.FingerprintSHA256] = true
		}
	}
	return out
}

func computeWaveProgress(waves []MigrationWave, stillVulnerable map[string]bool) []WaveProgress {
	out := make([]WaveProgress, 0, len(waves))
	for _, w := range waves {
		wp := WaveProgress{MigrationWave: w, Total: len(w.Members)}
		for _, m := range w.Members {
			if !stillVulnerable[m.Fingerprint] {
				wp.Migrated++
			}
		}
		if wp.Total > 0 {
			wp.ProgressPercent = wp.Migrated * 100 / wp.Total
		}
		out = append(out, wp)
	}
	return out
}

// syncWaveStatuses computes progress the same way computeWaveProgress does,
// then persists any lifecycle transition (advanceWaveStatus) back to the
// store — see W2-08/FR-R14: a regression must be a recorded fact, not merely
// something re-derived fresh on every request. Best-effort: a persist
// failure is not fatal to serving the (still-accurate) computed response,
// since the client will observe the same transition again on the next call.
func syncWaveStatuses(ctx context.Context, store MigrationWaveStore, waves []MigrationWave, stillVulnerable map[string]bool) []WaveProgress {
	progress := computeWaveProgress(waves, stillVulnerable)
	for i := range progress {
		next := advanceWaveStatus(progress[i].Status, progress[i].ProgressPercent, progress[i].Total)
		if next == progress[i].Status {
			continue
		}
		if err := store.UpdateWaveStatus(ctx, progress[i].ID, next); err == nil {
			progress[i].Status = next
		}
	}
	return progress
}

// registerPQCWaveHandlers mounts migration-wave CRUD + auto-derive, plus
// the EXECUTE propose/approve action (W4-03) as sub-paths of the same
// /api/v1/reports/pqc-waves/ prefix this function already owns -- kept in
// the same handler (rather than a second mux.HandleFunc registration on an
// overlapping pattern) to match this codebase's one-handler-per-resource-
// prefix convention and avoid any ServeMux pattern-precedence ambiguity
// between a subtree prefix and a more specific sub-path.
func registerPQCWaveHandlers(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, templateProvider TemplateProvider, store MigrationWaveStore, keys keystore.Store, auditProvider AuditProvider) {
	pendingStore := NewPendingActionStoreFromEnv()
	// Collection: GET list (with progress) / POST create.
	mux.HandleFunc("/api/v1/reports/pqc-waves", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		// W2-03/W2-08/D-102: pqc-waves is the same fleet-wide wave data as
		// pqc-countdown, already aggregate-super-admin-only — no per-tenant
		// breakdown exists for a migration wave (its members can span CAs
		// owned by different tenants).
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "wave store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			waves, err := store.ListWaves(r.Context())
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			progress := syncWaveStatuses(r.Context(), store, waves, vulnerableFingerprints(r.Context(), certProvider))
			writeJSONData(w, progress)
		case http.MethodPost:
			var req MigrationWave
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			if strings.TrimSpace(req.Name) == "" {
				writeBadRequest(w, "wave name is required")
				return
			}
			created, err := store.CreateWave(r.Context(), MigrationWave{
				Name: req.Name, Owner: req.Owner, TargetDate: req.TargetDate,
			})
			if err != nil {
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_create", "migration-wave", created.ID, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusCreated)
			writeJSONData(w, created)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	// POST auto-derive: replace all waves with inventory-derived ones.
	mux.HandleFunc("/api/v1/reports/pqc-waves/auto-derive", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "wave store unavailable")
			return
		}
		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		if err := store.DeleteAllWaves(r.Context()); err != nil {
			writeServiceUnavailable(w, "reset failed")
			return
		}
		derived := derivePQCWaves(result.Items)
		for _, d := range derived {
			if _, err := store.CreateWave(r.Context(), MigrationWave{
				Name: d.Name, Owner: d.Owner, Members: d.Members,
			}); err != nil {
				writeServiceUnavailable(w, "create wave failed")
				return
			}
		}
		emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeSuccess)
		waves, _ := store.ListWaves(r.Context())
		progress := syncWaveStatuses(r.Context(), store, waves, vulnerableFingerprints(r.Context(), certProvider))
		writeJSONData(w, progress)
	})

	// Item + members + accept: DELETE wave; POST/DELETE members; POST accept.
	mux.HandleFunc("/api/v1/reports/pqc-waves/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if denyAggregateReportForTenantScoped(w, principal) {
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "wave store unavailable")
			return
		}
		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/pqc-waves/")
		if tail == "" || tail == "auto-derive" {
			writeBadRequest(w, "wave id required")
			return
		}
		parts := strings.Split(tail, "/")
		waveID := parts[0]

		// .../{id}/members[/{fp}]
		if len(parts) >= 2 && parts[1] == "members" {
			switch r.Method {
			case http.MethodPost:
				var m MigrationWaveMember
				if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m.Fingerprint == "" {
					writeBadRequest(w, "fingerprint required")
					return
				}
				if err := store.AddMember(r.Context(), waveID, m); err != nil {
					writeServiceUnavailable(w, "add member failed")
					return
				}
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_add", "migration-wave", waveID, AuditOutcomeSuccess)
				writeJSONData(w, map[string]string{"status": "added"})
			case http.MethodDelete:
				if len(parts) < 3 || parts[2] == "" {
					writeBadRequest(w, "fingerprint required")
					return
				}
				if err := store.RemoveMember(r.Context(), waveID, parts[2]); err != nil {
					writeServiceUnavailable(w, "remove member failed")
					return
				}
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_remove", "migration-wave", waveID, AuditOutcomeSuccess)
				writeJSONData(w, map[string]string{"status": "removed"})
			default:
				writeMethodNotAllowed(w, "POST, DELETE")
			}
			return
		}

		// .../{id}/execute — propose a migrate-wave EXECUTE action (W4-03).
		if len(parts) == 2 && parts[1] == "execute" {
			handleWaveExecutePropose(w, r, principal, waveID, store, templateProvider, pendingStore, auditProvider)
			return
		}

		// .../{id}/execute/{actionID}/approve — approve + run (W4-03).
		if len(parts) == 4 && parts[1] == "execute" && parts[3] == "approve" {
			handleWaveExecuteApprove(w, r, auth, principal, waveID, parts[2], store, templateProvider, certProvider, keys, pendingStore, auditProvider)
			return
		}

		// .../{id}/accept — explicit lifecycle transition: proposed/accepted
		// stay reachable only via this action (no auto-accept), and it's the
		// only way to clear a sticky regressed wave (W2-08).
		if len(parts) == 2 && parts[1] == "accept" {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			if err := store.UpdateWaveStatus(r.Context(), waveID, waveStatusAccepted); err != nil {
				writeServiceUnavailable(w, "accept failed")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_accept", "migration-wave", waveID, AuditOutcomeSuccess)
			writeJSONData(w, map[string]string{"status": waveStatusAccepted})
			return
		}

		// .../{id}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if err := store.DeleteWave(r.Context(), waveID); err != nil {
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_delete", "migration-wave", waveID, AuditOutcomeSuccess)
		writeJSONData(w, map[string]string{"status": "deleted"})
	})
}

// writeJSONData writes {"data": v} with a 200 (unless a status was already set).
func writeJSONData(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Data any `json:"data"`
	}{Data: v})
}
