// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/pqc"
)

// WaveProgress is a migration wave plus live migration progress, computed from
// the current inventory: a member counts as migrated only when the tail of its
// renewal chain is a PQC certificate (D-105) and its latest wave execution did
// not leave it undelivered (W31-21). A member absent from the inventory is not
// migrated.
type WaveProgress struct {
	MigrationWave
	Total           int `json:"total"`
	Migrated        int `json:"migrated"`
	Undelivered     int `json:"undelivered"` // members whose successor was issued but not delivered (W31-21); never counted as migrated
	LeafOnly        int `json:"leaf_only"`   // members whose current cert is PQC-leaf under a classical chain (D-104)
	ProgressPercent int `json:"progress_percent"`
}

// waveChainMaxHops bounds the successor walk so a corrupt cycle cannot spin.
const waveChainMaxHops = 32

// waveCurrentReadiness maps each inventory fingerprint to the PQCReadiness of
// the tail of its SuccessorFP chain (the cert that is current today). A chain
// whose next link is missing from the inventory, or that cycles or exceeds
// waveChainMaxHops, resolves to the last cert actually seen. Empty labels are
// never stored.
func waveCurrentReadiness(items []CertificateItem) map[string]string {
	byFP := make(map[string]CertificateItem, len(items))
	for _, c := range items {
		byFP[c.FingerprintSHA256] = c
	}
	out := make(map[string]string, len(items))
	for _, c := range items {
		cur := c
		seen := map[string]bool{cur.FingerprintSHA256: true}
		for hop := 0; hop < waveChainMaxHops && cur.SuccessorFP != nil; hop++ {
			next, ok := byFP[*cur.SuccessorFP]
			if !ok || seen[next.FingerprintSHA256] {
				break
			}
			seen[next.FingerprintSHA256] = true
			cur = next
		}
		if cur.PQCReadiness != "" {
			out[c.FingerprintSHA256] = cur.PQCReadiness
		}
	}
	return out
}

func currentWaveReadiness(ctx context.Context, certProvider CertificateProvider) map[string]string {
	result, err := listAllCertificates(ctx, certProvider, CertificateListQuery{})
	if err != nil {
		return map[string]string{}
	}
	return waveCurrentReadiness(result.Items)
}

func computeWaveProgress(waves []MigrationWave, current map[string]string) []WaveProgress {
	out := make([]WaveProgress, 0, len(waves))
	for _, w := range waves {
		wp := WaveProgress{MigrationWave: w, Total: len(w.Members)}
		for _, m := range w.Members {
			label := current[m.Fingerprint]
			if waveMemberUndelivered(m.DeliveryStatus) {
				// The successor exists but the endpoint still serves the old
				// cert: not migrated, whatever the inventory says (D-105).
				wp.Undelivered++
			} else if pqc.ReadinessIsPQC(label) {
				wp.Migrated++
			}
			if label == "quantum_safe_leaf_only" {
				wp.LeafOnly++
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
// A wave with any leaf-only member is capped at 99% for the transition so it
// never becomes done (D-105); the reported percent stays the true one.
func syncWaveStatuses(ctx context.Context, store MigrationWaveStore, waves []MigrationWave, current map[string]string) []WaveProgress {
	progress := computeWaveProgress(waves, current)
	for i := range progress {
		pct := progress[i].ProgressPercent
		if progress[i].LeafOnly > 0 && pct > 99 {
			pct = 99
		}
		next := advanceWaveStatus(progress[i].Status, pct, progress[i].Total)
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
	targets := newManagedTargetStoreFromEnv()
	deliver := unsupportedWaveDeliverer{}
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
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
			writeServiceUnavailable(w, "wave store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			waves, err := store.ListWaves(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
				writeServiceUnavailable(w, "list failed")
				return
			}
			progress := syncWaveStatuses(r.Context(), store, waves, currentWaveReadiness(r.Context(), certProvider))
			writeJSONData(w, progress)
		case http.MethodPost:
			var req MigrationWave
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_create", "migration-wave", "-", AuditOutcomeFailure)
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
				writeBadRequest(w, "invalid JSON")
				return
			}
			if strings.TrimSpace(req.Name) == "" {
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_create", "migration-wave", "-", AuditOutcomeFailure)
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
				writeBadRequest(w, "wave name is required")
				return
			}
			created, err := store.CreateWave(r.Context(), MigrationWave{
				Name: req.Name, Owner: req.Owner, TargetDate: req.TargetDate,
			})
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_create", "migration-wave", "-", AuditOutcomeFailure)
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
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
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
			writeServiceUnavailable(w, "wave store unavailable")
			return
		}
		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		if err := store.DeleteAllWaves(r.Context()); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
			writeServiceUnavailable(w, "reset failed")
			return
		}
		derived := derivePQCWaves(result.Items)
		for _, d := range derived {
			if _, err := store.CreateWave(r.Context(), MigrationWave{
				Name: d.Name, Owner: d.Owner, Members: d.Members,
			}); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeFailure)
				writeServiceUnavailable(w, "create wave failed")
				return
			}
		}
		emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_auto_derive", "migration-wave", "all", AuditOutcomeSuccess)
		waves, _ := store.ListWaves(r.Context())
		progress := syncWaveStatuses(r.Context(), store, waves, currentWaveReadiness(r.Context(), certProvider))
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
					emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_add", "migration-wave", waveID, AuditOutcomeFailure)
					writeBadRequest(w, "fingerprint required")
					return
				}
				if err := store.AddMember(r.Context(), waveID, m); err != nil {
					emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_add", "migration-wave", waveID, AuditOutcomeFailure)
					writeServiceUnavailable(w, "add member failed")
					return
				}
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_add", "migration-wave", waveID, AuditOutcomeSuccess)
				writeJSONData(w, map[string]string{"status": "added"})
			case http.MethodDelete:
				if len(parts) < 3 || parts[2] == "" {
					emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_remove", "migration-wave", waveID, AuditOutcomeFailure)
					writeBadRequest(w, "fingerprint required")
					return
				}
				if err := store.RemoveMember(r.Context(), waveID, parts[2]); err != nil {
					emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_member_remove", "migration-wave", waveID, AuditOutcomeFailure)
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
			handleWaveExecuteApprove(w, r, auth, principal, waveID, parts[2], store, templateProvider, certProvider, keys, pendingStore, auditProvider, targets, deliver, newWaveHooks(r, principal, pendingStore, auditProvider))
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
				emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_accept", "migration-wave", waveID, AuditOutcomeFailure)
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
			emitAuditEvent(r, auditProvider, principal.ID, "pqc.wave_delete", "migration-wave", waveID, AuditOutcomeFailure)
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

const (
	waveApprovalTTLEnv     = "KRYPTKEEPER_PQC_WAVE_APPROVAL_TTL_HOURS"
	defaultWaveApprovalTTL = 24 * time.Hour
)

// waveNow and waveAlertProvider are test seams.
var (
	waveNow           = time.Now
	waveAlertProvider = NewNotificationProviderFromEnv
)

// waveApprovalTTL is how long a proposed wave execution stays redeemable. It is
// separate from APPROVAL_TTL_HOURS (72h, shared by every approval) because a
// wave re-issues a whole fleet and a stale approval should not outlive the
// context it was granted in. Invalid or non-positive values fall back to 24h
// so a typo can neither disable expiry nor expire everything instantly.
func waveApprovalTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv(waveApprovalTTLEnv))
	if raw == "" {
		return defaultWaveApprovalTTL
	}
	h, err := strconv.ParseFloat(raw, 64)
	if err != nil || h <= 0 || h > 24*365 {
		logging.Infof("pqc wave: invalid %s=%q, using %s", waveApprovalTTLEnv, raw, defaultWaveApprovalTTL)
		return defaultWaveApprovalTTL
	}
	return time.Duration(h * float64(time.Hour))
}

// newWaveHooks builds the per-request hooks (they close over r for audit
// attribution): approval-window enforcement, one audit row per member and
// alerts on member failure or wave regression.
func newWaveHooks(r *http.Request, pd AuthPrincipal, pending PendingActionStore, audit AuditProvider) waveHooks {
	return waveHooks{
		PreApprove: func(a PendingAction) string {
			created, err := time.Parse(time.RFC3339, a.CreatedAt)
			if err != nil {
				return "approval has no valid creation time; propose again"
			}
			ttl := waveApprovalTTL()
			if waveNow().Sub(created) <= ttl {
				return ""
			}
			// Best effort: reject the row so it cannot be retried; the refusal
			// stands even if the store write fails.
			res, _ := json.Marshal(map[string]any{"expired": true, "reason": "not approved within " + ttl.String()})
			if err := pending.Decide(r.Context(), a.ID, "rejected", expirySweeper, res); err != nil {
				logging.Infof("pqc wave: mark expired action %s rejected: %v", a.ID, err)
			}
			return fmt.Sprintf("approval window expired (%s); propose the wave execution again", ttl)
		},
		MemberResult: func(waveID string, m migrateWaveMemberResult) {
			outcome := AuditOutcomeSuccess
			if m.Status == pqc.MemberFailed || m.Status == pqc.MemberDeliveryUnsupported {
				outcome = AuditOutcomeFailure
			}
			detail := fmt.Sprintf("fingerprint=%s status=%s delivery=%s reason=%s", m.Fingerprint, m.Status, m.Delivery, m.Reason)
			emitAuditEventDetail(r, audit, pd.ID, "pqc.wave_member_result", "migration-wave", waveID, outcome, detail)
			if m.Status == pqc.MemberFailed {
				sendWaveAlert(r.Context(), "pqc_wave.member_failed", waveID, detail)
			}
		},
		WaveOutcome: func(waveID string, res migrateWaveExecutionResult) {
			if !res.Regressed {
				return
			}
			detail := fmt.Sprintf("migrated=%d failed=%d skipped=%d unsupported=%d", res.Migrated, res.Failed, res.Skipped, res.Unsupported)
			emitAuditEventDetail(r, audit, pd.ID, "pqc.wave_regressed", "migration-wave", waveID, AuditOutcomeFailure, detail)
			sendWaveAlert(r.Context(), "pqc_wave.regressed", waveID, detail)
		},
	}
}

// sendWaveAlert fans an alert out to every enabled notification rule (rules
// carry no event-type filter yet). Failures are logged, never returned: an
// alert problem must not fail the approval that is already executing.
func sendWaveAlert(ctx context.Context, kind, waveID, detail string) {
	p := waveAlertProvider()
	if p == nil {
		return
	}
	rules, err := p.ListRules(ctx)
	if err != nil {
		logging.Infof("pqc wave: list notification rules for %s: %v", kind, err)
		return
	}
	if !p.Delivers() {
		logging.Infof("pqc wave: notification provider %q only records; %s reaches no channel", p.Name(), kind)
	}
	msg := fmt.Sprintf("[%s] wave %s: %s", kind, waveID, detail)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if _, err := p.TestDelivery(ctx, rule.Channel, rule.Target, msg); err != nil {
			logging.Infof("pqc wave: rule %s delivery of %s failed: %v", rule.ID, kind, err)
		}
	}
}
