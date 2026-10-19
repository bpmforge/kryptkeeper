// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W34-10: what the latest scan could do on a target, and why renewal is
// Blocked. Kept in its own store interface (like targetPreflightStore) so the
// other ManagedTargetStore implementations are untouched; the columns come
// from migration 000345 (renewal_privilege_required from 000342).

// Block kinds.
const (
	// BlockKindPrivilege: a service-attributed file needs root to replace and
	// the credential has no sudo mode. Derived each time, never persisted as a
	// hard stop: switching the credential clears it.
	BlockKindPrivilege = "privilege"
	// BlockKindRollback: a rollback failed, so the host may hold a half
	// installed state. Persisted until an operator unblocks the target.
	BlockKindRollback = "rollback"
)

// TargetState is the per-target scan and block state.
type TargetState struct {
	RenewalPrivilegeRequired bool
	LastPrivilegeMode        string
	UnreadableCount          int
	LastScannedAt            string
	BlockedKind              string
	BlockedReason            string
	BlockedAt                string
}

// targetStateStore is implemented by the DB-backed managed target stores.
type targetStateStore interface {
	TargetStates(ctx context.Context) (map[string]TargetState, error)
	RecordTargetScan(ctx context.Context, id, privilegeMode string, unreadable int, at time.Time) error
	SetTargetBlocked(ctx context.Context, id, kind, reason string) error
	ClearTargetBlocked(ctx context.Context, id string) error
}

// TargetBlock is the Blocked state shown for a target, with the recipe that
// clears it.
type TargetBlock struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Fix    string `json:"fix"`
	Since  string `json:"since,omitempty"`
}

func targetStatesQuery(postgres bool) string {
	return `SELECT id, COALESCE(renewal_privilege_required, ` + boolDefault(postgres) + `), COALESCE(last_privilege_mode, ''), COALESCE(unreadable_count, 0),
       COALESCE(last_scanned_at, ''), COALESCE(blocked_kind, ''), COALESCE(blocked_reason, ''), COALESCE(blocked_at, '') FROM managed_targets`
}

func boolDefault(postgres bool) string {
	if postgres {
		return "FALSE"
	}
	return "0"
}

func loadTargetStates(ctx context.Context, db *sql.DB, postgres bool) (map[string]TargetState, error) {
	rows, err := db.QueryContext(ctx, targetStatesQuery(postgres))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]TargetState{}
	for rows.Next() {
		var id string
		var st TargetState
		if err := rows.Scan(&id, &st.RenewalPrivilegeRequired, &st.LastPrivilegeMode, &st.UnreadableCount, &st.LastScannedAt,
			&st.BlockedKind, &st.BlockedReason, &st.BlockedAt); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

func execTargetState(ctx context.Context, db *sql.DB, postgres bool, q string, args ...any) error {
	res, err := db.ExecContext(ctx, dialectQuery(postgres, q), args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errManagedTargetNotFound
	}
	return nil
}

func (s *sqliteManagedTargetStore) TargetStates(ctx context.Context) (map[string]TargetState, error) {
	return loadTargetStates(ctx, s.db, false)
}

func (s *postgresManagedTargetStore) TargetStates(ctx context.Context) (map[string]TargetState, error) {
	return loadTargetStates(ctx, s.db, true)
}

func (s *sqliteManagedTargetStore) RecordTargetScan(ctx context.Context, id, mode string, unreadable int, at time.Time) error {
	return execTargetState(ctx, s.db, false, `UPDATE managed_targets SET last_privilege_mode = ?, unreadable_count = ?, last_scanned_at = ? WHERE id = ?`,
		mode, unreadable, at.UTC().Format(time.RFC3339), id)
}

func (s *postgresManagedTargetStore) RecordTargetScan(ctx context.Context, id, mode string, unreadable int, at time.Time) error {
	return execTargetState(ctx, s.db, true, `UPDATE managed_targets SET last_privilege_mode = ?, unreadable_count = ?, last_scanned_at = ? WHERE id = ?`,
		mode, unreadable, at.UTC().Format(time.RFC3339), id)
}

func (s *sqliteManagedTargetStore) SetTargetBlocked(ctx context.Context, id, kind, reason string) error {
	return execTargetState(ctx, s.db, false, `UPDATE managed_targets SET blocked_kind = ?, blocked_reason = ?, blocked_at = ? WHERE id = ?`,
		kind, reason, time.Now().UTC().Format(time.RFC3339), id)
}

func (s *postgresManagedTargetStore) SetTargetBlocked(ctx context.Context, id, kind, reason string) error {
	return execTargetState(ctx, s.db, true, `UPDATE managed_targets SET blocked_kind = ?, blocked_reason = ?, blocked_at = ? WHERE id = ?`,
		kind, reason, time.Now().UTC().Format(time.RFC3339), id)
}

func (s *sqliteManagedTargetStore) ClearTargetBlocked(ctx context.Context, id string) error {
	return execTargetState(ctx, s.db, false, `UPDATE managed_targets SET blocked_kind = NULL, blocked_reason = NULL, blocked_at = NULL WHERE id = ?`, id)
}

func (s *postgresManagedTargetStore) ClearTargetBlocked(ctx context.Context, id string) error {
	return execTargetState(ctx, s.db, true, `UPDATE managed_targets SET blocked_kind = NULL, blocked_reason = NULL, blocked_at = NULL WHERE id = ?`, id)
}

// targetStateBlocker adapts a target store to the renewal executor's
// targetBlocker (W34-18): a rollback that failed blocks the target until an
// operator unblocks it.
type targetStateBlocker struct{ store ManagedTargetStore }

func (b targetStateBlocker) BlockTarget(ctx context.Context, targetID, reason string) error {
	ss, ok := b.store.(targetStateStore)
	if !ok {
		return fmt.Errorf("target store cannot record a block")
	}
	return ss.SetTargetBlocked(ctx, targetID, BlockKindRollback, reason)
}

// credentialSudoMode reads the sudo_mode of a target's ssh_key credential.
// ok is false when it cannot be told (no store, no credential, not an ssh_key,
// unreadable), and callers must then not block on it.
func credentialSudoMode(ctx context.Context, creds OutboundCredentialStore, ref string) (mode string, ok bool) {
	if creds == nil || ref == "" {
		return "", false
	}
	meta, err := creds.Get(ctx, ref)
	if err != nil || meta.CredentialType != CredentialTypeSSHKey {
		return "", false
	}
	plain, err := creds.Resolve(ctx, ref)
	if err != nil {
		return "", false
	}
	defer zeroize(plain)
	var p sshCredentialPayload
	if json.Unmarshal(plain, &p) != nil {
		return "", false
	}
	if p.SudoMode == "" {
		return "none", true
	}
	return p.SudoMode, true
}

// privilegeFix is the recipe that clears a privilege block: give the
// credential a privileged mode, or hand the service account the files.
func privilegeFix(t ManagedTarget) string {
	paths := strings.TrimSpace(strings.Join([]string{t.InstallCertPath, t.InstallKeyPath}, " "))
	chown := "Or make the files writable by the service account: chown <service-user> <cert and key paths> && chmod 600 <key path>."
	if paths != "" {
		chown = fmt.Sprintf("Or make the files writable by the service account: chown <service-user> %s && chmod 600 %s.", paths, orDefaultString(t.InstallKeyPath, "<key path>"))
	}
	return "Add a privileged credential (helper mode from the target's privilege bundle, or a sudo mode) and re-test it. " + chown
}

func orDefaultString(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// computeTargetBlock decides whether renewal on t is Blocked. credMode is the
// credential's sudo_mode, and credKnown says it could be read.
func computeTargetBlock(t ManagedTarget, st TargetState, credMode string, credKnown bool) *TargetBlock {
	if st.BlockedKind == BlockKindRollback {
		return &TargetBlock{Kind: BlockKindRollback, Reason: orDefaultString(st.BlockedReason, "a renewal rollback failed"), Since: st.BlockedAt,
			Fix: "Check the host's certificate, key and service state by hand, then unblock the target."}
	}
	if t.AutoRenew && st.RenewalPrivilegeRequired && credKnown && credMode == "none" {
		return &TargetBlock{Kind: BlockKindPrivilege, Reason: "renewal needs root on this host", Fix: privilegeFix(t), Since: st.BlockedAt}
	}
	return nil
}

// withTargetState decorates targets for a response with the scan state and the
// Blocked verdict. Nothing is persisted. A store that carries no state, or a
// read error, returns the targets unchanged.
func withTargetState(ctx context.Context, store ManagedTargetStore, creds OutboundCredentialStore, items []ManagedTarget) []ManagedTarget {
	ss, ok := store.(targetStateStore)
	if !ok || len(items) == 0 {
		return items
	}
	states, err := ss.TargetStates(ctx)
	if err != nil {
		logging.Infof("target state unavailable: %v", err)
		return items
	}
	out := make([]ManagedTarget, len(items))
	for i, t := range items {
		out[i] = t
		st, has := states[t.ID]
		if !has {
			continue
		}
		out[i].RenewalPrivilegeRequired = st.RenewalPrivilegeRequired
		out[i].LastPrivilegeMode = st.LastPrivilegeMode
		out[i].UnreadableCount = st.UnreadableCount
		out[i].LastScannedAt = st.LastScannedAt
		mode, known := "", false
		if st.RenewalPrivilegeRequired {
			mode, known = credentialSudoMode(ctx, creds, t.CredentialRef)
		}
		out[i].Blocked = computeTargetBlock(t, st, mode, known)
	}
	return out
}

// withoutBlockedTargets drops targets the sweep must not push to and audits
// each Blocked transition once: a privilege block appears, or clears when the
// credential gains a sudo mode or a scan sees the files standard. The persisted
// kind is the previous verdict, so a block that persists across ticks stays
// silent.
func (s *RenewalScheduler) withoutBlockedTargets(ctx context.Context, eligible []ManagedTarget) []ManagedTarget {
	ss, ok := s.targetStore.(targetStateStore)
	if !ok || len(eligible) == 0 {
		return eligible
	}
	states, err := ss.TargetStates(ctx)
	if err != nil {
		logging.Infof("renewal scheduler: target state unreadable, not filtering blocked targets: %v", err)
		return eligible
	}
	var out []ManagedTarget
	for _, t := range eligible {
		st := states[t.ID]
		mode, known := "", false
		if st.RenewalPrivilegeRequired {
			mode, known = credentialSudoMode(ctx, s.credStore, t.CredentialRef)
		}
		block := computeTargetBlock(t, st, mode, known)
		switch {
		case block != nil && block.Kind == BlockKindPrivilege && st.BlockedKind != BlockKindPrivilege:
			if err := ss.SetTargetBlocked(ctx, t.ID, BlockKindPrivilege, block.Reason); err != nil {
				logging.Warnf("renewal scheduler: recording block on %s: %v", t.ID, err)
			}
			s.auditTarget(ctx, t.ID, "target.renewal.blocked", AuditOutcomeSkipped, block.Kind+": "+block.Reason)
			logging.Infof("renewal scheduler: target %q (%s) is Blocked: %s", t.Name, t.Host, block.Reason)
		case block == nil && st.BlockedKind == BlockKindPrivilege:
			if err := ss.ClearTargetBlocked(ctx, t.ID); err != nil {
				logging.Warnf("renewal scheduler: clearing block on %s: %v", t.ID, err)
			}
			s.auditTarget(ctx, t.ID, "target.renewal.unblocked", AuditOutcomeSuccess, "privilege block cleared")
		}
		if block != nil {
			continue
		}
		out = append(out, t)
	}
	return out
}

func (s *RenewalScheduler) auditTarget(ctx context.Context, targetID, action string, outcome AuditOutcome, detail string) {
	if s.auditProvider == nil {
		return
	}
	if err := s.auditProvider.AppendEntry(ctx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "renewal-scheduler",
		ResourceType: "target", ResourceID: targetID, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("renewal scheduler: audit append failed action=%s: %v", action, err)
	}
}
