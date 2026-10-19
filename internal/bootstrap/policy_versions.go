// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"slices"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// W22-15 (FR-P8, FR-P50): approval-gated policy loosening with version
// history and revert.
//
// A change that removes protection (longer validity, lower key floor, a new
// algorithm, CA certs allowed, policy disabled or narrowed to fewer CAs) never
// applies on the PATCH: it is parked in the pending-action queue and the
// executor below applies it only after a second approver. Tightening applies at
// once. Every applied change appends a version, so any state can be restored,
// and a restore that would itself loosen goes through the same gate.

// ActionPolicyLoosen is the pending-action type of a parked policy loosening.
// It is executed through the executor map (WithActionExecutor), not
// executePendingAction, so validActionType deliberately does not list it.
const ActionPolicyLoosen = "policy.loosen"

// Version change kinds.
const (
	policyChangeCreate = "create"
	policyChangeUpdate = "update"
	policyChangeLoosen = "loosen"
	policyChangeRevert = "revert"
)

var errPolicyStale = errors.New("policy changed since proposal")

const policyVersionsSchema = `
CREATE TABLE IF NOT EXISTS issuance_policy_versions (
  policy_id TEXT NOT NULL, version INTEGER NOT NULL,
  name TEXT NOT NULL, enabled INTEGER NOT NULL, ca_id TEXT NOT NULL DEFAULT '', rules TEXT NOT NULL,
  changed_by TEXT NOT NULL, change_kind TEXT NOT NULL,
  created_at TEXT NOT NULL, PRIMARY KEY (policy_id, version));`

// PolicyVersion is one applied state of a policy.
type PolicyVersion struct {
	PolicyID   string         `json:"policy_id"`
	Version    int            `json:"version"`
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	CAID       string         `json:"ca_id"`
	Rules      ca.PolicyRules `json:"rules"`
	ChangedBy  string         `json:"changed_by"`
	ChangeKind string         `json:"change_kind"`
	CreatedAt  string         `json:"created_at"`
}

// Policy is the version's state as an IssuancePolicy.
func (v PolicyVersion) Policy() ca.IssuancePolicy {
	return ca.IssuancePolicy{ID: v.PolicyID, Name: v.Name, Enabled: v.Enabled, CAID: v.CAID, Rules: v.Rules}
}

type policyVersionStore struct {
	db *sql.DB
	ph func(int) string
}

func newPolicyVersionStore(pe *ca.PolicyEngine) *policyVersionStore {
	db, postgres := pe.DB()
	ph := sqlitePlaceholder
	if postgres {
		ph = postgresPlaceholder
	}
	return &policyVersionStore{db: db, ph: ph}
}

func (s *policyVersionStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, policyVersionsSchema)
	return err
}

// Append records pol as the next version (max+1, starting at 1). The read and
// the insert share a transaction so versions stay gap-free; a concurrent
// writer loses on the primary key rather than duplicating a number.
func (s *policyVersionStore) Append(ctx context.Context, pol ca.IssuancePolicy, by, kind string) (int, error) {
	rules, err := json.Marshal(pol.Rules)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed
	var max int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM issuance_policy_versions WHERE policy_id = `+s.ph(1), pol.ID).Scan(&max); err != nil {
		return 0, err
	}
	enabled := 0
	if pol.Enabled {
		enabled = 1
	}
	next := max + 1
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO issuance_policy_versions
		(policy_id, version, name, enabled, ca_id, rules, changed_by, change_kind, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9)),
		pol.ID, next, pol.Name, enabled, pol.CAID, string(rules), by, kind, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

func scanPolicyVersion(sc interface{ Scan(...any) error }) (PolicyVersion, error) {
	var v PolicyVersion
	var enabled int
	var rules string
	if err := sc.Scan(&v.PolicyID, &v.Version, &v.Name, &enabled, &v.CAID, &rules, &v.ChangedBy, &v.ChangeKind, &v.CreatedAt); err != nil {
		return PolicyVersion{}, err
	}
	v.Enabled = enabled != 0
	if err := json.Unmarshal([]byte(rules), &v.Rules); err != nil {
		return PolicyVersion{}, fmt.Errorf("policy version %s/%d rules: %w", v.PolicyID, v.Version, err)
	}
	return v, nil
}

const policyVersionCols = `policy_id, version, name, enabled, ca_id, rules, changed_by, change_kind, created_at`

func (s *policyVersionStore) List(ctx context.Context, id string) ([]PolicyVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+policyVersionCols+` FROM issuance_policy_versions WHERE policy_id = `+s.ph(1)+` ORDER BY version`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PolicyVersion{}
	for rows.Next() {
		v, err := scanPolicyVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *policyVersionStore) Get(ctx context.Context, id string, v int) (PolicyVersion, bool, error) {
	pv, err := scanPolicyVersion(s.db.QueryRowContext(ctx, `SELECT `+policyVersionCols+` FROM issuance_policy_versions WHERE policy_id = `+s.ph(1)+` AND version = `+s.ph(2), id, v))
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyVersion{}, false, nil
	}
	return pv, err == nil, err
}

// Latest returns the newest version number, 0 when there is no history.
func (s *policyVersionStore) Latest(ctx context.Context, id string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM issuance_policy_versions WHERE policy_id = `+s.ph(1), id).Scan(&n)
	return n, err
}

// ensureBase gives a policy that predates W22-15 a version 1 holding its
// current state, so a revert always has a base to return to.
func (s *policyVersionStore) ensureBase(ctx context.Context, cur ca.IssuancePolicy) (int, error) {
	n, err := s.Latest(ctx, cur.ID)
	if err != nil || n > 0 {
		return n, err
	}
	return s.Append(ctx, cur, "system", policyChangeCreate)
}

// policyLoosening lists why next removes protection relative to old; empty
// means pure tightening or a no-op. Zero values mean "unrestricted", so
// dropping a limit to 0 loosens it.
func policyLoosening(old, next ca.IssuancePolicy) []string {
	var r []string
	if next.Rules.MaxValidityDays > old.Rules.MaxValidityDays || (old.Rules.MaxValidityDays > 0 && next.Rules.MaxValidityDays == 0) {
		r = append(r, "longer or removed max validity")
	}
	if next.Rules.MinRSABits < old.Rules.MinRSABits {
		r = append(r, "lower RSA key floor")
	}
	if len(old.Rules.AllowedAlgorithms) > 0 {
		if len(next.Rules.AllowedAlgorithms) == 0 {
			r = append(r, "algorithm allow-list removed")
		} else {
			for _, a := range next.Rules.AllowedAlgorithms {
				if !slices.Contains(old.Rules.AllowedAlgorithms, a) {
					r = append(r, "algorithm added: "+a)
				}
			}
		}
	}
	if next.Rules.AllowCACerts && !old.Rules.AllowCACerts {
		r = append(r, "CA certificates allowed")
	}
	if old.Enabled && !next.Enabled {
		r = append(r, "policy disabled")
	}
	// Narrowing scope: a policy for every CA ("") or CA X stops covering
	// something when it is pointed at a different specific CA. Moving to ""
	// widens coverage and is a tightening.
	if next.CAID != "" && next.CAID != old.CAID {
		r = append(r, "policy scope narrowed to a specific CA")
	}
	return r
}

// policyLoosenParams is the payload of a parked loosening.
type policyLoosenParams struct {
	PolicyID    string            `json:"policy_id"`
	Proposed    ca.IssuancePolicy `json:"proposed"`
	Reasons     []string          `json:"reasons"`
	BaseVersion int               `json:"base_version"`
	ChangeKind  string            `json:"change_kind"`
}

// newPolicyLoosenExecutor applies an approved loosening. The queue has already
// enforced approver role, no-self-approval and quorum; this adds the two checks
// only it can: the approver must be allowed to touch instance-global policy,
// and the policy must be the one the proposal was made against.
func newPolicyLoosenExecutor(pe *ca.PolicyEngine, versions *policyVersionStore, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		// Policies are instance-global: with multi-tenancy on, only a platform
		// super-admin may approve a change to them.
		if !tenantBypass(approver) {
			return nil, errors.New("instance-wide policy: platform super-admin approval required when multi-tenancy is on")
		}
		var p policyLoosenParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid policy params: %w", err)
		}
		if p.PolicyID == "" || p.Proposed.ID != p.PolicyID {
			return nil, errors.New("invalid policy params: policy id mismatch")
		}
		cur, found, err := pe.GetPolicy(p.PolicyID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("policy no longer exists")
		}
		latest, err := versions.ensureBase(ctx, cur)
		if err != nil {
			return nil, err
		}
		if latest != p.BaseVersion {
			return nil, errPolicyStale
		}
		kind, auditAction := policyChangeLoosen, "policy.update"
		if p.ChangeKind == policyChangeRevert {
			kind, auditAction = policyChangeRevert, "policy.revert"
		}
		saved, err := pe.UpsertPolicy(p.Proposed)
		if err != nil {
			return nil, err
		}
		ver, err := versions.Append(ctx, saved, approver.ID, kind)
		if err != nil {
			return nil, fmt.Errorf("policy applied but version not recorded: %w", err)
		}
		if audit != nil {
			summary := policySummary(saved)
			if aerr := audit.AppendEntry(ctx, AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: auditAction, ActorType: "user", ActorID: approver.ID,
				ResourceType: "policy", ResourceID: saved.ID, Outcome: AuditOutcomeSuccess, Tenant: DefaultTenant,
				ChangeSummary: "applied after approval of " + action.ID + " (proposed by " + action.ProposedBy + "; " + strings.Join(p.Reasons, "; ") + "): " + summary,
			}); aerr != nil {
				logging.Errorf("policy %s changed after approval but the audit append failed: %v", saved.ID, aerr)
			}
		}
		return json.Marshal(map[string]any{"policy_id": saved.ID, "version": ver})
	}
}
