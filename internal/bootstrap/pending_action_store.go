// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// PendingAction is a proposed change awaiting human approval — the generalized
// approval queue for AI-proposed (and other) writes. Unlike the issuance-only
// ApprovalRequest, this models any action_type with arbitrary params.
type PendingAction struct {
	ID         string          `json:"id"`
	ActionType string          `json:"action_type"` // revoke | bulk_revoke
	Params     json.RawMessage `json:"params"`
	ProposedBy string          `json:"proposed_by"`
	Rationale  string          `json:"rationale,omitempty"`
	Status     string          `json:"status"` // pending | executing | approved | rejected | failed
	ApprovedBy string          `json:"approved_by,omitempty"`
	DecidedAt  string          `json:"decided_at,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	CreatedAt  string          `json:"created_at"`
	// Tenant the proposer belonged to (v2.2). Stamped at creation so the queue
	// can be scoped without re-resolving the action's target. "" => default.
	Tenant string `json:"tenant,omitempty"`
	// QuorumN approvals from distinct humans are required (of QuorumM
	// eligible); stamped at proposal time from the per-class policy so a later
	// policy change cannot weaken an action already in the queue (W22-10).
	QuorumN        int `json:"quorum_n"`
	QuorumM        int `json:"quorum_m"`
	ApprovalsCount int `json:"approvals_count"`
}

// PendingActionStore persists proposed actions and their decisions.
type PendingActionStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, a PendingAction) (PendingAction, error)
	List(ctx context.Context, status string) ([]PendingAction, error)
	Get(ctx context.Context, id string) (PendingAction, bool, error)
	Decide(ctx context.Context, id, status, approvedBy string, result json.RawMessage) error
}

// approvalDelegationSchema (W22-11) lives here, with the DDL the stores run on
// open, because the delegation store borrows the pending-action or approval
// store's DB handle rather than opening its own.
const approvalDelegationSchema = `
CREATE TABLE IF NOT EXISTS approval_delegations (
    delegator TEXT NOT NULL, tenant TEXT NOT NULL DEFAULT 'default', delegate TEXT NOT NULL,
    starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (delegator, tenant));`

const pendingActionSchema = `
CREATE TABLE IF NOT EXISTS pending_actions (
    id TEXT PRIMARY KEY, action_type TEXT NOT NULL, params_json TEXT NOT NULL,
    proposed_by TEXT NOT NULL, rationale TEXT, status TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT, decided_at TEXT, result_json TEXT, created_at TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT 'default',
    quorum_n INTEGER NOT NULL DEFAULT 1, quorum_m INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);
CREATE TABLE IF NOT EXISTS pending_action_approvals (
    action_id TEXT NOT NULL, human TEXT NOT NULL, approver_id TEXT NOT NULL,
    created_at TEXT NOT NULL, PRIMARY KEY (action_id, human));
` + approvalDelegationSchema

type dbPendingActionStore struct {
	db *sql.DB
	ph func(n int) string
}

func newPendingActionID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "act-" + hex.EncodeToString(b), nil
}

func (s *dbPendingActionStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, pendingActionSchema); err != nil {
		return err
	}
	// Best-effort upgrade for pre-v2.2 tables created without the tenant column.
	// Ignore the error: a duplicate-column failure means it already exists.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE pending_actions ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'") // best-effort upgrade: duplicate-column error = already migrated
	// Same self-heal for the W22-10 quorum columns.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE pending_actions ADD COLUMN quorum_n INTEGER NOT NULL DEFAULT 1") // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE pending_actions ADD COLUMN quorum_m INTEGER NOT NULL DEFAULT 1") // best-effort upgrade: duplicate-column error = already migrated
	return nil
}

func (s *dbPendingActionStore) Create(ctx context.Context, a PendingAction) (PendingAction, error) {
	id, err := newPendingActionID()
	if err != nil {
		return PendingAction{}, err
	}
	a.ID = id
	a.Status = "pending"
	a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if len(a.Params) == 0 {
		a.Params = json.RawMessage("{}")
	}
	if a.Tenant == "" {
		a.Tenant = DefaultTenant
	}
	if a.QuorumN == 0 {
		a.QuorumN, a.QuorumM = quorumFor(a.ActionType)
	}
	if a.QuorumM < a.QuorumN {
		a.QuorumM = a.QuorumN
	}
	q := fmt.Sprintf(`INSERT INTO pending_actions
		(id, action_type, params_json, proposed_by, rationale, status, created_at, tenant, quorum_n, quorum_m)
		VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9))
	if _, err := s.db.ExecContext(ctx, q, a.ID, a.ActionType, string(a.Params),
		a.ProposedBy, a.Rationale, a.CreatedAt, a.Tenant, a.QuorumN, a.QuorumM); err != nil {
		return PendingAction{}, err
	}
	notifyApprovalPending(pendingActionPendingEvent(a))
	return a, nil
}

func scanPendingAction(scan func(...any) error) (PendingAction, error) {
	var a PendingAction
	var params, result sql.NullString
	var rationale, approvedBy, decidedAt, tenant sql.NullString
	if err := scan(&a.ID, &a.ActionType, &params, &a.ProposedBy, &rationale,
		&a.Status, &approvedBy, &decidedAt, &result, &a.CreatedAt, &tenant,
		&a.QuorumN, &a.QuorumM, &a.ApprovalsCount); err != nil {
		return PendingAction{}, err
	}
	a.Params = json.RawMessage(params.String)
	a.Rationale = rationale.String
	a.ApprovedBy = approvedBy.String
	a.DecidedAt = decidedAt.String
	a.Tenant = tenant.String
	if a.Tenant == "" {
		a.Tenant = DefaultTenant
	}
	if result.Valid && result.String != "" {
		a.Result = json.RawMessage(result.String)
	}
	return a, nil
}

const pendingActionCols = `id, action_type, params_json, proposed_by, rationale,
	status, approved_by, decided_at, result_json, created_at, tenant, quorum_n, quorum_m,
	(SELECT COUNT(*) FROM pending_action_approvals WHERE action_id = pending_actions.id) AS approvals_count`

func (s *dbPendingActionStore) List(ctx context.Context, status string) ([]PendingAction, error) {
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			fmt.Sprintf("SELECT %s FROM pending_actions WHERE status = %s ORDER BY created_at DESC", pendingActionCols, s.ph(1)), status)
	} else {
		rows, err = s.db.QueryContext(ctx,
			fmt.Sprintf("SELECT %s FROM pending_actions ORDER BY created_at DESC", pendingActionCols))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingAction{}
	for rows.Next() {
		a, err := scanPendingAction(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *dbPendingActionStore) Get(ctx context.Context, id string) (PendingAction, bool, error) {
	row := s.db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT %s FROM pending_actions WHERE id = %s", pendingActionCols, s.ph(1)), id)
	a, err := scanPendingAction(row.Scan)
	if err == sql.ErrNoRows {
		return PendingAction{}, false, nil
	}
	if err != nil {
		return PendingAction{}, false, err
	}
	return a, true, nil
}

// statusExecuting marks an action whose approval has been claimed and whose
// executor is running. Decide(..., statusExecuting, ...) is the compare-and-set:
// exactly one caller moves pending -> executing, so an approved action runs
// once however many approvals race (A01-003).
const statusExecuting = "executing"

// Decide moves an action to status. "executing" and "rejected" require the
// action to still be pending; the terminal approved/failed outcomes may
// follow either a claim ("executing") or a direct decision from pending.
func (s *dbPendingActionStore) Decide(ctx context.Context, id, status, approvedBy string, result json.RawMessage) error {
	from := "status = 'pending'"
	if status == "approved" || status == "failed" {
		from = "status IN ('pending', 'executing')"
	}
	q := fmt.Sprintf(`UPDATE pending_actions SET status = %s, approved_by = %s, decided_at = %s, result_json = %s
		WHERE id = %s AND %s`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), from)
	res, err := s.db.ExecContext(ctx, q, status, approvedBy, time.Now().UTC().Format(time.RFC3339), string(result), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("action not found or already decided")
	}
	notifyApprovalDecided(ctx, chatopsKindAction, id, status, approvedBy)
	return nil
}

// NewPendingActionStoreFromEnv opens the shared DB and ensures the schema.
// Returns nil if the DB is unavailable (callers tolerate nil).
func NewPendingActionStoreFromEnv() PendingActionStore {
	state := newDBProviderState[*dbPendingActionStore](
		"pending-action",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbPendingActionStore { return &dbPendingActionStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) *dbPendingActionStore { return &dbPendingActionStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("pending-action", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("pending-action", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
