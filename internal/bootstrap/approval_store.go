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
	"errors"
	"fmt"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

var (
	errApprovalNotFound = errors.New("approval request not found")
	errApprovalDecided  = errors.New("approval request already decided")
)

// ApprovalRequest is a pending certificate issuance waiting for approval.
type ApprovalRequest struct {
	ID                string  `json:"id"`
	TemplateID        string  `json:"template_id"`
	CAID              string  `json:"ca_id"`
	Requester         string  `json:"requester"`
	Status            string  `json:"status"` // pending, approved, rejected
	CSRPEM            string  `json:"csr_pem"`
	TeamID            string  `json:"team_id,omitempty"`
	RequestedAt       string  `json:"requested_at"`
	DecidedAt         *string `json:"decided_at,omitempty"`
	DecidedBy         *string `json:"decided_by,omitempty"`
	RejectReason      *string `json:"reject_reason,omitempty"`
	IssuedFingerprint *string `json:"issued_fingerprint,omitempty"`
	// Kind says which issuer completes the approval: "x509" (default) or "ssh"
	// (W26-31). An SSH row has no CA or CSR; SSHRequest is the original issue
	// request and Tenant scopes the row, since CA-derived tenancy is unavailable.
	Kind       string               `json:"kind"`
	SSHRequest *sshCertIssueRequest `json:"ssh_request,omitempty"`
	Tenant     string               `json:"tenant,omitempty"`
	// OnBehalfOf (W33-23) is the delegator whose team a delegate filed this for;
	// Requester stays the delegate, TeamID is the delegator.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
}

const (
	approvalKindX509 = "x509"
	approvalKindSSH  = "ssh"
)

// ApprovalStore persists and retrieves approval requests.
type ApprovalStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, req ApprovalRequest) error
	Get(ctx context.Context, id string) (ApprovalRequest, error)
	List(ctx context.Context, status string, limit, offset int) ([]ApprovalRequest, int, error)
	Decide(ctx context.Context, id, decidedBy, status, rejectReason string) error
	SetIssued(ctx context.Context, id, fingerprint string) error
}

// approvalSchema mirrors migration 000013_cert_approval_requests — see G-47:
// this store, unlike every other DB-backed store in the package, never
// created its own table, and depended entirely on that migration actually
// running (which G-33 established never happens against a live deployment).
const approvalSchema = `
CREATE TABLE IF NOT EXISTS cert_approval_requests (
    id               TEXT PRIMARY KEY,
    template_id      TEXT NOT NULL,
    ca_id            TEXT NOT NULL,
    requester        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    csr_pem          TEXT NOT NULL,
    team_id          TEXT,
    requested_at     TEXT NOT NULL,
    decided_at       TEXT,
    decided_by       TEXT,
    reject_reason    TEXT,
    issued_fingerprint TEXT,
    kind             TEXT NOT NULL DEFAULT 'x509',
    request_json     TEXT,
    tenant           TEXT,
    on_behalf_of     TEXT
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON cert_approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_template ON cert_approval_requests(template_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_requester ON cert_approval_requests(requester);
` + approvalDelegationSchema + codesignAttestationSchema

// codesignAttestationSchema mirrors migration 000184. It lives here, with the DDL the approval
// stores run on open, because the attestation store borrows their DB handle.
const codesignAttestationSchema = `
CREATE TABLE IF NOT EXISTS codesign_attestations (
    csr_sha256 TEXT PRIMARY KEY, template_id TEXT NOT NULL, format TEXT NOT NULL,
    serial TEXT, firmware TEXT, key_spki_sha256 TEXT NOT NULL, attestation_pem TEXT NOT NULL,
    intermediates_pem TEXT, vendor_root_sha256 TEXT NOT NULL, verified_at TEXT NOT NULL);
`

// approvalKindColumns are the W26-31 additions (migration 000187). A table
// created before it lacks them and CREATE TABLE IF NOT EXISTS will not add
// them, so they are added here; "already there" is the expected outcome.
var approvalKindColumns = []string{
	"kind TEXT NOT NULL DEFAULT 'x509'",
	"request_json TEXT",
	"tenant TEXT",
	"on_behalf_of TEXT",
}

func ensureApprovalSchema(ctx context.Context, db *sql.DB, postgres bool) error {
	if _, err := db.ExecContext(ctx, approvalSchema); err != nil {
		return err
	}
	for _, col := range approvalKindColumns {
		stmt := "ALTER TABLE cert_approval_requests ADD COLUMN "
		if postgres {
			stmt += "IF NOT EXISTS "
		}
		if _, err := db.ExecContext(ctx, stmt+col); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

func newApprovalID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "apr-" + hex.EncodeToString(b), nil
}

// --- SQLite implementation ---

type sqliteApprovalStore struct{ db *sql.DB }

func (s *sqliteApprovalStore) EnsureSchema(ctx context.Context) error {
	return ensureApprovalSchema(ctx, s.db, false)
}

func (s *sqliteApprovalStore) Create(ctx context.Context, req ApprovalRequest) error {
	kind, requestJSON, err := approvalKindFields(req)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cert_approval_requests
		  (id, template_id, ca_id, requester, status, csr_pem, team_id, requested_at, kind, request_json, tenant, on_behalf_of)
		VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.TemplateID, req.CAID, req.Requester,
		req.CSRPEM, nullString(req.TeamID), req.RequestedAt, kind, requestJSON, nullString(req.Tenant), nullString(req.OnBehalfOf))
	if err == nil {
		notifyApprovalPending(approvalPendingEvent(req))
	}
	return err
}

func (s *sqliteApprovalStore) Get(ctx context.Context, id string) (ApprovalRequest, error) {
	return scanApprovalRow(s.db.QueryRowContext(ctx, `
		SELECT id, template_id, ca_id, requester, status, csr_pem, team_id,
		       requested_at, decided_at, decided_by, reject_reason, issued_fingerprint,
		       kind, request_json, tenant, on_behalf_of
		FROM cert_approval_requests WHERE id = ?`, id))
}

func (s *sqliteApprovalStore) List(ctx context.Context, status string, limit, offset int) ([]ApprovalRequest, int, error) {
	return listApprovalRows(s.db, ctx, status, limit, offset, "?", "?", "?", "?")
}

func (s *sqliteApprovalStore) Decide(ctx context.Context, id, decidedBy, status, rejectReason string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `
		UPDATE cert_approval_requests
		SET status = ?, decided_at = ?, decided_by = ?, reject_reason = ?
		WHERE id = ? AND status = 'pending'`,
		status, now, decidedBy, nullString(rejectReason), id)
	if err != nil {
		return err
	}
	if err := checkDecideResult(res, id); err != nil {
		return err
	}
	notifyApprovalDecided(ctx, chatopsKindApproval, id, status, decidedBy)
	return nil
}

func (s *sqliteApprovalStore) SetIssued(ctx context.Context, id, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cert_approval_requests SET issued_fingerprint = ? WHERE id = ?`,
		fingerprint, id)
	return err
}

// --- Postgres implementation ---

type postgresApprovalStore struct{ db *sql.DB }

func (s *postgresApprovalStore) EnsureSchema(ctx context.Context) error {
	return ensureApprovalSchema(ctx, s.db, true)
}

func (s *postgresApprovalStore) Create(ctx context.Context, req ApprovalRequest) error {
	kind, requestJSON, err := approvalKindFields(req)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cert_approval_requests
		  (id, template_id, ca_id, requester, status, csr_pem, team_id, requested_at, kind, request_json, tenant, on_behalf_of)
		VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9, $10, $11)`,
		req.ID, req.TemplateID, req.CAID, req.Requester,
		req.CSRPEM, nullString(req.TeamID), req.RequestedAt, kind, requestJSON, nullString(req.Tenant), nullString(req.OnBehalfOf))
	if err == nil {
		notifyApprovalPending(approvalPendingEvent(req))
	}
	return err
}

func (s *postgresApprovalStore) Get(ctx context.Context, id string) (ApprovalRequest, error) {
	return scanApprovalRow(s.db.QueryRowContext(ctx, `
		SELECT id, template_id, ca_id, requester, status, csr_pem, team_id,
		       requested_at, decided_at, decided_by, reject_reason, issued_fingerprint,
		       kind, request_json, tenant, on_behalf_of
		FROM cert_approval_requests WHERE id = $1`, id))
}

func (s *postgresApprovalStore) List(ctx context.Context, status string, limit, offset int) ([]ApprovalRequest, int, error) {
	return listApprovalRows(s.db, ctx, status, limit, offset, "$1", "$2", "$3", "$4")
}

func (s *postgresApprovalStore) Decide(ctx context.Context, id, decidedBy, status, rejectReason string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `
		UPDATE cert_approval_requests
		SET status = $1, decided_at = $2, decided_by = $3, reject_reason = $4
		WHERE id = $5 AND status = 'pending'`,
		status, now, decidedBy, nullString(rejectReason), id)
	if err != nil {
		return err
	}
	if err := checkDecideResult(res, id); err != nil {
		return err
	}
	notifyApprovalDecided(ctx, chatopsKindApproval, id, status, decidedBy)
	return nil
}

func (s *postgresApprovalStore) SetIssued(ctx context.Context, id, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cert_approval_requests SET issued_fingerprint = $1 WHERE id = $2`,
		fingerprint, id)
	return err
}

// --- shared helpers ---

// approvalKindFields is the kind plus the serialised SSH request for the row.
func approvalKindFields(req ApprovalRequest) (kind string, requestJSON sql.NullString, err error) {
	kind = req.Kind
	if kind == "" {
		kind = approvalKindX509
	}
	if req.SSHRequest != nil {
		raw, merr := json.Marshal(req.SSHRequest)
		if merr != nil {
			return "", sql.NullString{}, merr
		}
		requestJSON = sql.NullString{String: string(raw), Valid: true}
	}
	return kind, requestJSON, nil
}

// fillApprovalKind applies the nullable W26-31 columns to a scanned row.
func fillApprovalKind(r *ApprovalRequest, kind, requestJSON, tenant sql.NullString) {
	r.Kind = kind.String
	if r.Kind == "" {
		r.Kind = approvalKindX509
	}
	r.Tenant = tenant.String
	if requestJSON.Valid && requestJSON.String != "" {
		var req sshCertIssueRequest
		if json.Unmarshal([]byte(requestJSON.String), &req) == nil {
			r.SSHRequest = &req
		}
	}
}

func scanApprovalRow(row *sql.Row) (ApprovalRequest, error) {
	var r ApprovalRequest
	var teamID, decidedAt, decidedBy, rejectReason, issuedFP, kind, requestJSON, tenant, onBehalf sql.NullString
	err := row.Scan(&r.ID, &r.TemplateID, &r.CAID, &r.Requester, &r.Status,
		&r.CSRPEM, &teamID, &r.RequestedAt,
		&decidedAt, &decidedBy, &rejectReason, &issuedFP, &kind, &requestJSON, &tenant, &onBehalf)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalRequest{}, errApprovalNotFound
	}
	if err != nil {
		return ApprovalRequest{}, err
	}
	r.TeamID = teamID.String
	fillApprovalKind(&r, kind, requestJSON, tenant)
	r.OnBehalfOf = onBehalf.String
	if decidedAt.Valid {
		r.DecidedAt = &decidedAt.String
	}
	if decidedBy.Valid {
		r.DecidedBy = &decidedBy.String
	}
	if rejectReason.Valid {
		r.RejectReason = &rejectReason.String
	}
	if issuedFP.Valid {
		r.IssuedFingerprint = &issuedFP.String
	}
	return r, nil
}

func listApprovalRows(db *sql.DB, ctx context.Context, status string, limit, offset int,
	p1, p2, p3, p4 string) ([]ApprovalRequest, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	var rows *sql.Rows
	var err error
	var total int
	if status != "" {
		err = db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM cert_approval_requests WHERE status = %s", p1),
			status).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
		rows, err = db.QueryContext(ctx,
			fmt.Sprintf(`SELECT id, template_id, ca_id, requester, status, csr_pem, team_id,
			       requested_at, decided_at, decided_by, reject_reason, issued_fingerprint,
		       kind, request_json, tenant, on_behalf_of
			  FROM cert_approval_requests WHERE status = %s
			  ORDER BY requested_at DESC LIMIT %s OFFSET %s`, p1, p2, p3),
			status, limit, offset)
	} else {
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM cert_approval_requests").Scan(&total)
		if err != nil {
			return nil, 0, err
		}
		rows, err = db.QueryContext(ctx,
			fmt.Sprintf(`SELECT id, template_id, ca_id, requester, status, csr_pem, team_id,
			       requested_at, decided_at, decided_by, reject_reason, issued_fingerprint,
		       kind, request_json, tenant, on_behalf_of
			  FROM cert_approval_requests
			  ORDER BY requested_at DESC LIMIT %s OFFSET %s`, p1, p2),
			limit, offset)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var items []ApprovalRequest
	for rows.Next() {
		var r ApprovalRequest
		var teamID, decidedAt, decidedBy, rejectReason, issuedFP, kind, requestJSON, tenant, onBehalf sql.NullString
		if err := rows.Scan(&r.ID, &r.TemplateID, &r.CAID, &r.Requester, &r.Status,
			&r.CSRPEM, &teamID, &r.RequestedAt,
			&decidedAt, &decidedBy, &rejectReason, &issuedFP, &kind, &requestJSON, &tenant, &onBehalf); err != nil {
			return nil, 0, err
		}
		r.TeamID = teamID.String
		fillApprovalKind(&r, kind, requestJSON, tenant)
		r.OnBehalfOf = onBehalf.String
		if decidedAt.Valid {
			r.DecidedAt = &decidedAt.String
		}
		if decidedBy.Valid {
			r.DecidedBy = &decidedBy.String
		}
		if rejectReason.Valid {
			r.RejectReason = &rejectReason.String
		}
		if issuedFP.Valid {
			r.IssuedFingerprint = &issuedFP.String
		}
		items = append(items, r)
	}
	if items == nil {
		items = []ApprovalRequest{}
	}
	return items, total, rows.Err()
}

func checkDecideResult(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Either not found or already decided — check which.
		return errApprovalDecided
	}
	return nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// newApprovalStoreFromEnv opens the same SQLite/Postgres DB as other
// providers and ensures its schema (G-47/S-06: this store used to depend
// entirely on migration 000013 running, which never happens against a live
// deployment — see approvalSchema).
func newApprovalStoreFromEnv() (ApprovalStore, error) {
	state := newDBProviderState[ApprovalStore](
		"approval",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) ApprovalStore { return &sqliteApprovalStore{db: db} },
		func(db *sql.DB) ApprovalStore { return &postgresApprovalStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// approvalSystemActor decides approvals the system cancels (W33-23).
const approvalSystemActor = "system:team-membership"

// CancelPendingForRequester rejects every pending approval filed by requester
// in teamID (any team when teamID is empty), and every pending approval filed
// on the requester's behalf when the delegator leaves (OnBehalfOf ==
// requester). Each cancellation leaves a system audit entry. A row decided by
// someone else in the meantime is skipped. It returns the number cancelled.
// The matching rows are collected before any is decided so paging is not
// disturbed by the status changes.
func CancelPendingForRequester(ctx context.Context, store ApprovalStore, audit AuditProvider, requester, teamID string, now time.Time) (int, error) {
	if store == nil || strings.TrimSpace(requester) == "" {
		return 0, errors.New("cancel pending: store and requester required")
	}
	var victims []ApprovalRequest
	const page = 200
	for off := 0; ; off += page {
		rows, total, err := store.List(ctx, "pending", page, off)
		if err != nil {
			return 0, err
		}
		for _, a := range rows {
			byRequester := a.Requester == requester && (teamID == "" || a.TeamID == teamID)
			byDelegator := a.OnBehalfOf == requester && (teamID == "" || a.TeamID == teamID)
			if byRequester || byDelegator {
				victims = append(victims, a)
			}
		}
		if off+page >= total || len(rows) == 0 {
			break
		}
	}
	reason := "requester left team " + teamID
	cancelled := 0
	for _, a := range victims {
		if err := store.Decide(ctx, a.ID, approvalSystemActor, "rejected", reason); err != nil {
			if errors.Is(err, errApprovalDecided) {
				continue
			}
			return cancelled, err
		}
		cancelled++
		if audit != nil {
			e := AuditEntry{
				Timestamp: now.UTC().Format(time.RFC3339), Action: "approval.cancel", ActorType: "system", ActorID: approvalSystemActor,
				ResourceType: "approval", ResourceID: a.ID, Outcome: AuditOutcomeSuccess, Tenant: a.Tenant,
				ChangeSummary: fmt.Sprintf("requester=%s team=%s reason=left_team", requester, teamID),
			}
			if err := audit.AppendEntry(ctx, e); err != nil {
				logging.Errorf("approval cancel: audit append failed id=%s: %v", a.ID, err)
			}
		}
	}
	return cancelled, nil
}
