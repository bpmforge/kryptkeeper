// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	kkdb "kryptkeeper/internal/db"
	_ "modernc.org/sqlite"
)

type dbAuditStore interface {
	EnsureSchema(ctx context.Context) error
	ListEntries(context.Context, AuditListQuery) (AuditListResult, error)
	AppendEntry(context.Context, AuditEntry) error
}

type sqliteAuditStore struct{ db *sql.DB }
type postgresAuditStore struct{ db *sql.DB }

type dbAuditProvider struct {
	store   dbAuditStore
	openErr error
}

// sqliteAuditSchema mirrors migrations 000004_audit_log_append_only +
// 000011_audit_log_security_fields combined, plus the W2-04 tenant column —
// see G-48/S-07: this store, like cert_approval_requests before S-06, never
// created its own table and depended entirely on those migrations actually
// running (which G-33 established never happens against a live deployment).
// Every statement is idempotent (IF NOT EXISTS) so EnsureSchema can safely
// run on every boot, not just the first. The outcome and actor_type CHECKs
// carry migration 000076's widened vocabulary (AuditOutcome); a table that
// predates it is widened by EnsureSchema via kkdb.EnsureAuditOutcomeVocabulary.
const sqliteAuditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    action                    TEXT NOT NULL,
    actor_type                TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system', 'agent', 'workload')),
    actor_id                  TEXT NOT NULL,
    actor_email               TEXT,
    resource_type             TEXT NOT NULL,
    resource_id               TEXT NOT NULL,
    client_ip                 TEXT,
    trace_id                  TEXT,
    details                   TEXT NOT NULL DEFAULT '{}',
    diff                      TEXT,
    outcome                   TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied', 'skipped', 'pending_approval', 'proposed', 'executed', 'issuance_failed', 'partial')),
    source_ip                 TEXT,
    user_agent                TEXT,
    session_id                TEXT,
    change_summary            TEXT,
    tenant                    TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;`

// postgresAuditSchema mirrors the same two migrations for Postgres: range
// partitioning by month, an append-only trigger via a plpgsql function, and
// row-level security. Every statement is written to be idempotent across
// repeated boots: CREATE TABLE/INDEX use IF NOT EXISTS (Postgres supports
// this on partitioned tables), the trigger and policy are DROP IF EXISTS
// then re-created (no portable CREATE-OR-REPLACE for either across the PG
// versions this project targets), and ENABLE ROW LEVEL SECURITY is a no-op
// if already enabled. The partition loop re-runs every boot too, which is a
// deliberate bonus: it keeps 3 months of partitions ahead of "now" without a
// separate maintenance job, at the cost of not backfilling months missed by
// a long-uptime gap (same limitation the original migration had).
const postgresAuditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
    id                        BIGINT GENERATED ALWAYS AS IDENTITY,
    timestamp                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action                    VARCHAR(100) NOT NULL,
    actor_type                VARCHAR(20) NOT NULL
                              CHECK (actor_type IN ('user', 'api_key', 'system', 'agent', 'workload')),
    actor_id                  VARCHAR(128) NOT NULL,
    actor_email               VARCHAR(255),
    resource_type             VARCHAR(50) NOT NULL,
    resource_id               VARCHAR(128) NOT NULL,
    client_ip                 INET,
    trace_id                  VARCHAR(64),
    details                   JSONB NOT NULL DEFAULT '{}',
    diff                      JSONB,
    outcome                   VARCHAR(32) NOT NULL DEFAULT 'success'
                              CHECK (outcome IN ('success', 'failure', 'denied', 'skipped', 'pending_approval', 'proposed', 'executed', 'issuance_failed', 'partial')),
    source_ip                 TEXT,
    user_agent                TEXT,
    session_id                TEXT,
    change_summary            TEXT,
    tenant                    TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

DO $$
DECLARE
    start_month DATE;
    end_month DATE;
    part_name TEXT;
BEGIN
    FOR i IN 0..2 LOOP
        start_month := date_trunc('month', NOW())::date + (i || ' month')::interval;
        end_month := start_month + interval '1 month';
        part_name := format('audit_log_%s', to_char(start_month, 'YYYY_MM'));

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
            part_name,
            start_month,
            end_month
        );
    END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);

CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS trigger AS $f$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$f$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_append_only ON audit_log;
CREATE TRIGGER trg_audit_log_append_only
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_insert_only ON audit_log;
CREATE POLICY audit_insert_only ON audit_log
    FOR INSERT WITH CHECK (TRUE);`

func (s *sqliteAuditStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, sqliteAuditSchema); err != nil {
		return err
	}
	ensureAuditTenantColumn(s.db)
	return kkdb.EnsureAuditOutcomeVocabulary(s.db, "sqlite")
}

func (s *postgresAuditStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, postgresAuditSchema); err != nil {
		return err
	}
	ensureAuditTenantColumn(s.db)
	return kkdb.EnsureAuditOutcomeVocabulary(s.db, "postgres")
}

// newDBAuditProviderFromEnv opens the database-backed audit trail. Failing to
// open it or to create its schema (S-07/G-48: table, trigger and RLS
// self-heal) is returned so the hub refuses to start: an audit trail that
// silently drops every row is worse than not running.
func newDBAuditProviderFromEnv() (AuditProvider, error) {
	state := newDBProviderState[dbAuditStore](
		"audit",
		auditSQLiteDSNFromEnv,
		auditPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbAuditStore { return &sqliteAuditStore{db: db} },
		func(db *sql.DB) dbAuditStore { return &postgresAuditStore{db: db} },
	)
	if state.openErr != nil {
		return nil, fmt.Errorf("audit database unavailable: %w", state.openErr)
	}
	if state.store == nil {
		return nil, fmt.Errorf("audit database store not configured")
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("audit_log schema initialization failed: %w", err)
	}
	return &dbAuditProvider{store: state.store}, nil
}

func newDBAuditStoreFromEnv() (dbAuditStore, error) {
	state := newDBProviderState[dbAuditStore](
		"audit",
		auditSQLiteDSNFromEnv,
		auditPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbAuditStore { return &sqliteAuditStore{db: db} },
		func(db *sql.DB) dbAuditStore { return &postgresAuditStore{db: db} },
	)
	if state.store != nil {
		if err := state.store.EnsureSchema(context.Background()); err != nil {
			log.Fatalf("APP_AUDIT_PROVIDER=db: audit_log schema initialization failed, refusing to start with a silently non-functional audit trail: %v", err)
		}
	}
	return state.store, state.openErr
}

// ensureAuditTenantColumn best-effort-adds the W2-04 tenant column to an
// audit_log table that predates it (a table created by a real migration run
// before this ticket, or before W2-04 landed). Errors are ignored: "column
// already exists" is the expected steady state on every table EnsureSchema
// itself just created (tenant is now part of sqliteAuditSchema/
// postgresAuditSchema from the start).
func ensureAuditTenantColumn(db *sql.DB) {
	_, _ = db.Exec("ALTER TABLE audit_log ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'") // best-effort upgrade: duplicate-column error = already migrated
}

// The audit trail lives in the hub's core database unless APP_AUDIT_DB_DSN
// says otherwise: both resolvers fall back through the same variables, in the
// same order, as OpenCoreDB, and currentDBMode picks the driver for both, so a
// postgres hub can never audit into a local sqlite file.
func auditSQLiteDSNFromEnv() (string, error) {
	if strings.TrimSpace(os.Getenv("APP_AUDIT_DB_DSN")) == "" {
		return resolveSQLiteDSNFromEnv("APP_CORE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
	}
	return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
}

func auditPostgresDSNFromEnv() string {
	return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "APP_CORE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
}

func (p *dbAuditProvider) ListEntries(ctx context.Context, query AuditListQuery) (AuditListResult, error) {
	if err := dbProviderUnavailable("audit", p.openErr); err != nil {
		return AuditListResult{}, err
	}
	if p.store == nil {
		return AuditListResult{}, fmt.Errorf("audit db store not configured")
	}
	return p.store.ListEntries(ctx, query)
}

func (p *dbAuditProvider) AppendEntry(ctx context.Context, entry AuditEntry) error {
	if err := dbProviderUnavailable("audit", p.openErr); err != nil {
		return err
	}
	if p.store == nil {
		return fmt.Errorf("audit db store not configured")
	}
	return p.store.AppendEntry(ctx, entry)
}

func (s *sqliteAuditStore) ListEntries(ctx context.Context, query AuditListQuery) (AuditListResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	order := query.Order
	if order == "" {
		order = "desc"
	}

	whereClauses := make([]string, 0)
	args := make([]any, 0)
	if query.Action != "" {
		whereClauses = append(whereClauses, "action = ?")
		args = append(args, query.Action)
	}
	if query.ActorType != "" {
		whereClauses = append(whereClauses, "actor_type = ?")
		args = append(args, query.ActorType)
	}
	if query.ActorID != "" {
		whereClauses = append(whereClauses, "actor_id = ?")
		args = append(args, query.ActorID)
	}
	if query.ResourceType != "" {
		whereClauses = append(whereClauses, "resource_type = ?")
		args = append(args, query.ResourceType)
	}
	if query.ResourceID != "" {
		whereClauses = append(whereClauses, "resource_id = ?")
		args = append(args, query.ResourceID)
	}
	if query.TraceID != "" {
		whereClauses = append(whereClauses, "trace_id = ?")
		args = append(args, query.TraceID)
	}
	if query.Outcome != "" {
		whereClauses = append(whereClauses, "outcome = ?")
		args = append(args, string(query.Outcome))
	}
	if query.After != "" {
		whereClauses = append(whereClauses, "timestamp > ?")
		args = append(args, query.After)
	}
	if query.Before != "" {
		whereClauses = append(whereClauses, "timestamp < ?")
		args = append(args, query.Before)
	}
	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = " WHERE " + strings.Join(whereClauses, " AND ")
	}

	var total int
	countQuery := `SELECT COUNT(*) FROM audit_log` + whereSQL
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return AuditListResult{}, err
	}

	orderDir := "DESC"
	if order == "asc" {
		orderDir = "ASC"
	}
	listQuery := `
SELECT id, timestamp, action, actor_type, actor_id, resource_type, resource_id,
       COALESCE(trace_id, ''), outcome,
       COALESCE(source_ip, ''), COALESCE(user_agent, ''), COALESCE(session_id, ''), COALESCE(change_summary, ''),
       COALESCE(tenant, '')
FROM audit_log
` + whereSQL + `
ORDER BY timestamp ` + orderDir + `, id ` + orderDir + `
LIMIT ? OFFSET ?
`
	listArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.db.QueryContext(ctx, listQuery, listArgs...)
	if err != nil {
		return AuditListResult{}, err
	}
	defer rows.Close()

	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &e.ActorType, &e.ActorID, &e.ResourceType, &e.ResourceID,
			&e.TraceID, &e.Outcome, &e.SourceIP, &e.UserAgent, &e.SessionID, &e.ChangeSummary, &e.Tenant); err != nil {
			return AuditListResult{}, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return AuditListResult{}, err
	}

	return AuditListResult{Entries: entries, Total: total, Limit: limit}, nil
}

func (s *postgresAuditStore) ListEntries(ctx context.Context, query AuditListQuery) (AuditListResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	order := query.Order
	if order == "" {
		order = "desc"
	}

	whereClauses := make([]string, 0)
	args := make([]any, 0)
	nextArg := 1
	addFilter := func(clause string, value any) {
		whereClauses = append(whereClauses, fmt.Sprintf(clause, nextArg))
		args = append(args, value)
		nextArg++
	}
	if query.Action != "" {
		addFilter("action = $%d", query.Action)
	}
	if query.ActorType != "" {
		addFilter("actor_type = $%d", query.ActorType)
	}
	if query.ActorID != "" {
		addFilter("actor_id = $%d", query.ActorID)
	}
	if query.ResourceType != "" {
		addFilter("resource_type = $%d", query.ResourceType)
	}
	if query.ResourceID != "" {
		addFilter("resource_id = $%d", query.ResourceID)
	}
	if query.TraceID != "" {
		addFilter("trace_id = $%d", query.TraceID)
	}
	if query.Outcome != "" {
		addFilter("outcome = $%d", string(query.Outcome))
	}
	if query.After != "" {
		addFilter("timestamp > $%d", query.After)
	}
	if query.Before != "" {
		addFilter("timestamp < $%d", query.Before)
	}
	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = " WHERE " + strings.Join(whereClauses, " AND ")
	}

	var total int
	countQuery := `SELECT COUNT(*) FROM audit_log` + whereSQL
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return AuditListResult{}, err
	}

	orderDir := "DESC"
	if order == "asc" {
		orderDir = "ASC"
	}
	limitPlaceholder := fmt.Sprintf("$%d", nextArg)
	args = append(args, limit)
	nextArg++
	offsetPlaceholder := fmt.Sprintf("$%d", nextArg)
	args = append(args, offset)

	listQuery := `
SELECT id, timestamp, action, actor_type, actor_id, resource_type, resource_id,
       COALESCE(trace_id, ''), outcome,
       COALESCE(source_ip, ''), COALESCE(user_agent, ''), COALESCE(session_id, ''), COALESCE(change_summary, ''),
       COALESCE(tenant, '')
FROM audit_log
` + whereSQL + `
ORDER BY timestamp ` + orderDir + `, id ` + orderDir + `
LIMIT ` + limitPlaceholder + ` OFFSET ` + offsetPlaceholder + `
`
	rows, err := s.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return AuditListResult{}, err
	}
	defer rows.Close()

	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var (
			e  AuditEntry
			ts time.Time
		)
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.ActorType, &e.ActorID, &e.ResourceType, &e.ResourceID,
			&e.TraceID, &e.Outcome, &e.SourceIP, &e.UserAgent, &e.SessionID, &e.ChangeSummary, &e.Tenant); err != nil {
			return AuditListResult{}, err
		}
		e.Timestamp = ts.UTC().Format(time.RFC3339)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return AuditListResult{}, err
	}

	return AuditListResult{Entries: entries, Total: total, Limit: limit}, nil
}

func (s *sqliteAuditStore) AppendEntry(ctx context.Context, entry AuditEntry) error {
	timestamp := strings.TrimSpace(entry.Timestamp)
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log(timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome,
                      source_ip, user_agent, session_id, change_summary, tenant)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, timestamp, entry.Action, entry.ActorType, entry.ActorID, entry.ResourceType, entry.ResourceID,
		nullableString(entry.TraceID), entry.Outcome,
		nullableString(entry.SourceIP), nullableString(entry.UserAgent), nullableString(entry.SessionID), nullableString(entry.ChangeSummary),
		auditEntryTenantOrDefault(entry.Tenant))
	return err
}

func (s *postgresAuditStore) AppendEntry(ctx context.Context, entry AuditEntry) error {
	timestamp := time.Now().UTC()
	if trimmed := strings.TrimSpace(entry.Timestamp); trimmed != "" {
		if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
			timestamp = parsed.UTC()
		}
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log(timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome,
                      source_ip, user_agent, session_id, change_summary, tenant)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
`, timestamp, entry.Action, entry.ActorType, entry.ActorID, entry.ResourceType, entry.ResourceID,
		nullableString(entry.TraceID), entry.Outcome,
		nullableString(entry.SourceIP), nullableString(entry.UserAgent), nullableString(entry.SessionID), nullableString(entry.ChangeSummary),
		auditEntryTenantOrDefault(entry.Tenant))
	return err
}

// auditEntryTenantOrDefault falls back to DefaultTenant for entries built
// before W2-04 (e.g. constructed directly in tests/other providers rather
// than through emitAuditEventDetail, which always sets Tenant).
func auditEntryTenantOrDefault(tenant string) string {
	if trimmed := strings.TrimSpace(tenant); trimmed != "" {
		return trimmed
	}
	return DefaultTenant
}

func nullableString(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}
