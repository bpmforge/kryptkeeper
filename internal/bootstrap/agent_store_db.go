// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// agentStoreSchema is the idempotent DDL the DB store ensures at construction,
// so it works even on a DB where migration 000015 wasn't applied separately.
//
// token is kept (NOT NULL) for schema compatibility with pre-W2-09 databases,
// but is no longer written to for new agents — token_hash (added by the
// best-effort ALTER TABLE in EnsureSchema, migration 000024) is the real
// credential store. See hashAgentToken/agentTokenMatches (G-28, D-037).
const agentStoreSchema = `
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, token TEXT NOT NULL,
    registered_at TEXT NOT NULL, last_seen TEXT, inventory_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS agent_inventory (
    agent_id TEXT NOT NULL, fingerprint TEXT NOT NULL, subject TEXT, issuer TEXT,
    not_before TEXT, not_after TEXT, source TEXT, auto_renewable INTEGER NOT NULL DEFAULT 0,
    dns_names TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS agent_endpoints (
    agent_id TEXT NOT NULL, server_type TEXT, cert_path TEXT, key_path TEXT,
    server_name TEXT, listen_port INTEGER, config_path TEXT);
-- agent_tasks.ca_url (W19-26): retained for schema compatibility with
-- migration 000015 -- dropping a live column needs a migration this ticket's
-- scope doesn't call for -- but no Go code reads or writes it any more. It
-- was always declared, never assigned by the hub and never read by the agent
-- (cmd/kryptkeeper-agent / internal/agentclient derive the ACME directory
-- from KRYPTKEEPER_HUB_URL instead; see acme_renewer.go). See insertTaskTx
-- and scanTasks below, which no longer reference this column.
CREATE TABLE IF NOT EXISTS agent_tasks (
    task_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, fingerprint TEXT, subject TEXT,
    action TEXT, ca_url TEXT, not_after TEXT, server_type TEXT, cert_path TEXT,
    key_path TEXT, reload_method TEXT, verify_host_port TEXT,
    identifiers TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS agent_results (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, task_id TEXT, fingerprint TEXT,
    outcome TEXT, served_fingerprint TEXT, rolled_back INTEGER NOT NULL DEFAULT 0,
    detail TEXT, reported_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_agent_inventory_agent ON agent_inventory(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_endpoints_agent ON agent_endpoints(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_results_agent ON agent_results(agent_id);`

// dbAgentStore is a SQLite/Postgres-backed AgentStore — restart-safe persistence
// for agent registrations, inventory, endpoints, tasks, and results.
type dbAgentStore struct {
	db            *sql.DB
	ph            func(n int) string
	thresholdDays int
}

func (s *dbAgentStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, agentStoreSchema); err != nil {
		return err
	}
	// Best-effort upgrade for pre-W2-09 tables created without token_hash.
	// Ignore the error: a duplicate-column failure means it already exists.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE agents ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''") // best-effort upgrade: duplicate-column error = already migrated
	// W19-13: same best-effort upgrade for pre-existing agent_inventory/agent_tasks
	// tables (this store's own DSN may not be the one internal/db/migrate.go
	// applies 000057_agent_dns_identifiers to -- see the dedupAgentTasks doc
	// comment above for why EnsureSchema keeps its own copy of every column add).
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE agent_inventory ADD COLUMN dns_names TEXT NOT NULL DEFAULT '[]'") // best-effort upgrade: duplicate-column error = already migrated
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE agent_tasks ADD COLUMN identifiers TEXT NOT NULL DEFAULT '[]'")   // best-effort upgrade: duplicate-column error = already migrated
	// W19-26: same best-effort upgrade for pre-000059 agent_tasks tables.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE agent_tasks ADD COLUMN created_at TEXT NOT NULL DEFAULT ''") // best-effort upgrade: duplicate-column error = already migrated
	if err := s.dedupAgentTasks(ctx); err != nil {
		return fmt.Errorf("dedup agent_tasks: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tasks_agent_fingerprint ON agent_tasks(agent_id, fingerprint)"); err != nil {
		return fmt.Errorf("create agent_tasks unique index: %w", err)
	}
	return s.migrateLegacyPlaintextTokens(ctx)
}

// dedupAgentTasks collapses any pre-existing duplicate (agent_id,
// fingerprint) rows in agent_tasks to one survivor per pair before
// EnsureSchema creates the unique index below — a bare CREATE UNIQUE INDEX
// would fail on any database already holding a duplicate produced by the
// submitInventory/sweepAgentRenewals race this closes (W4-05; see
// insertTaskTx's ON CONFLICT DO NOTHING for the going-forward half of the
// fix). This runs the same repair as
// internal/db/migrations/{postgres,sqlite}/000041_agent_tasks_unique, not
// instead of it: RunMigrations only applies to whatever DB OpenCoreDB opens
// (APP_CORE_DB_DSN), while NewAgentStoreFromEnv resolves its own DSN
// (APP_AUDIT_DB_DSN / KRYPTKEEPER_DATA_DIR) and calls EnsureSchema directly
// — the two collapse to the same file only when no DSN override is set.  A
// deployment pointing the agent store at a separate database needs
// EnsureSchema's own copy of this repair, or the migration's fix silently
// would not apply there.
//
// The dedup query is plain ANSI SQL (subquery + GROUP BY + MIN), not
// engine-specific self-join/rowid syntax, so it runs unchanged on both
// sqlite and postgres — GROUP BY treats NULL fingerprints as one group on
// both engines identically (unlike the unique index below, which treats
// NULLs as distinct on both), so dedup is strictly more aggressive than
// the index requires. Harmless here: matchRenewalTasks never assigns an
// empty fingerprint and insertTaskTx never writes NULL, so this only ever
// matters for pre-existing bad data, not anything the app itself writes.
func (s *dbAgentStore) dedupAgentTasks(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM agent_tasks WHERE task_id NOT IN
		(SELECT MIN(task_id) FROM agent_tasks GROUP BY agent_id, fingerprint)`)
	return err
}

// migrateLegacyPlaintextTokens hashes any row still holding a plaintext token
// (token_hash empty, token non-empty — i.e. registered before W2-09) in place
// and clears the plaintext column. This is a lazy migration: no agent
// re-enrollment is required, since the plaintext is already in hand
// server-side at migration time. After this runs, no row should carry a
// plaintext token — see agentTokenMatches for the runtime check.
func (s *dbAgentStore) migrateLegacyPlaintextTokens(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id, token FROM agents WHERE token_hash = '' AND token != ''")
	if err != nil {
		return fmt.Errorf("migrate legacy agent tokens: query: %w", err)
	}
	type legacy struct{ id, token string }
	var pending []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.id, &l.token); err != nil {
			rows.Close()
			return fmt.Errorf("migrate legacy agent tokens: scan: %w", err)
		}
		pending = append(pending, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrate legacy agent tokens: rows: %w", err)
	}

	for _, l := range pending {
		q := fmt.Sprintf("UPDATE agents SET token_hash = %s, token = '' WHERE id = %s", s.ph(1), s.ph(2))
		if _, err := s.db.ExecContext(ctx, q, hashAgentToken(l.token), l.id); err != nil {
			return fmt.Errorf("migrate legacy agent token for %s: %w", l.id, err)
		}
	}
	if len(pending) > 0 {
		log.Printf("agent store: migrated %d legacy plaintext agent token(s) to hashed storage", len(pending))
	}

	// Verify (log-only, not fatal): NewAgentStoreFromEnv falls back to the
	// fully in-memory, plaintext, non-constant-time store on any EnsureSchema
	// error — failing here on a leftover row would trade "mostly hashed, one
	// stuck row" for "every token plaintext in memory," which is worse, not
	// safer. Surface it loudly instead so an operator can investigate.
	var remaining int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE token != ''").Scan(&remaining); err != nil {
		return fmt.Errorf("verify agent token migration: %w", err)
	}
	if remaining > 0 {
		log.Printf("agent store: WARNING — %d agent row(s) still hold a plaintext token after migration; investigate", remaining)
	}
	return nil
}

// hashAgentToken derives the at-rest credential for an agent token. Agent
// tokens are generateToken(32) — 256 bits of crypto/rand entropy — so a plain
// SHA-256 digest (no per-token salt/KDF) is sufficient: brute-forcing the
// hash is exactly as hard as guessing the token itself, unlike a low-entropy
// user password.
func hashAgentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// agentTokenMatches compares a presented token against a stored hash in
// constant time. An empty storedHash (row not yet migrated, or not found)
// never matches.
func agentTokenMatches(storedHash, token string) bool {
	if storedHash == "" {
		return false
	}
	computed := hashAgentToken(token)
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(computed)) == 1
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTimeOrZero(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// authToken verifies (agentID, token) against the agents table's stored hash,
// in constant time (G-28).
func (s *dbAgentStore) authToken(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, agentID, token string) error {
	var storedHash string
	err := q.QueryRowContext(ctx, fmt.Sprintf("SELECT token_hash FROM agents WHERE id = %s", s.ph(1)), agentID).Scan(&storedHash)
	if err == sql.ErrNoRows {
		return ErrAgentUnauthorized
	}
	if err != nil {
		return err
	}
	if !agentTokenMatches(storedHash, token) {
		return ErrAgentUnauthorized
	}
	return nil
}

func (s *dbAgentStore) register(name string, agentType AgentType) (id, token string, err error) {
	id, err = generateToken(8)
	if err != nil {
		return "", "", fmt.Errorf("generate agent id: %w", err)
	}
	token, err = generateToken(32)
	if err != nil {
		return "", "", fmt.Errorf("generate agent token: %w", err)
	}
	// token is stored empty; only its hash is persisted (G-28).
	q := fmt.Sprintf(`INSERT INTO agents (id, name, type, token, token_hash, registered_at, inventory_count)
		VALUES (%s, %s, %s, '', %s, %s, 0)`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5))
	if _, err = s.db.ExecContext(context.Background(), q, id, name, string(agentType),
		hashAgentToken(token), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return "", "", fmt.Errorf("insert agent: %w", err)
	}
	return id, token, nil
}

func (s *dbAgentStore) heartbeat(agentID, token string) error {
	ctx := context.Background()
	if err := s.authToken(ctx, s.db, agentID, token); err != nil {
		return err
	}
	q := fmt.Sprintf("UPDATE agents SET last_seen = %s WHERE id = %s", s.ph(1), s.ph(2))
	if _, err := s.db.ExecContext(ctx, q, time.Now().UTC().Format(time.RFC3339), agentID); err != nil {
		return err
	}
	return nil
}

func (s *dbAgentStore) submitInventory(agentID, token string, certs []AgentDiscoveredCert, endpoints []AgentEndpoint) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.authToken(ctx, tx, agentID, token); err != nil {
		return err
	}

	// Replace inventory.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM agent_inventory WHERE agent_id = %s", s.ph(1)), agentID); err != nil {
		return err
	}
	for _, c := range certs {
		dnsNames, err := json.Marshal(c.DNSNames)
		if err != nil {
			return fmt.Errorf("marshal dns_names: %w", err)
		}
		q := fmt.Sprintf(`INSERT INTO agent_inventory
			(agent_id, fingerprint, subject, issuer, not_before, not_after, source, auto_renewable, dns_names)
			VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)`,
			s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9))
		if _, err := tx.ExecContext(ctx, q, agentID, c.Fingerprint, c.Subject, c.Issuer,
			rfc3339OrEmpty(c.NotBefore), rfc3339OrEmpty(c.NotAfter), c.Source, boolToInt(c.AutoRenewable), string(dnsNames)); err != nil {
			return err
		}
	}

	// Replace endpoints.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM agent_endpoints WHERE agent_id = %s", s.ph(1)), agentID); err != nil {
		return err
	}
	for _, e := range endpoints {
		q := fmt.Sprintf(`INSERT INTO agent_endpoints
			(agent_id, server_type, cert_path, key_path, server_name, listen_port, config_path)
			VALUES (%s, %s, %s, %s, %s, %s, %s)`,
			s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7))
		if _, err := tx.ExecContext(ctx, q, agentID, e.ServerType, e.CertPath, e.KeyPath,
			e.ServerName, e.ListenPort, e.ConfigPath); err != nil {
			return err
		}
	}

	// Assign tasks using the shared matcher over current tasks + results.
	existingTasks, err := s.tasksTx(ctx, tx, agentID)
	if err != nil {
		return err
	}
	results, err := s.resultsTx(ctx, tx, agentID)
	if err != nil {
		return err
	}
	newTasks := matchRenewalTasks(certs, endpoints, existingTasks, results, s.thresholdDays, time.Now().UTC(), newRenewalTaskID)
	for _, t := range newTasks {
		if _, err := s.insertTaskTx(ctx, tx, agentID, t); err != nil {
			return err
		}
	}

	upd := fmt.Sprintf("UPDATE agents SET inventory_count = %s, last_seen = %s WHERE id = %s",
		s.ph(1), s.ph(2), s.ph(3))
	if _, err := tx.ExecContext(ctx, upd, len(certs), time.Now().UTC().Format(time.RFC3339), agentID); err != nil {
		return err
	}
	return tx.Commit()
}

// insertTaskTx inserts a renewal task, silently skipping (rather than
// erroring) an insert that collides on (agent_id, fingerprint) with a row
// already committed by a concurrent transaction — e.g. submitInventory
// racing RenewalAgentDriver's sweepAgentRenewals for the same
// newly-eligible fingerprint, both having read "no existing task" before
// either committed (W4-05). ON CONFLICT DO NOTHING relies on the unique
// index EnsureSchema/migration 000041 create; a plain INSERT would instead
// fail the whole caller transaction on the losing side, turning a duplicate
// task into a discarded inventory push for submitInventory specifically —
// strictly worse than the bug being fixed. The returned bool reports
// whether a row was actually inserted, so callers that count newly-assigned
// tasks (sweepAgentRenewals) don't over-report a collision as a success.
func (s *dbAgentStore) insertTaskTx(ctx context.Context, tx *sql.Tx, agentID string, t AgentRenewalTask) (bool, error) {
	identifiers, err := json.Marshal(t.Identifiers)
	if err != nil {
		return false, fmt.Errorf("marshal identifiers: %w", err)
	}
	// ca_url is intentionally omitted -- see the CREATE TABLE comment above
	// (W19-26); the column stays for schema compatibility but nothing writes
	// to it any more.
	createdAt := t.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	q := fmt.Sprintf(`INSERT INTO agent_tasks
		(task_id, agent_id, fingerprint, subject, action, not_after,
		 server_type, cert_path, key_path, reload_method, verify_host_port, identifiers, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT (agent_id, fingerprint) DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12), s.ph(13))
	res, err := tx.ExecContext(ctx, q, t.TaskID, agentID, t.Fingerprint, t.Subject, t.Action,
		rfc3339OrEmpty(t.NotAfter), t.ServerType, t.CertPath, t.KeyPath, t.ReloadMethod, t.VerifyHostPort, string(identifiers), rfc3339OrEmpty(createdAt))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// rowQuerier is satisfied by *sql.DB and *sql.Tx.
type rowQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *dbAgentStore) scanTasks(rows *sql.Rows) ([]AgentRenewalTask, error) {
	defer rows.Close()
	out := []AgentRenewalTask{}
	for rows.Next() {
		var t AgentRenewalTask
		var notAfter, identifiers, createdAt string
		if err := rows.Scan(&t.TaskID, &t.Fingerprint, &t.Subject, &t.Action,
			&notAfter, &t.ServerType, &t.CertPath, &t.KeyPath, &t.ReloadMethod, &t.VerifyHostPort, &identifiers, &createdAt); err != nil {
			return nil, err
		}
		t.NotAfter = parseTimeOrZero(notAfter)
		t.CreatedAt = parseTimeOrZero(createdAt)
		// identifiers is '' on a row written before the best-effort ALTER TABLE
		// ran (default only applies to new rows on some engines) -- treat that
		// the same as an empty JSON array rather than failing the whole scan.
		if identifiers != "" {
			if err := json.Unmarshal([]byte(identifiers), &t.Identifiers); err != nil {
				return nil, fmt.Errorf("unmarshal identifiers: %w", err)
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// taskCols deliberately excludes ca_url (W19-26; see the CREATE TABLE
// comment on agent_tasks above) -- the column still exists on disk but is
// dead, so nothing here reads it back.
const taskCols = `task_id, fingerprint, subject, action, not_after,
	server_type, cert_path, key_path, reload_method, verify_host_port, identifiers, created_at`

func (s *dbAgentStore) tasksTx(ctx context.Context, q rowQuerier, agentID string) ([]AgentRenewalTask, error) {
	rows, err := q.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM agent_tasks WHERE agent_id = %s", taskCols, s.ph(1)), agentID)
	if err != nil {
		return nil, err
	}
	return s.scanTasks(rows)
}

func (s *dbAgentStore) getTasks(agentID, token string) ([]AgentRenewalTask, error) {
	ctx := context.Background()
	if err := s.authToken(ctx, s.db, agentID, token); err != nil {
		return nil, err
	}
	return s.tasksTx(ctx, s.db, agentID)
}

// tasksFor returns an agent's currently-queued tasks with no token check --
// the admin path (see AgentStore.tasksFor doc comment in handlers_agents.go).
// Swallows a query error to nil like the other admin-read helpers in this
// file (endpointsFor, resultsFor) rather than propagating it: the read-only
// admin surface degrades to "nothing to show" instead of a 500 on a
// transient DB hiccup.
func (s *dbAgentStore) tasksFor(agentID string) []AgentRenewalTask {
	out, err := s.tasksTx(context.Background(), s.db, agentID)
	if err != nil {
		return nil
	}
	return out
}

func (s *dbAgentStore) submitRenewalResult(agentID, token string, result AgentRenewalResult) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.authToken(ctx, tx, agentID, token); err != nil {
		return err
	}

	id, err := generateToken(12)
	if err != nil {
		return err
	}
	reportedAt := result.ReportedAt
	if reportedAt == "" {
		reportedAt = time.Now().UTC().Format(time.RFC3339)
	}
	ins := fmt.Sprintf(`INSERT INTO agent_results
		(id, agent_id, task_id, fingerprint, outcome, served_fingerprint, rolled_back, detail, reported_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9))
	if _, err := tx.ExecContext(ctx, ins, "res-"+id, agentID, result.TaskID, result.Fingerprint,
		result.Outcome, result.ServedFingerprint, boolToInt(result.RolledBack), result.Detail, reportedAt); err != nil {
		return err
	}

	// Clear the completed task (by task_id, else by fingerprint).
	if result.TaskID != "" {
		_, err = tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM agent_tasks WHERE agent_id = %s AND task_id = %s", s.ph(1), s.ph(2)), agentID, result.TaskID)
	} else if result.Fingerprint != "" {
		_, err = tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM agent_tasks WHERE agent_id = %s AND fingerprint = %s", s.ph(1), s.ph(2)), agentID, result.Fingerprint)
	}
	if err != nil {
		return err
	}

	// Trim history to the most recent maxAgentResults.
	trim := fmt.Sprintf(`DELETE FROM agent_results WHERE agent_id = %s AND id NOT IN
		(SELECT id FROM agent_results WHERE agent_id = %s ORDER BY reported_at DESC LIMIT %d)`,
		s.ph(1), s.ph(2), maxAgentResults)
	if _, err := tx.ExecContext(ctx, trim, agentID, agentID); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE agents SET last_seen = %s WHERE id = %s", s.ph(1), s.ph(2)),
		time.Now().UTC().Format(time.RFC3339), agentID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *dbAgentStore) endpointsFor(agentID string) []AgentEndpoint {
	rows, err := s.db.QueryContext(context.Background(),
		fmt.Sprintf("SELECT server_type, cert_path, key_path, server_name, listen_port, config_path FROM agent_endpoints WHERE agent_id = %s", s.ph(1)), agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []AgentEndpoint{}
	for rows.Next() {
		var e AgentEndpoint
		if err := rows.Scan(&e.ServerType, &e.CertPath, &e.KeyPath, &e.ServerName, &e.ListenPort, &e.ConfigPath); err != nil {
			return out
		}
		out = append(out, e)
	}
	return out
}

func (s *dbAgentStore) resultsTx(ctx context.Context, q rowQuerier, agentID string) ([]AgentRenewalResult, error) {
	rows, err := q.QueryContext(ctx,
		fmt.Sprintf("SELECT task_id, fingerprint, outcome, served_fingerprint, rolled_back, detail, reported_at FROM agent_results WHERE agent_id = %s ORDER BY reported_at ASC", s.ph(1)), agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentRenewalResult{}
	for rows.Next() {
		var r AgentRenewalResult
		var rolled int
		if err := rows.Scan(&r.TaskID, &r.Fingerprint, &r.Outcome, &r.ServedFingerprint, &rolled, &r.Detail, &r.ReportedAt); err != nil {
			return nil, err
		}
		r.RolledBack = rolled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *dbAgentStore) resultsFor(agentID string) []AgentRenewalResult {
	out, err := s.resultsTx(context.Background(), s.db, agentID)
	if err != nil {
		return nil
	}
	return out
}

func (s *dbAgentStore) allResults() []AgentResultEntry {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT agent_id, task_id, fingerprint, outcome, served_fingerprint, rolled_back, detail, reported_at FROM agent_results")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []AgentResultEntry
	for rows.Next() {
		var e AgentResultEntry
		var rolled int
		if err := rows.Scan(&e.AgentID, &e.Result.TaskID, &e.Result.Fingerprint, &e.Result.Outcome,
			&e.Result.ServedFingerprint, &rolled, &e.Result.Detail, &e.Result.ReportedAt); err != nil {
			return out
		}
		e.Result.RolledBack = rolled != 0
		out = append(out, e)
	}
	return out
}

// endpointCount distinguishes a failed query from a genuine zero (S-63):
// a broken agent DB used to report "0 endpoints managed" on the SLO
// dashboard, indistinguishable from an empty fleet.
func (s *dbAgentStore) endpointCount() (int, error) {
	var n int
	if err := s.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM agent_endpoints").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *dbAgentStore) agentCounts() (total, active int) {
	rows, err := s.db.QueryContext(context.Background(), "SELECT last_seen FROM agents")
	if err != nil {
		return 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var ls sql.NullString
		if err := rows.Scan(&ls); err != nil {
			return total, active
		}
		total++
		if ls.Valid {
			t := parseTimeOrZero(ls.String)
			if !t.IsZero() && computeAgentStatus(&t) == AgentStatusActive {
				active++
			}
		}
	}
	return total, active
}

func (s *dbAgentStore) list() []AgentInfo {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT id, name, type, registered_at, last_seen, inventory_count FROM agents")
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []AgentInfo{}
	for rows.Next() {
		var info AgentInfo
		var registeredAt string
		var lastSeen sql.NullString
		var typ string
		if err := rows.Scan(&info.ID, &info.Name, &typ, &registeredAt, &lastSeen, &info.InventoryCount); err != nil {
			return out
		}
		info.Type = AgentType(typ)
		info.RegisteredAt = parseTimeOrZero(registeredAt)
		if lastSeen.Valid && lastSeen.String != "" {
			t := parseTimeOrZero(lastSeen.String)
			info.LastSeen = &t
		}
		info.Status = computeAgentStatus(info.LastSeen)
		out = append(out, info)
	}
	return out
}

// fallbackAgentStore is the ONE in-memory agent store the whole process shares
// when no database is configured.
//
// NewAgentStoreFromEnv has more than one caller — handlers.go builds one for
// the HTTP handlers, and cmd/kryptkeeper/main.go builds one for the scheduled
// renewal driver (S-35). With a DSN configured that is harmless: both resolve
// the same DSN and therefore the same database. Without one, each call used to
// return a SEPARATE in-memory map, so the driver swept a store the handlers
// never wrote to and could never assign a task — a silent no-op that looks
// exactly like "no certs are due".
//
// Deliberately scoped to the fallback only. The DB path stays un-memoized, so
// this introduces no process-global database handle and no cross-test coupling
// for the configured case; it shares only the store that is already
// process-local by nature. Tests construct NewAgentStore() directly and are
// unaffected — nothing in the tree calls NewAgentStoreFromEnv except the two
// production sites above.
// fallbackAgentStoreOnce is a *sync.Once (not a value) so tests can swap it
// out for a fresh one via t.Cleanup — reassigning the pointer copies no lock,
// while the production path never reassigns it, so the process still gets
// exactly one Once for its whole lifetime.
var (
	fallbackAgentStoreOnce = new(sync.Once)
	fallbackAgentStore     AgentStore
)

func sharedFallbackAgentStore() AgentStore {
	fallbackAgentStoreOnce.Do(func() { fallbackAgentStore = NewAgentStore() })
	return fallbackAgentStore
}

// NewAgentStoreFromEnv returns a DB-backed agent store when a DB is configured,
// falling back to a process-shared in-memory store if the DB is unavailable
// (mirrors the other providers). The DB store self-ensures its schema.
func NewAgentStoreFromEnv() AgentStore {
	state := newDBProviderState[*dbAgentStore](
		"agent-store",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbAgentStore {
			return &dbAgentStore{db: db, ph: sqlitePlaceholder, thresholdDays: renewalThresholdDaysFromEnv()}
		},
		func(db *sql.DB) *dbAgentStore {
			return &dbAgentStore{db: db, ph: postgresPlaceholder, thresholdDays: renewalThresholdDaysFromEnv()}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("agent-store", state.openErr) // logs the outage itself; return value is the same sentinel
		return sharedFallbackAgentStore()
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("agent-store", err) // logs the outage itself; return value is the same sentinel
		return sharedFallbackAgentStore()
	}
	return state.store
}
