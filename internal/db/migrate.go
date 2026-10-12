// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package db is Kryptkeeper's versioned SQL migration runner (W10-01/G-33).
//
// The 26 numbered files under migrations/{postgres,sqlite}/ existed but were
// never executed by any code path — per-store EnsureSchema() methods only
// ever issue idempotent CREATE TABLE IF NOT EXISTS, so every ALTER TABLE
// migration (adding a column to an existing table) has never actually run
// against a real deployment. RunMigrations makes them live: applied in
// order, each tracked in a schema_migrations version table, each in its own
// transaction so a failure never leaves a half-applied migration.
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/postgres/*.sql migrations/sqlite/*.sql
var migrationsFS embed.FS

var versionPrefixRe = regexp.MustCompile(`^(\d{6})_`)

type migrationFile struct {
	version int
	name    string
	upSQL   string
	downSQL string
}

const createSchemaMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`

// RunMigrations applies every embedded migration for engine ("postgres" or
// "sqlite") that isn't yet recorded in schema_migrations, in ascending
// version order. Each migration runs in its own transaction: the migration's
// own SQL and its schema_migrations bookkeeping row commit or roll back
// together. Safe to call on every boot — a fully up-to-date DB is a no-op.
func RunMigrations(db *sql.DB, engine string) error {
	if engine != "postgres" && engine != "sqlite" {
		return fmt.Errorf("unsupported migration engine %q (expected postgres or sqlite)", engine)
	}

	if _, err := db.Exec(createSchemaMigrationsTable); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	repairPreExistingNarrowDiscoverySchema(db, engine)

	migrations, err := loadMigrations(engine)
	if err != nil {
		return err
	}

	applied, err := appliedVersions(db)
	if err != nil {
		return err
	}

	warnIfCISeedDataPresent(db, engine, applied)

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		// S-42: the seed migration's own header says "deterministic seed data
		// for CI/test", but it sat ungated in the main sequence, so every
		// install got a fake root CA, a fake certificate, two active
		// privileged users and an API key. Those rows reached production
		// inventory counts and compliance reports.
		//
		// Skipped by default and left unrecorded, so enabling the flag later
		// still applies it. Nothing downstream references the seeded rows, and
		// the runner keys off a version set rather than a contiguous sequence,
		// so leaving 7 unapplied is safe.
		if isCISeedMigration(m) && !ciSeedDataEnabled() {
			log.Printf("migration %s skipped: CI seed data is off by default; set %s=true to apply it",
				migrationLabel(m), ciSeedEnvVar)
			continue
		}
		if m.upSQL == "" {
			return fmt.Errorf("migration %s has no .up.sql file for engine %q", migrationLabel(m), engine)
		}
		apply := applyUp
		if migrationUsesTolerantApply(m) {
			apply = applyUpTolerant
		}
		if err := apply(db, engine, m); err != nil {
			return fmt.Errorf("apply migration %s: %w", migrationLabel(m), err)
		}
	}
	return nil
}

// RollbackMigration applies down.sql for every applied migration with a
// version greater than toVersion, in descending order, removing each from
// schema_migrations as it rolls back. toVersion itself is left applied.
func RollbackMigration(db *sql.DB, engine string, toVersion int) error {
	if engine != "postgres" && engine != "sqlite" {
		return fmt.Errorf("unsupported migration engine %q (expected postgres or sqlite)", engine)
	}

	migrations, err := loadMigrations(engine)
	if err != nil {
		return err
	}
	byVersion := make(map[int]migrationFile, len(migrations))
	for _, m := range migrations {
		byVersion[m.version] = m
	}

	applied, err := appliedVersions(db)
	if err != nil {
		return err
	}

	var toRollback []int
	for v := range applied {
		if v > toVersion {
			toRollback = append(toRollback, v)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(toRollback)))

	for _, v := range toRollback {
		m, ok := byVersion[v]
		if !ok {
			return fmt.Errorf("rollback: migration version %d is applied but no longer embedded", v)
		}
		if m.downSQL == "" {
			return fmt.Errorf("rollback: migration %s has no .down.sql file for engine %q", migrationLabel(m), engine)
		}
		if err := applyDown(db, engine, m); err != nil {
			return fmt.Errorf("rollback migration %s: %w", migrationLabel(m), err)
		}
	}
	return nil
}

func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan schema_migrations version: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return applied, nil
}

func applyUp(db *sql.DB, engine string, m migrationFile) error {
	parts := splitMigrationSQL(m.upSQL)

	if parts.pre != "" {
		// e.g. PRAGMA foreign_keys=OFF — SQLite treats this as a no-op
		// inside an active transaction (confirmed empirically before
		// writing this), so it must run in autocommit mode, before the
		// runner's own Tx begins.
		if _, err := db.Exec(parts.pre); err != nil {
			return fmt.Errorf("pre-transaction statements: %w", err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds

	if _, err := tx.Exec(parts.tx); err != nil {
		return err
	}

	insert := "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)"
	if engine == "postgres" {
		insert = "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)"
	}
	if _, err := tx.Exec(insert, m.version, m.name, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if parts.post != "" {
		if _, err := db.Exec(parts.post); err != nil {
			return fmt.Errorf("post-transaction statements (migration already committed): %w", err)
		}
	}
	return nil
}

// migrationsTolerateAlreadySatisfied are migration versions whose ADD COLUMN
// (and, for 000021, its accompanying CREATE INDEX) statements may already be
// satisfied by a pre-existing full-shape audit_log schema (G-81/S-19): a data
// directory that ran APP_AUDIT_PROVIDER=db before RunMigrations ever executed
// gets its audit_log table created full-shape by S-07's EnsureSchema
// (source_ip/user_agent/session_id/change_summary/tenant all present from
// creation), so 000011/000021's own blind ALTER TABLE ADD COLUMN
// duplicate-fails the moment migrations finally run — the opposite direction
// from G-77/S-14 (a table missing columns migrations expect), which
// column-repair cannot fix. Deliberately a narrow, named set rather than a
// blanket "ignore all migration errors" — every OTHER migration keeps failing
// on any error exactly as before.
//
// isAlreadySatisfiedDDLError's broad "already exists" match is only safe
// because every migration in this set is ADD COLUMN/CREATE INDEX statements
// exclusively — "already exists" can only mean the tolerated case there. If a
// future migration is added to this set, re-verify its statements are
// equally unambiguous before relying on the same substring check.
// 000053 (endpoint server_tech/recommended_install_mode) is the discovery
// analogue of the audit case above: EnsureSchema best-effort-adds these two
// columns for a discovery-only data directory, so in the EnsureSchema-then-
// migrations ordering 000053's ADD COLUMN duplicate-fails. Both statements
// are ADD COLUMN exclusively, so the same tolerance is safe.
//
// 000020 (pending_actions.tenant) is the same shape: the pending-action
// store's EnsureSchema creates pending_actions WITH tenant, so a data
// directory first used with a non-ca provider and later switched to ca
// duplicate-failed here (UPGRADE_TEST_v0.9 finding 1). Its other statements
// are CREATE ... IF NOT EXISTS, so the tolerance is equally unambiguous.
var migrationsTolerateAlreadySatisfied = map[int]bool{
	59: true, 11: true, 20: true, 21: true, 23: true, 24: true, 32: true, 47: true, 53: true, 55: true, 56: true, 57: true,
}

// isAlreadySatisfiedDDLError reports whether err is a duplicate-column or
// duplicate-index error, confirmed empirically against both engines:
// sqlite (mattn/go-sqlite3) reports "duplicate column name: X" and
// "index X already exists"; Postgres reports "column \"X\" of relation \"Y\"
// already exists" and "relation \"X\" already exists" (both SQLSTATE
// 42701/42P07, verified with a disposable postgres:16-alpine container).
// Any other error is treated as genuine and still fails the migration.
func isAlreadySatisfiedDDLError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate column name") || strings.Contains(msg, "already exists")
}

// splitSQLStatements splits a simple migration body (no embedded semicolons
// in string literals or comments — true of every migration in
// migrationsTolerateAlreadySatisfied today) into individual statements, each
// re-terminated with ";" for the driver.
func splitSQLStatements(sqlText string) []string {
	// Whole-line "--" comments are dropped first: a ';' inside a header comment
	// (000057 has one) would otherwise split a comment into a bogus statement.
	var body strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	raw := strings.Split(body.String(), ";")
	var out []string
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s+";")
	}
	return out
}

// additiveStatementRe matches the only statement shapes that are safe to
// run "tolerantly": each either adds something that a store's first-use
// self-heal may already have created (ADD COLUMN, CREATE TABLE/INDEX IF NOT
// EXISTS), so an "already exists"/"duplicate column" error can only mean the
// desired state is already in place. Anything else (DROP, RENAME, ALTER
// COLUMN, INSERT, UPDATE, triggers, plain CREATE TABLE ...) does not match.
var additiveStatementRe = regexp.MustCompile(
	`(?is)^\s*(?:alter\s+table\s+(?:if\s+exists\s+)?\S+\s+add\s+column\b|` +
		`create\s+table\s+if\s+not\s+exists\b|` +
		`create\s+(?:unique\s+)?index\s+if\s+not\s+exists\b)`)

// destructiveClauseRe rejects an ALTER TABLE that starts with ADD COLUMN but
// also carries a non-additive clause (ALTER TABLE t ADD COLUMN a.., DROP COLUMN b).
var destructiveClauseRe = regexp.MustCompile(`(?is)\b(drop|rename|alter\s+column|add\s+constraint)\b`)

// migrationIsAllAdditive reports whether every statement of m's up SQL is an
// additive, idempotent-in-effect DDL statement (see additiveStatementRe) and
// the migration needs no pre/post-transaction handling. Such a migration can
// never be meaningfully broken by a store having self-healed the same
// column/table/index first, so the runner applies it tolerantly. This makes
// the "non-ca provider first, then ca" collision class (000020, 000070,
// 000071, ...) impossible for any future ADD COLUMN migration without anyone
// having to remember to extend migrationsTolerateAlreadySatisfied.
func migrationIsAllAdditive(m migrationFile) bool {
	parts := splitMigrationSQL(m.upSQL)
	if parts.pre != "" || parts.post != "" {
		return false
	}
	stmts := splitSQLStatements(parts.tx)
	if len(stmts) == 0 {
		return false
	}
	for _, stmt := range stmts {
		if !additiveStatementRe.MatchString(stmt) || destructiveClauseRe.MatchString(stmt) {
			return false
		}
	}
	return true
}

// migrationUsesTolerantApply is true for the explicit legacy list and for any
// all-additive migration.
func migrationUsesTolerantApply(m migrationFile) bool {
	return migrationsTolerateAlreadySatisfied[m.version] || migrationIsAllAdditive(m)
}

// applyUpTolerant applies a migration in migrationsTolerateAlreadySatisfied
// statement-by-statement in autocommit mode (not the runner's normal
// single-Tx-per-migration path used by applyUp), tolerating a
// duplicate-column/duplicate-index error on any individual statement.
// Autocommit-per-statement is required, not just convenient: Postgres aborts
// an ENTIRE transaction on its first error ("current transaction is aborted,
// commands ignored until end of transaction block"), so tolerating one
// statement's error while still running the rest of the SAME transaction is
// only possible without a shared Tx (or with per-statement SAVEPOINTs, which
// this avoids for simplicity given the narrow, known-simple migration
// bodies this applies to). Any error that is NOT a duplicate-column/index
// error still fails the migration immediately, exactly as applyUp would.
func applyUpTolerant(db *sql.DB, engine string, m migrationFile) error {
	parts := splitMigrationSQL(m.upSQL)

	if parts.pre != "" {
		if _, err := db.Exec(parts.pre); err != nil {
			return fmt.Errorf("pre-transaction statements: %w", err)
		}
	}

	for _, stmt := range splitSQLStatements(parts.tx) {
		if _, err := db.Exec(stmt); err != nil {
			if !isAlreadySatisfiedDDLError(err) {
				return fmt.Errorf("statement %q: %w", stmt, err)
			}
			log.Printf("migration %s: statement already satisfied, skipping (%v): %s",
				migrationLabel(m), err, stmt)
		}
	}

	insert := "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)"
	if engine == "postgres" {
		insert = "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)"
	}
	if _, err := db.Exec(insert, m.version, m.name, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}

	if parts.post != "" {
		if _, err := db.Exec(parts.post); err != nil {
			return fmt.Errorf("post-transaction statements (migration already committed): %w", err)
		}
	}
	return nil
}

func applyDown(db *sql.DB, engine string, m migrationFile) error {
	parts := splitMigrationSQL(m.downSQL)

	if parts.pre != "" {
		if _, err := db.Exec(parts.pre); err != nil {
			return fmt.Errorf("pre-transaction statements: %w", err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(parts.tx); err != nil {
		return err
	}

	del := "DELETE FROM schema_migrations WHERE version = ?"
	if engine == "postgres" {
		del = "DELETE FROM schema_migrations WHERE version = $1"
	}
	if _, err := tx.Exec(del, m.version); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if parts.post != "" {
		if _, err := db.Exec(parts.post); err != nil {
			return fmt.Errorf("post-transaction statements (rollback already committed): %w", err)
		}
	}
	return nil
}

type migrationSQLParts struct {
	pre  string // executed in autocommit mode, before the runner's Tx begins
	tx   string // executed inside the runner's own Tx
	post string // executed in autocommit mode, after the runner's Tx commits
}

// splitMigrationSQL separates a migration file into up to three pieces
// around its own "BEGIN;"/"COMMIT;" markers (if present), so applyUp/
// applyDown can run each piece with the correct transactional scope instead
// of blindly wrapping the whole file in one Go-level *sql.Tx:
//
//   - Migration files are inconsistent about self-wrapping in a transaction
//     (some do, some rely on the runner) — a literal BEGIN executed inside
//     an already-open Tx fails ("cannot start a transaction within a
//     transaction", confirmed empirically against mattn/go-sqlite3), so any
//     embedded BEGIN;/COMMIT; markers are stripped from the piece that runs
//     inside the runner's Tx.
//   - At least one real migration (000025_principal_tenant, SQLite's FK-
//     rebuild-dance workaround) needs a PRAGMA statement OUTSIDE any
//     transaction — SQLite defines PRAGMA foreign_keys as a no-op while a
//     transaction is open (confirmed empirically: the value silently stays
//     unchanged), so a leading/trailing PRAGMA is run in autocommit mode
//     before the Tx begins / after it commits, exactly reproducing what
//     running the raw .sql file through a real sqlite3 client would do.
func splitMigrationSQL(sqlText string) migrationSQLParts {
	lines := strings.Split(sqlText, "\n")

	isBlankOrComment := func(line string) bool {
		t := strings.TrimSpace(line)
		return t == "" || strings.HasPrefix(t, "--")
	}
	hasRealContent := func(lines []string) bool {
		for _, l := range lines {
			if !isBlankOrComment(l) {
				return true
			}
		}
		return false
	}

	beginIdx, endIdx := -1, -1
	for i, l := range lines {
		if strings.EqualFold(strings.TrimSpace(l), "BEGIN;") {
			beginIdx = i
			break
		}
	}
	if beginIdx >= 0 {
		for i := len(lines) - 1; i > beginIdx; i-- {
			if strings.EqualFold(strings.TrimSpace(lines[i]), "COMMIT;") {
				endIdx = i
				break
			}
		}
	}

	if beginIdx < 0 || endIdx < 0 {
		// No self-wrapping found — the whole file runs inside the runner's Tx.
		return migrationSQLParts{tx: strings.TrimSpace(sqlText)}
	}

	pre := strings.Join(lines[:beginIdx], "\n")
	body := strings.Join(lines[beginIdx+1:endIdx], "\n")
	post := strings.Join(lines[endIdx+1:], "\n")

	parts := migrationSQLParts{tx: strings.TrimSpace(body)}
	if hasRealContent(lines[:beginIdx]) {
		parts.pre = strings.TrimSpace(pre)
	}
	if hasRealContent(lines[endIdx+1:]) {
		parts.post = strings.TrimSpace(post)
	}
	return parts
}

func migrationLabel(m migrationFile) string {
	return fmt.Sprintf("%06d_%s", m.version, m.name)
}

// S-42. Migration 000007 seeds "deterministic seed data for CI/test" — its own
// words — and was an ungated member of the main sequence, so it ran on every
// install. It creates a root CA, a certificate, a team, two ACTIVE privileged
// users (one pki-admin) and an API key, all on fixed 00000000-…-0000000001xx
// identifiers. Those rows are counted by the report endpoints, which is how
// crypto-posture and expiry-timeline came to claim 4 certificates while the
// inventory listed 3.
const (
	ciSeedEnvVar         = "KRYPTKEEPER_SEED_CI_DATA"
	ciSeedMigrationName  = "seed_baseline_data"
	ciSeedVersion        = 7
	ciSeedRemovalCommand = "kryptkeeper --remove-ci-seed"
)

// The fixed identifiers migration 000007 inserts. Kept in one place so the
// warning, the removal path and the tests cannot drift from each other.
var ciSeedUserIDs = []string{
	"00000000-0000-0000-0000-000000000103",
	"00000000-0000-0000-0000-000000000104",
}

func ciSeedDataEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ciSeedEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isCISeedMigration(m migrationFile) bool {
	return m.name == ciSeedMigrationName
}

// warnIfCISeedDataPresent covers the installs that already applied 000007
// before it was gated. Removing a CA and a certificate from a live database is
// destructive and not something a boot should decide to do on an operator's
// behalf, so this only tells the truth loudly and points at the deliberate
// removal path.
func warnIfCISeedDataPresent(db *sql.DB, engine string, applied map[int]bool) {
	if !applied[ciSeedVersion] || ciSeedDataEnabled() {
		return
	}
	var n int
	// users is the row that matters most: these two accounts are active and
	// privileged, and until S-40 the admin console could not even list them.
	q := `SELECT COUNT(*) FROM users WHERE id IN (?, ?)`
	if engine == "postgres" {
		q = `SELECT COUNT(*) FROM users WHERE id IN ($1, $2)`
	}
	if err := db.QueryRow(q, ciSeedUserIDs[0], ciSeedUserIDs[1]).Scan(&n); err != nil || n == 0 {
		return
	}
	log.Printf("WARNING: this database contains CI seed data from migration %06d_%s "+
		"(%d seeded user account(s), plus a seeded root CA, certificate and API key). "+
		"It inflates certificate counts and compliance reports. Remove it with: %s",
		ciSeedVersion, ciSeedMigrationName, n, ciSeedRemovalCommand)
}

// repairPreExistingNarrowDiscoverySchema closes G-77's discovery-table half
// (S-14): a data directory that ran discovery scanning or DB-mode audit
// before the core DB / migrations ever ran (APP_CERTIFICATE_PROVIDER unset
// or not "ca") has certificates/scan_jobs/endpoints created by bootstrap's
// own narrower inline dbDiscoveryStore.EnsureSchema, not by migrations
// 000002/000003. When migrations finally run on that same data directory,
// their own CREATE TABLE IF NOT EXISTS for these tables silently no-ops
// against the pre-existing narrower shape, so a later statement in the same
// migration that references a migration-only column (starting with
// migration 000002's own index on certificates.serial_number) fails with
// "no such column". Adding each missing column here, before migrations run,
// makes those later statements succeed against the now-widened table.
//
// Every statement is best-effort: on every real boot that has ever called
// OpenCoreDB before discovery/audit (i.e. every boot where migrations
// created these tables first), every column here already exists and the
// ALTER simply errors "duplicate column name", which is ignored — the
// same convention as ensureAuditTenantColumn/ensureWaveStatusColumn.
//
// certificate_endpoints is not repaired here: its bootstrap-inline shape
// already matches migration 000003's column-for-column.
//
// audit_log has the OPPOSITE-direction collision (bootstrap's inline
// schema is already full-shape post-S-07, so a later migration's own blind
// ALTER TABLE ADD COLUMN fails with "duplicate column" instead of "no such
// column") and is deliberately NOT covered here — column-repair cannot fix
// that direction; see migrationsTolerateAlreadySatisfied/applyUpTolerant
// (G-81/S-19) instead.
func repairPreExistingNarrowDiscoverySchema(db *sql.DB, engine string) {
	var stmts []string
	switch engine {
	case "sqlite":
		stmts = sqliteNarrowDiscoverySchemaRepairs
	case "postgres":
		stmts = postgresNarrowDiscoverySchemaRepairs
	default:
		return
	}
	for _, stmt := range stmts {
		_, _ = db.Exec(stmt) // best-effort upgrade: duplicate-column error = already migrated
	}
}

// sqliteNarrowDiscoverySchemaRepairs adds every column
// migrations/sqlite/000002_templates_ca_certs_core.up.sql,
// 000003_discovery_endpoints.up.sql, and 000012_certificate_ownership.up.sql
// define for certificates/scan_jobs/endpoints, that bootstrap's own
// sqliteDiscoverySchema (discovery_db_provider.go) does not. CHECK
// constraints and foreign keys are intentionally omitted — ALTER TABLE ADD
// COLUMN cannot express the multi-column ones, and the goal here is making
// later migration statements resolve the columns they reference, not
// reproducing every constraint by hand.
var sqliteNarrowDiscoverySchemaRepairs = []string{
	"ALTER TABLE certificates ADD COLUMN serial_number TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN subject_dn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN common_name TEXT",
	"ALTER TABLE certificates ADD COLUMN subject_alt_names TEXT",
	"ALTER TABLE certificates ADD COLUMN issuer_dn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN issuer_cn TEXT",
	"ALTER TABLE certificates ADD COLUMN ca_id TEXT",
	"ALTER TABLE certificates ADD COLUMN template_id TEXT",
	"ALTER TABLE certificates ADD COLUMN team_id TEXT",
	"ALTER TABLE certificates ADD COLUMN valid_from TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN valid_until TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN public_key_algorithm TEXT NOT NULL DEFAULT 'RSA'",
	"ALTER TABLE certificates ADD COLUMN key_size_bits INTEGER",
	"ALTER TABLE certificates ADD COLUMN signature_algorithm TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN extended_key_usage TEXT",
	"ALTER TABLE certificates ADD COLUMN key_usage TEXT",
	"ALTER TABLE certificates ADD COLUMN chain_complete INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE certificates ADD COLUMN chain_trusted INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE certificates ADD COLUMN pqc_vulnerable INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE certificates ADD COLUMN risk_flags TEXT NOT NULL DEFAULT '[]'",
	"ALTER TABLE certificates ADD COLUMN grade TEXT NOT NULL DEFAULT 'A'",
	"ALTER TABLE certificates ADD COLUMN renewal_method TEXT",
	"ALTER TABLE certificates ADD COLUMN renewal_status TEXT DEFAULT 'active'",
	"ALTER TABLE certificates ADD COLUMN predecessor_fingerprint TEXT",
	"ALTER TABLE certificates ADD COLUMN successor_fingerprint TEXT",
	"ALTER TABLE certificates ADD COLUMN revoked_at TEXT",
	"ALTER TABLE certificates ADD COLUMN revocation_reason INTEGER",
	"ALTER TABLE certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'discovery_network'",
	"ALTER TABLE certificates ADD COLUMN raw_cert_b64 TEXT",
	"ALTER TABLE certificates ADD COLUMN created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
	"ALTER TABLE certificates ADD COLUMN updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
	// owner_email/owner_team/service_name/labels are deliberately NOT
	// repaired here: migration 000012_certificate_ownership is a real,
	// not-yet-applied migration that adds them itself via a bare (non-
	// idempotent, on sqlite) ALTER TABLE ADD COLUMN -- pre-adding them here
	// would make 000012 fail with "duplicate column name" instead.

	"ALTER TABLE scan_jobs ADD COLUMN results_summary TEXT",
	"ALTER TABLE scan_jobs ADD COLUMN created_by TEXT",
	"ALTER TABLE scan_jobs ADD COLUMN started_at TEXT",
	"ALTER TABLE scan_jobs ADD COLUMN completed_at TEXT",

	"ALTER TABLE endpoints ADD COLUMN tls_versions TEXT",
	"ALTER TABLE endpoints ADD COLUMN cipher_suites TEXT",
	"ALTER TABLE endpoints ADD COLUMN is_default_cert INTEGER NOT NULL DEFAULT 1",
	"ALTER TABLE endpoints ADD COLUMN last_scan_job_id TEXT",
	"ALTER TABLE endpoints ADD COLUMN tags TEXT",
}

// postgresNarrowDiscoverySchemaRepairs is the same repair for Postgres,
// matching migrations/postgres/000002_templates_ca_certs_core.up.sql,
// 000003_discovery_endpoints.up.sql, and
// 000012_certificate_ownership.up.sql. ca_id/template_id/team_id are UUID
// (matching the migration-owned column type) rather than TEXT, since
// Postgres enforces column types strictly on later joins/FK additions in
// ways sqlite's dynamic typing does not.
var postgresNarrowDiscoverySchemaRepairs = []string{
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS serial_number VARCHAR(128) NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS subject_dn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS common_name VARCHAR(255)",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS subject_alt_names TEXT[]",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS issuer_dn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS issuer_cn VARCHAR(255)",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS ca_id UUID",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS template_id UUID",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS team_id UUID",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW()",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ NOT NULL DEFAULT NOW()",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS public_key_algorithm VARCHAR(20) NOT NULL DEFAULT 'RSA'",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS key_size_bits INTEGER",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS signature_algorithm VARCHAR(50) NOT NULL DEFAULT ''",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS extended_key_usage TEXT[]",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS key_usage TEXT[]",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS chain_complete BOOLEAN NOT NULL DEFAULT FALSE",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS chain_trusted BOOLEAN NOT NULL DEFAULT FALSE",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS pqc_vulnerable BOOLEAN NOT NULL DEFAULT FALSE",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS risk_flags TEXT[] NOT NULL DEFAULT '{}'",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS grade VARCHAR(1) NOT NULL DEFAULT 'A'",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS renewal_method VARCHAR(20)",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS renewal_status VARCHAR(20) DEFAULT 'active'",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS predecessor_fingerprint VARCHAR(64)",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS successor_fingerprint VARCHAR(64)",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS revocation_reason SMALLINT",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS source VARCHAR(30) NOT NULL DEFAULT 'discovery_network'",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS raw_cert_b64 TEXT",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
	"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
	// owner_email/owner_team/service_name/labels: left to migration
	// 000012_certificate_ownership, same reasoning as the sqlite list above
	// (that migration's own ADD COLUMN IF NOT EXISTS is idempotent on
	// Postgres already, but its labels column type (JSONB) belongs to that
	// migration, not duplicated here).

	"ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS results_summary JSONB",
	"ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS created_by UUID",
	"ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ",
	"ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ",

	"ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS tls_versions TEXT[]",
	"ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS cipher_suites TEXT[]",
	"ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS is_default_cert BOOLEAN NOT NULL DEFAULT TRUE",
	"ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_scan_job_id UUID",
	"ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS tags TEXT[]",
}

// loadMigrations reads and pairs every {version}_{name}.{up,down}.sql file
// embedded for engine, sorted ascending by version.
func loadMigrations(engine string) ([]migrationFile, error) {
	dir := "migrations/" + engine
	entries, err := fs.ReadDir(migrationsFS, dir)
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations dir %q: %w", dir, err)
	}

	byVersion := map[int]*migrationFile{}
	for _, e := range entries {
		name := e.Name()
		match := versionPrefixRe.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		version, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, fmt.Errorf("parse migration version from %q: %w", name, err)
		}

		content, err := migrationsFS.ReadFile(dir + "/" + name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}

		mf, ok := byVersion[version]
		if !ok {
			base := strings.TrimPrefix(name, match[1]+"_")
			base = strings.TrimSuffix(base, ".up.sql")
			base = strings.TrimSuffix(base, ".down.sql")
			mf = &migrationFile{version: version, name: base}
			byVersion[version] = mf
		}
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			mf.upSQL = string(content)
		case strings.HasSuffix(name, ".down.sql"):
			mf.downSQL = string(content)
		}
	}

	out := make([]migrationFile, 0, len(byVersion))
	for _, mf := range byVersion {
		out = append(out, *mf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
