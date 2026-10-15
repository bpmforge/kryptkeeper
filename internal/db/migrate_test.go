// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func freshSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "migrate_test.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("enable foreign_keys: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info row: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// fkColumnExists reports whether table has a FOREIGN KEY constraint on
// column, via SQLite's PRAGMA foreign_key_list (not table_info -- FKs are a
// separate pragma from columns).
func fkColumnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA foreign_key_list(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA foreign_key_list(%s): %v", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, seq int
		var tbl, from, to string
		var onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &tbl, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan foreign_key_list row: %v", err)
		}
		if from == column {
			return true
		}
	}
	return false
}

// tableColumnNames returns table's column names via PRAGMA table_info, in
// column order.
func tableColumnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info row: %v", err)
		}
		cols = append(cols, name)
	}
	return cols
}

// assertSameColumnSet fails the test if before and after (column name lists
// from tableColumnNames) don't contain exactly the same set of columns --
// guards a table-rebuild migration (SQLite's only way to drop a constraint)
// against silently dropping a column that isn't in the rebuild's own
// column list, which a plain "the FK is gone" assertion would never catch.
func assertSameColumnSet(t *testing.T, label string, before, after []string) {
	t.Helper()
	beforeSet := make(map[string]bool, len(before))
	for _, c := range before {
		beforeSet[c] = true
	}
	afterSet := make(map[string]bool, len(after))
	for _, c := range after {
		afterSet[c] = true
	}
	for c := range beforeSet {
		if !afterSet[c] {
			t.Errorf("%s: column %q present before, missing after -- the rebuild dropped it", label, c)
		}
	}
	for c := range afterSet {
		if !beforeSet[c] {
			t.Errorf("%s: column %q present after, missing before -- unexpected new column", label, c)
		}
	}
}

func TestRunMigrations_AppliesAllVersionsAndALTERs(t *testing.T) {
	// This test's subject is the runner: every embedded migration applies and
	// its ALTERs land. S-42 made 000007 (CI seed data) opt-in, so ask for it
	// here — otherwise the assertion below silently becomes "all but one".
	// That the seed is skipped by default is covered in ci_seed_test.go.
	t.Setenv(ciSeedEnvVar, "true")

	db := freshSQLiteDB(t)

	migrations, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) < 20 {
		t.Fatalf("expected at least 20 embedded sqlite migrations, got %d", len(migrations))
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != len(migrations) {
		t.Fatalf("schema_migrations has %d rows, want %d (one per embedded migration)", count, len(migrations))
	}

	// The four ALTER-driven columns the ticket specifically names, plus the
	// most recent one (000024) -- these are the acceptance-critical proof
	// that migrations are actually applied, not just tracked: inline
	// EnsureSchema() CREATE TABLE IF NOT EXISTS calls elsewhere in this
	// codebase would never add a column to an already-existing table.
	cases := []struct{ table, column string }{
		{"certificate_authorities", "cert_pem"},
		{"certificate_authorities", "key_id"},
		{"audit_log", "source_ip"},
		{"certificates", "owner_email"},
		{"pending_actions", "tenant"},
		{"agents", "token_hash"},
	}
	for _, c := range cases {
		if !columnExists(t, db, c.table, c.column) {
			t.Errorf("column %s.%s missing after RunMigrations -- the ALTER TABLE migration adding it never ran", c.table, c.column)
		}
	}
}

func TestRunMigrations_SecondRunIsNoOp(t *testing.T) {
	db := freshSQLiteDB(t)

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("first RunMigrations: %v", err)
	}
	var firstCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&firstCount); err != nil {
		t.Fatalf("count after first run: %v", err)
	}

	// Second run must not error (e.g. on a duplicate CREATE TABLE) and must
	// not re-apply anything already recorded.
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("second RunMigrations (expected no-op): %v", err)
	}
	var secondCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&secondCount); err != nil {
		t.Fatalf("count after second run: %v", err)
	}
	if secondCount != firstCount {
		t.Fatalf("second run changed schema_migrations row count: %d -> %d", firstCount, secondCount)
	}
}

// TestRunMigrations_AcmeAccountsGetsJWKColumn covers G-90 (W1-13): unlike
// every other ALTER-driven column migrations/sqlite/*.sql widens on an
// already-existing table, acme_accounts has never been created by any
// earlier migration -- it is solely owned by
// internal/acme/store_sqlite.go's EnsureSchema, which always runs strictly
// after RunMigrations. 000040_acme_account_key must therefore CREATE TABLE
// IF NOT EXISTS the full shape (jwk included) so a genuinely fresh database
// gets the column from migrations alone, before EnsureSchema's own CREATE
// TABLE IF NOT EXISTS ever runs and no-ops against it.
func TestRunMigrations_SSHCertificatesGetsTemplateIDColumn(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if !columnExists(t, db, "ssh_certificates", "template_id") {
		t.Fatal("ssh_certificates.template_id missing after RunMigrations -- 000070 never ran")
	}
}

func TestRunMigrations_AcmeAccountsGetsJWKColumn(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if !columnExists(t, db, "acme_accounts", "jwk") {
		t.Fatal("acme_accounts.jwk missing after RunMigrations on a fresh database -- 000040's up.sql never ran or never created the column")
	}
}

// TestRunMigrations_AgentTasksUniqueIndexDedupesExistingRowsAndEnforces
// covers W4-05: submitInventory and RenewalAgentDriver's sweepAgentRenewals
// can each independently read "no existing task" for the same (agent_id,
// fingerprint) before either commits, so a database migrated straight from
// pre-000041 could already hold duplicate agent_tasks rows. Applies every
// migration up to (not including) 000041 by name -- not by a numeric
// version cutoff, per the same reasoning
// TestRollbackMigration_RemovesVersionRowsAndReversesSchema documents
// (G-89/S-25): a fixed version number drifts out of sync as later
// migrations land -- then seeds two duplicate rows the way the race would,
// then lets RunMigrations finish (applying 000041 among the rest) and
// proves both halves of the fix: the pre-existing duplicate collapses to
// one row, and the new unique index rejects a fresh duplicate outright.
func TestRunMigrations_AgentTasksUniqueIndexDedupesExistingRowsAndEnforces(t *testing.T) {
	db := freshSQLiteDB(t)

	if _, err := db.Exec(createSchemaMigrationsTable); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	repairPreExistingNarrowDiscoverySchema(db, "sqlite")

	migrations, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	targetIdx := -1
	for i, m := range migrations {
		if m.name == "agent_tasks_unique" {
			targetIdx = i
			break
		}
	}
	if targetIdx <= 0 {
		t.Fatalf(`migration named "agent_tasks_unique" not found (or has no preceding migration)`)
	}
	for _, m := range migrations[:targetIdx] {
		apply := applyUp
		if migrationUsesTolerantApply(m) {
			apply = applyUpTolerant
		}
		if err := apply(db, "sqlite", m); err != nil {
			t.Fatalf("apply migration %s: %v", migrationLabel(m), err)
		}
	}

	// Seed the pre-existing race: two independent transactions both saw "no
	// existing task" for the same (agent_id, fingerprint) and both
	// committed a row, exactly as agent_store_db.go's insertTaskTx could do
	// before ON CONFLICT DO NOTHING existed.
	insert := `INSERT INTO agent_tasks
		(task_id, agent_id, fingerprint, subject, action, ca_url, not_after, server_type, cert_path, key_path, reload_method, verify_host_port)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for _, taskID := range []string{"task-dup-1", "task-dup-2"} {
		if _, err := db.Exec(insert, taskID, "agent-1", "fp-race", "CN=race", "renew", "", "", "nginx", "/c.crt", "/c.key", "", ""); err != nil {
			t.Fatalf("seed duplicate row %s: %v", taskID, err)
		}
	}
	var preCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM agent_tasks WHERE agent_id = ? AND fingerprint = ?", "agent-1", "fp-race").Scan(&preCount); err != nil {
		t.Fatalf("count seeded duplicates: %v", err)
	}
	if preCount != 2 {
		t.Fatalf("setup: expected 2 seeded duplicate rows before migration 000041, got %d", preCount)
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations (applying agent_tasks_unique and the rest): %v", err)
	}

	var postCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM agent_tasks WHERE agent_id = ? AND fingerprint = ?", "agent-1", "fp-race").Scan(&postCount); err != nil {
		t.Fatalf("count post-migration rows: %v", err)
	}
	if postCount != 1 {
		t.Fatalf("expected migration agent_tasks_unique to collapse the 2 duplicate rows to 1, got %d", postCount)
	}

	if _, err := db.Exec(insert, "task-dup-3", "agent-1", "fp-race", "CN=race", "renew", "", "", "nginx", "/c.crt", "/c.key", "", ""); err == nil {
		t.Fatal("expected a plain INSERT for an existing (agent_id, fingerprint) pair to violate the new unique index, got no error")
	}
}

// TestRunMigrations_CertificatesDropsNonAuthoritativeFKs covers S-51:
// certificates.template_id REFERENCES certificate_templates(id) and
// certificates.team_id REFERENCES teams(id), but neither table is
// authoritative in a default install -- templates are file-backed
// (APP_TEMPLATE_PROVIDER) and teams are never auto-created (team_id is
// actually the issuing principal's identifier, see handlers_certificates.go's
// authorizeCertificateMutationRequest). Both FKs independently rejected
// every real issuance. Proves the negative first: applies every migration up
// to (not including) 000042 by name, same reasoning as the agent_tasks_unique
// test above, then confirms the FK genuinely rejects a certificate row whose
// template_id/team_id don't exist before 000042 runs; then that the same
// insert succeeds once 000042 has dropped those two FKs (leaving ca_id and
// the self-referencing predecessor/successor FKs intact); then that rolling
// back restores enforcement.
func TestRunMigrations_CertificatesDropsNonAuthoritativeFKs(t *testing.T) {
	db := freshSQLiteDB(t)

	if _, err := db.Exec(createSchemaMigrationsTable); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	repairPreExistingNarrowDiscoverySchema(db, "sqlite")

	migrations, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	targetIdx := -1
	for i, m := range migrations {
		if m.name == "certificates_drop_nonauthoritative_fks" {
			targetIdx = i
			break
		}
	}
	if targetIdx <= 0 {
		t.Fatalf(`migration named "certificates_drop_nonauthoritative_fks" not found (or has no preceding migration)`)
	}
	for _, m := range migrations[:targetIdx] {
		apply := applyUp
		if migrationUsesTolerantApply(m) {
			apply = applyUpTolerant
		}
		if err := apply(db, "sqlite", m); err != nil {
			t.Fatalf("apply migration %s: %v", migrationLabel(m), err)
		}
	}

	insert := `INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, template_id, team_id,
		 valid_from, valid_until, public_key_algorithm, signature_algorithm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	row := []any{"fp-s51-1", "1", "CN=test", "CN=issuer", "nonexistent-template", "nonexistent-team",
		"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "RSA", "SHA256-RSA"}

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("enable foreign_keys: %v", err)
	}
	if _, err := db.Exec(insert, row...); err == nil {
		t.Fatal("expected a FOREIGN KEY violation before 000042 for a non-existent template_id/team_id, got no error -- this is the exact bug S-51 fixes")
	}

	colsBeforeUp := tableColumnNames(t, db, "certificates")

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	// The rebuild dance (SQLite's only way to drop a FK) copies data through
	// an explicit column list -- assert nothing was silently dropped or
	// added, not just that the FK itself is gone.
	// RunMigrations applies everything pending, so the "after" set includes
	// later migrations' legitimate additions: 000043 (W11-01 estate model)
	// adds origin + management_state. Add them to the expectation rather
	// than weakening the no-silent-drop assertion (the S-65 precedent).
	// 000051 adds pqc_readiness for the same reason: the classification was
	// computed at issuance and never stored, so DB-backed reads returned ""
	// and the posture report claimed 0 vulnerable for a vulnerable estate.
	// 000077 adds trust_class + is_ca (discovered-chain classification).
	assertSameColumnSet(t, "000042 up",
		append(append([]string{}, colsBeforeUp...), "origin", "management_state", "renewal_connector_id", "pqc_readiness", "trust_class", "is_ca"),
		tableColumnNames(t, db, "certificates"))

	if fkColumnExists(t, db, "certificates", "template_id") {
		t.Error("certificates.template_id FK still present after 000042")
	}
	if fkColumnExists(t, db, "certificates", "team_id") {
		t.Error("certificates.team_id FK still present after 000042")
	}
	if !fkColumnExists(t, db, "certificates", "ca_id") {
		t.Error("certificates.ca_id FK missing after 000042 -- ca_id is authoritative and must stay")
	}

	if _, err := db.Exec(insert, row...); err != nil {
		t.Fatalf("insert with non-existent template_id/team_id after 000042: %v (the whole point of S-51 is that this now succeeds)", err)
	}
	if _, err := db.Exec("DELETE FROM certificates WHERE fingerprint_sha256 = ?", "fp-s51-1"); err != nil {
		t.Fatalf("clean up seeded row before rollback: %v", err)
	}

	rollbackTo := migrations[targetIdx-1].version
	if err := RollbackMigration(db, "sqlite", rollbackTo); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}

	assertSameColumnSet(t, "000042 down", colsBeforeUp, tableColumnNames(t, db, "certificates"))

	if !fkColumnExists(t, db, "certificates", "template_id") {
		t.Error("certificates.template_id FK not restored after rolling back 000042")
	}
	if !fkColumnExists(t, db, "certificates", "team_id") {
		t.Error("certificates.team_id FK not restored after rolling back 000042")
	}

	row2 := append([]any{}, row...)
	row2[0] = "fp-s51-2"
	if _, err := db.Exec(insert, row2...); err == nil {
		t.Fatal("expected the FOREIGN KEY violation to return after rolling back 000042, got no error")
	}
}

// TestRollbackMigration_AcmeAccountKeyRemovesJWKColumn proves
// 000040_acme_account_key's down.sql actually runs, dropping only the jwk
// column it added -- not the whole acme_accounts table, which up.sql's
// CREATE TABLE IF NOT EXISTS did not itself introduce in any real
// deployment (see the migration's own down.sql comment on why the asymmetry
// is deliberate).
func TestRollbackMigration_AcmeAccountKeyRemovesJWKColumn(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if !columnExists(t, db, "acme_accounts", "jwk") {
		t.Fatal("acme_accounts.jwk missing after RunMigrations -- precondition for this test failed")
	}

	if err := RollbackMigration(db, "sqlite", 39); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}

	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='acme_accounts'").Scan(&exists); err != nil {
		t.Fatalf("check acme_accounts table: %v", err)
	}
	if exists == 0 {
		t.Fatal("acme_accounts table was dropped by rollback -- down.sql must only drop the jwk column, never the table")
	}
	if columnExists(t, db, "acme_accounts", "jwk") {
		t.Fatal("acme_accounts.jwk still present after rolling back 000040 -- down.sql did not run")
	}
}

func TestRollbackMigration_RemovesVersionRowsAndReversesSchema(t *testing.T) {
	db := freshSQLiteDB(t)

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	migrations, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) < 4 {
		t.Fatalf("expected at least 4 embedded migrations, got %d", len(migrations))
	}
	// Roll back to the version immediately preceding runtime_config's own
	// migration, found by name rather than counted from the tail. A fixed
	// tail-offset (e.g. "4th-from-last") is only safe until the total
	// migration count grows enough to land that offset exactly on
	// runtime_config's own version -- RollbackMigration leaves its
	// toVersion applied, so a rollbackTo equal to (not below)
	// runtime_config's version would leave the table it creates in place,
	// silently defeating this test's whole premise (verifying its
	// down.sql actually runs). Anchoring on the migration by name keeps
	// "rollbackTo is strictly below runtime_config" true by construction,
	// independent of how many migrations land after it (confirmed by G-89/
	// S-25 adding a 33rd migration and tripping exactly this).
	runtimeConfigIdx := -1
	for i, m := range migrations {
		if m.name == "runtime_config" {
			runtimeConfigIdx = i
			break
		}
	}
	if runtimeConfigIdx <= 0 {
		t.Fatalf(`migration named "runtime_config" not found (or has no preceding migration)`)
	}
	rollbackTo := migrations[runtimeConfigIdx-1].version
	latest := migrations[len(migrations)-1].version

	if !columnExists(t, db, "runtime_config", "envelope") {
		t.Fatal("runtime_config table missing after RunMigrations -- 000030's up.sql never ran")
	}

	if err := RollbackMigration(db, "sqlite", rollbackTo); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}

	// runtime_config's own migration is always above rollbackTo by
	// construction now (rollbackTo is the version immediately before it),
	// so it is always inside the rolled-back range -- verify its down.sql
	// actually dropped the table, not just the bookkeeping row.
	if latest > rollbackTo && columnExists(t, db, "runtime_config", "envelope") {
		t.Error("runtime_config table still exists after rollback -- 000030's down.sql did not run")
	}

	var maxVersion sql.NullInt64
	if err := db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&maxVersion); err != nil {
		t.Fatalf("query max version: %v", err)
	}
	if !maxVersion.Valid || int(maxVersion.Int64) != rollbackTo {
		t.Fatalf("max applied version after rollback = %v, want %d", maxVersion, rollbackTo)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version > ?", rollbackTo).Scan(&count); err != nil {
		t.Fatalf("count rows above rollback target: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d schema_migrations rows above the rollback target were not removed", count)
	}

	// 000024_agent_token_hash's down.sql drops agents.token_hash -- verify a
	// real down.sql actually ran (not just the bookkeeping row deleted), for
	// whichever of the ALTER migrations landed inside the rolled-back range.
	if rollbackTo < 24 {
		if columnExists(t, db, "agents", "token_hash") {
			t.Error("agents.token_hash still exists after rolling back past migration 24 -- down.sql did not run")
		}
	}
}

func TestRunMigrations_UnsupportedEngineRejected(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "mysql"); err == nil {
		t.Fatal("expected an error for an unsupported engine")
	}
}

func TestLoadMigrations_PostgresAndSQLiteHaveTheSameVersionSet(t *testing.T) {
	sqliteMigrations, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatalf("loadMigrations(sqlite): %v", err)
	}
	postgresMigrations, err := loadMigrations("postgres")
	if err != nil {
		t.Fatalf("loadMigrations(postgres): %v", err)
	}
	if len(sqliteMigrations) != len(postgresMigrations) {
		t.Fatalf("sqlite has %d migrations, postgres has %d -- the two engine directories have drifted", len(sqliteMigrations), len(postgresMigrations))
	}
	for i, m := range sqliteMigrations {
		if m.version != postgresMigrations[i].version {
			t.Fatalf("migration %d: sqlite version %d != postgres version %d", i, m.version, postgresMigrations[i].version)
		}
		if m.upSQL == "" || m.downSQL == "" {
			t.Errorf("sqlite migration %s missing up or down SQL", migrationLabel(m))
		}
		if postgresMigrations[i].upSQL == "" || postgresMigrations[i].downSQL == "" {
			t.Errorf("postgres migration %s missing up or down SQL", migrationLabel(postgresMigrations[i]))
		}
	}
}

// livePostgresDSN returns KRYPTKEEPER_TEST_POSTGRES_DSN, or skips the
// calling test if it is unset. Every caller then hands the DSN to
// freshPostgresDB, which unconditionally drops and recreates the target
// database's public schema -- so this must never point at a shared or
// production database. See README.md's "Live-Postgres integration tests"
// section, next to this variable, for the full contract.
func livePostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres integration test")
	}
	return dsn
}

// freshPostgresDB opens dsn and resets it to a known-empty schema state
// (drop and recreate the public schema) before returning, so a live-Postgres
// test starts clean regardless of what an earlier run -- including one with
// KRYPTKEEPER_SEED_CI_DATA=true, which recorded migration 000007 and made
// every later default run fail with "present but KRYPTKEEPER_SEED_CI_DATA is
// unset" -- left behind (S-67). The reset runs before the test body, not
// only in a t.Cleanup: a previous run that panicked or was killed leaves no
// cleanup to rely on, which is exactly how that poisoned state happened.
// Consequently no live-Postgres test in this file depends on another
// having run first, or on declaration order.
func freshPostgresDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// IF EXISTS makes this idempotent against the one state it must tolerate:
	// a database left schema-less by a previous run that died between the
	// DROP and the CREATE (SIGINT/panic/kill), or whose public schema is
	// simply absent (hardened or managed Postgres). Both statements run in a
	// single Exec so that window cannot exist for a run of this test itself.
	// S-67 review (MEDIUM): this is an unconditional DROP SCHEMA ... CASCADE
	// against whatever KRYPTKEEPER_TEST_POSTGRES_DSN names, and nothing makes
	// that database disposable. A sibling live-Postgres test
	// (audit_store_test.go's TestPostgresAuditStoreEnsureSchemaOnFreshDB) is
	// gated on APP_AUDIT_DB_DSN/KRYPTKEEPER_DB_DSN/DATABASE_URL, which someone
	// would plausibly point at this same database — and a plain typo would aim
	// it at a real one. Refuse anything that does not name itself a test
	// database, so the destructive path cannot be reached by accident.
	if name := postgresDBName(dsn); !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("refusing to DROP SCHEMA on database %q: KRYPTKEEPER_TEST_POSTGRES_DSN must name a "+
			"disposable database with \"test\" in its name", name)
	}

	if _, err := db.Exec("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatalf("reset postgres schema: %v", err)
	}
	return db
}

// TestRunMigrations_Postgres is a real integration test, skipped unless a
// live Postgres is reachable via KRYPTKEEPER_TEST_POSTGRES_DSN -- mirrors the
// LocalStack-style (AWS_ENDPOINT_URL) and S-07 (postgres audit schema) skip
// pattern already used elsewhere in this codebase. Until this package
// blank-imported the pgx stdlib driver (G-86), sql.Open("pgx", ...) failed
// with "unknown driver" before this test's body ever ran, regardless of DSN
// -- confirmed by real execution here (a disposable postgres:16-alpine
// container) rather than by source inspection alone. The multi-statement
// migration files this test exercises depend on pgx's Conn.Exec
// automatically switching to the simple query protocol whenever called with
// no bound arguments -- if a future change ever passes args through this
// path, pgx switches to the extended protocol and multi-statement execution
// breaks silently.
func TestRunMigrations_Postgres(t *testing.T) {
	// Pin the seed flag rather than assume it (S-65 review, MEDIUM). The
	// assertions below report "KRYPTKEEPER_SEED_CI_DATA is unset" as established
	// fact; run with it exported true and that message is literally false, which
	// sends the next maintainer after the migration runner instead of their own
	// environment. Every sibling test depending on the default-off state pins it
	// explicitly (ci_seed_test.go:48, :72, :127).
	t.Setenv(ciSeedEnvVar, "")

	dsn := livePostgresDSN(t)
	db := freshPostgresDB(t, dsn)

	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	migrations, err := loadMigrations("postgres")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	// S-42 made the CI seed migration (000007) opt-in: it skips application
	// AND recording by default. Verify the exact set of recorded versions rather
	// than a count comparison, which can mask compound faults (e.g., version 000007
	// present AND another version missing would both delta the count by one).
	// Read the recorded versions from the database.
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()
	recorded := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			t.Fatalf("scan version: %v", err)
		}
		recorded[version] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema_migrations: %v", err)
	}

	// For each embedded migration, assert that it is recorded iff it is not the
	// seed migration (which is skipped by default). This catches both:
	// 1. 000007 incorrectly applied when KRYPTKEEPER_SEED_CI_DATA is unset
	// 2. Any other version missing from schema_migrations
	for _, m := range migrations {
		shouldBeRecorded := m.version != ciSeedVersion
		isRecorded := recorded[m.version]
		if isRecorded != shouldBeRecorded {
			if shouldBeRecorded {
				t.Errorf("migration version %d (%s) missing from schema_migrations", m.version, m.name)
			} else {
				t.Errorf("migration version %d (%s, CI seed data) present in schema_migrations but KRYPTKEEPER_SEED_CI_DATA is unset", m.version, m.name)
			}
		}
	}
}

// TestRunMigrations_Postgres_CertificatesDropsNonAuthoritativeFKs is the
// Postgres half of S-51's acceptance criterion 2 (the constraint removal
// applies on both engines and has a working down migration) -- skipped
// unless a live Postgres is reachable, same reasoning as
// TestRunMigrations_Postgres above. Constraint names
// (certificates_template_id_fkey / certificates_team_id_fkey /
// certificates_ca_id_fkey) are Postgres's default auto-generated
// <table>_<column>_fkey -- confirmed against a disposable postgres:16-alpine
// container before writing 000042's up/down.sql, since
// 000002_templates_ca_certs_core never names these constraints explicitly.
// A pg_constraint-only check would have missed 000042's original bug: it
// dropped the FK but left both columns UUID-typed, so a real, non-UUID
// template_id/team_id (e.g. "tpl-web-server-1", the issuing principal's
// identifier) still failed with SQLSTATE 22P02 even with no FK left to
// violate. This inserts exactly such a row and asserts it succeeds.
func TestRunMigrations_Postgres_CertificatesDropsNonAuthoritativeFKs(t *testing.T) {
	dsn := livePostgresDSN(t)
	db := freshPostgresDB(t, dsn)

	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	certificateFKNames := func() map[string]bool {
		rows, err := db.Query(`SELECT conname FROM pg_constraint
			WHERE conrelid = 'certificates'::regclass AND contype = 'f'`)
		if err != nil {
			t.Fatalf("query pg_constraint: %v", err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatalf("scan constraint name: %v", err)
			}
			out[n] = true
		}
		return out
	}

	fks := certificateFKNames()
	if fks["certificates_template_id_fkey"] {
		t.Error("certificates_template_id_fkey still present after RunMigrations")
	}
	if fks["certificates_team_id_fkey"] {
		t.Error("certificates_team_id_fkey still present after RunMigrations")
	}
	if !fks["certificates_ca_id_fkey"] {
		t.Error("certificates_ca_id_fkey missing after RunMigrations -- ca_id is authoritative and must stay")
	}

	insert := `INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, template_id, team_id,
		 valid_from, valid_until, public_key_algorithm, signature_algorithm)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	row := []any{"fp-s51-postgres-1", "1", "CN=test", "CN=issuer", "tpl-web-server-1", "principal-a",
		"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "RSA", "SHA256-RSA"}

	if _, err := db.Exec(insert, row...); err != nil {
		t.Fatalf("insert with realistic non-UUID template_id/team_id after RunMigrations: %v (the whole point of S-51 is that this now succeeds -- a UUID-typed column would fail with SQLSTATE 22P02 even with no FK left to violate)", err)
	}
	if _, err := db.Exec("DELETE FROM certificates WHERE fingerprint_sha256 = $1", "fp-s51-postgres-1"); err != nil {
		t.Fatalf("clean up seeded row before rollback: %v", err)
	}

	migrations, err := loadMigrations("postgres")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	targetIdx := -1
	for i, m := range migrations {
		if m.name == "certificates_drop_nonauthoritative_fks" {
			targetIdx = i
			break
		}
	}
	if targetIdx <= 0 {
		t.Fatalf(`migration named "certificates_drop_nonauthoritative_fks" not found (or has no preceding migration)`)
	}
	rollbackTo := migrations[targetIdx-1].version

	if err := RollbackMigration(db, "postgres", rollbackTo); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}

	fks = certificateFKNames()
	if !fks["certificates_template_id_fkey"] {
		t.Error("certificates_template_id_fkey not restored after rolling back 000042")
	}
	if !fks["certificates_team_id_fkey"] {
		t.Error("certificates_team_id_fkey not restored after rolling back 000042")
	}
}

// postgresDBName extracts the database name from a Postgres DSN in either URL
// or key=value form, for freshPostgresDB's disposability guard (S-67 review).
// Returns "" when it cannot tell, which the guard treats as not-a-test-database
// — failing closed, since the operation it guards is destructive.
func postgresDBName(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
		return strings.TrimPrefix(u.Path, "/")
	}
	for _, field := range strings.Fields(dsn) {
		if rest, ok := strings.CutPrefix(field, "dbname="); ok {
			return rest
		}
	}
	return ""
}
