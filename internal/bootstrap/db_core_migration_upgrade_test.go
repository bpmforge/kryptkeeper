// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	kkdb "kryptkeeper/internal/db"

	_ "modernc.org/sqlite"
)

// TestRunMigrations_ToleratesPreExistingDeploymentSchema simulates the real
// upgrade scenario this repo is in (W10-01/G-33): the versioned migrations
// under internal/db/migrations/ have never executed against any real
// deployment — every live schema was built by the inline EnsureSchema()
// CREATE TABLE IF NOT EXISTS calls in discovery_db_provider.go and
// audit_db_provider.go, which by default share the same sqlite file as the
// core DB (both resolve KRYPTKEEPER_DATA_DIR/kryptkeeper.db).
//
// cmd/kryptkeeper/main.go always calls bootstrap.OpenCoreDB() (which now
// runs RunMigrations) before constructing the discovery or audit providers
// (line ~50 vs ~150/~172) — so on every real boot that has ever enabled the
// core DB, migrations run and create the authoritative, full-column
// versions of certificates/scan_jobs/endpoints/certificate_endpoints/
// audit_log FIRST, and discovery/audit's own inline CREATE TABLE IF NOT
// EXISTS calls become harmless no-ops against those same names afterward.
// This test proves that ordering is safe.
//
// Before migrations 000002-000004 were made idempotent (IF NOT EXISTS) as
// part of this ticket, this same test failed outright with "table
// certificates already exists" the moment schema_migrations was empty on a
// DB where discovery/audit schema already existed — which is the state of
// every real pre-existing deployment. See G-77 in DESIGN_REVIEW.md for the
// remaining, narrower gap this test does NOT cover: a data directory where
// discovery ran WITHOUT the core DB ever being enabled (so discovery's
// narrower certificates/scan_jobs/endpoints tables were created first,
// before any migration ever ran), which is deliberately not fixed here.
func TestRunMigrations_ToleratesPreExistingDeploymentSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The first-ever migration run against a DB with no schema_migrations
	// table at all -- the state of every real pre-existing deployment --
	// must not fail.
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations against a pre-existing (pre-migration-runner) deployment: %v", err)
	}

	// Matching main.go's real construction order: discovery and audit's own
	// EnsureSchema calls run AFTER the core DB (and its migrations) are
	// already up -- must be harmless no-ops against the migration-owned
	// tables, not errors.
	discovery := &sqliteDiscoveryStore{db: db}
	if err := discovery.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("discovery EnsureSchema after migrations: %v", err)
	}
	audit := &sqliteAuditStore{db: db}
	if err := audit.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("audit EnsureSchema after migrations: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count < 20 {
		t.Fatalf("schema_migrations has %d rows after upgrade run, want at least 20", count)
	}

	// The ALTER-driven columns must still land on the migration-owned tables
	// even though discovery/audit's narrower CREATE TABLE IF NOT EXISTS ran
	// first for the colliding table names.
	for _, c := range []struct{ table, column string }{
		{"certificate_authorities", "cert_pem"},
		{"audit_log", "source_ip"},
		{"audit_log", "tenant"},
	} {
		rows, err := db.Query("PRAGMA table_info(" + c.table + ")")
		if err != nil {
			t.Fatalf("PRAGMA table_info(%s): %v", c.table, err)
		}
		found := false
		for rows.Next() {
			var cid int
			var name, ctype string
			var notNull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				t.Fatalf("scan table_info: %v", err)
			}
			if name == c.column {
				found = true
			}
		}
		rows.Close()
		if !found {
			t.Errorf("column %s.%s missing after upgrade-path RunMigrations", c.table, c.column)
		}
	}

	// A second run (the normal every-boot case thereafter) must still be a
	// clean no-op.
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("second RunMigrations after upgrade: %v", err)
	}
}

// TestRunMigrations_RepairsPreExistingNarrowDiscoverySchema reproduces G-77's
// discovery-table half (S-14): a data directory that ran discovery scanning
// before the core DB was ever enabled (APP_CERTIFICATE_PROVIDER unset or not
// "ca", so bootstrap.OpenCoreDB/RunMigrations never ran) has
// certificates/scan_jobs/endpoints created by dbDiscoveryStore's own
// narrower inline EnsureSchema, not by migrations 000002/000003. Before
// S-14, RunMigrations against that same data directory failed outright
// ("no such column: serial_number") the moment migration 000002 tried to
// index a column its own CREATE TABLE IF NOT EXISTS silently skipped
// creating, since the narrower table already existed.
//
// This is the opposite ordering from
// TestRunMigrations_ToleratesPreExistingDeploymentSchema above (which proves
// migrations-then-EnsureSchema is safe -- the real ordering every boot that
// has ever called OpenCoreDB uses). This test proves the historically
// possible EnsureSchema-then-migrations ordering is ALSO safe now.
//
// audit_log's own pre-existing-schema collision runs the OPPOSITE
// direction (S-07 made its inline schema already full-shape, so a later
// migration's own ALTER TABLE ADD COLUMN duplicate-fails instead) and needs
// a structurally different fix (tolerating an already-satisfied ADD
// COLUMN, not adding missing ones) -- see
// TestRunMigrations_ToleratesPreExistingFullShapeAuditSchema below (G-81/S-19).
func TestRunMigrations_RepairsPreExistingNarrowDiscoverySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reverse-order.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	discovery := &sqliteDiscoveryStore{db: db}
	if err := discovery.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("discovery EnsureSchema (before any migration has ever run): %v", err)
	}

	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations against a pre-existing narrow discovery schema: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count < 20 {
		t.Fatalf("schema_migrations has %d rows, want at least 20", count)
	}

	// Spot-check a handful of columns from each migration these repairs
	// need to unblock: the founding migrations (000002/000003) plus
	// 000012, which must still be free to add ITS OWN columns afterward
	// (proving the repair didn't over-add and cause 000012 to
	// duplicate-fail).
	for _, c := range []struct{ table, column string }{
		{"certificates", "serial_number"},
		{"certificates", "subject_dn"},
		{"certificates", "risk_score"}, // pre-existing narrow column, untouched
		{"certificates", "owner_email"},
		{"scan_jobs", "results_summary"},
		{"endpoints", "is_default_cert"},
		{"certificate_endpoints", "currently_active"},
	} {
		rows, err := db.Query("PRAGMA table_info(" + c.table + ")")
		if err != nil {
			t.Fatalf("PRAGMA table_info(%s): %v", c.table, err)
		}
		found := false
		for rows.Next() {
			var cid int
			var name, ctype string
			var notNull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				t.Fatalf("scan table_info: %v", err)
			}
			if name == c.column {
				found = true
			}
		}
		rows.Close()
		if !found {
			t.Errorf("column %s.%s missing after reverse-order RunMigrations", c.table, c.column)
		}
	}

	// Discovery's own EnsureSchema, called again on every real boot after
	// this, must still be a harmless no-op against the now-widened tables.
	if err := discovery.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("discovery EnsureSchema after migrations: %v", err)
	}

	// A second RunMigrations (the normal every-boot case thereafter) must
	// still be a clean no-op.
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("second RunMigrations: %v", err)
	}
}

// TestRunMigrations_ToleratesPreExistingFullShapeAuditSchema reproduces
// G-81's exact scenario (S-19): a data directory that ran
// APP_AUDIT_PROVIDER=db before RunMigrations ever executed gets audit_log
// created full-shape by sqliteAuditStore.EnsureSchema (source_ip/
// user_agent/session_id/change_summary/tenant all present from creation,
// per S-07) -- so migrations 000011/000021's own blind ALTER TABLE ADD
// COLUMN duplicate-fail the moment migrations finally run. This is the
// opposite direction from TestRunMigrations_RepairsPreExistingNarrowDiscoverySchema
// above (a table missing columns migrations expect) and needs a
// structurally different fix: tolerating an already-satisfied ADD COLUMN,
// not adding missing ones.
func TestRunMigrations_ToleratesPreExistingFullShapeAuditSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-reverse-order.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	audit := &sqliteAuditStore{db: db}
	if err := audit.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("audit EnsureSchema (before any migration has ever run): %v", err)
	}

	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations against a pre-existing full-shape audit_log schema: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count < 20 {
		t.Fatalf("schema_migrations has %d rows, want at least 20", count)
	}

	// Migrations 000011 and 000021 must be recorded as applied even though
	// their own ADD COLUMN statements were all already-satisfied no-ops.
	for _, v := range []int{11, 21} {
		var recorded int
		if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", v).Scan(&recorded); err != nil {
			t.Fatalf("count schema_migrations version %d: %v", v, err)
		}
		if recorded != 1 {
			t.Errorf("migration %d not recorded as applied (count=%d)", v, recorded)
		}
	}

	// audit_log must have every column both S-07's schema and migrations
	// 000011/000021 define -- proving the tolerant path didn't skip real
	// work, only the already-satisfied duplicate ADD COLUMNs.
	for _, column := range []string{"source_ip", "user_agent", "session_id", "change_summary", "tenant"} {
		rows, err := db.Query("PRAGMA table_info(audit_log)")
		if err != nil {
			t.Fatalf("PRAGMA table_info(audit_log): %v", err)
		}
		found := false
		for rows.Next() {
			var cid int
			var name, ctype string
			var notNull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				t.Fatalf("scan table_info: %v", err)
			}
			if name == column {
				found = true
			}
		}
		rows.Close()
		if !found {
			t.Errorf("audit_log.%s missing after tolerant RunMigrations", column)
		}
	}

	// The tenant index migration 000021 creates must exist too -- proving
	// the tolerant path didn't silently drop the CREATE INDEX statement
	// alongside tolerating the ADD COLUMN.
	var indexCount int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_audit_tenant'",
	).Scan(&indexCount); err != nil {
		t.Fatalf("count idx_audit_tenant: %v", err)
	}
	if indexCount != 1 {
		t.Fatalf("idx_audit_tenant missing after tolerant RunMigrations")
	}

	// audit's own EnsureSchema, called again on every real boot after this,
	// must still be a harmless no-op.
	if err := audit.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("audit EnsureSchema after migrations: %v", err)
	}

	// A second RunMigrations (the normal every-boot case thereafter) must
	// still be a clean no-op -- proves the tolerant migrations don't get
	// silently re-run once genuinely applied.
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("second RunMigrations: %v", err)
	}
}
