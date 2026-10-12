// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"fmt"
	"log"
)

// RemoveCISeedData deletes the rows migration 000007 inserts (S-42).
//
// Fresh installs no longer apply that migration at all. This is the path for
// databases that already ran it before it was gated — including staging, which
// has been carrying a fake root CA and certificate in its trust inventory.
//
// It is deliberately NOT automatic. Deleting a CA and a certificate from a live
// database is destructive, and a boot sequence has no business deciding that on
// an operator's behalf: RunMigrations only warns and points here. Invoked by
// `kryptkeeper --remove-ci-seed`.
//
// The statement list mirrors 000007_seed_baseline_data.down.sql, in the same
// dependency order. audit_log is intentionally excluded — the append-only
// controls block mutation there by design, and the seed's audit entries are
// removed only when W4's down migration drops the table.
func RemoveCISeedData(db *sql.DB, engine string) (int64, error) {
	if engine != "postgres" && engine != "sqlite" {
		return 0, fmt.Errorf("unsupported engine %q (expected postgres or sqlite)", engine)
	}

	stmts := []string{
		`DELETE FROM scan_results WHERE id = '00000000-0000-0000-0000-000000000110'`,
		`DELETE FROM certificate_endpoints
		   WHERE certificate_fingerprint = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
		     AND endpoint_id = '00000000-0000-0000-0000-000000000109'`,
		`DELETE FROM endpoints WHERE id = '00000000-0000-0000-0000-000000000109'`,
		`DELETE FROM scan_jobs WHERE id = '00000000-0000-0000-0000-000000000108'`,
		`UPDATE certificate_authorities SET certificate_fingerprint_sha256 = NULL
		   WHERE id = '00000000-0000-0000-0000-000000000107'`,
		`DELETE FROM certificates
		   WHERE fingerprint_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'`,
		`DELETE FROM certificate_authorities WHERE id = '00000000-0000-0000-0000-000000000107'`,
		`DELETE FROM certificate_templates WHERE id = '00000000-0000-0000-0000-000000000106'`,
		`DELETE FROM api_keys WHERE id = '00000000-0000-0000-0000-000000000105'`,
		`DELETE FROM team_members WHERE team_id = '00000000-0000-0000-0000-000000000102'`,
		`DELETE FROM users WHERE id IN ('00000000-0000-0000-0000-000000000103','00000000-0000-0000-0000-000000000104')`,
		`DELETE FROM teams WHERE id = '00000000-0000-0000-0000-000000000102'`,
		`DELETE FROM notification_policies WHERE id = '00000000-0000-0000-0000-000000000101'`,
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var total int64
	for _, s := range stmts {
		res, err := tx.Exec(s)
		if err != nil {
			// A table that does not exist yet means this database never got
			// that far; that is not a failure to remove seed data.
			return 0, fmt.Errorf("remove ci seed data: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}

	// Drop the bookkeeping row too, so the warning stops firing and a later
	// KRYPTKEEPER_SEED_CI_DATA=true can re-apply the migration if CI wants it.
	del := `DELETE FROM schema_migrations WHERE version = ?`
	if engine == "postgres" {
		del = `DELETE FROM schema_migrations WHERE version = $1`
	}
	if _, err := tx.Exec(del, ciSeedVersion); err != nil {
		return 0, fmt.Errorf("clear schema_migrations row: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	log.Printf("removed CI seed data: %d row(s) across %d tables", total, len(stmts))
	return total, nil
}
