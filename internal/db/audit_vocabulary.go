// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"fmt"
	"strings"
)

// auditVocabularyMigration is the migration that widens audit_log.outcome (and
// actor_type) to the full AuditOutcome vocabulary.
const auditVocabularyMigration = 76

// auditVocabularyMarker is a value only the widened CHECK contains.
const auditVocabularyMarker = "pending_approval"

// EnsureAuditOutcomeVocabulary widens an audit_log that still carries the
// original success/failure/denied CHECK. RunMigrations does this through
// migration 000076, but only against the core database: an audit trail on its
// own DSN (APP_AUDIT_DB_DSN) is only ever opened through the audit store's
// idempotent CREATE TABLE IF NOT EXISTS, which never alters an existing table,
// so every append with a newer outcome kept failing there. The audit store
// calls this after creating its schema so that path self-heals the same way.
//
// It applies the very SQL of migration 000076, which is safe to repeat, and is
// a no-op when the table is absent or already current.
func EnsureAuditOutcomeVocabulary(db *sql.DB, engine string) error {
	stale, err := auditOutcomeVocabularyStale(db, engine)
	if err != nil || !stale {
		return err
	}
	migrations, err := loadMigrations(engine)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version != auditVocabularyMigration {
			continue
		}
		parts := splitMigrationSQL(m.upSQL)
		if parts.pre != "" {
			if _, err := db.Exec(parts.pre); err != nil {
				return fmt.Errorf("widen audit_log vocabulary: %w", err)
			}
		}
		if err := execInTx(db, parts.tx); err != nil {
			return fmt.Errorf("widen audit_log vocabulary: %w", err)
		}
		if parts.post != "" {
			if _, err := db.Exec(parts.post); err != nil {
				return fmt.Errorf("widen audit_log vocabulary (committed): %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("migration %06d is not embedded for engine %q", auditVocabularyMigration, engine)
}

func execInTx(db *sql.DB, stmts string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds
	if _, err := tx.Exec(stmts); err != nil {
		return err
	}
	return tx.Commit()
}

func auditOutcomeVocabularyStale(db *sql.DB, engine string) (bool, error) {
	var def sql.NullString
	var err error
	switch engine {
	case "sqlite":
		err = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'`).Scan(&def)
	case "postgres":
		err = db.QueryRow(`SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
			WHERE c.conrelid = to_regclass('audit_log') AND c.conname = 'audit_log_outcome_check'`).Scan(&def)
	default:
		return false, fmt.Errorf("unsupported engine %q", engine)
	}
	if err == sql.ErrNoRows {
		return false, nil // no audit_log (yet), or no named constraint to widen
	}
	if err != nil {
		return false, fmt.Errorf("inspect audit_log: %w", err)
	}
	return def.Valid && !strings.Contains(def.String, auditVocabularyMarker), nil
}
