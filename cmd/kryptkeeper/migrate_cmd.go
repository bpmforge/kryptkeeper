// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"time"

	"kryptkeeper/internal/bootstrap"
	kkdb "kryptkeeper/internal/db"
)

const migrateUsage = `usage:
  kryptkeeper migrate status
  kryptkeeper migrate down --to <version> --backup-id <id>

status prints the database and binary schema versions and exits 1 when the
database is newer than this binary. It never changes the database.

down rolls the schema back to <version> (that version stays applied). Stop
every hub replica first. It is refused when audit_log holds rows only the newer
schema can represent. Authority is shell access plus the database credentials:
there is no role check on a local command. --backup-id is the operator-supplied
label of the backup taken before the rollback (the db-<timestamp> name from
scripts/deploy/backup.sh); it is format-checked and recorded in the audit log,
not verified against a file.`

// backupIDRe keeps the recorded label to a single token so it cannot smuggle
// whitespace or control characters into the audit change summary.
var backupIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)

type migrateDeps struct {
	open  func() (*sql.DB, string, error)
	audit func(ctx context.Context, e bootstrap.AuditEntry) error
}

func defaultMigrateDeps() migrateDeps {
	return migrateDeps{
		open: func() (*sql.DB, string, error) {
			db, isPostgres, err := bootstrap.OpenCoreDBNoMigrate()
			if err != nil {
				return nil, "", err
			}
			if isPostgres {
				return db, "postgres", nil
			}
			return db, "sqlite", nil
		},
		audit: appendAuditEntry,
	}
}

// appendAuditEntry resolves the same audit store the hub would use.
func appendAuditEntry(ctx context.Context, e bootstrap.AuditEntry) error {
	p, _, err := bootstrap.ResolveAuditProvider(true)
	if err != nil {
		return err
	}
	return p.AppendEntry(ctx, e)
}

func migrateAndExit(args []string) {
	os.Exit(runMigrate(args, os.Stdout, os.Stderr, defaultMigrateDeps()))
}

// runMigrate returns 0 on success, 1 when refused or failed, 2 on usage error.
func runMigrate(args []string, out, errOut io.Writer, d migrateDeps) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, migrateUsage)
		return 2
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(errOut, migrateUsage)
			return 2
		}
		return migrateStatus(out, errOut, d)
	case "down":
		return migrateDown(args[1:], out, errOut, d)
	default:
		fmt.Fprintf(errOut, "migrate: unknown subcommand %q\n%s\n", args[0], migrateUsage)
		return 2
	}
}

func migrateStatus(out, errOut io.Writer, d migrateDeps) int {
	db, engine, err := d.open()
	if err != nil {
		fmt.Fprintf(errOut, "migrate status: %v\n", err)
		return 1
	}
	defer db.Close()
	st, err := kkdb.Status(db, engine)
	if err != nil {
		fmt.Fprintf(errOut, "migrate status: %v\n", err)
		return 1
	}
	state := st.State
	switch st.State {
	case "pending":
		state = fmt.Sprintf("pending (%d to apply)", len(st.Pending))
	case "newer":
		state = "newer (database is ahead of this binary)"
	}
	fmt.Fprintf(out, "%-18s%s\n", "engine:", st.Engine)
	fmt.Fprintf(out, "%-18s%06d\n", "database schema:", st.DBVersion)
	fmt.Fprintf(out, "%-18s%06d\n", "binary schema:", st.BinaryVersion)
	fmt.Fprintf(out, "%-18s%s\n", "state:", state)
	if st.State == "newer" {
		return 1
	}
	return 0
}

func migrateDown(args []string, out, errOut io.Writer, d migrateDeps) int {
	fs := flag.NewFlagSet("migrate down", flag.ContinueOnError)
	fs.SetOutput(errOut)
	toRaw := fs.String("to", "", "schema version to roll back to")
	backupID := fs.String("backup-id", "", "id of the backup taken before this rollback")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(errOut, migrateUsage)
		return 2
	}
	to, err := strconv.Atoi(*toRaw)
	if err != nil || to < 0 {
		fmt.Fprintf(errOut, "migrate down: --to must be a schema version >= 0\n%s\n", migrateUsage)
		return 2
	}
	if !backupIDRe.MatchString(*backupID) {
		fmt.Fprintln(errOut, "migrate down: --backup-id is required and must match "+backupIDRe.String()+
			"; take a backup first (scripts/deploy/backup.sh) and pass its db-<timestamp> name")
		return 1
	}

	db, engine, err := d.open()
	if err != nil {
		fmt.Fprintf(errOut, "migrate down: %v\n", err)
		return 1
	}
	defer db.Close()
	st, err := kkdb.Status(db, engine)
	if err != nil {
		fmt.Fprintf(errOut, "migrate down: %v\n", err)
		return 1
	}

	plan, err := kkdb.PlanDowngrade(db, engine, to)
	ctx := context.Background()
	if err != nil {
		var refused *kkdb.DowngradeRefusedError
		if errors.As(err, &refused) {
			auditMigrateDown(ctx, errOut, d, st.DBVersion, to, *backupID, bootstrap.AuditOutcomeDenied, refused.Reason)
		}
		fmt.Fprintf(errOut, "migrate down: %v\n", err)
		return 1
	}
	if len(plan) == 0 {
		fmt.Fprintf(out, "nothing to roll back: database schema %06d is at or below %06d\n", st.DBVersion, to)
		return 0
	}

	if err := kkdb.RollbackMigration(db, engine, to); err != nil {
		auditMigrateDown(ctx, errOut, d, st.DBVersion, to, *backupID, bootstrap.AuditOutcomeFailure, err.Error())
		fmt.Fprintf(errOut, "migrate down: %v\n", err)
		return 1
	}
	// Rolling back past the migration that created audit_log drops the audit
	// table, so this write is best effort and only warns on failure.
	auditMigrateDown(ctx, errOut, d, st.DBVersion, to, *backupID, bootstrap.AuditOutcomeSuccess, "")
	fmt.Fprintf(out, "rolled back %d migration(s): %06d -> %06d\n", len(plan), st.DBVersion, to)
	return 0
}

func auditMigrateDown(ctx context.Context, errOut io.Writer, d migrateDeps, from, to int, backupID string, outcome bootstrap.AuditOutcome, detail string) {
	if d.audit == nil {
		return
	}
	summary := map[string]any{"backup_id": backupID, "from": from, "to": to}
	if detail != "" {
		summary["detail"] = detail
	}
	raw, _ := json.Marshal(summary)
	entry := bootstrap.AuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Action:        "schema.migrate.down",
		ActorType:     "user",
		ActorID:       cliActorID(),
		ResourceType:  "schema",
		ResourceID:    fmt.Sprintf("%06d->%06d", from, to),
		Outcome:       outcome,
		ChangeSummary: string(raw),
	}
	if err := d.audit(ctx, entry); err != nil {
		fmt.Fprintf(errOut, "warning: could not record schema.migrate.down in the audit log: %v\n", err)
	}
}

func cliActorID() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}
