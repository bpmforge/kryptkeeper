// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/bootstrap"
	kkdb "kryptkeeper/internal/db"
)

type migrateHarness struct {
	deps    migrateDeps
	db      *sql.DB
	audited []bootstrap.AuditEntry
}

func newMigrateHarness(t *testing.T, migrate bool) *migrateHarness {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kk.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if migrate {
		if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
			t.Fatal(err)
		}
	}
	h := &migrateHarness{db: db}
	// The command closes the handle it is given; hand it a thin wrapper so the
	// test can keep inspecting the same file afterwards.
	path := dbPath(t, db)
	h.deps = migrateDeps{
		open: func() (*sql.DB, string, error) {
			c, err := sql.Open("sqlite", path)
			if err != nil {
				return nil, "", err
			}
			c.SetMaxOpenConns(1)
			return c, "sqlite", nil
		},
		audit: func(_ context.Context, e bootstrap.AuditEntry) error {
			h.audited = append(h.audited, e)
			return nil
		},
	}
	t.Cleanup(func() { _ = db.Close() })
	return h
}

func dbPath(t *testing.T, db *sql.DB) string {
	t.Helper()
	var seq int
	var name, file string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func (h *migrateHarness) run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = runMigrate(args, &out, &errOut, h.deps)
	return code, out.String(), errOut.String()
}

func (h *migrateHarness) maxVersion(t *testing.T) int {
	t.Helper()
	var v int
	if err := h.db.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func latestSQLiteVersion(t *testing.T) int {
	t.Helper()
	probe, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	st, err := kkdb.Status(probe, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	return st.BinaryVersion
}

func TestMigrateStatus_PrintsFourLines(t *testing.T) {
	h := newMigrateHarness(t, true)
	latest := latestSQLiteVersion(t)
	code, out, errOut := h.run("status")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	want := fmt.Sprintf("engine:           sqlite\ndatabase schema:  %06d\nbinary schema:    %06d\nstate:            current\n", latest, latest)
	if out != want {
		t.Fatalf("status output:\n%q\nwant:\n%q", out, want)
	}
}

func TestMigrateStatus_PendingAndNewer(t *testing.T) {
	h := newMigrateHarness(t, false)
	if code, out, _ := h.run("status"); code != 0 || !strings.Contains(out, "pending (") || !strings.Contains(out, "to apply)") {
		t.Fatalf("empty db: exit %d output %q, want pending", code, out)
	}

	if err := kkdb.RunMigrations(h.db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	future := latestSQLiteVersion(t) + 3
	if _, err := h.db.Exec("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, 'future', 'x')", future); err != nil {
		t.Fatal(err)
	}
	code, out, _ := h.run("status")
	if code != 1 || !strings.Contains(out, "newer (database is ahead of this binary)") || !strings.Contains(out, fmt.Sprintf("%06d", future)) {
		t.Fatalf("newer db: exit %d output %q", code, out)
	}
}

func TestMigrateDown_UsageAndBackupID(t *testing.T) {
	h := newMigrateHarness(t, true)
	before := h.maxVersion(t)

	cases := []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"no subcommand", nil, 2, "usage"},
		{"unknown subcommand", []string{"sideways"}, 2, "unknown subcommand"},
		{"status extra arg", []string{"status", "x"}, 2, "usage"},
		{"missing --to", []string{"down", "--backup-id", "db-20260101T000000Z"}, 2, "--to"},
		{"negative --to", []string{"down", "--to", "-1", "--backup-id", "db-20260101T000000Z"}, 2, "--to"},
		{"non-numeric --to", []string{"down", "--to", "abc", "--backup-id", "db-20260101T000000Z"}, 2, "--to"},
		{"missing backup id", []string{"down", "--to", "70"}, 1, "--backup-id"},
		{"short backup id", []string{"down", "--to", "70", "--backup-id", "db-1"}, 1, "scripts/deploy/backup.sh"},
		{"hostile backup id", []string{"down", "--to", "70", "--backup-id", "db-2026 01;rm"}, 1, "--backup-id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := h.run(c.args...)
			if code != c.code || !strings.Contains(errOut, c.msg) {
				t.Fatalf("exit %d stderr %q, want exit %d containing %q", code, errOut, c.code, c.msg)
			}
		})
	}
	if got := h.maxVersion(t); got != before {
		t.Fatalf("schema moved %d -> %d despite refused commands", before, got)
	}
	if len(h.audited) != 0 {
		t.Fatalf("usage refusals must not be audited, got %d entries", len(h.audited))
	}
}

func TestMigrateDown_RefusedWhenNewVocabularyRows(t *testing.T) {
	h := newMigrateHarness(t, true)
	latest := h.maxVersion(t)
	if _, err := h.db.Exec(`INSERT INTO audit_log (action, actor_type, actor_id, resource_type, resource_id, outcome, change_summary, tenant)
		VALUES ('approval.request', 'user', 'alice', 'test', 'r1', 'pending_approval', 'x', 'default')`); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := h.run("down", "--to", "75", "--backup-id", "db-20260101T000000Z")
	if code != 1 || !strings.Contains(errOut, "000076 vocabulary") {
		t.Fatalf("exit %d stderr %q, want exit 1 naming the 000076 vocabulary", code, errOut)
	}
	if got := h.maxVersion(t); got != latest {
		t.Fatalf("schema moved %d -> %d on a refused rollback", latest, got)
	}
	if len(h.audited) != 1 || h.audited[0].Action != "schema.migrate.down" || h.audited[0].Outcome != bootstrap.AuditOutcomeDenied {
		t.Fatalf("audit = %+v, want one denied schema.migrate.down", h.audited)
	}
}

func TestMigrateDown_SucceedsAndAudits(t *testing.T) {
	h := newMigrateHarness(t, true)
	latest := h.maxVersion(t)
	// Versions are gap-tolerant (CLAUDE.md), so the rollback target is the
	// highest applied version below latest, not latest-1.
	var target int
	if err := h.db.QueryRow("SELECT MAX(version) FROM schema_migrations WHERE version < ?", latest).Scan(&target); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := h.run("down", "--to", fmt.Sprint(target), "--backup-id", "db-20260101T000000Z")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if want := fmt.Sprintf("rolled back 1 migration(s): %06d -> %06d\n", latest, target); out != want {
		t.Fatalf("output %q, want %q", out, want)
	}
	if got := h.maxVersion(t); got != target {
		t.Fatalf("schema_migrations max = %d, want %d", got, target)
	}
	if len(h.audited) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audited))
	}
	e := h.audited[0]
	if e.Action != "schema.migrate.down" || e.Outcome != bootstrap.AuditOutcomeSuccess || e.ActorType != "user" ||
		!strings.HasPrefix(e.ActorID, "cli") || e.ResourceType != "schema" ||
		e.ResourceID != fmt.Sprintf("%06d->%06d", latest, target) {
		t.Fatalf("audit entry = %+v", e)
	}
	for _, want := range []string{`"backup_id":"db-20260101T000000Z"`, fmt.Sprintf(`"from":%d`, latest), fmt.Sprintf(`"to":%d`, target)} {
		if !strings.Contains(e.ChangeSummary, want) {
			t.Fatalf("ChangeSummary %q lacks %s", e.ChangeSummary, want)
		}
	}

	code, out, _ = h.run("down", "--to", fmt.Sprint(target), "--backup-id", "db-20260101T000000Z")
	if code != 0 || !strings.Contains(out, "nothing to roll back") || len(h.audited) != 1 {
		t.Fatalf("repeat: exit %d output %q audits %d, want a silent no-op", code, out, len(h.audited))
	}
}

func TestMigrateDown_AuditFailureIsOnlyAWarning(t *testing.T) {
	h := newMigrateHarness(t, true)
	h.deps.audit = func(context.Context, bootstrap.AuditEntry) error { return fmt.Errorf("audit_log: no such table") }
	target := h.maxVersion(t) - 1
	code, _, errOut := h.run("down", "--to", fmt.Sprint(target), "--backup-id", "db-20260101T000000Z")
	if code != 0 || !strings.Contains(errOut, "could not record schema.migrate.down") {
		t.Fatalf("exit %d stderr %q, want success with an audit warning", code, errOut)
	}
}

// TestBootRefusesNewerSchema runs the real binary: an N-1 hub started against
// an N database must exit non-zero quickly and name both versions.
func TestBootRefusesNewerSchema(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "kk")
	if out, err := exec.Command(goBin, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "kryptkeeper.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	latest := latestSQLiteVersion(t)
	if _, err := db.Exec("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, 'future', 'x')", latest+2); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"APP_CERTIFICATE_PROVIDER=ca",
		"KRYPTKEEPER_DB_MODE=sqlite",
		"KRYPTKEEPER_DATA_DIR=" + dataDir,
		"APP_BOOTSTRAP_TOKEN=t",
		"KRYPTKEEPER_KEYSTORE_PASSPHRASE=p",
	}
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("binary did not exit within 5s:\n%s", out)
	}
	if runErr == nil {
		t.Fatalf("binary exited 0 against a newer schema:\n%s", out)
	}
	for _, want := range []string{fmt.Sprintf("%06d", latest+2), fmt.Sprintf("%06d", latest)} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("output lacks version %s:\n%s", want, out)
		}
	}
}
