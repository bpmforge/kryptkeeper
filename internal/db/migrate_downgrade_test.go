// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func latestVersion(t *testing.T, engine string) int {
	t.Helper()
	ms, err := loadMigrations(engine)
	if err != nil {
		t.Fatal(err)
	}
	return maxEmbeddedVersion(ms)
}

func insertFutureVersion(t *testing.T, db *sql.DB, engine string, version int) {
	t.Helper()
	q := "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, 'from_the_future', '2099-01-01T00:00:00Z')"
	if engine == "postgres" {
		q = "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, 'from_the_future', '2099-01-01T00:00:00Z')"
	}
	if _, err := db.Exec(q, version); err != nil {
		t.Fatalf("insert future version: %v", err)
	}
}

func assertRefusesNewer(t *testing.T, db *sql.DB, engine string) {
	t.Helper()
	latest := latestVersion(t, engine)
	if err := RunMigrations(db, engine); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}
	insertFutureVersion(t, db, engine, latest+2)

	start := time.Now()
	err := RunMigrations(db, engine)
	elapsed := time.Since(start)

	var newer *SchemaNewerError
	if !errors.As(err, &newer) {
		t.Fatalf("RunMigrations error = %v, want *SchemaNewerError", err)
	}
	if newer.DBVersion != latest+2 || newer.BinaryVersion != latest {
		t.Fatalf("versions = db %d binary %d, want db %d binary %d", newer.DBVersion, newer.BinaryVersion, latest+2, latest)
	}
	for _, want := range []string{sixDigits(latest + 2), sixDigits(latest)} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name version %s", err, want)
		}
	}
	if elapsed > 5*time.Second {
		t.Fatalf("refusal took %v, want < 5s", elapsed)
	}
}

func sixDigits(v int) string { return fmt.Sprintf("%06d", v) }

func TestRunMigrations_RefusesNewerSchema_SQLite(t *testing.T) {
	assertRefusesNewer(t, freshSQLiteDB(t), "sqlite")
}

func TestRunMigrations_RefusesNewerSchema_Postgres(t *testing.T) {
	dsn := livePostgresDSN(t)
	assertRefusesNewer(t, freshPostgresDB(t, dsn), "postgres")
}

func TestStatus_CurrentPendingNewer(t *testing.T) {
	db := freshSQLiteDB(t)
	latest := latestVersion(t, "sqlite")

	st, err := Status(db, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if st.DBVersion != 0 || st.State != "pending" || st.BinaryVersion != latest {
		t.Fatalf("empty db status = %+v, want DBVersion 0 / pending / binary %d", st, latest)
	}
	for _, v := range st.Pending {
		if v == ciSeedVersion {
			t.Fatalf("CI seed %d must not be reported pending: %v", ciSeedVersion, st.Pending)
		}
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if st, _ = Status(db, "sqlite"); st.State != "current" || st.DBVersion != latest || len(st.Pending) != 0 {
		t.Fatalf("migrated status = %+v, want current at %d", st, latest)
	}

	if _, err := db.Exec("DELETE FROM schema_migrations WHERE version = ?", latest); err != nil {
		t.Fatal(err)
	}
	if st, _ = Status(db, "sqlite"); st.State != "pending" || !reflect.DeepEqual(st.Pending, []int{latest}) {
		t.Fatalf("one-behind status = %+v, want pending [%d]", st, latest)
	}

	insertFutureVersion(t, db, "sqlite", latest+1)
	if st, _ = Status(db, "sqlite"); st.State != "newer" || st.DBVersion != latest+1 {
		t.Fatalf("ahead status = %+v, want newer at %d", st, latest+1)
	}
}

func TestPlanDowngrade_RefusesWhenNewVocabularyRows(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insertAuditSQLite, "approval.request", "user", "r1", "pending_approval", "needs approval"); err != nil {
		t.Fatal(err)
	}

	_, err := PlanDowngrade(db, "sqlite", 75)
	var refused *DowngradeRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("PlanDowngrade(75) error = %v, want *DowngradeRefusedError", err)
	}
	if refused.Version != 76 || refused.Rows != 1 || !strings.Contains(refused.Reason, "append-only") {
		t.Fatalf("refusal = %+v", refused)
	}

	if _, err := PlanDowngrade(db, "sqlite", 78); err != nil {
		t.Fatalf("PlanDowngrade(78) does not cross 76 and must pass: %v", err)
	}
}

func TestPlanDowngrade_OrderAndNoop(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	latest := latestVersion(t, "sqlite")

	// Versions are gap-tolerant (CLAUDE.md): use the two real versions below
	// latest, not latest-1 and latest-2.
	ms, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	var below []int
	for _, m := range ms {
		if m.version < latest {
			below = append(below, m.version)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(below)))
	prev, prev2 := below[0], below[1]

	plan, err := PlanDowngrade(db, "sqlite", prev2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, []int{latest, prev}) {
		t.Fatalf("plan = %v, want [%d %d]", plan, latest, prev)
	}
	for _, to := range []int{latest, latest + 5} {
		plan, err := PlanDowngrade(db, "sqlite", to)
		if err != nil || len(plan) != 0 {
			t.Fatalf("PlanDowngrade(%d) = %v, %v; want empty", to, plan, err)
		}
	}
	if _, err := PlanDowngrade(db, "sqlite", -1); err == nil {
		t.Fatal("negative target must be an error")
	}
}

func TestPlanDowngrade_RefusesUnembeddedAppliedVersion(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	insertFutureVersion(t, db, "sqlite", latestVersion(t, "sqlite")+1)
	if _, err := PlanDowngrade(db, "sqlite", 70); err == nil || !strings.Contains(err.Error(), "not embedded") {
		t.Fatalf("error = %v, want a not-embedded refusal", err)
	}
}

func TestMigrationError_TextMatchesFailedMigrationRe(t *testing.T) {
	cause := errors.New("no such column: x")
	err := &MigrationError{Version: 12, Name: "certificate_ownership", Err: cause}
	re := regexp.MustCompile(`^apply migration \d{6}_[A-Za-z0-9_]+: `)
	if !re.MatchString(err.Error()) {
		t.Fatalf("text %q does not match the pattern bootstrap.failedMigrationRe parses", err.Error())
	}
	if !errors.Is(err, cause) || errors.Unwrap(err) != cause {
		t.Fatal("MigrationError must unwrap to its cause")
	}
}

func TestAppliedThisProcess_RecordsApplied(t *testing.T) {
	before := len(AppliedThisProcess())
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	got := AppliedThisProcess()
	if len(got) <= before {
		t.Fatalf("AppliedThisProcess grew %d -> %d, want growth after a fresh migrate", before, len(got))
	}
	got[0] = -1
	if AppliedThisProcess()[0] == -1 {
		t.Fatal("AppliedThisProcess must return a copy")
	}
}
