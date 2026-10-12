// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

func TestMigrationIsAllAdditive_Classification(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want bool
	}{
		{"add column", "ALTER TABLE t ADD COLUMN a TEXT;", true},
		{"add column if not exists", "ALTER TABLE t ADD COLUMN IF NOT EXISTS a TEXT;", true},
		{"two add columns + comment", "-- c\nALTER TABLE t ADD COLUMN a TEXT;\nALTER TABLE t ADD COLUMN b TEXT;", true},
		{"create table if not exists + index", "CREATE TABLE IF NOT EXISTS x (a TEXT);\nCREATE UNIQUE INDEX IF NOT EXISTS i ON x(a);", true},
		{"plain create table", "CREATE TABLE x (a TEXT);", false},
		{"plain create index", "CREATE INDEX i ON x(a);", false},
		{"drop column", "ALTER TABLE t DROP COLUMN a;", false},
		{"add + drop in one", "ALTER TABLE t ADD COLUMN a TEXT, DROP COLUMN b;", false},
		{"add constraint", "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0);", false},
		{"insert", "INSERT INTO t VALUES (1);", false},
		{"mixed", "ALTER TABLE t ADD COLUMN a TEXT;\nUPDATE t SET a='x';", false},
		{"rebuild", "PRAGMA foreign_keys=OFF;\nALTER TABLE t ADD COLUMN a TEXT;", false},
		{"empty", "-- nothing\n", false},
	}
	for _, c := range cases {
		if got := migrationIsAllAdditive(migrationFile{upSQL: c.sql}); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// Every ADD COLUMN-only migration that a store also self-heals must apply
// tolerantly on both engines.
func TestAddColumnMigrationsAreAutoTolerant(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		ms, err := loadMigrations(engine)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ssh_certificates_template_id", "managed_targets_verify_host_port", "managed_targets_auto_renew_set_by"} {
			found := false
			for _, m := range ms {
				if m.name == name {
					found = true
					if !migrationUsesTolerantApply(m) {
						t.Errorf("%s/%s must apply tolerantly", engine, name)
					}
				}
			}
			if !found {
				t.Errorf("%s: migration %s not found", engine, name)
			}
		}
	}
}
