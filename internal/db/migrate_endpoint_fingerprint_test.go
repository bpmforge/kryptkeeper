// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"testing"
)

// fingerprintEngines runs fn against sqlite always and against live Postgres
// when KRYPTKEEPER_TEST_POSTGRES_DSN names a disposable database, so the two
// migration files are held to the same behaviour.
func fingerprintEngines(t *testing.T, fn func(t *testing.T, db *sql.DB, engine string)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, freshSQLiteDB(t), "sqlite") })
	t.Run("postgres", func(t *testing.T) {
		t.Setenv(ciSeedEnvVar, "")
		fn(t, freshPostgresDB(t, livePostgresDSN(t)), "postgres")
	})
}

func endpointHasColumn(t *testing.T, db *sql.DB, engine, column string) bool {
	t.Helper()
	if engine == "sqlite" {
		return columnExists(t, db, "endpoints", column)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'endpoints' AND column_name = $1", column).Scan(&n); err != nil {
		t.Fatalf("information_schema: %v", err)
	}
	return n > 0
}

func insertEndpoint(t *testing.T, db *sql.DB, engine, ip string, port int, protocol string) error {
	t.Helper()
	if engine == "postgres" {
		_, err := db.Exec("INSERT INTO endpoints (id, ip_address, port, protocol, tenant) VALUES ($1, $2, $3, $4, 'tenant-a')", "ep-"+ip, ip, port, protocol)
		return err
	}
	_, err := db.Exec("INSERT INTO endpoints (id, ip_address, port, protocol, tenant) VALUES (?, ?, ?, ?, 'tenant-a')", "ep-"+ip, ip, port, protocol)
	return err
}

func setConfidence(db *sql.DB, engine, ip, conf string) error {
	if engine == "postgres" {
		_, err := db.Exec("UPDATE endpoints SET tech_confidence = $1 WHERE ip_address = $2", conf, ip)
		return err
	}
	_, err := db.Exec("UPDATE endpoints SET tech_confidence = ? WHERE ip_address = ?", conf, ip)
	return err
}

func TestMigration000340_EndpointFingerprint(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		for _, c := range []string{"tech", "tech_confidence", "platform", "tls_stack", "tech_evidence"} {
			if !endpointHasColumn(t, db, engine, c) {
				t.Fatalf("endpoints.%s missing after 000340", c)
			}
		}
		for i, proto := range []string{"mssql", "mysql", "oracle", "redis", "mongodb", "kafka", "tls", "other"} {
			if err := insertEndpoint(t, db, engine, "10.0.0."+string(rune('1'+i)), 1000+i, proto); err != nil {
				t.Fatalf("protocol %q must be accepted: %v", proto, err)
			}
		}
		if err := insertEndpoint(t, db, engine, "10.0.1.1", 1, "bogus"); err == nil {
			t.Fatal("an unknown protocol must still violate the CHECK")
		}
		if err := setConfidence(db, engine, "10.0.0.1", "high"); err != nil {
			t.Fatalf("high confidence rejected: %v", err)
		}
		if err := setConfidence(db, engine, "10.0.0.1", "certain"); err == nil {
			t.Fatal("tech_confidence outside high|medium|low must violate the CHECK")
		}

		// Down: new-protocol rows survive as 'other', tenant data is intact, the
		// fingerprint columns are gone, and the identity index still enforces
		// one row per tenant, address and port.
		if err := RollbackMigration(db, engine, 339); err != nil {
			t.Fatalf("RollbackMigration: %v", err)
		}
		if endpointHasColumn(t, db, engine, "tech") || endpointHasColumn(t, db, engine, "tech_evidence") {
			t.Fatal("fingerprint columns still present after rollback")
		}
		var protocol, tenant string
		if err := db.QueryRow("SELECT protocol, tenant FROM endpoints WHERE port = 1000").Scan(&protocol, &tenant); err != nil {
			t.Fatalf("read back mssql row: %v", err)
		}
		if protocol != "other" || tenant != "tenant-a" {
			t.Fatalf("rolled-back row = %q/%q, want other/tenant-a", protocol, tenant)
		}
		if err := insertEndpoint(t, db, engine, "10.0.0.1", 1000, "tls"); err == nil {
			t.Fatal("duplicate tenant/address/port must still be rejected after rollback")
		}
		if err := insertEndpoint(t, db, engine, "10.0.2.1", 1433, "mssql"); err == nil {
			t.Fatal("mssql must violate the narrowed CHECK after rollback")
		}

		// Up again over populated data is clean and idempotent.
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
		if !endpointHasColumn(t, db, engine, "tech") {
			t.Fatal("tech missing after re-apply")
		}
	})
}

func TestMigration000341_AuthorizedIssuers(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		ph := func(n int) string {
			if engine == "postgres" {
				return "$" + string(rune('0'+n))
			}
			return "?"
		}
		insert := func(id, tenant, kind, value string) error {
			_, err := db.Exec("INSERT INTO authorized_issuers (id, tenant, name, kind, value, created_by, created_at) VALUES ("+
				ph(1)+","+ph(2)+",'n',"+ph(3)+","+ph(4)+",'tester','2030-01-01T00:00:00Z')", id, tenant, kind, value)
			return err
		}
		if err := insert("a1", "", "issuer_dn", "CN=Corp CA"); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := insert("a2", "", "issuer_dn", "CN=Corp CA"); err == nil {
			t.Fatal("the same rule twice in one tenant must violate the unique index")
		}
		if err := insert("a3", "tenant-b", "issuer_dn", "CN=Corp CA"); err != nil {
			t.Fatalf("the same rule in another tenant is allowed: %v", err)
		}
		if err := insert("a4", "", "bogus", "x"); err == nil {
			t.Fatal("an unknown kind must violate the CHECK")
		}
		if !endpointHasColumnIn(t, db, engine, "certificates", "issuer_class") {
			t.Fatal("certificates.issuer_class missing")
		}
		if err := RollbackMigration(db, engine, 340); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if endpointHasColumnIn(t, db, engine, "certificates", "issuer_class") {
			t.Fatal("issuer_class still present after rollback")
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
	})
}

func endpointHasColumnIn(t *testing.T, db *sql.DB, engine, table, column string) bool {
	t.Helper()
	if engine == "sqlite" {
		return columnExists(t, db, table, column)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2", table, column).Scan(&n); err != nil {
		t.Fatalf("information_schema: %v", err)
	}
	return n > 0
}
