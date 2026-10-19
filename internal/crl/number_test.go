// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"kryptkeeper/internal/db"
)

func openSharedSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func newMigratedSQLite(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crl.db")
	d := openSharedSQLite(t, path)
	if err := db.RunMigrations(d, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return path
}

func generatorWith(t *testing.T, a NumberAllocator) (*Generator, *testCRLCA) {
	t.Helper()
	ca := newTestCRLCA(t)
	g := NewGenerator(
		func(string) ([]RevokedCert, error) { return nil, nil },
		func(string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil },
		time.Hour,
	).WithNumberAllocator(a)
	return g, ca
}

// Two generators (two replicas) on one DB must never issue the same number
// for a CA, and the numbers each issues must rise.
func TestTwoGeneratorsSharingADBNeverRepeatANumber(t *testing.T) {
	path := newMigratedSQLite(t)
	a, caA := generatorWith(t, NewDBNumberAllocator(openSharedSQLite(t, path), false))
	b, _ := generatorWith(t, NewDBNumberAllocator(openSharedSQLite(t, path), false))
	b.caFunc = func(string) (*x509.Certificate, crypto.Signer, error) { return caA.cert, caA.key, nil }

	const perGen = 25
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for _, g := range []*Generator{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var prev *big.Int
			for i := 0; i < perGen; i++ {
				c, err := g.Generate("ca-1")
				if err != nil {
					t.Errorf("generate: %v", err)
					return
				}
				if prev != nil && c.Number.Cmp(prev) <= 0 {
					t.Errorf("number went %s -> %s", prev, c.Number)
				}
				prev = c.Number
				mu.Lock()
				if seen[c.Number.String()] {
					t.Errorf("number %s issued twice", c.Number)
				}
				seen[c.Number.String()] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 2*perGen {
		t.Fatalf("issued %d distinct numbers, want %d", len(seen), 2*perGen)
	}
}

// A restarted generator (new instance, same DB) continues after the last
// number instead of restarting at 1; base and delta share the sequence.
func TestRestartContinuesFromLastNumber(t *testing.T) {
	path := newMigratedSQLite(t)
	g1, ca := generatorWith(t, NewDBNumberAllocator(openSharedSQLite(t, path), false))
	g1.WithDelta(time.Minute, "http://crl.example")
	var last *big.Int
	for i := 0; i < 3; i++ {
		c, err := g1.Generate("ca-1")
		if err != nil {
			t.Fatal(err)
		}
		last = c.Number
	}
	d, err := g1.GenerateDelta("ca-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Number.Cmp(last) <= 0 {
		t.Fatalf("delta number %s must exceed base %s", d.Number, last)
	}
	last = d.Number

	g2, _ := generatorWith(t, NewDBNumberAllocator(openSharedSQLite(t, path), false))
	g2.caFunc = func(string) (*x509.Certificate, crypto.Signer, error) { return ca.cert, ca.key, nil }
	c, err := g2.Generate("ca-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := new(big.Int).Add(last, big.NewInt(1)); c.Number.Cmp(want) != 0 {
		t.Fatalf("after restart number = %s, want %s", c.Number, want)
	}
	// Another CA has its own sequence.
	o, err := g2.Generate("ca-2")
	if err != nil || o.Number.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("ca-2 first number = %v err=%v, want 1", o, err)
	}
}

type failingAllocator struct{}

func (failingAllocator) Next(context.Context, string) (*big.Int, error) {
	return nil, errors.New("db down")
}

// A DB failure must fail the CRL, never fall back to a counter that can go backwards.
func TestAllocatorFailureFailsGeneration(t *testing.T) {
	g, _ := generatorWith(t, failingAllocator{})
	if _, err := g.Generate("ca-1"); err == nil {
		t.Fatal("Generate succeeded despite allocator failure")
	}
}

func TestPostgresAllocatorMonotonic(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set")
	}
	// A private schema: other packages' tests run migrations against the same
	// Postgres concurrently, so this test must not migrate the shared one.
	schema := fmt.Sprintf("crl_num_%d", time.Now().UnixNano())
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE") })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	d, err := sql.Open("pgx", dsn+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	up, err := os.ReadFile("../db/migrations/postgres/000124_crl_numbers.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(string(up)); err != nil {
		t.Fatalf("apply 000124: %v", err)
	}
	scope := "pg-test-" + time.Now().Format("150405.000000000")
	a1 := NewDBNumberAllocator(d, true)
	a2 := NewDBNumberAllocator(d, true) // second "replica"
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	for _, a := range []*DBNumberAllocator{a1, a2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				n, err := a.Next(context.Background(), scope)
				if err != nil {
					t.Errorf("next: %v", err)
					return
				}
				mu.Lock()
				if seen[n.String()] {
					t.Errorf("duplicate %s", n)
				}
				seen[n.String()] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 50 {
		t.Fatalf("distinct = %d, want 50", len(seen))
	}
	n, _ := a1.Next(context.Background(), scope)
	if n.Cmp(big.NewInt(51)) != 0 {
		t.Fatalf("next = %s, want 51", n)
	}
}
