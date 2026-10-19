// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func isolatePoolCache(t *testing.T, open func(string) (*sql.DB, error)) {
	t.Helper()
	pgPoolsMu.Lock()
	saved := pgPoolsByService
	pgPoolsByService = map[string]*sql.DB{}
	pgPoolsMu.Unlock()
	prev := openPostgresDBFn
	openPostgresDBFn = open
	t.Cleanup(func() {
		openPostgresDBFn = prev
		pgPoolsMu.Lock()
		pgPoolsByService = saved
		pgPoolsMu.Unlock()
	})
}

// H-F3: a dial that hangs for one service must not block another service's
// store constructor behind pgPoolsMu.
func TestSharedPoolOpenDoesNotHoldLockWhileDialing(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	isolatePoolCache(t, func(dsn string) (*sql.DB, error) {
		if dsn == "slow" {
			close(entered)
			<-release
		}
		return sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "x.db"))
	})
	done := make(chan struct{})
	go func() {
		_, _ = openSharedPostgresDB("svc-a", "slow")
		close(done)
	}()
	<-entered
	fast := make(chan error, 1)
	go func() { _, err := openSharedPostgresDB("svc-b", "fast"); fast <- err }()
	select {
	case err := <-fast:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second service blocked behind a hung dial: pgPoolsMu held while opening")
	}
	close(release)
	<-done
}

// H-F3: two concurrent first opens of one service end up sharing one pool.
func TestSharedPoolConcurrentOpenSharesWinner(t *testing.T) {
	gate := make(chan struct{})
	isolatePoolCache(t, func(string) (*sql.DB, error) {
		db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "x.db"))
		<-gate
		return db, err
	})
	res := make(chan *sql.DB, 2)
	for i := 0; i < 2; i++ {
		go func() { db, _ := openSharedPostgresDB("svc", "dsn"); res <- db }()
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	a, b := <-res, <-res
	if a != b {
		t.Fatal("racing opens of one service returned different pools")
	}
}

// H-F2: shutdown closes and forgets every shared pool.
func TestCloseSharedPostgresPoolsClosesAndForgets(t *testing.T) {
	isolatePoolCache(t, func(string) (*sql.DB, error) {
		return sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "x.db"))
	})
	db, err := openSharedPostgresDB("svc", "dsn")
	if err != nil {
		t.Fatal(err)
	}
	CloseSharedPostgresPools()
	if err := db.Ping(); err == nil {
		t.Fatal("shared pool still open after CloseSharedPostgresPools")
	}
	pgPoolsMu.Lock()
	n := len(pgPoolsByService)
	pgPoolsMu.Unlock()
	if n != 0 {
		t.Fatalf("cache not emptied: %d", n)
	}
}
