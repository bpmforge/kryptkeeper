// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

const (
	dbMaxOpenConnsEnv = "KRYPTKEEPER_DB_MAX_OPEN_CONNS"
	dbMaxIdleConnsEnv = "KRYPTKEEPER_DB_MAX_IDLE_CONNS"

	// Every store type opens its own pool (about 40 pgx pools per hub once
	// constructors of one store share a pool; see docs/deployment.md), so these
	// are per-pool, not per-process. 3/1 keeps two replicas at ~80 steady idle
	// connections against Postgres's default max_connections=100; the former
	// 5/2 pinned ~66 idle on ONE replica.
	defaultPGMaxOpenConns = 3
	defaultPGMaxIdleConns = 1

	// Returns connections of rarely-used stores to Postgres instead of
	// holding them for the life of the process.
	pgConnMaxIdleTime = 60 * time.Second
)

type dbPoolConfig struct {
	maxOpen     int
	maxIdle     int
	maxIdleTime time.Duration
}

// pgPoolConfigFromEnv never fails: a bad knob must not stop a hub from
// booting, so it warns and falls back to the default.
func pgPoolConfigFromEnv(getenv func(string) string) dbPoolConfig {
	cfg := dbPoolConfig{
		maxOpen:     defaultPGMaxOpenConns,
		maxIdle:     defaultPGMaxIdleConns,
		maxIdleTime: pgConnMaxIdleTime,
	}
	cfg.maxOpen = positiveIntEnv(getenv, dbMaxOpenConnsEnv, cfg.maxOpen)
	cfg.maxIdle = positiveIntEnv(getenv, dbMaxIdleConnsEnv, cfg.maxIdle)
	if cfg.maxIdle > cfg.maxOpen {
		logging.Infof("%s=%d exceeds %s=%d; using idle=%d", dbMaxIdleConnsEnv, cfg.maxIdle, dbMaxOpenConnsEnv, cfg.maxOpen, defaultPGMaxIdleConns)
		cfg.maxIdle = defaultPGMaxIdleConns
		if cfg.maxIdle > cfg.maxOpen {
			cfg.maxIdle = cfg.maxOpen
		}
	}
	return cfg
}

func positiveIntEnv(getenv func(string) string, name string, def int) int {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		logging.Infof("invalid %s=%q (want integer >= 1); using default %d", name, raw, def)
		return def
	}
	return n
}

// pgPoolLogOnce is process-wide on purpose: ~33 stores call openPostgresDB
// and the settings are identical for all of them, so one line is enough.
var pgPoolLogOnce sync.Once

// openPostgresDB is the single entry point for pgx pools so the env knobs
// apply to every store. The DSN is never logged.
func openPostgresDB(dsn string) (*sql.DB, error) {
	cfg := pgPoolConfigFromEnv(os.Getenv)
	pgPoolLogOnce.Do(func() {
		logging.Infof("postgres pool settings (per store pool): max_open=%d max_idle=%d conn_max_idle_time=%s", cfg.maxOpen, cfg.maxIdle, cfg.maxIdleTime)
	})
	return openPool("pgx", dsn, cfg)
}

// openPostgresDBFn is a test seam: the pool-budget test counts opens without a server.
var openPostgresDBFn = openPostgresDB

// pgPoolsByService lets the several constructors of one store (the credential
// store alone is built ~15 times per hub: once per handler group and
// scheduler) share one pool instead of each pinning its own idle connection.
// Without it a single hub held ~120 connections at startup, past Postgres's
// default max_connections=100, and the stores opened last silently came up
// nil or in-memory (credential store 503, break-glass non-persistent).
//
// H-F1, kept package-level on purpose: newDBProviderState is a free generic
// function reached from 45 constructors that have no common receiver, so an
// injected registry would mean threading it through every one of them. The
// cost is that two hubs in one process (tests) share the cache; tests that
// reset a shared Postgres database must call closeSharedPostgresPools (see
// freshPostgresForTest).
//
// Close contract: production closes the cache once, at hub shutdown, through
// CloseSharedPostgresPools (deferred in main before any store is built, so it
// runs after the server and schedulers have stopped; a logging.Fatal path
// skips defers and relies on process exit). No store may Close() a shared
// pool; one that does must be listed in pgUnsharedServices, which
// TestNoSharedServiceClosesItsPool enforces. As a backstop,
// openSharedPostgresDB re-opens a cached pool that no longer answers Ping, so
// a holder built after a stray Close gets a live pool (holders built before it
// still see the closed one).
var (
	pgPoolsMu        sync.Mutex
	pgPoolsByService = map[string]*sql.DB{}
)

// pgUnsharedServices own their pool's lifetime: they are opened for one-shot
// use and Close()d, which would kill a shared pool under everyone else.
var pgUnsharedServices = map[string]bool{"compliance-attestation": true}

// pgPingTimeout bounds every liveness check so a hung Postgres cannot stall
// store construction for the driver's own timeout.
const pgPingTimeout = 3 * time.Second

// openSharedPostgresDB never dials or pings while holding pgPoolsMu: a hung
// server would otherwise block every store constructor behind one dial (H-F3).
func openSharedPostgresDB(service, dsn string) (*sql.DB, error) {
	if pgUnsharedServices[service] {
		return openPostgresDBFn(dsn)
	}
	key := service + "\x00" + dsn
	pgPoolsMu.Lock()
	cached := pgPoolsByService[key]
	pgPoolsMu.Unlock()
	if cached != nil {
		ctx, cancel := context.WithTimeout(context.Background(), pgPingTimeout)
		err := cached.PingContext(ctx)
		cancel()
		if err == nil {
			return cached, nil
		}
		pgPoolsMu.Lock()
		stale := pgPoolsByService[key] == cached
		if stale {
			delete(pgPoolsByService, key)
		}
		pgPoolsMu.Unlock()
		if stale {
			_ = cached.Close()
		}
	}
	db, err := openPostgresDBFn(dsn)
	if err != nil {
		return nil, err
	}
	pgPoolsMu.Lock()
	defer pgPoolsMu.Unlock()
	if winner, ok := pgPoolsByService[key]; ok {
		_ = db.Close() // lost the insert race; share the winner's pool
		return winner, nil
	}
	pgPoolsByService[key] = db
	return db, nil
}

// CloseSharedPostgresPools releases every shared pool at hub shutdown so
// Postgres sees a clean disconnect instead of dropped sockets on SIGTERM.
func CloseSharedPostgresPools() { closeSharedPostgresPools() }

// closeSharedPostgresPools closes and forgets every cached pool. Hub shutdown
// (via CloseSharedPostgresPools) and tests that DROP/recreate the schema under
// a live DSN use it, so no later holder inherits connections with stale cached
// prepared statements.
func closeSharedPostgresPools() {
	pgPoolsMu.Lock()
	pools := pgPoolsByService
	pgPoolsByService = map[string]*sql.DB{}
	pgPoolsMu.Unlock()
	for _, db := range pools {
		_ = db.Close()
	}
}
