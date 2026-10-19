// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"time"
)

// NumberAllocator hands out CRL numbers. Next must return a number strictly
// greater than every number it returned before for the same scope, across
// processes and restarts (RFC 5280 5.2.3). A scope is a CA id, or
// "<ca>/s<N>" for a shard.
type NumberAllocator interface {
	Next(ctx context.Context, scope string) (*big.Int, error)
}

// DBNumberAllocator keeps one counter row per scope in crl_numbers
// (migration 000124). One upsert-with-RETURNING statement is the whole
// protocol, so replicas sharing the DB cannot draw the same number.
type DBNumberAllocator struct {
	db       *sql.DB
	postgres bool
}

// NewDBNumberAllocator uses the shared core DB; postgres selects $N placeholders.
func NewDBNumberAllocator(db *sql.DB, postgres bool) *DBNumberAllocator {
	return &DBNumberAllocator{db: db, postgres: postgres}
}

// Next atomically increments and returns the counter for scope.
func (a *DBNumberAllocator) Next(ctx context.Context, scope string) (*big.Int, error) {
	q := `INSERT INTO crl_numbers (scope, last_number) VALUES (?, 1)
ON CONFLICT (scope) DO UPDATE SET last_number = crl_numbers.last_number + 1
RETURNING last_number`
	if a.postgres {
		q = `INSERT INTO crl_numbers (scope, last_number) VALUES ($1, 1)
ON CONFLICT (scope) DO UPDATE SET last_number = crl_numbers.last_number + 1
RETURNING last_number`
	}
	// SQLite serialises writers; a concurrent writer surfaces as SQLITE_BUSY
	// when no busy_timeout is configured, so retry briefly instead of failing
	// the CRL. The statement is atomic, so a retry can never skip or repeat.
	var n int64
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		err = a.db.QueryRowContext(ctx, q, scope).Scan(&n)
		if err == nil {
			return big.NewInt(n), nil
		}
		if a.postgres || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(attempt+1) * 10 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("allocate CRL number for %q: %w", scope, err)
}

// WithNumberAllocator makes the generator take CRL numbers from a. Without
// it the generator falls back to a per-process in-memory counter, which is
// only correct for a single process that never restarts (tests, or a
// deployment with no database); it restarts at 1 and differs between
// replicas, so production wiring must always supply a DB allocator. Call
// before serving.
func (g *Generator) WithNumberAllocator(a NumberAllocator) *Generator {
	g.allocator = a
	return g
}
