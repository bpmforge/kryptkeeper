// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/discovery"
	"kryptkeeper/internal/discovery/scanner"
)

// W12-04: the wiring W7-06 disclosed. Mesh/SaaS discovery runs on a
// schedule and persists through the SAME store network scans use —
// same tables, same dedupe, same finding funnel, no parallel store.

const haLockMeshDiscovery = "mesh-discovery-scheduler"

// scanResultUpserter is the slice of the discovery store the mesh
// sweep needs; both concrete stores implement it.
type scanResultUpserter interface {
	upsertScanResults(ctx context.Context, results []scanner.DiscoveredEndpoint) (upsertOutcome, error)
}

// MeshDiscoveryScheduler periodically sweeps mesh + SaaS sources.
type MeshDiscoveryScheduler struct {
	mesh         *discovery.MeshDiscovery
	store        scanResultUpserter
	pollInterval time.Duration

	// nil when unavailable (soft-fail) — single-replica behavior.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewMeshDiscoverySchedulerFromEnv is dormant (nil) when mesh discovery
// is unconfigured or the discovery DB is unavailable.
func NewMeshDiscoverySchedulerFromEnv() *MeshDiscoveryScheduler {
	mesh := discovery.NewMeshDiscoveryFromEnv()
	if mesh == nil {
		return nil
	}
	state := newDBProviderState[dbDiscoveryStore](
		"mesh-discovery",
		discoveryDBSQLiteDSNFromEnv,
		discoveryDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_DISCOVERY_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) dbDiscoveryStore { return &sqliteDiscoveryStore{db: db} },
		func(db *sql.DB) dbDiscoveryStore { return &postgresDiscoveryStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		log.Printf("mesh discovery: disabled (store unavailable: %v)", state.openErr)
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		log.Printf("mesh discovery: disabled (schema: %v)", err)
		return nil
	}
	upserter, ok := any(state.store).(scanResultUpserter)
	if !ok {
		log.Print("mesh discovery: disabled (store cannot persist scan results)")
		return nil
	}
	minutes := 60
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_SWEEP_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			minutes = n
		}
	}
	return &MeshDiscoveryScheduler{
		mesh:          mesh,
		store:         upserter,
		pollInterval:  time.Duration(minutes) * time.Minute,
		haCoordinator: newHACoordinatorFromEnvLogged(),
		stop:          make(chan struct{}),
	}
}

func (s *MeshDiscoveryScheduler) Start() {
	go func() {
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.tick(context.Background(), time.Now())
			}
		}
	}()
}

func (s *MeshDiscoveryScheduler) Stop() { s.once.Do(func() { close(s.stop) }) }

func (s *MeshDiscoveryScheduler) tick(ctx context.Context, now time.Time) {
	// HA gate: only the lease holder sweeps; lock errors fail closed.
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockMeshDiscovery, 2*s.pollInterval)
		if err != nil {
			log.Printf("mesh discovery: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}
	result := s.mesh.Discover(ctx, fmt.Sprintf("mesh-%d", now.Unix()))
	out, err := s.store.upsertScanResults(ctx, result.Endpoints)
	if err != nil {
		log.Printf("mesh discovery: persist failed: %v", err)
		return
	}
	// W19-22: a per-endpoint failure (e.g. a still-unhandled CHECK) no
	// longer aborts the whole sweep -- upsertScanResults isolates it per
	// row and reports it here instead of silently discarding it.
	if out.Skipped > 0 {
		log.Printf("mesh discovery: %d endpoint(s) persisted, %d skipped: %s", out.Persisted, out.Skipped, out.FirstSkipReason)
	}
	if result.ErrorCount > 0 {
		// A permission-denied source (e.g. K8s RBAC 403 reading a mesh
		// secret) is also persisted as an endpoint row carrying a
		// discovery-error issue (discoveryErrorIssuesJSON) -- visible via
		// GET /api/v1/discovery/endpoints, not only this log line.
		log.Printf("mesh discovery: sweep completed with %d source error(s)", result.ErrorCount)
	}
}
