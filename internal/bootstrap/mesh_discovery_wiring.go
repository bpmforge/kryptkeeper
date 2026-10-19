// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/logging"
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

// shortLivedMaxLifetime: a leaf valid for at most this long is a mesh-issued
// workload cert (Istio/Linkerd rotate in hours), noise once it has expired.
const shortLivedMaxLifetime = 48 * time.Hour

// meshClusterSweep is one configured kubeconfig source (W24-23).
type meshClusterSweep struct {
	name string
	mesh *discovery.MeshDiscovery
}

// MeshDiscoveryScheduler periodically sweeps mesh + SaaS sources.
type MeshDiscoveryScheduler struct {
	mesh *discovery.MeshDiscovery
	// clusters is re-read every tick; nil means only s.mesh, unprefixed.
	clusters func(ctx context.Context) []meshClusterSweep
	// leafRetention nil means the 7-day default.
	leafRetention func(ctx context.Context) time.Duration
	// saasEndpoints, when it returns a non-empty list, replaces the env
	// SaaS list of the legacy sweep (discovery.saas_endpoints).
	saasEndpoints func(ctx context.Context) []string
	store         scanResultUpserter
	pollInterval  time.Duration

	// nil when unavailable (soft-fail) — single-replica behavior.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewMeshDiscoverySchedulerFromEnv is dormant (nil) when mesh discovery
// is unconfigured or the discovery DB is unavailable.
func NewMeshDiscoverySchedulerFromEnv() *MeshDiscoveryScheduler {
	mesh := discovery.NewMeshDiscoveryFromEnv()
	if mesh == nil && !meshClustersConfigured() {
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
		logging.Warnf("mesh discovery: disabled (store unavailable: %v)", state.openErr)
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		logging.Infof("mesh discovery: disabled (schema: %v)", err)
		return nil
	}
	upserter, ok := any(state.store).(scanResultUpserter)
	if !ok {
		logging.Warn("mesh discovery: disabled (store cannot persist scan results)")
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
		clusters:      loadMeshClusterSweeps,
		leafRetention: meshLeafRetention,
		saasEndpoints: configuredSaaSEndpoints,
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
			logging.Warnf("mesh discovery: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}
	var eps []scanner.DiscoveredEndpoint
	errCount := 0
	for _, sw := range s.sweeps(ctx) {
		result := sw.mesh.Discover(ctx, fmt.Sprintf("mesh-%d-%s", now.Unix(), sw.name))
		for _, ep := range result.Endpoints {
			if sw.name != "" {
				ep.Host = sw.name + "/" + ep.Host
			}
			eps = append(eps, ep)
		}
		if result.ErrorCount > 0 {
			errCount += result.ErrorCount
			logging.Infof("mesh discovery: cluster %q had %d source error(s)", sw.name, result.ErrorCount)
		}
	}
	retention := defaultMeshLeafRetention
	if s.leafRetention != nil {
		retention = s.leafRetention(ctx)
	}
	eps, dropped := suppressStaleShortLived(eps, now, retention)
	if dropped > 0 {
		logging.Infof("mesh discovery: suppressed %d stale short-lived leaf cert(s) older than %s", dropped, retention)
	}
	out, err := s.store.upsertScanResults(ctx, eps)
	if err != nil {
		logging.Warnf("mesh discovery: persist failed: %v", err)
		return
	}
	// W19-22: a per-endpoint failure (e.g. a still-unhandled CHECK) no
	// longer aborts the whole sweep -- upsertScanResults isolates it per
	// row and reports it here instead of silently discarding it.
	if out.Skipped > 0 {
		logging.Infof("mesh discovery: %d endpoint(s) persisted, %d skipped: %s", out.Persisted, out.Skipped, out.FirstSkipReason)
	}
	if errCount > 0 {
		// A permission-denied source (e.g. K8s RBAC 403 reading a mesh
		// secret) is also persisted as an endpoint row carrying a
		// discovery-error issue (discoveryErrorIssuesJSON) -- visible via
		// GET /api/v1/discovery/endpoints, not only this log line.
		logging.Infof("mesh discovery: sweep completed with %d source error(s)", errCount)
	}
}

// sweeps is the legacy env sweep (unprefixed, owns SaaS endpoints) followed
// by one sweep per configured cluster.
func (s *MeshDiscoveryScheduler) sweeps(ctx context.Context) []meshClusterSweep {
	var out []meshClusterSweep
	legacy := s.mesh
	if s.saasEndpoints != nil {
		if list := s.saasEndpoints(ctx); len(list) > 0 {
			legacy = discovery.NewMeshDiscovery(legacyMeshConfigFromEnv(list), nil)
		}
	}
	if legacy != nil {
		out = append(out, meshClusterSweep{mesh: legacy})
	}
	if s.clusters != nil {
		out = append(out, s.clusters(ctx)...)
	}
	return out
}

// legacyMeshConfigFromEnv mirrors discovery.NewMeshDiscoveryFromEnv's
// KRYPTKEEPER_MESH_K8S_* vocabulary, with the SaaS list overridden.
func legacyMeshConfigFromEnv(saas []string) discovery.MeshConfig {
	cfg := discovery.MeshConfig{
		K8sBaseURL:    strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_K8S_URL")),
		BearerToken:   strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_K8S_TOKEN")),
		SaaSEndpoints: saas,
	}
	if ca := os.Getenv("KRYPTKEEPER_MESH_K8S_CA_CERT"); ca != "" {
		cfg.CACert = []byte(ca)
	} else if f := strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_K8S_CA_CERT_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			cfg.CACert = b
		}
	}
	return cfg
}

// configuredSaaSEndpoints reads discovery.saas_endpoints: a JSON array of
// "host:port" strings. Empty or invalid means "use the env list".
func configuredSaaSEndpoints(ctx context.Context) []string {
	cfg, _ := sharedDiscoveryStores.get()
	return parseSaaSEndpoints(discoveryConfigValueFrom(ctx, cfg, "discovery.saas_endpoints"))
}

func parseSaaSEndpoints(raw string) []string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") {
		return nil
	}
	var list []string
	if json.Unmarshal([]byte(raw), &list) != nil {
		return nil
	}
	out := list[:0]
	for _, e := range list {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func meshClustersConfigured() bool {
	srcs, err := kubeClusterSourcesLoader(context.Background())
	return err == nil && len(srcs) > 0
}

func loadMeshClusterSweeps(ctx context.Context) []meshClusterSweep {
	srcs, err := kubeClusterSourcesLoader(ctx)
	if err != nil {
		logging.Infof("mesh discovery: cluster config: %v", err)
		return nil
	}
	var out []meshClusterSweep
	for _, c := range srcs {
		if c.credErr != "" {
			logging.Infof("mesh discovery: cluster %q skipped: %s", c.Name, c.credErr)
			continue
		}
		out = append(out, meshClusterSweep{name: c.Name, mesh: discovery.NewMeshDiscovery(discovery.MeshConfig{K8sBaseURL: c.APIURL, BearerToken: c.Token, CACert: c.CACert}, nil)})
	}
	return out
}

// suppressStaleShortLived drops short-lived non-CA mesh leaves that began more
// than retention ago (they have long since rotated away), at ingest so they
// never reach the inventory. An endpoint left with no certs is dropped unless
// it carries an Error (a failed source must stay visible).
func suppressStaleShortLived(eps []scanner.DiscoveredEndpoint, now time.Time, retention time.Duration) (kept []scanner.DiscoveredEndpoint, dropped int) {
	for _, ep := range eps {
		switch ep.Protocol {
		case "istio-mesh", "linkerd-mesh", "k8s-tls-secret":
		default:
			kept = append(kept, ep)
			continue
		}
		certs := make([]scanner.DiscoveredCert, 0, len(ep.Certs))
		for _, c := range ep.Certs {
			if !c.IsCA && c.ValidUntil.Sub(c.ValidFrom) <= shortLivedMaxLifetime && now.Sub(c.ValidFrom) > retention {
				dropped++
				continue
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 && ep.Error == "" {
			continue
		}
		ep.Certs = certs
		kept = append(kept, ep)
	}
	return kept, dropped
}
