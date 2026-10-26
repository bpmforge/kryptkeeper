// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"fmt"
	"kryptkeeper/internal/logging"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/bootstrap"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/crl"
)

// revocationHTTPHandler serves only the CRL and OCSP endpoints. CRLs and OCSP
// responses are signed by the CA, so they need no transport security, and
// RFC 5280 relying parties fetch CDP/AIA over plain HTTP. Over HTTPS the
// main listener's client-certificate request (W20-08) makes Windows' WinHTTP
// revocation fetch fail with ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED (W20-10).
// Nothing else is reachable here: no API, UI or enrollment over plaintext.
func revocationHTTPHandler(crl, ocsp http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/crl/", crl)
	mux.Handle("/ocsp", ocsp)
	mux.Handle("/ocsp/", ocsp)
	return mux
}

// externalCAGuard answers 404 external_ca for the CRL of an external CA: the
// hub holds no key for it and its revocation data lives at the upstream, so
// serving an empty list from here would read as "nothing revoked" (W36-02).
func externalCAGuard(engine ca.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := crl.RequestCAID(r.URL.Path); ok {
			if c, err := engine.GetCA(id); err == nil && c.Type == ca.CATypeExternal {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"external_ca","message":"this CA is operated by an external issuer; use its own CRL and OCSP"}`))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// startRevocationHTTP serves revocationHTTPHandler on
// KRYPTKEEPER_REVOCATION_HTTP_ADDR when it is set. It is opt-in: a hub
// without it keeps a single TLS listener.
func startRevocationHTTP(crl, ocsp http.Handler) {
	addr := strings.TrimSpace(os.Getenv("KRYPTKEEPER_REVOCATION_HTTP_ADDR"))
	if addr == "" {
		return
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           revocationHTTPHandler(crl, ocsp),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		logging.Infof("revocation endpoints (CRL, OCSP) over plain HTTP on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Infof("revocation HTTP listener stopped: %v", err)
		}
	}()
}

// revocationBaseURL is where certificates point relying parties for CRL and
// OCSP: KRYPTKEEPER_REVOCATION_BASE_URL (the plain-HTTP listener's public
// address) when set, otherwise the hub's public base URL.
func revocationBaseURL(publicBase string) string {
	if v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_REVOCATION_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(publicBase, "/")
}

// versionSyncer is a revocation cache that can be told the shared DB's
// revocation version stamp (crl.Generator, ocsp.Responder).
type versionSyncer interface{ SyncVersion(stamp string) bool }

const (
	defaultRevocationSyncInterval = 5 * time.Second
	minRevocationSyncInterval     = time.Second
)

// revocationStamp is a cheap version stamp of the revocation state shared by
// all replicas, "<count>|<max revoked_at>" over certificates.revoked_at (W23-26,
// derived, no migration). A revoke raises the count or the max; an un-revoke
// (certificateHold removal) lowers the count. Residual edge: one revoke plus
// one un-revoke between two polls that leave the max unchanged keeps the stamp
// equal; the 24h CRL/OCSP validity still bounds that. CAST makes the postgres
// TIMESTAMPTZ comparable as text; the SQL is identical on both engines. Cost
// is one aggregate scan of certificates per poll (W23-29 soak to confirm).
func revocationStamp(ctx context.Context, db *sql.DB) (string, error) {
	var count int64
	var maxAt string
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(CAST(MAX(revoked_at) AS TEXT), '') FROM certificates WHERE revoked_at IS NOT NULL`,
	).Scan(&count, &maxAt)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d|%s", count, maxAt), nil
}

// revocationSyncInterval reads KRYPTKEEPER_REVOCATION_SYNC_INTERVAL: default
// 5s, floor 1s, invalid values log and fall back to the default.
func revocationSyncInterval() time.Duration {
	v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_REVOCATION_SYNC_INTERVAL"))
	if v == "" {
		return defaultRevocationSyncInterval
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		logging.Infof("invalid KRYPTKEEPER_REVOCATION_SYNC_INTERVAL %q: using %s", v, defaultRevocationSyncInterval)
		return defaultRevocationSyncInterval
	}
	if d < minRevocationSyncInterval {
		return minRevocationSyncInterval
	}
	return d
}

// startRevocationSync polls the shared DB's revocation stamp and makes every
// syncer drop its cache when it changes, so a revoke on one replica reaches
// CRL and OCSP on all of them. A no-op without a database. A stamp query
// error keeps the caches: clearing on a DB blip would make every replica
// re-sign everything and mask the outage.
func startRevocationSync(ctx context.Context, db *sql.DB, syncers ...versionSyncer) {
	if db == nil {
		return
	}
	go runRevocationSync(ctx, db, revocationSyncInterval(), syncers...)
}

func runRevocationSync(ctx context.Context, db *sql.DB, interval time.Duration, syncers ...versionSyncer) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	poll := func() {
		stamp, err := revocationStamp(ctx, db)
		if err != nil {
			if ctx.Err() == nil {
				logging.Warnf("revocation stamp unavailable, keeping caches: %v", err)
			}
			return
		}
		changed := false
		for _, s := range syncers {
			if s.SyncVersion(stamp) {
				changed = true
			}
		}
		if changed {
			logging.Infof("revocation stamp changed: caches dropped")
		}
	}
	poll() // record the baseline stamp
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			poll()
		}
	}
}

// crlDeltaIntervalFromEnv reads KRYPTKEEPER_CRL_DELTA_INTERVAL (a Go
// duration). Unset, 0 or invalid mean delta CRLs are off (W23-49).
func crlDeltaIntervalFromEnv() time.Duration {
	v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_CRL_DELTA_INTERVAL"))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		logging.Infof("invalid KRYPTKEEPER_CRL_DELTA_INTERVAL %q: delta CRLs stay off", v)
		return 0
	}
	if d == 0 {
		return 0
	}
	logging.Infof("delta CRLs enabled, interval %s", d)
	return d
}

// crlAuditSink turns generator events into audit rows; crl.stale also logs
// the ALERT line (repo convention: log line plus audit row).
func crlAuditSink(audit bootstrap.AuditProvider) func(crl.Event) {
	return func(ev crl.Event) {
		if ev.Action == crl.ActionStale {
			logging.Infof("ALERT crl.stale ca=%s %s", ev.CAID, ev.Detail)
		}
		if audit == nil {
			return
		}
		outcome := bootstrap.AuditOutcomeSuccess
		if ev.Failure {
			outcome = bootstrap.AuditOutcomeFailure
		}
		if err := audit.AppendEntry(context.Background(), bootstrap.AuditEntry{
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			Action:        ev.Action,
			ActorType:     "system",
			ActorID:       "crl",
			ResourceType:  "crl",
			ResourceID:    ev.CAID,
			Outcome:       outcome,
			ChangeSummary: ev.Detail,
		}); err != nil {
			logging.Warnf("crl audit append failed action=%s ca=%s: %v", ev.Action, ev.CAID, err)
		}
	}
}

// configureCRL wires audit events and, when KRYPTKEEPER_CRL_DELTA_INTERVAL is
// set, delta CRLs onto g. KRYPTKEEPER_CRL_SHARDS>1 turns on IDP-partitioned
// shard CRLs instead; the two are mutually exclusive in v1.0 (no per-shard
// deltas), and shards win.
func configureCRL(g *crl.Generator, audit bootstrap.AuditProvider, publicBase string) {
	g.WithEventSink(crlAuditSink(audit))
	shards := crl.ShardCountFromEnv()
	if shards > 1 {
		g.WithShards(shards, publicBase)
		if crlDeltaIntervalFromEnv() > 0 {
			logging.Warn("KRYPTKEEPER_CRL_DELTA_INTERVAL ignored: delta CRLs cannot be combined with KRYPTKEEPER_CRL_SHARDS")
		}
		return
	}
	if d := crlDeltaIntervalFromEnv(); d > 0 {
		g.WithDelta(d, publicBase)
	}
}

// shardPointers makes the default CRL pointer ("<base>/crl/<ca>.crl") the
// serial's shard URL. A CA with its own crl_distribution_points keeps them
// (operator override, as in W20-12); OCSP URLs pass through.
func shardPointers(base ca.RevocationPointersFunc, publicBase string, n int) ca.RevocationPointersForSerialFunc {
	return func(caID string, serial *big.Int) ([]string, []string) {
		crlURLs, ocspURLs := base(caID)
		if len(crlURLs) == 1 && crlURLs[0] == publicBase+"/crl/"+caID+".crl" {
			crlURLs = []string{crl.ShardURL(publicBase, caID, crl.ShardIndex(serial, n))}
		}
		return crlURLs, ocspURLs
	}
}
