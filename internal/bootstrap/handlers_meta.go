// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/keystore"
)

// ReadinessProbe reports whether the hub's dependencies (storage backend,
// keystore) are reachable. nil is treated as always-ready, so callers that
// have no dependency to check (e.g. a plain in-memory bootstrap.Run) keep
// today's static-200 behavior.
type ReadinessProbe func(ctx context.Context) error

// errShuttingDown is what the readiness probe returns once SIGTERM arrived;
// /healthz stays 200 so the kubelet does not restart a pod that is draining.
var errShuttingDown = errors.New("shutting down")

// withDrainProbe makes the probe fail with errShuttingDown once draining is
// set, before any dependency is consulted.
func withDrainProbe(draining *atomic.Bool, next ReadinessProbe) ReadinessProbe {
	return func(ctx context.Context) error {
		if draining != nil && draining.Load() {
			return errShuttingDown
		}
		if next == nil {
			return nil
		}
		return next(ctx)
	}
}

const readinessTimeout = 2 * time.Second

func registerMetaHandlers(mux *http.ServeMux, ready ReadinessProbe) {
	banner := getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "kryptkeeper bootstrap app")
	})
	// An unmounted API path (a feature that is off, e.g. SCEP without
	// KRYPTKEEPER_SCEP_ENABLED) must not fall through to the banner: clients
	// got 200 text/plain for GET and 405 for POST, and the UI reported a
	// load failure instead of "not enabled".
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeNotFound(w, "no such API endpoint, or the feature behind it is not enabled")
	})
	mux.HandleFunc("/", banner)
	// /healthz is LIVENESS ONLY (process is up) — it must never check
	// dependencies. A transient DB/keystore blip should make the pod
	// unready, not restart it.
	mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
			defer cancel()
			if err := ready(ctx); err != nil {
				if errors.Is(err, errShuttingDown) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"status":"unready","error":"shutting down"}`))
					return
				}
				logging.Warnf("/readyz: dependency check failed: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"unready","error":"dependency check failed"}`))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}))
	mux.HandleFunc("/api/v1/meta", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		version := os.Getenv("APP_VERSION")
		if version == "" {
			version = "dev"
		}

		resp := struct {
			Service     string `json:"service"`
			Version     string `json:"version"`
			Commit      string `json:"commit,omitempty"`
			Environment string `json:"environment,omitempty"`
			// W23-32: lets the FIPS image smoke (and operators) confirm the
			// live module state instead of trusting the image tag.
			FIPS keystore.FIPSPostureInfo `json:"fips"`
		}{
			Service:     "kryptkeeper",
			Version:     version,
			Commit:      os.Getenv("APP_COMMIT"),
			Environment: os.Getenv("APP_ENV"),
			FIPS:        keystore.FIPSPosture(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/meta response: %v", err)
		}
	}))
}
