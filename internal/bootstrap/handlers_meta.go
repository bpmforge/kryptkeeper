// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// ReadinessProbe reports whether the hub's dependencies (storage backend,
// keystore) are reachable. nil is treated as always-ready, so callers that
// have no dependency to check (e.g. a plain in-memory bootstrap.Run) keep
// today's static-200 behavior.
type ReadinessProbe func(ctx context.Context) error

const readinessTimeout = 2 * time.Second

func registerMetaHandlers(mux *http.ServeMux, ready ReadinessProbe) {
	mux.HandleFunc("/", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "kryptkeeper bootstrap app")
	}))
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
				log.Printf("/readyz: dependency check failed: %v", err)
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
		}{
			Service:     "kryptkeeper",
			Version:     version,
			Commit:      os.Getenv("APP_COMMIT"),
			Environment: os.Getenv("APP_ENV"),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/meta response: %v", err)
		}
	}))
}
