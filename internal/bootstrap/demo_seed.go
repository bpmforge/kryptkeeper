// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"os"
	"strings"
	"time"
)

// configKeyDemoSeededAt is the runtime-config key that marks a hub as holding
// demo data (W37-07, D-310). `kryptkeeper demo seed` sets it through the public
// config API at the end of seeding and `demo reset` deletes it, so the marker
// and its audit trail need no route of their own.
const configKeyDemoSeededAt = "demo.seeded_at"

// deploymentEnvironment is the environment name the hub reports on /meta.
// KRYPTKEEPER_ENV wins over the older APP_ENV.
func deploymentEnvironment() string {
	if v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_ENV")); v != "" {
		return v
	}
	return os.Getenv("APP_ENV")
}

// demoSeedingForbidden is true on a production hub. The hub enforces it on the
// marker write, so a hand-rolled client cannot sidestep the CLI's own check.
func demoSeedingForbidden() bool {
	return strings.EqualFold(deploymentEnvironment(), "production")
}

// registerDemoStatusHandler mounts GET /api/v1/demo/status, which the UI polls
// to decide whether to show the demo banner. It exposes nothing beyond the
// marker, so any authenticated principal may read it.
func registerDemoStatusHandler(mux *http.ServeMux, auth *Authenticator, store ConfigStore) {
	mux.HandleFunc("/api/v1/demo/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if _, err := auth.AuthenticatePrincipalDetails(r, time.Now()); err != nil {
			writeUnauthorized(w)
			return
		}
		status := struct {
			Demo     bool   `json:"demo"`
			SeededAt string `json:"seeded_at,omitempty"`
		}{}
		if store != nil {
			entry, ok, err := store.Get(r.Context(), configKeyDemoSeededAt)
			if err != nil {
				writeServiceUnavailable(w, "demo status unavailable")
				return
			}
			if ok && entry.Value != "" {
				status.Demo, status.SeededAt = true, entry.Value
			}
		}
		writeJSONData(w, status)
	})
}
