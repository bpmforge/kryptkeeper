// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"testing"
)

func newDemoTestMux(t *testing.T, store ConfigStore) *http.ServeMux {
	t.Helper()
	mux, auth := newConfigTestMux(t, store)
	registerDemoStatusHandler(mux, auth, store)
	return mux
}

func demoStatus(t *testing.T, mux *http.ServeMux) (demo bool, seededAt string) {
	t.Helper()
	rec := doConfigRequest(mux, http.MethodGet, "/api/v1/demo/status", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Demo     bool   `json:"demo"`
			SeededAt string `json:"seeded_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data.Demo, resp.Data.SeededAt
}

func TestDemoStatusFollowsTheMarker(t *testing.T) {
	t.Setenv("KRYPTKEEPER_ENV", "")
	mux := newDemoTestMux(t, newConfigTestStore(t))
	if demo, _ := demoStatus(t, mux); demo {
		t.Fatal("a fresh hub must not report demo data")
	}
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/demo.seeded_at", "test-token", `{"value":"2026-10-25T00:00:00Z"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set marker = %d: %s", rec.Code, rec.Body.String())
	}
	if demo, at := demoStatus(t, mux); !demo || at != "2026-10-25T00:00:00Z" {
		t.Fatalf("after seeding got demo=%v seeded_at=%q", demo, at)
	}
	if rec := doConfigRequest(mux, http.MethodDelete, "/api/v1/config/demo.seeded_at", "test-token", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("clear marker = %d", rec.Code)
	}
	if demo, _ := demoStatus(t, mux); demo {
		t.Fatal("reset must clear the demo flag")
	}
}

func TestDemoStatusRequiresAuthAndGet(t *testing.T) {
	mux := newDemoTestMux(t, newConfigTestStore(t))
	if rec := doConfigRequest(mux, http.MethodGet, "/api/v1/demo/status", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d", rec.Code)
	}
	if rec := doConfigRequest(mux, http.MethodPost, "/api/v1/demo/status", "test-token", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", rec.Code)
	}
}

func TestDemoMarkerRefusedInProduction(t *testing.T) {
	t.Setenv("KRYPTKEEPER_ENV", "production")
	mux := newDemoTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/demo.seeded_at", "test-token", `{"value":"x"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("production marker write = %d, want 409", rec.Code)
	}
	if demo, _ := demoStatus(t, mux); demo {
		t.Fatal("a refused write must not leave a marker")
	}
}

func TestDemoDeploymentEnvironmentPrefersKryptkeeperEnv(t *testing.T) {
	t.Setenv("APP_ENV", "staging")
	t.Setenv("KRYPTKEEPER_ENV", "")
	if got := deploymentEnvironment(); got != "staging" {
		t.Fatalf("APP_ENV fallback = %q", got)
	}
	t.Setenv("KRYPTKEEPER_ENV", "Production")
	if got := deploymentEnvironment(); got != "Production" || !demoSeedingForbidden() {
		t.Fatalf("KRYPTKEEPER_ENV = %q forbidden=%v", got, demoSeedingForbidden())
	}
}
