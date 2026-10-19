// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

// L-11: scan jobs and discovered endpoints had no tenant, so any tenant admin
// listed, cancelled and requeued another tenant's scans and read its endpoints.
func TestLeakL11_DiscoveryScopedToTenant(t *testing.T) {
	setupTenantWritePathTest(t) // env, tenants, activeTenantStore
	stubEndpointAudit(t)

	// Both tenants scan the same address: each must get its own endpoint row.
	scans := make(chan struct{}, 8)
	origScan, origAfter := runDiscoveryScan, afterDiscoveryScanPersist
	runDiscoveryScan = func(_ context.Context, jobID, _, _ string, _ []int) *scanner.ScanResult {
		return &scanner.ScanResult{JobID: jobID, Status: "completed", Endpoints: []scanner.DiscoveredEndpoint{{
			Host: "203.0.113.9", Port: 443, Protocol: "tls", ScannedAt: time.Now().UTC(),
			Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-l11", 10)},
		}}}
	}
	afterDiscoveryScanPersist = func(string) { scans <- struct{}{} }
	t.Cleanup(func() { runDiscoveryScan, afterDiscoveryScanPersist = origScan, origAfter })

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "l11.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteDiscoveryStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	provider := &dbDiscoveryProvider{store: store}

	auth := NewAuthenticatorFromEnv()
	_, acme, _ := auth.CreateAPIKey("acme-l11", "acme-l11", "pki-admin", []string{"*"}, "", "acme", time.Now())
	_, globex, _ := auth.CreateAPIKey("globex-l11", "globex-l11", "pki-admin", []string{"*"}, "", "globex", time.Now())
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, provider, NewEventBus(4), stubAuditProvider{})

	scanAs := func(tenant string) string {
		ctx := withDiscoveryScope(context.Background(), AuthPrincipal{Tenant: tenant, TenantScoped: true})
		res, err := provider.CreateScan(ctx, "targeted", "203.0.113.9", nil)
		if err != nil {
			t.Fatalf("create scan as %s: %v", tenant, err)
		}
		<-scans
		return res.ID
	}
	acmeJob, globexJob := scanAs("acme"), scanAs("globex")
	_ = scanAs("acme") // a re-scan must update acme's row, not touch globex's

	jobIDs := func(token, tenant string) []string {
		code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/discovery/scan-jobs", token, tenant, "")
		if code != http.StatusOK {
			t.Fatalf("list scan jobs: %d %s", code, body)
		}
		var resp struct {
			Data struct {
				ScanJobs []DiscoveryScanJob `json:"scan_jobs"`
			} `json:"data"`
			Meta struct {
				Total int `json:"total"`
			} `json:"meta"`
		}
		_ = json.Unmarshal([]byte(body), &resp)
		if resp.Meta.Total != len(resp.Data.ScanJobs) {
			t.Fatalf("total %d leaks rows outside the caller's tenant (listed %d)", resp.Meta.Total, len(resp.Data.ScanJobs))
		}
		var ids []string
		for _, j := range resp.Data.ScanJobs {
			ids = append(ids, j.ID)
		}
		return ids
	}
	if ids := jobIDs(acme, "acme"); len(ids) != 2 || ids[0] == globexJob || ids[1] == globexJob {
		t.Fatalf("acme must see only its two jobs, got %v", ids)
	}
	if ids := jobIDs(globex, "globex"); len(ids) != 1 || ids[0] != globexJob {
		t.Fatalf("globex must see only its job, got %v", ids)
	}
	if ids := jobIDs("root-token", ""); len(ids) != 3 {
		t.Fatalf("super-admin sees every job, got %v", ids)
	}

	endpointCount := func(token, tenant string) int {
		code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/discovery/endpoints", token, tenant, "")
		if code != http.StatusOK {
			t.Fatalf("list endpoints: %d %s", code, body)
		}
		var resp struct {
			Meta struct {
				Total int `json:"total"`
			} `json:"meta"`
		}
		_ = json.Unmarshal([]byte(body), &resp)
		return resp.Meta.Total
	}
	summaryCount := func(token, tenant string) (endpoints int, mapped int) {
		code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/discovery/summary", token, tenant, "")
		if code != http.StatusOK {
			t.Fatalf("summary: %d %s", code, body)
		}
		var resp struct {
			Data struct {
				DiscoveredEndpoints int `json:"discovered_endpoints"`
				MappedCertificates  int `json:"mapped_certificates"`
			} `json:"data"`
		}
		_ = json.Unmarshal([]byte(body), &resp)
		return resp.Data.DiscoveredEndpoints, resp.Data.MappedCertificates
	}
	if n := endpointCount(acme, "acme"); n != 1 {
		t.Fatalf("acme sees exactly its own endpoint row, got %d", n)
	}
	if n := endpointCount(globex, "globex"); n != 1 {
		t.Fatalf("globex sees exactly its own endpoint row, got %d", n)
	}
	if n := endpointCount("root-token", ""); n != 2 {
		t.Fatalf("one row per tenant for the shared address, super-admin sees 2, got %d", n)
	}
	if e, m := summaryCount(acme, "acme"); e != 1 || m != 1 {
		t.Fatalf("acme summary must count only its rows, got endpoints=%d mapped=%d", e, m)
	}
	if e, _ := summaryCount("root-token", ""); e != 2 {
		t.Fatalf("super-admin summary is fleet-wide, got %d", e)
	}

	// Mutations on another tenant's job are 404 and change nothing.
	if code, _ := tenantReqBody(mux, http.MethodPost, "/api/v1/discovery/scan-jobs/requeue", acme, "acme", `{"scan_job_id":"`+globexJob+`","reason":"x"}`); code != http.StatusNotFound {
		t.Fatalf("cross-tenant requeue want 404, got %d", code)
	}
	if code, _ := tenantReqBody(mux, http.MethodPost, "/api/v1/discovery/scan-jobs/cancel", acme, "acme", `{"scan_job_id":"`+globexJob+`","reason":"x"}`); code != http.StatusNotFound {
		t.Fatalf("cross-tenant cancel want 404, got %d", code)
	}
	if n := len(jobIDs(globex, "globex")); n != 1 {
		t.Fatalf("globex must be unaffected by acme's attempts, has %d jobs", n)
	}
	// Own job still works, and a super-admin requeue lands in the job's tenant.
	if code, body := tenantReqBody(mux, http.MethodPost, "/api/v1/discovery/scan-jobs/requeue", acme, "acme", `{"scan_job_id":"`+acmeJob+`","reason":"x"}`); code != http.StatusAccepted {
		t.Fatalf("own requeue want 202, got %d %s", code, body)
	}
	if code, body := tenantReqBody(mux, http.MethodPost, "/api/v1/discovery/scan-jobs/requeue", "root-token", "", `{"scan_job_id":"`+globexJob+`","reason":"x"}`); code != http.StatusAccepted {
		t.Fatalf("super-admin requeue want 202, got %d %s", code, body)
	}
	if n := len(jobIDs(globex, "globex")); n != 2 {
		t.Fatalf("super-admin requeue must stay in globex, globex has %d jobs", n)
	}
	if n := len(jobIDs(acme, "acme")); n != 3 {
		t.Fatalf("acme should have 3 jobs after its own requeue, has %d", n)
	}
}
