// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"
)

// The product path, live: a managed target with discovery_mode=winrm and a
// stored windows_password credential, scanned through the sqlite discovery
// store exactly as the scheduler or "Discover now" would. Gated like
// agentdiscovery's live suite; see live_winrm_test.go there for the env.
func TestLiveWinRMDiscoveryThroughStores(t *testing.T) {
	if os.Getenv("KK_LIVE_WINRM") != "1" {
		t.Skip("set KK_LIVE_WINRM=1 with a prepared Windows host to run")
	}
	targets, creds := winrmTestStores(t)
	// The host under test comes from the same env the agentdiscovery live
	// suite uses; no lab address is hardcoded in the tree.
	liveHost := "127.0.0.1"
	if u, err := url.Parse(os.Getenv("KK_WINRM_URL")); err == nil && u.Hostname() != "" {
		liveHost = u.Hostname()
	}
	payload := `{"base_url":"` + os.Getenv("KK_WINRM_URL") + `","username":"` + os.Getenv("KK_WINRM_USER") + `","password":"` + os.Getenv("KK_WINRM_PASS") + `"}`
	if _, err := creds.Create(context.Background(), "cred-live", "live", CredentialTypeWindowsPassword, "", []byte(payload)); err != nil {
		t.Fatal(err)
	}
	tgt, err := targets.Create(context.Background(), ManagedTarget{ID: "t-live", Name: "live-win", Host: liveHost, DiscoveryMode: "winrm", InstallMode: "iis", RenewalMethod: "manual", CredentialRef: "cred-live"})
	if err != nil {
		t.Fatal(err)
	}

	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	store.SetWinRMScanner(newWinRMTargetScanner(targets, creds, liveWinRMEnumerator))
	done := make(chan struct{})
	orig := afterDiscoveryScanPersist
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() { afterDiscoveryScanPersist = orig })

	res, err := store.CreateScan(context.Background(), scanTypeWinRM, tgt.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		t.Fatal("scan did not finish")
	}
	jobs, _ := store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 50})
	for _, j := range jobs.ScanJobs {
		if j.ID == res.ID {
			t.Logf("job %s status=%s", j.ID, j.Status)
			if j.Status != "completed" {
				t.Fatalf("live winrm scan must complete: %+v", j)
			}
		}
	}
	eps, _ := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 100})
	for _, e := range eps.Endpoints {
		if e.Hostname == liveHost && e.Port == 5986 {
			t.Logf("endpoint persisted: %+v", e)
			return
		}
	}
	t.Fatalf("WinRM endpoint not persisted: %+v", eps.Endpoints)
}
