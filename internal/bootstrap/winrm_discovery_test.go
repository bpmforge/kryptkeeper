// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/discovery/scanner"
)

// W18-12: discovery_mode=winrm was schema-only. These prove the hub now
// resolves the target's credential, runs the scanner, and persists what
// it finds through the ordinary scan path.

func winrmTestStores(t *testing.T) (*sqliteManagedTargetStore, *sqliteOutboundCredentialStore) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "winrm-discovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	targets := &sqliteManagedTargetStore{db: db}
	creds := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := targets.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := creds.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return targets, creds
}

func testX509(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestWinRMTargetScannerResolvesCredentialAndMapsCerts(t *testing.T) {
	targets, creds := winrmTestStores(t)
	_, err := creds.Create(context.Background(), "cred-win", "iis", CredentialTypeWindowsPassword, "",
		[]byte(`{"base_url":"https://192.0.2.10:5986/wsman","username":"kktest","password":"pw-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := targets.Create(context.Background(), ManagedTarget{ID: "t-win", Name: "win", Host: "192.0.2.10", DiscoveryMode: "winrm", InstallMode: "iis", RenewalMethod: "manual", CredentialRef: "cred-win"})
	if err != nil {
		t.Fatal(err)
	}
	var seen agentdiscovery.WinRMConfig
	leaf, root := testX509(t, "web-leaf"), testX509(t, "corp-root")
	enumerate := func(_ context.Context, cfg agentdiscovery.WinRMConfig, host string) agentdiscovery.AgentlessScanResult {
		seen = cfg
		return agentdiscovery.AgentlessScanResult{Host: host,
			Certs:      []agentclient.DiscoveredCert{{Source: "agentless-winrm:My"}, {Source: "agentless-winrm:Root"}},
			Parsed:     []*x509.Certificate{leaf, root},
			IISService: "Running",
			// One legacy root Go cannot parse: a warning, not a failure.
			Errors: []string{host + ": unparseable cert in CA"}}
	}
	res := newWinRMTargetScanner(targets, creds, enumerate)(context.Background(), tgt.ID)

	if seen.EndpointURL != "https://192.0.2.10:5986/wsman" || seen.Username != "kktest" || seen.Password != "pw-secret" {
		t.Fatalf("scanner did not receive the resolved credential: %+v", seen)
	}
	if res.Status != "completed" || len(res.Endpoints) != 1 || res.CertsFound != 2 || res.ErrorCount != 1 {
		t.Fatalf("result: %+v", res)
	}
	if res.Endpoints[0].Error != "" {
		t.Fatal("a per-cert warning must not mark the endpoint failed, or the upsert drops everything it found")
	}
	ep := res.Endpoints[0]
	if ep.Host != "192.0.2.10" || ep.Port != 5986 || ep.Protocol != "winrm-https" || ep.RecommendedInstallMode != "iis" || ep.ServerTech != "iis" {
		t.Fatalf("endpoint: %+v", ep)
	}
	if ep.Certs[0].CommonName != "web-leaf" || ep.Certs[0].Raw == nil || ep.Certs[1].CommonName != "corp-root" {
		t.Fatalf("certs not mapped with raw DER: %+v", ep.Certs)
	}
}

// W18-17: the install recommendation must come from what the host
// reports, not from the transport used to reach it. A target with no
// W3SVC service must get no IIS recommendation.
func TestWinRMTargetScannerLeavesInstallModeEmptyWithoutIIS(t *testing.T) {
	targets, creds := winrmTestStores(t)
	_, err := creds.Create(context.Background(), "cred-win2", "app", CredentialTypeWindowsPassword, "",
		[]byte(`{"base_url":"https://192.0.2.171:5986/wsman","username":"kktest","password":"pw-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := targets.Create(context.Background(), ManagedTarget{ID: "t-win2", Name: "win2", Host: "192.0.2.171", DiscoveryMode: "winrm", InstallMode: "acme", RenewalMethod: "manual", CredentialRef: "cred-win2"})
	if err != nil {
		t.Fatal(err)
	}
	enumerate := func(_ context.Context, _ agentdiscovery.WinRMConfig, host string) agentdiscovery.AgentlessScanResult {
		return agentdiscovery.AgentlessScanResult{Host: host, IISService: "absent"}
	}
	res := newWinRMTargetScanner(targets, creds, enumerate)(context.Background(), tgt.ID)
	if len(res.Endpoints) != 1 {
		t.Fatalf("result: %+v", res)
	}
	ep := res.Endpoints[0]
	if ep.ServerTech != "" || ep.RecommendedInstallMode != "" {
		t.Fatalf("a host reporting no W3SVC service must not get an IIS recommendation: %+v", ep)
	}
}

func TestWinRMTargetScannerRefusesWrongModeOrCredentialType(t *testing.T) {
	targets, creds := winrmTestStores(t)
	_, _ = creds.Create(context.Background(), "cred-tok", "f5", CredentialTypeAPIToken, "", []byte(`{"token":"t"}`))
	net, _ := targets.Create(context.Background(), ManagedTarget{ID: "t-net", Name: "n", Host: "h", DiscoveryMode: "network", InstallMode: "acme", RenewalMethod: "manual"})
	tok, _ := targets.Create(context.Background(), ManagedTarget{ID: "t-tok", Name: "w", Host: "h", DiscoveryMode: "winrm", InstallMode: "iis", RenewalMethod: "manual", CredentialRef: "cred-tok"})
	called := false
	enumerate := func(context.Context, agentdiscovery.WinRMConfig, string) agentdiscovery.AgentlessScanResult {
		called = true
		return agentdiscovery.AgentlessScanResult{}
	}
	run := newWinRMTargetScanner(targets, creds, enumerate)
	for name, id := range map[string]string{"network target": net.ID, "api_token credential": tok.ID, "unknown target": "nope"} {
		res := run(context.Background(), id)
		if res.Status != "failed" || len(res.Endpoints) != 1 || res.Endpoints[0].Error == "" {
			t.Fatalf("%s: must fail with a reason: %+v", name, res)
		}
	}
	if called {
		t.Fatal("no host must be contacted when the target or credential is wrong")
	}
}

func TestDiscoverySchedulerFilesWinRMScansForManagedTargets(t *testing.T) {
	targets, _ := winrmTestStores(t)
	win, _ := targets.Create(context.Background(), ManagedTarget{ID: "t-w1", Name: "w", Host: "h1", DiscoveryMode: "winrm", InstallMode: "iis", RenewalMethod: "manual", CredentialRef: "c"})
	_, _ = targets.Create(context.Background(), ManagedTarget{ID: "t-n2", Name: "n", Host: "h2", DiscoveryMode: "network", InstallMode: "acme", RenewalMethod: "manual"})
	rec := &recordingDiscoveryProvider{}
	s := newDiscoveryScheduler(rec, time.Hour, nil, nil).WithManagedTargets(targets)
	s.runOnce(context.Background())
	calls := rec.snapshot()
	if len(calls) != 1 || calls[0] != "winrm|"+win.ID {
		t.Fatalf("expected exactly one winrm scan for the winrm target, got %v", calls)
	}
}

func TestSQLiteDiscoveryStoreRunsAndPersistsWinRMScan(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	done := make(chan struct{})
	orig := afterDiscoveryScanPersist
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() { afterDiscoveryScanPersist = orig })

	// Without a runner the type is refused up front, never queued.
	if _, err := store.CreateScan(context.Background(), scanTypeWinRM, "target-1", nil); err == nil || !strings.Contains(err.Error(), "no runner") {
		t.Fatalf("winrm without a runner must be refused: %v", err)
	}

	leaf := testX509(t, "iis-leaf")
	store.SetWinRMScanner(func(_ context.Context, targetID string) scanner.ScanResult {
		return scanner.ScanResult{Status: "completed", CertsFound: 1, Endpoints: []scanner.DiscoveredEndpoint{{
			Host: "192.0.2.10", Port: 5986, Protocol: "winrm-https", ScannedAt: time.Now().UTC(),
			Certs: []scanner.DiscoveredCert{scanner.CertToDiscovered(leaf, "192.0.2.10", true)},
		}}}
	})
	res, err := store.CreateScan(context.Background(), scanTypeWinRM, "target-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	jobs, _ := store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 50})
	var status string
	for _, j := range jobs.ScanJobs {
		if j.ID == res.ID {
			status = j.Status
		}
	}
	if status != "completed" {
		t.Fatalf("winrm scan job must complete, got %q", status)
	}
	eps, err := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range eps.Endpoints {
		if e.Hostname == "192.0.2.10" && e.Port == 5986 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the WinRM endpoint must be persisted like any scan: %+v", eps.Endpoints)
	}
}

// A failed runner's reason must land in scan_jobs.error_message: live, an
// unreachable host and a mis-wired runner were indistinguishable rows.
func TestSQLiteDiscoveryStorePersistsWinRMFailureReason(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	done := make(chan struct{})
	orig := afterDiscoveryScanPersist
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() { afterDiscoveryScanPersist = orig })
	store.SetWinRMScanner(func(context.Context, string) scanner.ScanResult {
		return scanner.ScanResult{Status: "failed", ErrorCount: 1, Endpoints: []scanner.DiscoveredEndpoint{{Host: "h", Port: 5986, Protocol: "winrm-https", Error: "dial tcp h:5986: connect: operation timed out"}}}
	})
	res, err := store.CreateScan(context.Background(), scanTypeWinRM, "t-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	var status, msg string
	if err := db.QueryRow("SELECT status, COALESCE(error_message,'') FROM scan_jobs WHERE id = ?", res.ID).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(msg, "timed out") {
		t.Fatalf("status=%q error_message=%q", status, msg)
	}
}
