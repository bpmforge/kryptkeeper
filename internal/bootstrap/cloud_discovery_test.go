// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/cloudinventory"
)

// W5-12: cloudinventory wired into real cloud scan types — no longer
// dead code — with the reserved scan_jobs.type values honored.

type fakeCloudConnector struct {
	certs []cloudinventory.CloudCertificate
	err   error
}

func (f *fakeCloudConnector) ListCertificates(context.Context) ([]cloudinventory.CloudCertificate, error) {
	return f.certs, f.err
}

// overrideCloudConnector swaps the factory for one test and returns a
// channel closed when the scan finalizes.
func overrideCloudConnector(t *testing.T, fake *fakeCloudConnector, wantType string) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	origFactory := newCloudConnector
	origAfter := afterDiscoveryScanPersist
	newCloudConnector = func(_ context.Context, scanType string) (cloudConnector, error) {
		if scanType != wantType {
			t.Errorf("connector factory called with %q, want %q", scanType, wantType)
		}
		return fake, nil
	}
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() {
		newCloudConnector = origFactory
		afterDiscoveryScanPersist = origAfter
	})
	return done
}

func waitForScan(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cloud scan never finalized")
	}
}

func TestCloudScanPersistsResultsToJobRow(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	fake := &fakeCloudConnector{certs: []cloudinventory.CloudCertificate{
		{Provider: "aws-acm", ResourceID: "arn:1", CommonName: "a.example.com", Status: "ISSUED"},
		{Provider: "aws-acm", ResourceID: "arn:2", CommonName: "b.example.com", Status: "EXPIRED"},
	}}
	done := overrideCloudConnector(t, fake, "cloud_acm")

	result, err := store.CreateScan(context.Background(), "cloud_acm", "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForScan(t, done)

	var jobType, status string
	var summary, errMsg *string
	err = db.QueryRow("SELECT type, status, results_summary, error_message FROM scan_jobs WHERE id = ?", result.ID).
		Scan(&jobType, &status, &summary, &errMsg)
	if err != nil {
		t.Fatalf("job row: %v", err)
	}
	// The reserved CHECK value is honored verbatim.
	if jobType != "cloud_acm" {
		t.Fatalf("job type %q, want cloud_acm", jobType)
	}
	if status != "completed" {
		t.Fatalf("status %q, want completed (err=%v)", status, errMsg)
	}
	if summary == nil {
		t.Fatal("results_summary not persisted")
	}
	var parsed cloudScanSummary
	if err := json.Unmarshal([]byte(*summary), &parsed); err != nil {
		t.Fatalf("summary parse: %v", err)
	}
	if parsed.Certificates != 2 || len(parsed.Items) != 2 || parsed.Provider != "cloud_acm" {
		t.Fatalf("unexpected summary: %+v", parsed)
	}
	if parsed.Items[0].CommonName != "a.example.com" {
		t.Fatalf("item content lost: %+v", parsed.Items[0])
	}
}

func TestCloudScanConnectorFailureFinalizesFailed(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	fake := &fakeCloudConnector{err: errors.New("no credentials")}
	done := overrideCloudConnector(t, fake, "cloud_gcp_cm")

	result, err := store.CreateScan(context.Background(), "cloud_gcp_cm", "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForScan(t, done)

	var status string
	var errMsg *string
	if err := db.QueryRow("SELECT status, error_message FROM scan_jobs WHERE id = ?", result.ID).Scan(&status, &errMsg); err != nil {
		t.Fatalf("job row: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status %q, want failed", status)
	}
	if errMsg == nil || !strings.Contains(*errMsg, "no credentials") {
		t.Fatalf("error_message must carry the cause, got %v", errMsg)
	}
}

func TestUnknownScanTypeRefusedBeforeInsert(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	if _, err := store.CreateScan(context.Background(), "ct_log", "x", nil); err == nil {
		t.Fatal("a reserved-but-runnerless type must be refused, not queued forever")
	}
	var count int
	// Only the two seeded jobs remain — nothing was inserted.
	if err := db.QueryRow("SELECT COUNT(*) FROM scan_jobs WHERE type = 'ct_log'").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("refused scan must not leave a row, found %d", count)
	}
}

// W24-17: scope fan-out.

type scopeFake struct {
	certs []cloudinventory.CloudCertificate
	err   error
}

func (f scopeFake) ListCertificates(context.Context) ([]cloudinventory.CloudCertificate, error) {
	return f.certs, f.err
}

func awsTestScope(region string) cloudinventory.Scope {
	return cloudinventory.Scope{Provider: cloudinventory.ProviderAWSACM, Profile: "prod", Region: region}
}

// overrideCloudScopes injects scopes and per-region fakes and returns the
// completion channel. A scan of the legacy factory fails the test.
func overrideCloudScopes(t *testing.T, scopes []cloudinventory.Scope, fakes map[string]scopeFake) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	origLoad, origScope, origAfter := loadCloudScopes, newCloudScopeConnector, afterDiscoveryScanPersist
	loadCloudScopes = func(context.Context) ([]cloudinventory.Scope, error) { return scopes, nil }
	newCloudScopeConnector = func(_ context.Context, s cloudinventory.Scope) (cloudConnector, error) {
		f, ok := fakes[s.Region]
		if !ok {
			return nil, errors.New("no credentials")
		}
		return f, nil
	}
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() {
		loadCloudScopes, newCloudScopeConnector, afterDiscoveryScanPersist = origLoad, origScope, origAfter
	})
	return done
}

func runCloudACMScan(t *testing.T, done <-chan struct{}) (status, errMsg string, sum cloudScanSummary) {
	t.Helper()
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	result, err := store.CreateScan(context.Background(), "cloud_acm", "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForScan(t, done)
	var summary, em *string
	if err := db.QueryRow("SELECT status, results_summary, error_message FROM scan_jobs WHERE id = ?", result.ID).Scan(&status, &summary, &em); err != nil {
		t.Fatal(err)
	}
	if em != nil {
		errMsg = *em
	}
	if summary != nil && *summary != "" {
		if err := json.Unmarshal([]byte(*summary), &sum); err != nil {
			t.Fatalf("summary: %v", err)
		}
	}
	return status, errMsg, sum
}

func fakeACMCerts(region string, n int) []cloudinventory.CloudCertificate {
	out := make([]cloudinventory.CloudCertificate, n)
	for i := range out {
		out[i] = cloudinventory.CloudCertificate{Provider: "aws-acm", Region: region, ResourceID: fmt.Sprintf("arn:%s:%d", region, i)}
	}
	return out
}

func TestCloudScanFanOutOneScopeFails(t *testing.T) {
	done := overrideCloudScopes(t, []cloudinventory.Scope{awsTestScope("us-east-1"), awsTestScope("eu-west-1")}, map[string]scopeFake{
		"us-east-1": {certs: fakeACMCerts("us-east-1", 2)},
		"eu-west-1": {err: errors.New("list certificates: AccessDenied")},
	})
	status, errMsg, sum := runCloudACMScan(t, done)
	if status != scanStatusCompletedWithErrors {
		t.Fatalf("status %q", status)
	}
	if !strings.Contains(errMsg, "1 of 2 scopes failed: aws-acm/prod/eu-west-1: list certificates: AccessDenied") {
		t.Fatalf("error_message %q", errMsg)
	}
	if sum.Certificates != 2 || len(sum.Items) != 2 || len(sum.Scopes) != 2 || sum.Scopes[1].Error == "" || sum.Scopes[0].Error != "" {
		t.Fatalf("summary %+v", sum)
	}
}

func TestCloudScanAllScopesFail(t *testing.T) {
	done := overrideCloudScopes(t, []cloudinventory.Scope{awsTestScope("a"), awsTestScope("b")}, map[string]scopeFake{
		"a": {err: errors.New("boom")},
	})
	status, errMsg, _ := runCloudACMScan(t, done)
	if status != "failed" || !strings.Contains(errMsg, "2 of 2 scopes failed") || !strings.Contains(errMsg, "aws-acm/prod/b: connector init: no credentials") {
		t.Fatalf("status %q msg %q", status, errMsg)
	}
}

func TestCloudScanRerunNoDuplicates(t *testing.T) {
	scopes := []cloudinventory.Scope{awsTestScope("us-east-1"), awsTestScope("eu-west-1")}
	fakes := map[string]scopeFake{
		"us-east-1": {certs: append(fakeACMCerts("us-east-1", 3), fakeACMCerts("us-east-1", 1)...)}, // provider repeats an id
		"eu-west-1": {certs: fakeACMCerts("eu-west-1", 2)},
	}
	var counts [2]int
	for i := range counts {
		done := overrideCloudScopes(t, scopes, fakes)
		_, _, sum := runCloudACMScan(t, done)
		seen := map[string]bool{}
		for _, it := range sum.Items {
			k := it.Scope + "|" + it.ResourceID
			if seen[k] {
				t.Fatalf("duplicate %s", k)
			}
			seen[k] = true
		}
		counts[i] = sum.Certificates
	}
	if counts[0] != 5 || counts[1] != 5 {
		t.Fatalf("counts %v, want 5 and 5", counts)
	}
}

func TestCloudScanNoScopesUsesLegacyConnector(t *testing.T) {
	origLoad := loadCloudScopes
	loadCloudScopes = func(context.Context) ([]cloudinventory.Scope, error) {
		// A scope for another provider must not divert an ACM scan.
		return []cloudinventory.Scope{{Provider: cloudinventory.ProviderGCPCertManager, ProjectID: "p"}}, nil
	}
	t.Cleanup(func() { loadCloudScopes = origLoad })
	done := overrideCloudConnector(t, &fakeCloudConnector{certs: fakeACMCerts("us-east-1", 2)}, "cloud_acm")
	status, _, sum := runCloudACMScan(t, done)
	if status != "completed" || sum.Certificates != 2 || len(sum.Scopes) != 0 {
		t.Fatalf("status %q summary %+v", status, sum)
	}
}

func TestCloudScanScopeConfigErrorFails(t *testing.T) {
	origLoad := loadCloudScopes
	loadCloudScopes = func(context.Context) ([]cloudinventory.Scope, error) { return nil, errors.New("bad") }
	t.Cleanup(func() { loadCloudScopes = origLoad })
	done := overrideCloudConnector(t, &fakeCloudConnector{}, "cloud_acm")
	status, errMsg, _ := runCloudACMScan(t, done)
	if status != "failed" || errMsg != "scope config: bad" {
		t.Fatalf("status %q msg %q", status, errMsg)
	}
}

func TestParseCloudScopes(t *testing.T) {
	good := `[{"provider":"aws-acm","profile":"prod","region":"us-east-1"},{"provider":"azure-keyvault","vault_url":"https://a.vault.azure.net"},{"provider":"gcp-certmanager","project_id":"p1"}]`
	if s, err := parseCloudScopes(good); err != nil || len(s) != 3 {
		t.Fatalf("%v %v", s, err)
	}
	if s, err := parseCloudScopes(" "); err != nil || s != nil {
		t.Fatalf("empty: %v %v", s, err)
	}
	for _, bad := range []string{`nope`, `[{"provider":"aws-acm"}]`, `[{"provider":"x"}]`} {
		if _, err := parseCloudScopes(bad); err == nil {
			t.Fatalf("expected error for %s", bad)
		}
	}
}

func fanOutScopes() ([]cloudinventory.Scope, map[string]scopeFake) {
	regions := []string{"us-east-1", "eu-west-1", "ap-south-1"}
	var scopes []cloudinventory.Scope
	fakes := map[string]scopeFake{}
	for _, r := range regions {
		scopes = append(scopes, awsTestScope(r))
		fakes[r] = scopeFake{certs: fakeACMCerts(r, 500)}
	}
	return scopes, fakes
}

func TestCloudScan500PerScope(t *testing.T) {
	scopes, fakes := fanOutScopes()
	done := overrideCloudScopes(t, scopes, fakes)
	start := time.Now()
	_, _, sum := runCloudACMScan(t, done)
	if sum.Certificates != 1500 || len(sum.Items) != cloudScanMaxItems {
		t.Fatalf("certificates %d items %d", sum.Certificates, len(sum.Items))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("1500 certs took %s", d)
	}
}

func BenchmarkCloudScan500(b *testing.B) {
	scopes, fakes := fanOutScopes()
	origLoad, origScope := loadCloudScopes, newCloudScopeConnector
	loadCloudScopes = func(context.Context) ([]cloudinventory.Scope, error) { return scopes, nil }
	newCloudScopeConnector = func(_ context.Context, s cloudinventory.Scope) (cloudConnector, error) { return fakes[s.Region], nil }
	b.Cleanup(func() { loadCloudScopes, newCloudScopeConnector = origLoad, origScope })
	noop := func(string, string, string) {}
	for i := 0; i < b.N; i++ {
		runCloudScopeFanOut(context.Background(), noop, "bench", scanTypeCloudACM, scopes)
	}
}
