// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
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
