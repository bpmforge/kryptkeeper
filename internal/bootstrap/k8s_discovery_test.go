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

	"kryptkeeper/internal/certmanager"
)

// W19-17: k8s-certmanager was accepted by discovery_scanner_provider.go
// but had no case in handlers_discovery.go's scan_type switch and no
// runner on the DB stores at all, so it was unreachable via the API under
// either discovery provider. These prove the DB path now runs the
// injected connector and persists results — the cloud_discovery_test.go
// precedent, since k8s-certmanager shares the cloud types' "no target,
// scope is the connector's credentials" contract.

type fakeCertManagerConnector struct {
	certs []certmanager.Certificate
	err   error
}

func (f *fakeCertManagerConnector) ListCertificates(context.Context) ([]certmanager.Certificate, error) {
	return f.certs, f.err
}

// overrideCertManagerConnector swaps the factory for one test and returns
// a channel closed when the scan finalizes.
func overrideCertManagerConnector(t *testing.T, fake *fakeCertManagerConnector) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	origFactory := newCertManagerConnectorForScan
	origAfter := afterDiscoveryScanPersist
	newCertManagerConnectorForScan = func() (certManagerCertLister, error) {
		return fake, nil
	}
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() {
		newCertManagerConnectorForScan = origFactory
		afterDiscoveryScanPersist = origAfter
	})
	return done
}

func TestK8sCertManagerScanPersistsResultsToJobRow(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	fake := &fakeCertManagerConnector{certs: []certmanager.Certificate{
		{Namespace: "uat", Name: "uat-leaf", CommonName: "uat-leaf.example.com", Ready: true},
		{Namespace: "uat", Name: "uat-other", CommonName: "other.example.com", Ready: false},
	}}
	done := overrideCertManagerConnector(t, fake)

	result, err := store.CreateScan(context.Background(), scanTypeK8sCertManager, "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if result.Target != "" {
		t.Fatalf("k8s-certmanager scan takes no target, got %q", result.Target)
	}
	waitForScan(t, done)

	var jobType, status string
	var summary, errMsg *string
	err = db.QueryRow("SELECT type, status, results_summary, error_message FROM scan_jobs WHERE id = ?", result.ID).
		Scan(&jobType, &status, &summary, &errMsg)
	if err != nil {
		t.Fatalf("job row: %v", err)
	}
	if jobType != scanTypeK8sCertManager {
		t.Fatalf("job type %q, want %q", jobType, scanTypeK8sCertManager)
	}
	if status != "completed" {
		t.Fatalf("status %q, want completed (err=%v)", status, errMsg)
	}
	if summary == nil {
		t.Fatal("results_summary not persisted")
	}
	var parsed k8sCertManagerScanSummary
	if err := json.Unmarshal([]byte(*summary), &parsed); err != nil {
		t.Fatalf("summary unmarshal: %v", err)
	}
	if parsed.Certificates != 2 || len(parsed.Items) != 2 {
		t.Fatalf("summary %+v, want 2 certificates", parsed)
	}
	if parsed.Items[0].CommonName != "uat-leaf.example.com" {
		t.Fatalf("summary missing the cert-manager-issued certificate: %+v", parsed.Items)
	}
}

func TestK8sCertManagerScanConnectorFailureFinalizesFailed(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	done := overrideCertManagerConnector(t, &fakeCertManagerConnector{err: errors.New("k8s api auth error (401)")})

	result, err := store.CreateScan(context.Background(), scanTypeK8sCertManager, "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForScan(t, done)

	var status string
	var errMsg *string
	if err := db.QueryRow("SELECT status, error_message FROM scan_jobs WHERE id = ?", result.ID).Scan(&status, &errMsg); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status %q, want failed", status)
	}
	if errMsg == nil || !strings.Contains(*errMsg, "401") {
		t.Fatalf("error_message %v must carry the connector's reason", errMsg)
	}
}

func TestK8sCertManagerScanRejectedWithoutRunner(t *testing.T) {
	// Sanity: the type-refusal guard still lists k8s-certmanager as a
	// real runner, not silently falling through to the network scanner.
	// (There's no "no runner" state to hit for k8s-certmanager itself --
	// unlike winrm it needs no per-provider SetXScanner wiring -- so this
	// just confirms an unrelated bogus type is still refused up front.)
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	if _, err := store.CreateScan(context.Background(), "not-a-real-type", "x", nil); err == nil || !strings.Contains(err.Error(), "no runner") {
		t.Fatalf("bogus scan type must be refused up front: %v", err)
	}
}
