// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"kryptkeeper/internal/discovery/scanner"
)

func endpointByHostPort(t *testing.T, s *sqliteDiscoveryStore, host string, port int) (DiscoveryEndpoint, bool) {
	t.Helper()
	res, err := s.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	for _, ep := range res.Endpoints {
		if ep.Hostname == host && ep.Port == port {
			return ep, true
		}
	}
	return DiscoveryEndpoint{}, false
}

func certActive(t *testing.T, s *sqliteDiscoveryStore, fp string) bool {
	t.Helper()
	var active int
	if err := s.db.QueryRow("SELECT currently_active FROM certificate_endpoints WHERE certificate_fingerprint = ?", fp).Scan(&active); err != nil {
		t.Fatalf("query %s: %v", fp, err)
	}
	return active == 1
}

// A plain-HTTP host and a TLS 1.0-only host used to vanish from a /27 scan
// that reported "completed": the upsert dropped every errored endpoint.
func TestUpsertRecordsOpenButFailedEndpointsAndDropsClosedOnes(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()
	results := []scanner.DiscoveredEndpoint{
		{Host: "10.0.0.5", Port: 443, Protocol: "https", Reachable: true,
			Error: "not a TLS service: tls: first record does not look like a TLS handshake", Findings: []string{"NOT_TLS: first record does not look like a TLS handshake"}},
		{Host: "10.0.0.6", Port: 443, Protocol: "https", Reachable: true,
			Error: "tls handshake: EOF", Findings: []string{"TLS_HANDSHAKE_FAILED: EOF"}},
		{Host: "10.0.0.7", Port: 443, Protocol: "https", TLSVersion: "TLSv1.0", Reachable: true,
			Findings: []string{"DEPRECATED_TLS_VERSION: TLSv1.0"}},
		{Host: "10.0.0.8", Port: 443, Protocol: "https", Error: "tls dial: connection refused"},
	}
	out, err := s.upsertScanResults(ctx, results)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if out.Persisted != 3 || out.Skipped != 0 {
		t.Fatalf("outcome = %+v, want 3 persisted (the closed port dropped, not counted as a skip)", out)
	}
	for host, code := range map[string]string{"10.0.0.5": "NOT_TLS", "10.0.0.6": "TLS_HANDSHAKE_FAILED", "10.0.0.7": "DEPRECATED_TLS_VERSION"} {
		ep, ok := endpointByHostPort(t, s, host, 443)
		if !ok {
			t.Errorf("%s was not recorded", host)
			continue
		}
		if len(ep.Issues) != 1 || scanner.FindingCode(ep.Issues[0]) != code {
			t.Errorf("%s issues = %v, want one %s finding", host, ep.Issues, code)
		}
	}
	if _, ok := endpointByHostPort(t, s, "10.0.0.8", 443); ok {
		t.Error("a closed port must not be recorded: a range scan would flood the inventory")
	}
}

func TestUpsertStalenessSweepOnlyWhenCertsWereGenuinelyObserved(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()
	seed := func(host, fp string) {
		t.Helper()
		ep := scanner.DiscoveredEndpoint{Host: host, Port: 443, Protocol: "https", Certs: []scanner.DiscoveredCert{testDiscoveredCert(fp, 0)}}
		if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
			t.Fatal(err)
		}
	}
	seed("plain.test", "fp-plain")
	seed("flaky.test", "fp-flaky")
	seed("legacy.test", "fp-legacy")

	_, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{
		{Host: "plain.test", Port: 443, Protocol: "https", Reachable: true, Error: "not a TLS service", Findings: []string{"NOT_TLS: x"}},
		{Host: "flaky.test", Port: 443, Protocol: "https", Reachable: true, Error: "tls handshake: EOF", Findings: []string{"TLS_HANDSHAKE_FAILED: EOF"}},
		{Host: "legacy.test", Port: 443, Protocol: "https", Reachable: true, Findings: []string{"DEPRECATED_TLS_VERSION: TLSv1.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if certActive(t, s, "fp-plain") {
		t.Error("a server now answering plain text no longer serves its certificate: mapping should be marked gone")
	}
	if !certActive(t, s, "fp-flaky") {
		t.Error("a transient handshake failure is no evidence the certificate is gone")
	}
	if !certActive(t, s, "fp-legacy") {
		t.Error("a legacy server whose certificate we could not read must keep its previous mapping")
	}
}

func TestUpsertSkipsCipherAuditWhenEndpointAlreadyHasFindings(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	var dials atomic.Int32
	orig := auditEndpointTLSIssues
	auditEndpointTLSIssues = func(string, int) []string { dials.Add(1); return nil }
	t.Cleanup(func() { auditEndpointTLSIssues = orig })

	_, err := s.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{
		{Host: "legacy.test", Port: 443, Protocol: "https", Reachable: true, Findings: []string{"DEPRECATED_TLS_VERSION: TLSv1.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 0 {
		t.Fatalf("cipheraudit dials a default-min-1.2 client; on a legacy host it would stamp a false 'connection failed' beside the real finding (%d dials)", dials.Load())
	}
}

func TestScanJobOutcome(t *testing.T) {
	closed := func(port int) scanner.DiscoveredEndpoint {
		return scanner.DiscoveredEndpoint{Host: "10.0.0.5", Port: port, Error: "tls dial: connection refused"}
	}
	t.Run("failed scan names 443, not whichever catalogue port finished first", func(t *testing.T) {
		// Shuffled the way concurrent goroutines append them.
		res := &scanner.ScanResult{Status: "failed", TotalScanned: 3, Endpoints: []scanner.DiscoveredEndpoint{closed(5986), closed(465), closed(443)}}
		status, msg := scanJobOutcome(res, upsertOutcome{}, nil)
		if status != "failed" || !strings.Contains(msg, "10.0.0.5:443") || strings.Contains(msg, "5986") || strings.Contains(msg, ":465") {
			t.Fatalf("status=%q msg=%q, want failed naming 10.0.0.5:443 only", status, msg)
		}
	})
	t.Run("completed with errors lists the hosts that answered and failed", func(t *testing.T) {
		res := &scanner.ScanResult{Status: "completed_with_errors", Unreachable: 20, ReachableFailed: 2, Endpoints: []scanner.DiscoveredEndpoint{
			closed(443),
			{Host: "10.0.0.9", Port: 443, Reachable: true, Error: "e", Findings: []string{"NOT_TLS: plain"}},
			{Host: "10.0.0.6", Port: 443, Reachable: true, Error: "e", Findings: []string{"TLS_HANDSHAKE_FAILED: EOF"}},
		}}
		status, msg := scanJobOutcome(res, upsertOutcome{}, nil)
		want := "2 endpoint(s) answered but failed (10.0.0.6:443 TLS_HANDSHAKE_FAILED, 10.0.0.9:443 NOT_TLS); 20 closed or filtered port(s) not recorded"
		if status != "completed_with_errors" || msg != want {
			t.Fatalf("status=%q msg=%q\nwant %q", status, msg, want)
		}
	})
	t.Run("clean completed has no message", func(t *testing.T) {
		if status, msg := scanJobOutcome(&scanner.ScanResult{Status: "completed"}, upsertOutcome{}, nil); status != "completed" || msg != "" {
			t.Fatalf("status=%q msg=%q", status, msg)
		}
	})
	t.Run("persist error fails the job", func(t *testing.T) {
		if status, msg := scanJobOutcome(&scanner.ScanResult{Status: "completed"}, upsertOutcome{}, errors.New("disk full")); status != "failed" || msg != "disk full" {
			t.Fatalf("status=%q msg=%q", status, msg)
		}
	})
}

// Runs against the migrated schema: scan_jobs.status carries a CHECK
// constraint, so this also proves migration 000078 admits the new status.
func TestCreateScanPersistsPartialFailureStatusAndExposesError(t *testing.T) {
	s := newMigratedDiscoveryStore(t)
	done := stubDiscoveryScan(t, &scanner.ScanResult{
		Status: "completed_with_errors", Unreachable: 30, ReachableFailed: 1, TotalScanned: 31,
		Endpoints: []scanner.DiscoveredEndpoint{
			{Host: "10.0.0.5", Port: 443, Protocol: "https", Reachable: true, Error: "not a TLS service", Findings: []string{"NOT_TLS: plain"}},
		},
	})
	created, err := s.CreateScan(context.Background(), "full", "10.0.0.0/27", nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	<-done

	jobs, err := s.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Status: "completed_with_errors", Limit: 10})
	if err != nil {
		t.Fatalf("ListScanJobs: %v", err)
	}
	if len(jobs.ScanJobs) != 1 || jobs.ScanJobs[0].ID != created.ID {
		t.Fatalf("want the job listed under completed_with_errors, got %+v", jobs.ScanJobs)
	}
	if !strings.Contains(jobs.ScanJobs[0].Error, "10.0.0.5:443 NOT_TLS") {
		t.Fatalf("job error = %q, want it to name the failed host", jobs.ScanJobs[0].Error)
	}
	if _, ok := endpointByHostPort(t, s, "10.0.0.5", 443); !ok {
		t.Fatal("the plain-HTTP host must be in the inventory")
	}
}

func TestCreateScanFailedJobErrorNamesRequestedPort(t *testing.T) {
	s := newMigratedDiscoveryStore(t)
	mk := func(p int) scanner.DiscoveredEndpoint {
		return scanner.DiscoveredEndpoint{Host: "10.0.0.5", Port: p, Error: "tls dial: connection refused"}
	}
	done := stubDiscoveryScan(t, &scanner.ScanResult{Status: "failed", TotalScanned: 3, Endpoints: []scanner.DiscoveredEndpoint{mk(5986), mk(465), mk(443)}})
	if _, err := s.CreateScan(context.Background(), "targeted", "10.0.0.5", nil); err != nil {
		t.Fatal(err)
	}
	<-done
	jobs, err := s.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Status: "failed", Limit: 10})
	if err != nil || len(jobs.ScanJobs) != 1 {
		t.Fatalf("jobs=%+v err=%v", jobs.ScanJobs, err)
	}
	if e := jobs.ScanJobs[0].Error; !strings.Contains(e, "10.0.0.5:443") || strings.Contains(e, "5986") {
		t.Fatalf("job error = %q, want it to name 10.0.0.5:443", e)
	}
}
