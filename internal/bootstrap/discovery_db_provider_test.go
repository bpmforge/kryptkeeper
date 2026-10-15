// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/discovery/scanner"

	_ "modernc.org/sqlite"
)

// stubDiscoveryScan swaps runDiscoveryScan for the duration of a test so
// CreateScan's background goroutine doesn't make real network connections,
// and synchronizes on afterDiscoveryScanPersist so the returned channel
// closes only once the whole background scan-and-persist goroutine has
// finished (including the DB writes), not merely once the stub scanner call
// returns — the persist step still runs in the background afterward, and a
// test that only waited for the scan call would race its own cleanup
// (closing the DB) against that persist step.
func stubDiscoveryScan(t *testing.T, result *scanner.ScanResult) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	origScan := runDiscoveryScan
	origAfter := afterDiscoveryScanPersist
	runDiscoveryScan = func(_ context.Context, jobID, _, _ string, _ []int) *scanner.ScanResult {
		result.JobID = jobID
		return result
	}
	afterDiscoveryScanPersist = func(string) { close(done) }
	t.Cleanup(func() {
		runDiscoveryScan = origScan
		afterDiscoveryScanPersist = origAfter
	})
	return done
}

// testDiscoveredCert builds a DiscoveredCert that satisfies every NOT
// NULL/CHECK constraint of the real certificates schema.
func testDiscoveredCert(fp string, risk int) scanner.DiscoveredCert {
	return scanner.DiscoveredCert{
		Fingerprint:        fp,
		SerialNumber:       "1234",
		CommonName:         "test." + fp,
		SubjectDN:          "CN=test." + fp,
		IssuerDN:           "CN=test-issuer",
		ValidFrom:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:         time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		PublicKeyAlgorithm: "ECDSA",
		SignatureAlgorithm: "ECDSA-SHA256",
		RiskScore:          risk,
	}
}

func setupDiscoveryTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "discovery-test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Minimal schema matching W3 + W2 (certificates for risk joins)
	for _, stmt := range []string{
		// The REAL certificates shape (000002 + later ALTERs), not a
		// two-column stand-in: the stand-in hid that the discovery upsert
		// could never satisfy the NOT NULL/CHECK constraints in production.
		`CREATE TABLE certificates (
			fingerprint_sha256   TEXT PRIMARY KEY,
			serial_number        TEXT NOT NULL,
			subject_dn           TEXT NOT NULL,
			common_name          TEXT,
			issuer_cn            TEXT,
			key_size_bits        INTEGER,
			subject_alt_names    TEXT,
			issuer_dn            TEXT NOT NULL,
			valid_from           TEXT NOT NULL,
			valid_until          TEXT NOT NULL,
			public_key_algorithm TEXT NOT NULL CHECK (public_key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'ML-DSA')),
			signature_algorithm  TEXT NOT NULL,
			risk_score           INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
			risk_flags           TEXT NOT NULL DEFAULT '[]',
			raw_cert_b64         TEXT,
			source               TEXT NOT NULL DEFAULT 'api'
			                     CHECK (source IN ('api', 'acme', 'est', 'scep', 'discovery_network',
			                                       'discovery_ssh', 'discovery_winrm', 'discovery_agent',
			                                       'discovery_cloud', 'discovery_k8s', 'ct_log', 'import')),
			origin               TEXT NOT NULL DEFAULT 'internal'
			                     CHECK (origin IN ('internal', 'imported', 'discovered', 'synced')),
			management_state     TEXT NOT NULL DEFAULT 'managed'
			                     CHECK (management_state IN ('managed', 'external', 'unmanaged')),
			chain_complete       INTEGER NOT NULL DEFAULT 0,
			chain_trusted        INTEGER NOT NULL DEFAULT 0,
			trust_class          TEXT,
			is_ca                INTEGER NOT NULL DEFAULT 0,
			updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		)`,
		`CREATE TABLE scan_jobs (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			connector TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'queued',
			error_message TEXT,
			results_summary TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		)`,
		`CREATE TABLE endpoints (
			id TEXT PRIMARY KEY,
			ip_address TEXT NOT NULL,
			hostname TEXT,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tls',
			sni_name TEXT NOT NULL DEFAULT '',
			issues TEXT NOT NULL DEFAULT '[]',
			server_tech TEXT,
			recommended_install_mode TEXT,
			ssh_banner TEXT,
			ssh_host_key_algorithms TEXT,
			crypto_posture TEXT,
			last_scanned TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		)`,
		`CREATE UNIQUE INDEX idx_endpoint_unique_identity ON endpoints(ip_address, port, sni_name)`,
		`CREATE TABLE certificate_endpoints (
			certificate_fingerprint TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
			first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
			last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
			currently_active INTEGER NOT NULL DEFAULT 1,
			endpoint_flags TEXT NOT NULL DEFAULT '[]',
			endpoint_risk_score INTEGER NOT NULL DEFAULT 0,
			chain_complete INTEGER,
			chain_trusted INTEGER,
			PRIMARY KEY (certificate_fingerprint, endpoint_id)
		)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}
	}

	// Seed data
	for _, stmt := range []string{
		`INSERT INTO certificates (fingerprint_sha256, serial_number, subject_dn, issuer_dn, valid_from, valid_until, public_key_algorithm, signature_algorithm, risk_score)
			VALUES ('fp-safe', '1', 'CN=safe', 'CN=issuer', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'RSA', 'SHA256-RSA', 10),
			       ('fp-risky', '2', 'CN=risky', 'CN=issuer', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'RSA', 'SHA256-RSA', 85)`,
		`INSERT INTO scan_jobs (id, type, connector, scope, status) VALUES
			('scan-1', 'network', 'test', '{"cidr":"10.0.0.0/24"}', 'complete'),
			('scan-2', 'full', 'test', '{"cidr":"192.168.0.0/16"}', 'running'),
			('scan-3', 'targeted', 'test', '{"target":"legacy.internal"}', 'queued')`,
		`INSERT INTO endpoints (id, ip_address, hostname, port, protocol) VALUES
			('ep-1', '10.0.0.1', 'safe.internal', 443, 'tls'),
			('ep-2', '10.0.0.2', 'risky.internal', 443, 'tls'),
			('ep-3', '10.0.0.3', 'web.internal', 80, 'http')`,
		`INSERT INTO certificate_endpoints (certificate_fingerprint, endpoint_id, currently_active) VALUES
			('fp-safe', 'ep-1', 1),
			('fp-risky', 'ep-2', 1)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to seed data: %v", err)
		}
	}

	return db
}

func TestSQLiteDiscoveryStoreGetSummary(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	summary, err := store.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.DiscoveredEndpoints != 3 {
		t.Errorf("expected 3 endpoints, got %d", summary.DiscoveredEndpoints)
	}
	if summary.MappedCertificates != 2 {
		t.Errorf("expected 2 mapped certs, got %d", summary.MappedCertificates)
	}
	if summary.RiskyEndpoints != 1 {
		t.Errorf("expected 1 risky endpoint, got %d", summary.RiskyEndpoints)
	}
	if summary.ActiveScanJobs != 2 {
		t.Errorf("expected 2 active scan jobs (running+queued), got %d", summary.ActiveScanJobs)
	}
}

func TestSQLiteDiscoveryStoreListEndpoints(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	// All endpoints
	result, err := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 total, got %d", result.Total)
	}
	if len(result.Endpoints) != 3 {
		t.Errorf("expected 3 endpoints, got %d", len(result.Endpoints))
	}

	// Filter by protocol
	result, err = store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Protocol: "http", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 http endpoint, got %d", result.Total)
	}

	// Filter risky only
	result, err = store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{RiskyOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 risky endpoint, got %d", result.Total)
	}
}

func TestSQLiteDiscoveryStoreListScanJobs(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	// All jobs
	result, err := store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 total, got %d", result.Total)
	}

	// Filter by status
	result, err = store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Status: "running", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 running job, got %d", result.Total)
	}

	// Search by scope
	result, err = store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Q: "legacy", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 matching job, got %d", result.Total)
	}
}

func TestSQLiteDiscoveryStoreCreateScan(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	done := stubDiscoveryScan(t, &scanner.ScanResult{Status: "completed"})

	result, err := store.CreateScan(context.Background(), "full", "10.0.0.0/24", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// W2-05: CreateScan now actually runs the scan (in the background)
	// instead of queuing forever with nothing ever executing it.
	if result.Status != "running" {
		t.Errorf("expected running, got %q", result.Status)
	}
	if result.ID == "" {
		t.Error("expected non-empty ID")
	}
	<-done

	// Verify it's in the DB
	jobs, err := store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jobs.Total != 4 {
		t.Errorf("expected 4 jobs after create, got %d", jobs.Total)
	}
}

// TestSQLiteDiscoveryStoreCreateScan_PersistsCanonicalCompletedStatus
// reproduces G-87/S-23: sqliteDiscoveryStore.runAndPersistScan used to
// persist "complete" (no "d") for a successful scan, while
// scannerDiscoveryProvider/discovery_file_provider.go both use "completed" —
// the same DiscoveryScanJob.Status field, two different spellings for the
// same state. This asserts the persisted, listed status is exactly
// "completed".
func TestSQLiteDiscoveryStoreCreateScan_PersistsCanonicalCompletedStatus(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	done := stubDiscoveryScan(t, &scanner.ScanResult{Status: "completed"})

	result, err := store.CreateScan(context.Background(), "full", "10.0.0.0/24", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	<-done

	jobs, err := store.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found *DiscoveryScanJob
	for i := range jobs.ScanJobs {
		if jobs.ScanJobs[i].ID == result.ID {
			found = &jobs.ScanJobs[i]
		}
	}
	if found == nil {
		t.Fatalf("created scan job %s not found in list", result.ID)
	}
	if found.Status != "completed" {
		t.Errorf("expected canonical status %q, got %q", "completed", found.Status)
	}
}

func TestSQLiteDiscoveryStoreCancelScanJob(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	// Cancel a running job
	result, err := store.CancelScanJob(context.Background(), "scan-2", "test cancel")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "canceled" {
		t.Errorf("expected canceled, got %q", result.Status)
	}

	// Cancel an already-complete job should report not found
	result, err = store.CancelScanJob(context.Background(), "scan-1", "test cancel")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "not_found_or_already_terminal" {
		t.Errorf("expected not_found_or_already_terminal, got %q", result.Status)
	}
}

func TestSQLiteDiscoveryStoreRequeueScanJob(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	result, err := store.RequeueScanJob(context.Background(), "scan-1", "retry after fix")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "queued" {
		t.Errorf("expected queued, got %q", result.Status)
	}
	if result.PreviousID != "scan-1" {
		t.Errorf("expected previous_id scan-1, got %q", result.PreviousID)
	}
	if result.ScanJobID == "" || result.ScanJobID == "scan-1" {
		t.Error("expected new job ID different from original")
	}

	// Requeue non-existent job should fail
	_, err = store.RequeueScanJob(context.Background(), "scan-nonexistent", "should fail")
	if err == nil {
		t.Error("expected error for non-existent job")
	}
}

// --- W2-05: fresh-DB self-heal + dedup/staleness upsert ---

// stubEndpointAudit swaps auditEndpointTLSIssues for the duration of a test
// so upsertScanResults (called directly by several tests below, bypassing
// the runDiscoveryScan seam entirely) never makes a live TLS connection —
// matches stubDiscoveryScan's rationale. Defaults to "no issues"; tests that
// care about specific issue content override the var themselves.
func stubEndpointAudit(t *testing.T) {
	t.Helper()
	orig := auditEndpointTLSIssues
	auditEndpointTLSIssues = func(string, int) []string { return nil }
	t.Cleanup(func() { auditEndpointTLSIssues = orig })
}

func newFreshDiscoveryStore(t *testing.T) *sqliteDiscoveryStore {
	t.Helper()
	stubEndpointAudit(t)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "discovery-fresh.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteDiscoveryStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	return s
}

func TestSQLiteDiscoveryStoreEnsureSchemaOnFreshDB(t *testing.T) {
	s := newFreshDiscoveryStore(t)

	summary, err := s.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("GetSummary on fresh (empty) db: %v", err)
	}
	if summary.DiscoveredEndpoints != 0 {
		t.Errorf("expected 0 endpoints on fresh db, got %d", summary.DiscoveredEndpoints)
	}

	// EnsureSchema must be safe to run again (the normal case on every
	// process restart) — every statement is IF NOT EXISTS.
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema re-run on already-initialized db: %v", err)
	}
}

func TestUpsertScanResults_DedupsOnIPPortSNI(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()

	ep := scanner.DiscoveredEndpoint{
		Host: "shop.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-1", 0)},
	}

	// Re-scanning the same (ip, port, sni) three times must not create
	// duplicate endpoint rows.
	for i := 0; i < 3; i++ {
		if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}

	var endpointCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM endpoints").Scan(&endpointCount); err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if endpointCount != 1 {
		t.Fatalf("expected exactly 1 endpoint row after 3 re-scans, got %d", endpointCount)
	}

	var mappingCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM certificate_endpoints").Scan(&mappingCount); err != nil {
		t.Fatalf("count certificate_endpoints: %v", err)
	}
	if mappingCount != 1 {
		t.Fatalf("expected exactly 1 certificate_endpoints row after 3 re-scans, got %d", mappingCount)
	}
}

// TestUpsertScanResults_MarksNonObservedCertGone is the discriminating
// staleness test (W2-05/D-032/R-D2): a cert seen in one scan but absent from
// the next must flip to currently_active=false, scoped only to the endpoint
// actually re-scanned — a different, untouched endpoint's mapping must stay
// active. An upsert-only implementation with no stale-sweep would pass the
// dedup test above but fail this one.
func TestUpsertScanResults_MarksNonObservedCertGone(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()

	target := scanner.DiscoveredEndpoint{
		Host: "app.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-old", 0)},
	}
	other := scanner.DiscoveredEndpoint{
		Host: "other.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-other", 0)},
	}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{target, other}); err != nil {
		t.Fatalf("initial scan: %v", err)
	}

	// Re-scan only `target`, now presenting a different cert (fp-new) —
	// fp-old was not re-observed and must be marked gone. `other` was not
	// touched by this scan at all and must be unaffected.
	target.Certs = []scanner.DiscoveredCert{testDiscoveredCert("fp-new", 0)}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{target}); err != nil {
		t.Fatalf("re-scan: %v", err)
	}

	activeByFingerprint := func(fp string) bool {
		var active int
		err := s.db.QueryRow("SELECT currently_active FROM certificate_endpoints WHERE certificate_fingerprint = ?", fp).Scan(&active)
		if err != nil {
			t.Fatalf("query %s: %v", fp, err)
		}
		return active == 1
	}

	if activeByFingerprint("fp-old") {
		t.Error("expected fp-old (not re-observed) to be marked currently_active=false")
	}
	if !activeByFingerprint("fp-new") {
		t.Error("expected fp-new (freshly observed) to be currently_active=true")
	}
	if !activeByFingerprint("fp-other") {
		t.Error("expected fp-other on the untouched endpoint to remain currently_active=true — staleness must be scoped to the re-scanned endpoint only")
	}
}

// TestUpsertScanResults_SkipsErroredEndpoints proves an endpoint the scan
// couldn't even reach (Error != "") is left alone entirely rather than
// treated as evidence its existing cert mapping is gone.
func TestUpsertScanResults_SkipsErroredEndpoints(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()

	ep := scanner.DiscoveredEndpoint{
		Host: "flaky.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-1", 0)},
	}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatalf("initial scan: %v", err)
	}

	// Re-scan attempt fails to connect this time — must not touch fp-1.
	failed := scanner.DiscoveredEndpoint{Host: "flaky.example.com", Port: 443, Error: "connection refused"}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{failed}); err != nil {
		t.Fatalf("errored re-scan: %v", err)
	}

	var active int
	if err := s.db.QueryRow("SELECT currently_active FROM certificate_endpoints WHERE certificate_fingerprint = 'fp-1'").Scan(&active); err != nil {
		t.Fatalf("query: %v", err)
	}
	if active != 1 {
		t.Error("expected fp-1 to remain currently_active=true after a failed (not a not-observed) re-scan attempt")
	}
}

// TestUpsertScanResults_PersistsCertRiskScore is the G-55 regression: a
// scan-observed cert's risk_score (computed by the scanner) must land in the
// certificates mirror table, and a later re-scan with an updated score must
// overwrite it, so GetSummary/ListEndpoints' risk-score JOINs resolve
// against real data instead of an always-empty/stale table.
func TestUpsertScanResults_PersistsCertRiskScore(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()

	ep := scanner.DiscoveredEndpoint{
		Host: "risky.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-risk", 85)},
	}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatalf("initial scan: %v", err)
	}

	var score int
	if err := s.db.QueryRow("SELECT risk_score FROM certificates WHERE fingerprint_sha256 = 'fp-risk'").Scan(&score); err != nil {
		t.Fatalf("query certificates: %v", err)
	}
	if score != 85 {
		t.Errorf("expected risk_score 85, got %d", score)
	}

	result, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{RiskyOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("ListEndpoints RiskyOnly: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected the scanned risky endpoint to surface via the real risk-score JOIN, got total=%d", result.Total)
	}

	// Re-scan with an updated (lower) risk score — must overwrite, not stack.
	ep.Certs[0].RiskScore = 5
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatalf("re-scan: %v", err)
	}
	if err := s.db.QueryRow("SELECT risk_score FROM certificates WHERE fingerprint_sha256 = 'fp-risk'").Scan(&score); err != nil {
		t.Fatalf("query certificates after re-scan: %v", err)
	}
	if score != 5 {
		t.Errorf("expected risk_score updated to 5, got %d", score)
	}
}

// TestUpsertScanResults_PersistsCipherauditIssues is the acceptance-3
// regression for the actual persist path: auditEndpointTLSIssues's return
// value must land in endpoints.issues through upsertScanResults' real
// INSERT ... ON CONFLICT statement (not just via a hand-seeded UPDATE, as
// TestSQLiteDiscoveryStoreListEndpointFindings uses), and a re-scan with a
// different issue set must overwrite rather than duplicate/append.
func TestUpsertScanResults_PersistsCipherauditIssues(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()

	auditEndpointTLSIssues = func(host string, port int) []string {
		return []string{"TLS 1.1 is deprecated (RFC 8996)", "Weak cipher: RC4"}
	}

	ep := scanner.DiscoveredEndpoint{
		Host: "audited.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-audited", 0)},
	}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatalf("initial scan: %v", err)
	}

	findings, err := s.ListEndpointFindings(ctx)
	if err != nil {
		t.Fatalf("ListEndpointFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 endpoint with issues, got %d: %+v", len(findings), findings)
	}
	if len(findings[0].Issues) != 2 {
		t.Fatalf("expected 2 issues persisted from auditEndpointTLSIssues, got %v", findings[0].Issues)
	}
	if len(findings[0].CertFingerprints) != 1 || findings[0].CertFingerprints[0] != "fp-audited" {
		t.Fatalf("expected [fp-audited] as the endpoint's active cert, got %v", findings[0].CertFingerprints)
	}

	// Re-scan with a single, different issue — issues = excluded.issues on
	// conflict must overwrite the prior JSON, not merge or duplicate it.
	auditEndpointTLSIssues = func(host string, port int) []string {
		return []string{"Non-AEAD cipher suite"}
	}
	if _, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatalf("re-scan: %v", err)
	}
	findings, err = s.ListEndpointFindings(ctx)
	if err != nil {
		t.Fatalf("ListEndpointFindings after re-scan: %v", err)
	}
	if len(findings) != 1 || len(findings[0].Issues) != 1 || findings[0].Issues[0] != "Non-AEAD cipher suite" {
		t.Fatalf("expected re-scan to overwrite issues to exactly [\"Non-AEAD cipher suite\"], got %+v", findings)
	}
}

// TestUpsertScanResults_AuditRunsOutsideWriteTransaction is a regression test
// for a gate finding: upsertScanResults used to call auditEndpointTLSIssues
// (a cipheraudit TLS dial in production) from inside its open write tx, once
// per endpoint. From the second endpoint in a batch onward, that dial ran
// while the tx already held a write lock (acquired by the first endpoint's
// INSERT) — a slow or unreachable target could hold that lock for its full
// dial timeout, contending with every other write in the app on sqlite's
// single-writer model. auditEndpointTLSIssuesBatch now runs every endpoint's
// audit call before BeginTx opens at all, so no write lock is ever held
// during a dial. Proven here by having the audit stub attempt a real write
// through a second connection to the same database file with a short busy
// timeout during the second endpoint's audit call: under the old ordering
// this would fail with SQLITE_BUSY; it must now succeed.
func TestUpsertScanResults_AuditRunsOutsideWriteTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery-lock-check.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteDiscoveryStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	orig := auditEndpointTLSIssues
	t.Cleanup(func() { auditEndpointTLSIssues = orig })

	callCount := 0
	var concurrentWriteErr error
	auditEndpointTLSIssues = func(host string, port int) []string {
		callCount++
		if callCount == 2 {
			probe, err := sql.Open("sqlite", path+"?_busy_timeout=50")
			if err != nil {
				t.Fatalf("open probe connection: %v", err)
			}
			defer probe.Close()
			_, concurrentWriteErr = probe.Exec(
				"INSERT INTO scan_jobs (id, type) VALUES ('probe-job', 'network')")
		}
		return nil
	}

	results := []scanner.DiscoveredEndpoint{
		{Host: "a.example.com", Port: 443, Protocol: "tls", Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-a", 0)}},
		{Host: "b.example.com", Port: 443, Protocol: "tls", Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-b", 0)}},
	}
	if _, err := s.upsertScanResults(context.Background(), results); err != nil {
		t.Fatalf("upsertScanResults: %v", err)
	}

	if callCount != 2 {
		t.Fatalf("expected auditEndpointTLSIssues to be called once per endpoint (2), got %d", callCount)
	}
	if concurrentWriteErr != nil {
		t.Fatalf("concurrent write during the second endpoint's audit call was blocked — "+
			"auditEndpointTLSIssues is running inside the write transaction again: %v", concurrentWriteErr)
	}
}

// TestSQLiteDiscoveryStoreListEndpointFindings proves the store's bulk read
// pairs each endpoint's persisted cipheraudit issues with the fingerprints
// of certificates it currently presents, and skips endpoints with no issues
// entirely (they contribute nothing to the funnel).
func TestSQLiteDiscoveryStoreListEndpointFindings(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	if _, err := db.Exec(`UPDATE endpoints SET issues = '["TLS 1.1 is deprecated (RFC 8996)","Weak cipher: RC4"]' WHERE id = 'ep-2'`); err != nil {
		t.Fatalf("seed issues: %v", err)
	}
	// ep-3 has no certificate_endpoints mapping in setupDiscoveryTestDB and
	// no issues seeded — must not appear in the result at all.

	findings, err := store.ListEndpointFindings(context.Background())
	if err != nil {
		t.Fatalf("ListEndpointFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 endpoint with issues, got %d: %+v", len(findings), findings)
	}
	got := findings[0]
	if len(got.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(got.Issues))
	}
	if len(got.CertFingerprints) != 1 || got.CertFingerprints[0] != "fp-risky" {
		t.Fatalf("expected [fp-risky] as the endpoint's active cert, got %v", got.CertFingerprints)
	}
}

// TestComputeDiscoveryFindingFunnel proves discovery's raw/effective/
// suppressed math: raw counts every persisted issue with no dedup, an
// issue suppresses only when one of the endpoint's OWN current certs
// carries a matching active exception (not some other endpoint's cert),
// and raw is never reduced — only suppressed/effective move.
func TestComputeDiscoveryFindingFunnel(t *testing.T) {
	findings := []discoveryEndpointFindings{
		{Issues: []string{"TLS 1.1 is deprecated (RFC 8996)", "Weak cipher: RC4"}, CertFingerprints: []string{"fp-a"}},
		{Issues: []string{"TLS 1.1 is deprecated (RFC 8996)"}, CertFingerprints: []string{"fp-b"}},
	}

	funnel := computeDiscoveryFindingFunnel(findings, nil)
	if funnel.Raw != 3 || funnel.Suppressed != 0 || funnel.Effective != 3 {
		t.Fatalf("expected raw=3 suppressed=0 effective=3 with no exceptions, got %+v", funnel)
	}

	// An exception on fp-a's issue must not suppress the identical issue
	// string on fp-b's endpoint — suppression is scoped to the specific
	// certificate the exception names.
	exceptions := []FindingException{
		{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", FindingCode: "TLS 1.1 is deprecated (RFC 8996)"},
	}
	funnel = computeDiscoveryFindingFunnel(findings, exceptions)
	if funnel.Raw != 3 {
		t.Fatalf("expected raw to stay 3, got %d", funnel.Raw)
	}
	if funnel.Suppressed != 1 {
		t.Fatalf("expected exactly 1 suppressed (fp-a's issue only), got %d", funnel.Suppressed)
	}
	if funnel.Effective != 2 {
		t.Fatalf("expected effective = raw(3) - suppressed(1) = 2, got %d", funnel.Effective)
	}
}

func TestDBDiscoveryProviderFailsClosedOnOpenError(t *testing.T) {
	provider := &dbDiscoveryProvider{openErr: fmt.Errorf("connection refused")}

	_, err := provider.GetSummary(context.Background())
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}

	_, err = provider.ListEndpoints(context.Background(), DiscoveryEndpointQuery{})
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}

	_, err = provider.CreateScan(context.Background(), "full", "10.0.0.0/24", nil)
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}
}

// The two-column test schema used to hide that this upsert violated the
// real table's NOT NULL/CHECK constraints — every scan that found a cert
// failed to persist in production. This asserts the full row lands.
func TestUpsertScanResultsPersistsFullCertificateRow(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	cert := testDiscoveredCert("fp-full", 42)
	cert.DNSNames = []string{"full.example.com"}
	cert.RiskFlags = []string{"self_signed"}
	cert.Raw = []byte{0x30, 0x82}
	_, err := store.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{{
		Host: "full.example.com", Port: 8443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{cert},
	}})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var serial, subject, issuer, alg, source, origin, mgmt, raw string
	var risk int
	err = db.QueryRow(`SELECT serial_number, subject_dn, issuer_dn, public_key_algorithm,
		source, origin, management_state, raw_cert_b64, risk_score
		FROM certificates WHERE fingerprint_sha256 = 'fp-full'`).
		Scan(&serial, &subject, &issuer, &alg, &source, &origin, &mgmt, &raw, &risk)
	if err != nil {
		t.Fatalf("row: %v", err)
	}
	if serial != "1234" || subject != "CN=test.fp-full" || issuer != "CN=test-issuer" || alg != "ECDSA" || risk != 42 {
		t.Errorf("cert fields wrong: serial=%q subject=%q issuer=%q alg=%q risk=%d", serial, subject, issuer, alg, risk)
	}
	if source != "discovery_network" || origin != "discovered" || mgmt != "unmanaged" {
		t.Errorf("provenance wrong: source=%q origin=%q mgmt=%q", source, origin, mgmt)
	}
	if raw == "" {
		t.Error("raw_cert_b64 not persisted")
	}

	// The endpoint list must carry the real mapping — the UI's detail panel
	// shows these instead of a hostname text search.
	res, err := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	var found *DiscoveryEndpoint
	for i := range res.Endpoints {
		if res.Endpoints[i].Hostname == "full.example.com" {
			found = &res.Endpoints[i]
		}
	}
	if found == nil || len(found.MappedCerts) != 1 {
		t.Fatalf("expected full.example.com with 1 mapped cert, got %+v", res.Endpoints)
	}
	mc := found.MappedCerts[0]
	if mc.Fingerprint != "fp-full" || mc.CommonName != "test.fp-full" || mc.RiskScore != 42 {
		t.Errorf("mapped cert wrong: %+v", mc)
	}
}

// A certificate whose key algorithm the schema CHECK rejects is skipped
// with a log line; the scan itself must still persist everything else.
func TestUpsertScanResultsSkipsUnsupportedAlgorithm(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}

	bad := testDiscoveredCert("fp-dsa", 0)
	bad.PublicKeyAlgorithm = "DSA"
	good := testDiscoveredCert("fp-good", 0)
	_, err := store.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{{
		Host: "mixed.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{bad, good},
	}})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE fingerprint_sha256 IN ('fp-dsa','fp-good')`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected only the supported cert persisted, got %d rows", n)
	}
}

func TestScanScopeTarget(t *testing.T) {
	for in, want := range map[string]string{
		`{"target":"10.0.0.0/24"}`: "10.0.0.0/24",
		"bare-host:443":            "bare-host:443",
		`{"other":"x"}`:            `{"other":"x"}`,
	} {
		if got := scanScopeTarget(in); got != want {
			t.Errorf("scanScopeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// A job left queued/running by a dead process must not sit "running"
// forever — its runner goroutine died with that process.
func TestEnsureSchemaFailsOrphanedScanJobs(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	if _, err := db.Exec(`INSERT INTO scan_jobs (id, type, connector, scope, status)
		VALUES ('scan-orphan', 'targeted', 'api', '{}', 'running'),
		       ('scan-done', 'targeted', 'api', '{}', 'completed')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store := &sqliteDiscoveryStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	var status, msg string
	if err := db.QueryRow(`SELECT status, COALESCE(error_message,'') FROM scan_jobs WHERE id='scan-orphan'`).Scan(&status, &msg); err != nil {
		t.Fatalf("row: %v", err)
	}
	if status != "failed" || msg != "interrupted by server restart" {
		t.Errorf("orphan not swept: status=%q msg=%q", status, msg)
	}
	if err := db.QueryRow(`SELECT status FROM scan_jobs WHERE id='scan-done'`).Scan(&status); err != nil {
		t.Fatalf("row2: %v", err)
	}
	if status != "completed" {
		t.Errorf("terminal job must be untouched, got %q", status)
	}
}

func TestMergePortsAndParsing(t *testing.T) {
	got := mergePorts([]int{443, 8443}, []int{8443, 9999}, []int{0, 70000, 636})
	want := []int{443, 8443, 9999, 636}
	if len(got) != len(want) {
		t.Fatalf("mergePorts dedup/range failed: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mergePorts order: got %v want %v", got, want)
		}
	}
	if ps := parsePortList("443, 8443 ,x, 99999, 22"); len(ps) != 3 {
		t.Errorf("parsePortList should drop invalid tokens, got %v", ps)
	}
	if ports := scanScopePorts(`{"target":"h","ports":[8443,9999]}`); len(ports) != 2 || ports[1] != 9999 {
		t.Errorf("scanScopePorts: %v", ports)
	}
	if ports := scanScopePorts(`{"target":"h"}`); len(ports) != 0 {
		t.Errorf("scanScopePorts on portless scope should be empty, got %v", ports)
	}
}

// An SSH endpoint carries no cert but real host-key material — the "ssh for
// keys" half of discovery. It must persist the banner and algorithms and
// surface them through the endpoint list.
func TestUpsertPersistsSSHHostKeys(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()
	_, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{{
		Host: "bastion.example.com", Port: 22, Protocol: "ssh",
		Banner:            "SSH-2.0-OpenSSH_9.6",
		HostKeyAlgorithms: []string{"ssh-ed25519", "rsa-sha2-512", "ssh-rsa"},
	}})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	res, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var ep *DiscoveryEndpoint
	for i := range res.Endpoints {
		if res.Endpoints[i].Port == 22 {
			ep = &res.Endpoints[i]
		}
	}
	if ep == nil {
		t.Fatalf("SSH endpoint not persisted: %+v", res.Endpoints)
	}
	if ep.SSHBanner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("banner not persisted: %q", ep.SSHBanner)
	}
	if len(ep.SSHHostKeyAlgorithms) != 3 || ep.SSHHostKeyAlgorithms[2] != "ssh-rsa" {
		t.Errorf("host-key algorithms not persisted: %v", ep.SSHHostKeyAlgorithms)
	}
}

// --- W19-22: port-less (mesh/K8s-secret) sources + per-row isolation ---

// newMigratedDiscoveryStore runs the REAL versioned migrations
// (internal/db/migrate.go), not discovery_db_provider.go's own
// EnsureSchema/sqliteDiscoverySchema fallback — the distinction that hid
// this bug for so long (see setupDiscoveryTestDB and newFreshDiscoveryStore
// above, neither of which declares the real port/protocol CHECKs). Every
// production deployment gets the migrated schema first (db_core.go's
// OpenCoreDB runs RunMigrations before any store's EnsureSchema), so this
// is the only harness that actually exercises 000058's CHECK constraints.
func newMigratedDiscoveryStore(t *testing.T) *sqliteDiscoveryStore {
	t.Helper()
	stubEndpointAudit(t)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "discovery-migrated.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	s := &sqliteDiscoveryStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema after migrations: %v", err)
	}
	return s
}

// TestUpsertScanResultsPersistsPortlessMeshSource is the direct W19-22
// regression: before 000058, this INSERT failed outright against the real
// migrated schema with "CHECK constraint failed: port BETWEEN 1 AND
// 65535" — exactly the failure mode tests/live/mesh's kind fixture hit
// against a real Istio cluster (docs/STATUS.md, 2026-09-11).
func TestUpsertScanResultsPersistsPortlessMeshSource(t *testing.T) {
	s := newMigratedDiscoveryStore(t)
	ctx := context.Background()

	ep := scanner.DiscoveredEndpoint{
		Host: "istio-system/istio-ca-secret", Port: 0, Protocol: "istio-mesh",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-istio-ca", 0)},
	}
	out, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{ep})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if out.Persisted != 1 || out.Skipped != 0 {
		t.Fatalf("expected 1 persisted, 0 skipped, got %+v", out)
	}

	res, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *DiscoveryEndpoint
	for i := range res.Endpoints {
		if res.Endpoints[i].Hostname == "istio-system/istio-ca-secret" {
			found = &res.Endpoints[i]
		}
	}
	if found == nil {
		t.Fatalf("mesh secret not persisted: %+v", res.Endpoints)
	}
	if found.Port != 0 {
		t.Errorf("expected port 0 (no network listener), got %d", found.Port)
	}
	if found.Protocol != "istio-mesh" {
		t.Errorf("expected protocol recorded as 'istio-mesh' (not collapsed to 'other'), got %q", found.Protocol)
	}
	if len(found.MappedCerts) != 1 || found.MappedCerts[0].Fingerprint != "fp-istio-ca" {
		t.Errorf("expected the Istio CA cert mapped, got %+v", found.MappedCerts)
	}
}

// TestUpsertScanResultsIsolatesOneRowFailure is the acceptance-2 regression:
// one endpoint's persistence failure must not discard every OTHER result in
// the same sweep — the actual defect that lost every mesh sweep, since
// upsertScanResults used to return on the FIRST SQL error inside one shared
// transaction. An out-of-range port (a scanner bug, not a mesh source) is
// used here as a schema-agnostic way to force a real CHECK failure so this
// test proves per-row isolation independently of 000058's specific fix.
func TestUpsertScanResultsIsolatesOneRowFailure(t *testing.T) {
	s := newMigratedDiscoveryStore(t)
	ctx := context.Background()

	good := scanner.DiscoveredEndpoint{
		Host: "good.example.com", Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{testDiscoveredCert("fp-good-isolated", 0)},
	}
	bad := scanner.DiscoveredEndpoint{
		Host: "bad.example.com", Port: 70000, Protocol: "tls", // out of range: CHECK (port BETWEEN 0 AND 65535)
	}
	out, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{bad, good})
	if err != nil {
		t.Fatalf("upsert must not fail the whole sweep over one bad row: %v", err)
	}
	if out.Persisted != 1 || out.Skipped != 1 {
		t.Fatalf("expected 1 persisted + 1 skipped, got %+v", out)
	}
	if !strings.Contains(out.FirstSkipReason, "bad.example.com") {
		t.Errorf("expected the skip reason to identify the failing endpoint, got %q", out.FirstSkipReason)
	}

	res, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var foundGood bool
	for _, e := range res.Endpoints {
		if e.Hostname == "good.example.com" {
			foundGood = true
		}
		if e.Hostname == "bad.example.com" {
			t.Errorf("the out-of-range row must not have persisted: %+v", e)
		}
	}
	if !foundGood {
		t.Fatalf("the good endpoint in the same sweep must still persist, got %+v", res.Endpoints)
	}
}

// TestUpsertScanResultsSurfacesPortlessSourceError is the acceptance-3
// regression: a permission-denied port-less source (Error set, e.g. a K8s
// RBAC 403 reading a mesh secret) must be visible to a caller of the
// product API, not only a scheduler log line.
func TestUpsertScanResultsSurfacesPortlessSourceError(t *testing.T) {
	s := newMigratedDiscoveryStore(t)
	ctx := context.Background()

	denied := scanner.DiscoveredEndpoint{
		Host: "linkerd/linkerd-identity-issuer", Port: 0, Protocol: "linkerd-mesh",
		Error: "k8s GET /api/v1/namespaces/linkerd/secrets/linkerd-identity-issuer: HTTP 403",
	}
	out, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{denied})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if out.Persisted != 1 {
		t.Fatalf("expected the denied source itself to persist as a visible row, got %+v", out)
	}

	findings, err := s.ListEndpointFindings(ctx)
	if err != nil {
		t.Fatalf("ListEndpointFindings: %v", err)
	}
	if len(findings) != 1 || len(findings[0].Issues) != 1 {
		t.Fatalf("expected exactly 1 endpoint with 1 issue recording the denial, got %+v", findings)
	}
	if !strings.Contains(findings[0].Issues[0], "HTTP 403") {
		t.Errorf("expected the persisted issue to carry the permission error, got %q", findings[0].Issues[0])
	}

	// The actual product API a caller queries -- GET /api/v1/discovery/
	// endpoints via ListEndpoints -- must carry the same issue, not just
	// the internal ListEndpointFindings path GetSummary's finding funnel
	// uses.
	res, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if len(res.Endpoints) != 1 || len(res.Endpoints[0].Issues) != 1 {
		t.Fatalf("expected ListEndpoints to surface the denial as an issue, got %+v", res.Endpoints)
	}
	if !strings.Contains(res.Endpoints[0].Issues[0], "HTTP 403") {
		t.Errorf("expected ListEndpoints' issue to carry the permission error, got %q", res.Endpoints[0].Issues[0])
	}
	if len(res.Endpoints[0].MappedCerts) != 0 {
		t.Errorf("a denied source must carry no mapped certs, got %+v", res.Endpoints[0].MappedCerts)
	}
}

// TestUpsertScanResultsSkipsErroredRealNetworkEndpoints proves the
// unchanged W2-05 behavior: a real (port != 0) network target's transient
// failure is still dropped entirely, not turned into a visible row the way
// a port-less source's error now is.
func TestUpsertScanResultsSkipsErroredRealNetworkEndpoints(t *testing.T) {
	s := newMigratedDiscoveryStore(t)
	ctx := context.Background()

	failed := scanner.DiscoveredEndpoint{Host: "flaky.example.com", Port: 443, Error: "connection refused"}
	out, err := s.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{failed})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if out.Persisted != 0 || out.Skipped != 0 {
		t.Fatalf("expected a real network target's error to be dropped (not persisted, not counted as a skip), got %+v", out)
	}
}

func TestDiscoveryProtocolOrDefault(t *testing.T) {
	cases := map[string]string{
		"":               "tls",
		"tls":            "tls",
		"other":          "other",
		"https":          "tls",
		"kubernetes-api": "kubernetes",
		"k8s-tls-secret": "k8s-tls-secret",
		"istio-mesh":     "istio-mesh",
		"linkerd-mesh":   "linkerd-mesh",
		"ssh":            "other",
		"saas-api":       "other",
	}
	for in, want := range cases {
		if got := discoveryProtocolOrDefault(in); got != want {
			t.Errorf("discoveryProtocolOrDefault(%q) = %q, want %q", in, got, want)
		}
	}
}
