// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func setupDashboardActionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "dashboard-action-test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Minimal audit_log schema (no append-only triggers for test writes)
	if _, err := db.Exec(`
CREATE TABLE audit_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	action TEXT NOT NULL,
	actor_type TEXT NOT NULL,
	actor_id TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	trace_id TEXT,
	outcome TEXT NOT NULL DEFAULT 'success',
	source_ip TEXT,
	user_agent TEXT,
	session_id TEXT,
	change_summary TEXT
)
`); err != nil {
		t.Fatalf("failed to create audit_log: %v", err)
	}

	// Seed dashboard action events
	if _, err := db.Exec(`
INSERT INTO audit_log (timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome) VALUES
	('2026-04-08T03:00:00Z', 'dashboard.action.ack', 'system', 'dashboard', 'certificate', 'act-expired-certs', 'Owner assigned', 'success'),
	('2026-04-08T02:00:00Z', 'dashboard.action.resolve', 'system', 'dashboard', 'discovery', 'act-risky-endpoints', 'Decommissioned', 'success'),
	('2026-04-08T01:00:00Z', 'dashboard.action.create', 'system', 'dashboard', 'certificate', 'act-expiring-certs', NULL, 'success'),
	('2026-04-07T23:00:00Z', 'certificate.issue', 'user', 'u-1', 'certificate', 'fp-1', NULL, 'success')
`); err != nil {
		t.Fatalf("failed to seed audit_log: %v", err)
	}

	return db
}

func TestSQLiteDashboardActionStoreListHistory(t *testing.T) {
	db := setupDashboardActionTestDB(t)
	store := &sqliteDashboardActionStore{db: db}

	// All dashboard action history (should exclude non-dashboard events)
	result, err := store.ListHistory(context.Background(), DashboardActionHistoryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 dashboard actions (excluding certificate.issue), got %d", result.Total)
	}

	// Filter by category
	result, err = store.ListHistory(context.Background(), DashboardActionHistoryQuery{Category: "certificate", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 certificate-category actions, got %d", result.Total)
	}

	// Filter by status (outcome)
	result, err = store.ListHistory(context.Background(), DashboardActionHistoryQuery{Status: "success", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 successful actions, got %d", result.Total)
	}
}

func TestSQLiteDashboardActionStoreAckAction(t *testing.T) {
	db := setupDashboardActionTestDB(t)
	store := &sqliteDashboardActionStore{db: db}

	result, err := store.AckAction(context.Background(), "act-expiring-certs", "reviewed by ops")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "acknowledged" {
		t.Errorf("expected acknowledged, got %q", result.Status)
	}
	if result.ActionID != "act-expiring-certs" {
		t.Errorf("expected act-expiring-certs, got %q", result.ActionID)
	}

	// Verify audit entry was created
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'dashboard.action.ack' AND resource_id = 'act-expiring-certs'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 ack audit entry for act-expiring-certs, got %d", count)
	}
}

func TestSQLiteDashboardActionStoreResolveAction(t *testing.T) {
	db := setupDashboardActionTestDB(t)
	store := &sqliteDashboardActionStore{db: db}

	result, err := store.ResolveAction(context.Background(), "act-expired-certs", "all certs renewed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "resolved" {
		t.Errorf("expected resolved, got %q", result.Status)
	}
	if result.ResolvedAt == "" {
		t.Error("expected non-empty resolved_at")
	}
}

func TestDBDashboardActionProviderFailsClosedOnOpenError(t *testing.T) {
	provider := &dbDashboardActionProvider{openErr: fmt.Errorf("connection refused")}

	_, err := provider.ListHistory(context.Background(), DashboardActionHistoryQuery{})
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}

	_, err = provider.AckAction(context.Background(), "act-1", "test")
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}

	_, err = provider.ResolveAction(context.Background(), "act-1", "test")
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}
}
