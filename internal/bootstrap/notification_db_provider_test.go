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

func setupNotificationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "notification-test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Minimal schema matching W8
	for _, stmt := range []string{
		`CREATE TABLE notification_deliveries (
			id TEXT PRIMARY KEY,
			notification_policy_id TEXT,
			channel TEXT NOT NULL,
			target TEXT NOT NULL,
			subject TEXT,
			message TEXT,
			status TEXT NOT NULL DEFAULT 'queued',
			error_detail TEXT,
			retry_of_id TEXT,
			triggered_by TEXT NOT NULL DEFAULT 'system',
			queued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
			delivered_at TEXT,
			acknowledged_at TEXT,
			acknowledged_note TEXT,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}
	}

	// Seed data
	if _, err := db.Exec(`
INSERT INTO notification_deliveries (id, channel, target, status, triggered_by, queued_at) VALUES
	('notif-1', 'email', 'ops@example.com', 'failed', 'threshold', datetime('now', '-1 hour')),
	('notif-2', 'slack', '#alerts', 'sent', 'scan_complete', datetime('now', '-2 hours')),
	('notif-3', 'email', 'sec@example.com', 'queued', 'risk_alert', datetime('now', '-3 hours'))
`); err != nil {
		t.Fatalf("failed to seed data: %v", err)
	}

	return db
}

func TestSQLiteNotificationStoreGetSummary(t *testing.T) {
	db := setupNotificationTestDB(t)
	store := &sqliteNotificationStore{db: db}

	summary, err := store.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.PendingNotifications != 1 {
		t.Errorf("expected 1 pending (queued), got %d", summary.PendingNotifications)
	}
	if summary.DeliveryFailures24h != 1 {
		t.Errorf("expected 1 failure in 24h, got %d", summary.DeliveryFailures24h)
	}
}

func TestSQLiteNotificationStoreListDeliveries(t *testing.T) {
	db := setupNotificationTestDB(t)
	store := &sqliteNotificationStore{db: db}

	// All deliveries
	result, err := store.ListDeliveries(context.Background(), NotificationDeliveryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 total, got %d", result.Total)
	}

	// Filter by channel
	result, err = store.ListDeliveries(context.Background(), NotificationDeliveryQuery{Channel: "email", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 email deliveries, got %d", result.Total)
	}

	// Filter by status
	result, err = store.ListDeliveries(context.Background(), NotificationDeliveryQuery{Status: "failed", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 failed delivery, got %d", result.Total)
	}
}

func TestSQLiteNotificationStoreAckDelivery(t *testing.T) {
	db := setupNotificationTestDB(t)
	store := &sqliteNotificationStore{db: db}

	result, err := store.AckDelivery(context.Background(), "notif-1", "acknowledged by ops")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "acknowledged" {
		t.Errorf("expected acknowledged, got %q", result.Status)
	}

	// Verify the DB was updated
	var status string
	_ = db.QueryRow("SELECT status FROM notification_deliveries WHERE id = 'notif-1'").Scan(&status)
	if status != "acknowledged" {
		t.Errorf("expected DB status acknowledged, got %q", status)
	}
}

func TestSQLiteNotificationStoreRetryDelivery(t *testing.T) {
	db := setupNotificationTestDB(t)
	store := &sqliteNotificationStore{db: db}

	result, err := store.RetryDelivery(context.Background(), "notif-1", "retry after fix")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "queued" {
		t.Errorf("expected queued, got %q", result.Status)
	}
	if result.RetryJobID == "" {
		t.Error("expected non-empty retry job ID")
	}

	// Verify retry row exists
	var retryOf string
	_ = db.QueryRow("SELECT retry_of_id FROM notification_deliveries WHERE id = ?", result.RetryJobID).Scan(&retryOf)
	if retryOf != "notif-1" {
		t.Errorf("expected retry_of_id=notif-1, got %q", retryOf)
	}
}

func TestSQLiteNotificationStoreTestDelivery(t *testing.T) {
	db := setupNotificationTestDB(t)
	store := &sqliteNotificationStore{db: db}

	result, err := store.TestDelivery(context.Background(), "slack", "#test-channel", "test message")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "queued" {
		t.Errorf("expected queued, got %q", result.Status)
	}
	if result.Channel != "slack" {
		t.Errorf("expected slack, got %q", result.Channel)
	}

	// Verify it's in the DB
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM notification_deliveries").Scan(&count)
	if count != 4 {
		t.Errorf("expected 4 deliveries after test, got %d", count)
	}
}

func TestDBNotificationProviderFailsClosedOnOpenError(t *testing.T) {
	provider := &dbNotificationProvider{openErr: fmt.Errorf("connection refused")}

	_, err := provider.GetSummary(context.Background())
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}

	_, err = provider.ListDeliveries(context.Background(), NotificationDeliveryQuery{})
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}

	_, err = provider.TestDelivery(context.Background(), "email", "ops@test.com", "test")
	if err == nil {
		t.Error("expected error from fail-closed provider")
	}
}
