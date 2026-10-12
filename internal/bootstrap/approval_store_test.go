// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestApprovalStoreSelfHealsSchemaOnFreshDB is the S-06/G-47 regression: a
// brand-new database with no pre-existing cert_approval_requests table (i.e.
// no migration ever ran against it) must still work, since EnsureSchema now
// creates the table inline rather than depending on migration 000013.
func TestApprovalStoreSelfHealsSchemaOnFreshDB(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	store := &sqliteApprovalStore{db: db}
	ctx := context.Background()

	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}

	req := ApprovalRequest{
		ID: "apr-fresh", TemplateID: "tpl-1", CAID: "ca-1", Requester: "svc",
		Status: "pending", CSRPEM: "placeholder", RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := store.Create(ctx, req); err != nil {
		t.Fatalf("Create on fresh db: %v", err)
	}

	got, err := store.Get(ctx, "apr-fresh")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != req.ID || got.CAID != req.CAID {
		t.Fatalf("unexpected round-trip: %+v", got)
	}

	// EnsureSchema is idempotent — calling it again on an already-migrated
	// DB (the normal case on every process restart) must not error.
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}
