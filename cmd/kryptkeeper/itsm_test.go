// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/bootstrap"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/notifications/itsm"

	_ "modernc.org/sqlite"
)

type resolveFake struct {
	mu       sync.Mutex
	resolved []string
}

func (f *resolveFake) Kind() string                                          { return "jira" }
func (f *resolveFake) Find(context.Context, string) (*itsm.TicketRef, error) { return nil, nil }
func (f *resolveFake) Exists(context.Context, itsm.TicketRef) (bool, error)  { return true, nil }
func (f *resolveFake) Create(_ context.Context, ev itsm.Event) (itsm.TicketRef, error) {
	return itsm.TicketRef{Key: "T-" + ev.ID}, nil
}
func (f *resolveFake) Resolve(_ context.Context, ref itsm.TicketRef, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, ref.Key)
	return nil
}

func TestItsmRenewalResolver_ResolvesTicketsOfReplacedCertificate(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "itsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	store := itsm.NewStore(db, false)
	ctx := context.Background()
	if _, err := store.CreateConnection(ctx, itsm.Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: "https://x.example", CredentialRef: "r", Enabled: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	conn := &resolveFake{}
	svc := itsm.NewService(itsm.Config{Store: store, Conns: func(context.Context, string) (itsm.Connector, error) { return conn, nil }})
	for _, ev := range []itsm.Event{{ID: "e-old", Class: "renewal_failed", Fingerprint: "fp-old"}, {ID: "e-other", Class: "renewal_failed", Fingerprint: "fp-other"}} {
		if err := svc.Submit(ctx, "c1", ev); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Drain(ctx); err != nil {
		t.Fatal(err)
	}

	var hook bootstrap.RenewalVerifiedFunc = itsmRenewalResolver(svc, 60*time.Second)
	cancelled, cancel := context.WithCancel(ctx)
	hook(cancelled, "fp-old", "fp-new")
	cancel() // the caller's request ends; the resolve must still complete

	deadline := time.Now().Add(45 * time.Second) // the resolve runs async; a loaded CI runner took 20s+
	for time.Now().Before(deadline) {
		row, _ := store.GetEvent(ctx, "e-old")
		if row.Status == itsm.StatusResolved {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	old, _ := store.GetEvent(ctx, "e-old")
	other, _ := store.GetEvent(ctx, "e-other")
	if old.Status != itsm.StatusResolved || other.Status != itsm.StatusCreated {
		t.Fatalf("old=%s other=%s", old.Status, other.Status)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.resolved) != 1 || conn.resolved[0] != "T-e-old" {
		t.Fatalf("resolved %v", conn.resolved)
	}
}
