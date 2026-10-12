// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	kkdb "kryptkeeper/internal/db"
)

// newTestChallengeStore is a DBChallengeStore on a freshly migrated SQLite
// database, so the tests run against the real 000066 schema.
func newTestChallengeStore(t *testing.T) *DBChallengeStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "scep.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewDBChallengeStore(db, false)
}

func TestChallengeStoreLifecycle(t *testing.T) {
	s := newTestChallengeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	c, secret, err := s.Create(ctx, Challenge{CAID: "ca-1", CommonName: "dev1.example.com", DNSNames: []string{"dev1.example.com"},
		CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 || c.ID == "" {
		t.Fatalf("secret length %d, id %q", len(secret), c.ID)
	}
	var stored int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scep_challenges WHERE challenge_sha256 = ?`, secret).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("the plaintext secret must never be stored (rows with it: %d, err %v)", stored, err)
	}

	if _, err := s.Consume(ctx, "not-the-secret", now); !errors.Is(err, ErrChallengeUnknown) {
		t.Errorf("wrong secret: %v, want ErrChallengeUnknown", err)
	}
	got, err := s.Consume(ctx, secret, now)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.CommonName != "dev1.example.com" || len(got.DNSNames) != 1 || got.CAID != "ca-1" {
		t.Errorf("consumed %+v", got)
	}
	if _, err := s.Consume(ctx, secret, now); !errors.Is(err, ErrChallengeUsed) {
		t.Errorf("second consume: %v, want ErrChallengeUsed", err)
	}
	if err := s.Delete(ctx, c.ID); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("deleting a used challenge: %v, want ErrChallengeNotFound (it stays as a record)", err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || list[0].UsedAt == nil {
		t.Fatalf("list: %+v err %v", list, err)
	}
}

func TestChallengeStoreExpiryAndDelete(t *testing.T) {
	s := newTestChallengeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, expired, err := s.Create(ctx, Challenge{CAID: "ca-1", CommonName: "old", CreatedBy: "admin", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(ctx, expired, now); !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("expired: %v, want ErrChallengeExpired", err)
	}

	c, secret, err := s.Create(ctx, Challenge{CAID: "ca-1", CommonName: "gone", CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, c.ID); err != nil {
		t.Fatalf("delete unused: %v", err)
	}
	if _, err := s.Consume(ctx, secret, now); !errors.Is(err, ErrChallengeUnknown) {
		t.Errorf("deleted challenge: %v, want ErrChallengeUnknown", err)
	}
}

// Two devices racing with one challenge: exactly one may enroll.
func TestChallengeStoreConsumeIsOneTimeUnderRace(t *testing.T) {
	s := newTestChallengeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, secret, err := s.Create(ctx, Challenge{CAID: "ca-1", CommonName: "race", CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Consume(ctx, secret, now); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d of %d concurrent consumes succeeded, want exactly 1", wins, n)
	}
}
