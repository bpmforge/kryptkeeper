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

func newTestHADB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ha.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHACoordinatorAt builds a coordinator pinned to a fixed clock and
// replica ID, sharing db across instances to simulate multiple replicas
// contending for the same lock rows.
func newTestHACoordinatorAt(t *testing.T, db *sql.DB, replicaID string, at time.Time) *HACoordinator {
	t.Helper()
	c := &HACoordinator{
		db:        db,
		ph:        sqlitePlaceholder,
		replicaID: replicaID,
		now:       func() time.Time { return at },
	}
	if err := c.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return c
}

func TestHACoordinatorTryAcquire(t *testing.T) {
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		run  func(t *testing.T, db *sql.DB)
	}{
		{
			name: "first_acquire_succeeds",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				ok, err := a.TryAcquire(context.Background(), "lock-x", time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !ok {
					t.Fatal("expected first acquire of an unheld lock to succeed")
				}
			},
		},
		{
			name: "peer_with_live_lease_is_excluded",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", 5*time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(time.Second))
				ok, err := b.TryAcquire(context.Background(), "lock-x", 5*time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if ok {
					t.Fatal("expected a peer to be excluded while the current holder's lease is still live")
				}
			},
		},
		{
			name: "same_holder_renews_its_own_lease",
			run: func(t *testing.T, db *sql.DB) {
				a1 := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a1.TryAcquire(context.Background(), "lock-x", 5*time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				a2 := newTestHACoordinatorAt(t, db, "replica-a", base.Add(time.Minute))
				ok, err := a2.TryAcquire(context.Background(), "lock-x", 5*time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !ok {
					t.Fatal("expected the existing holder to renew its own lease before it lapses")
				}
			},
		},
		{
			name: "failover_after_lease_expiry",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				// replica-a never renews (simulated crash); replica-b tries
				// after the lease has lapsed.
				b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(2*time.Minute))
				ok, err := b.TryAcquire(context.Background(), "lock-x", time.Minute)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if !ok {
					t.Fatal("expected failover once the previous leader's lease had lapsed")
				}
			},
		},
		{
			name: "independent_lock_names_do_not_interfere",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", 5*time.Minute); err != nil || !ok {
					t.Fatalf("setup acquire lock-x: ok=%v err=%v", ok, err)
				}
				b := newTestHACoordinatorAt(t, db, "replica-b", base)
				ok, err := b.TryAcquire(context.Background(), "lock-y", 5*time.Minute)
				if err != nil {
					t.Fatalf("acquire lock-y: %v", err)
				}
				if !ok {
					t.Fatal("expected a distinct lock name to be independently acquirable by another replica")
				}
			},
		},
		{
			name: "non_positive_lease_duration_is_floored",
			run: func(t *testing.T, db *sql.DB) {
				a := newTestHACoordinatorAt(t, db, "replica-a", base)
				if ok, err := a.TryAcquire(context.Background(), "lock-x", 0); err != nil || !ok {
					t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
				}
				b := newTestHACoordinatorAt(t, db, "replica-b", base.Add(time.Second))
				ok, err := b.TryAcquire(context.Background(), "lock-x", 0)
				if err != nil {
					t.Fatalf("acquire: %v", err)
				}
				if ok {
					t.Fatal("expected a non-positive lease duration to be floored, not to expire immediately")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestHADB(t)
			tc.run(t, db)
		})
	}
}

func TestHACoordinatorRelease(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	t.Run("release_lets_a_peer_acquire_without_waiting_for_the_lease", func(t *testing.T) {
		db := newTestHADB(t)
		a := newTestHACoordinatorAt(t, db, "replica-a", base)
		if ok, err := a.TryAcquire(context.Background(), "lock-x", time.Hour); err != nil || !ok {
			t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
		}
		if err := a.Release(context.Background(), "lock-x"); err != nil {
			t.Fatalf("release: %v", err)
		}
		// Same instant, well before the hour-long lease would have lapsed.
		b := newTestHACoordinatorAt(t, db, "replica-b", base)
		ok, err := b.TryAcquire(context.Background(), "lock-x", time.Hour)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		if !ok {
			t.Fatal("expected a peer to acquire immediately after Release, not wait out the lease")
		}
	})

	t.Run("release_only_deletes_a_row_this_replica_holds", func(t *testing.T) {
		db := newTestHADB(t)
		a := newTestHACoordinatorAt(t, db, "replica-a", base)
		if ok, err := a.TryAcquire(context.Background(), "lock-x", time.Hour); err != nil || !ok {
			t.Fatalf("setup acquire: ok=%v err=%v", ok, err)
		}
		// replica-b never held this lock; its Release must not touch
		// replica-a's live lease.
		b := newTestHACoordinatorAt(t, db, "replica-b", base)
		if err := b.Release(context.Background(), "lock-x"); err != nil {
			t.Fatalf("release: %v", err)
		}
		c := newTestHACoordinatorAt(t, db, "replica-c", base.Add(time.Second))
		ok, err := c.TryAcquire(context.Background(), "lock-x", time.Hour)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		if ok {
			t.Fatal("expected replica-a's lease to still be live after an unrelated replica's Release")
		}
	})

	t.Run("release_of_a_lock_never_held_is_a_safe_no_op", func(t *testing.T) {
		db := newTestHADB(t)
		a := newTestHACoordinatorAt(t, db, "replica-a", base)
		if err := a.Release(context.Background(), "never-acquired"); err != nil {
			t.Fatalf("expected release of a nonexistent lock to be a no-op, got: %v", err)
		}
	})
}
