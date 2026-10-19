// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// HACoordinator arbitrates which hub replica may run a given scheduler tick,
// using one lease row per lock name in the shared DB (PE-9/D-048/FR-P10).
// A replica is leader for a lock as long as it keeps renewing the lease
// before it lapses; a replica that stops calling TryAcquire (crashed, wedged)
// simply stops renewing, and its lease lapses on its own — no heartbeat
// channel, unlock RPC, or graceful-shutdown path is needed for failover.
type HACoordinator struct {
	db *sql.DB
	// ph builds an N-indexed placeholder ("?" for SQLite, "$N" for Postgres) —
	// same convention as dbPostureSnapshotStore.
	ph func(n int) string
	// replicaID identifies this process for the lifetime of this coordinator.
	// It is regenerated on every process start (never persisted), so a
	// crashed-and-restarted replica competes for a lock like any other peer
	// rather than "renewing" a lease from a previous life it has no memory of.
	replicaID string
	// now is overridden in tests for deterministic lease-expiry checks.
	now func() time.Time

	// Readiness state (W23-27): guarded by mu.
	mu          sync.Mutex
	unready     bool
	outageStart time.Time
}

// minHALeaseDuration floors TryAcquire's leaseDuration argument — see the
// comment at its call site in TryAcquire for why a non-positive lease is
// unsafe rather than merely suboptimal.
const minHALeaseDuration = time.Minute

const haSchedulerLocksSchema = `
CREATE TABLE IF NOT EXISTS ha_scheduler_locks (
    lock_name        TEXT PRIMARY KEY,
    holder_id        TEXT NOT NULL,
    acquired_at      TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL
);`

var (
	processReplicaOnce sync.Once
	processReplicaID   string
	processReplicaErr  error
)

// newHACoordinatorID returns this PROCESS's replica identity, generated once
// and shared by every coordinator in the process (W30-27). Each scheduler
// builds its own coordinator but they all lock different names, so sharing is
// safe, and it makes "previous holder" mean one hub rather than one scheduler,
// which lets a hub's death be reported as one failover episode.
func newHACoordinatorID() (string, error) {
	processReplicaOnce.Do(func() {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			processReplicaErr = err
			return
		}
		processReplicaID = "replica-" + hex.EncodeToString(b)
	})
	return processReplicaID, processReplicaErr
}

func newHACoordinator(db *sql.DB, ph func(int) string) (*HACoordinator, error) {
	id, err := newHACoordinatorID()
	if err != nil {
		return nil, err
	}
	return &HACoordinator{
		db:        db,
		ph:        ph,
		replicaID: id,
		now:       func() time.Time { return time.Now().UTC() },
	}, nil
}

// EnsureSchema idempotently creates the lock table.
func (c *HACoordinator) EnsureSchema(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, haSchedulerLocksSchema)
	return err
}

// TryAcquire attempts to become (or remain) leader for lockName for
// leaseDuration from now. It returns true if this replica may proceed with
// the guarded work this tick. Callers should pass a leaseDuration safely
// longer than their own poll interval (e.g. 2x) — a lease shorter than the
// interval between two ticks would let a live, still-ticking leader lose its
// own lock to a peer between ticks, which is not a failover, just churn.
//
// The single INSERT .. ON CONFLICT .. DO UPDATE .. WHERE statement is the
// entire protocol. Its WHERE clause only lets the update through when the
// existing row is already held by this replica (renewal) or its lease has
// already lapsed (the previous leader died or stalled); two replicas racing
// this statement for the same lock at the same instant can't both win, since
// the DB serializes the two writes to the same primary key and the second
// writer's WHERE clause evaluates against the first writer's already-
// committed row.
func (c *HACoordinator) TryAcquire(ctx context.Context, lockName string, leaseDuration time.Duration) (bool, error) {
	// A caller-supplied leaseDuration <= 0 would write a lease that expires
	// at (or before) the moment it's acquired, so the next TryAcquire —
	// including the current holder's own renewal — would always win and the
	// lock would never actually hold. Floor it rather than trust the caller.
	if leaseDuration < minHALeaseDuration {
		leaseDuration = minHALeaseDuration
	}
	now := c.now()
	// W30-27: remember who held the lock so a win over a different holder can
	// be reported as a failover. Only read when an observer is installed.
	obs := currentHAFailoverObserver()
	var prev *haLeaseRow
	if obs != nil {
		prev = c.readLease(ctx, lockName)
	}
	nowStr := now.Format(time.RFC3339)
	leaseStr := now.Add(leaseDuration).Format(time.RFC3339)

	q := fmt.Sprintf(`
INSERT INTO ha_scheduler_locks (lock_name, holder_id, acquired_at, lease_expires_at)
VALUES (%s, %s, %s, %s)
ON CONFLICT (lock_name) DO UPDATE SET
    holder_id = excluded.holder_id,
    acquired_at = excluded.acquired_at,
    lease_expires_at = excluded.lease_expires_at
WHERE ha_scheduler_locks.holder_id = excluded.holder_id
   OR ha_scheduler_locks.lease_expires_at < excluded.acquired_at`,
		c.ph(1), c.ph(2), c.ph(3), c.ph(4))

	res, err := c.db.ExecContext(ctx, q, lockName, c.replicaID, nowStr, leaseStr)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 && prev != nil && prev.holder != c.replicaID {
		obs(ctx, HAFailover{
			LockName: lockName, PreviousHolder: prev.holder, NewHolder: c.replicaID,
			PreviousAcquiredAt: prev.acquiredAt, PreviousLeaseExpiresAt: prev.expiresAt, At: now,
		})
	}
	return n > 0, nil
}

// Release drops this replica's lease on lockName immediately, letting a peer
// (or this same replica after a restart) acquire it without waiting for the
// lease to lapse naturally (W19-25). Only a row this replica currently holds
// is deleted -- the WHERE clause mirrors TryAcquire's own "only touch what
// you own" discipline, so a replica that lost the lock to a peer between its
// last renewal and its own shutdown can never delete the peer's live lease.
// Deleting rather than expiring in place needs no extra branch for "lock
// name never existed" (DELETE of zero rows is not an error), which matters
// here because Stop must be safe to call even when this replica never held
// the lock at all (e.g. it was never the leader before shutdown).
func (c *HACoordinator) Release(ctx context.Context, lockName string) error {
	q := fmt.Sprintf(`DELETE FROM ha_scheduler_locks WHERE lock_name = %s AND holder_id = %s`,
		c.ph(1), c.ph(2))
	_, err := c.db.ExecContext(ctx, q, lockName, c.replicaID)
	return err
}

// newHACoordinatorFromEnv opens the same SQLite/Postgres DB as the other
// providers and ensures the lock table exists (posture_snapshot_store.go's
// EnsureSchema pattern — no dedicated migration for this table).
//
// APP_HA_LOCK_DB_DSN — dedicated DSN override; falls back to the same
// resolution chain as the rest of bootstrap's DB-backed providers.
func newHACoordinatorFromEnv() (*HACoordinator, error) {
	state := newDBProviderState[*HACoordinator](
		"ha-coordinator",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_HA_LOCK_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_HA_LOCK_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_HA_LOCK_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *HACoordinator {
			c, err := newHACoordinator(db, sqlitePlaceholder)
			if err != nil {
				logging.Warnf("ha coordinator: id generation failed: %v", err)
				return nil
			}
			return c
		},
		func(db *sql.DB) *HACoordinator {
			c, err := newHACoordinator(db, postgresPlaceholder)
			if err != nil {
				logging.Warnf("ha coordinator: id generation failed: %v", err)
				return nil
			}
			return c
		},
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newHACoordinatorFromEnvLogged is the soft-fail wrapper used at scheduler
// construction time (renewal_scheduler.go's
// newRenewalAlertCooldownStoreFromEnvLogged pattern): a coordinator outage
// degrades to "run unconditionally" — the pre-W6-01, single-replica
// behavior — rather than preventing the scheduler from starting at all.
func newHACoordinatorFromEnvLogged() *HACoordinator {
	c, err := newHACoordinatorFromEnv()
	if err != nil {
		logging.Warnf("ha coordinator: unavailable, schedulers will run unconditionally (single-replica behavior): %v", err)
		return nil
	}
	return c
}

// NewHACoordinatorFromEnvLogged exposes the soft-fail constructor so main can
// hang the readiness probe off a coordinator of its own. nil means no shared
// HA DB (single replica), in which case no probe should be installed. The CT
// monitor's leader lock (W24-20) uses it too.
func NewHACoordinatorFromEnvLogged() *HACoordinator { return newHACoordinatorFromEnvLogged() }

// haReplicaNotReadyAction is the alert/audit name for a replica that lost the
// shared DB (W23-27).
const haReplicaNotReadyAction = "ha.replica_not_ready"

// haReadinessTimeout stays below readinessTimeout so the probe, not the
// /readyz deadline, reports the failure.
const haReadinessTimeout = 1500 * time.Millisecond

// ReadinessProbe returns a probe that fails while the shared DB is
// unreachable. The first failure of an outage logs the ALERT line (the
// real-time alert); the audit row is written on recovery because the audit
// store lives in the same DB and cannot take writes during the outage.
func (c *HACoordinator) ReadinessProbe(audit AuditProvider) ReadinessProbe {
	return func(ctx context.Context) error {
		err := c.checkDB(ctx)
		c.mu.Lock()
		if err != nil {
			first := !c.unready
			if first {
				c.unready = true
				c.outageStart = c.now()
			}
			c.mu.Unlock()
			if first {
				logging.Infof("ALERT %s: %v", haReplicaNotReadyAction, err)
			}
			return fmt.Errorf("shared database unreachable: %w", err)
		}
		wasUnready, started := c.unready, c.outageStart
		c.unready = false
		c.mu.Unlock()
		if wasUnready && audit != nil {
			now := c.now()
			entry := AuditEntry{
				Timestamp:    now.Format(time.RFC3339),
				Action:       haReplicaNotReadyAction,
				ActorType:    "system",
				ActorID:      c.replicaID,
				ResourceType: "replica",
				ResourceID:   c.replicaID,
				Outcome:      AuditOutcomeFailure,
				ChangeSummary: fmt.Sprintf(`{"outage_started":%q,"outage_seconds":%d}`,
					started.Format(time.RFC3339), int(now.Sub(started).Seconds())),
			}
			if aerr := audit.AppendEntry(context.WithoutCancel(ctx), entry); aerr != nil {
				logging.Warnf("ha readiness: audit append failed: %v", aerr)
			}
		}
		return nil
	}
}

func (c *HACoordinator) checkDB(ctx context.Context) error {
	ctx2, cancel := context.WithTimeout(ctx, haReadinessTimeout)
	defer cancel()
	if err := c.db.PingContext(ctx2); err != nil {
		return err
	}
	var lease string
	err := c.db.QueryRowContext(ctx2, `SELECT lease_expires_at FROM ha_scheduler_locks LIMIT 1`).Scan(&lease)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}
