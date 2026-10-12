// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// haLockRenewalAgentDriver names this driver's lease row in
// ha_scheduler_locks (ha_coordinator.go, W6-01/PE-9/D-048) — same HA posture
// as renewal_scheduler.go and posture_scheduler.go: on >=2 replicas, only the
// lease holder sweeps, so two replicas racing the same tick can't both
// insert a task for the same newly-eligible fingerprint.
const haLockRenewalAgentDriver = "renewal-agent-driver"

// RenewalAgentDriver periodically re-evaluates every registered agent's
// last-known inventory against the renewal threshold and assigns
// AgentRenewalTask for certs that have newly aged into the window.
//
// Gap this closes (W4-05 acceptance #2 — verified against the code, not
// assumed): matchRenewalTasks already runs on every agent inventory push
// (memAgentStore/dbAgentStore submitInventory), and each push fully REPLACES
// the agent's stored inventory (r.inventory = certs; DELETE+reinsert for the
// DB store). That replace-on-push means a partial discovery miss — one
// cert's file moves while the rest are still found, so the cycle's cert
// list is non-empty and PostInventory still fires — drops the missing cert
// from the hub's inventory entirely on that very push. That is a different,
// unaddressed problem this driver cannot help with: once a cert is gone from
// the store there is nothing left to re-evaluate.
//
// The gap this driver DOES close is PostInventory not firing at ALL for a
// cycle. The agent's own poll loop (cmd/kryptkeeper-agent/main.go's
// runCycle) calls Heartbeat() every cycle regardless, but only calls
// PostInventory() when that cycle's discovery walk found ANY certs or
// endpoints (`if len(certs) > 0 || len(endpoints) > 0`). If discovery goes
// wholly empty for a stretch — every scan/config path misconfigured or
// removed, filesystem permissions revoked across the board, or the
// discovery subsystem itself failing silently — the agent keeps
// heartbeating (AgentStatusActive in the UI) while its last-known inventory
// row at the hub freezes at whatever the last successful push contained:
// nothing calls submitInventory again, so matchRenewalTasks never re-runs,
// and a cert already in that frozen snapshot can age straight through the
// renewal threshold with no task ever assigned and no visible signal that
// anything is wrong. This driver re-runs the same matcher on a timer
// against each agent's already-stored inventory, so eligibility is checked
// against wall-clock time passing, not only against inventory-push events.
// Re-tasking an agent that has since gone fully offline (heartbeat and
// inventory both stopped) is harmless: the task sits until the agent
// returns and polls for it, same as any other pending task.
type RenewalAgentDriver struct {
	store        AgentStore
	pollInterval time.Duration

	// haCoordinator is nil when unavailable (soft-fail — see
	// newHACoordinatorFromEnvLogged), which preserves the pre-W6-01
	// single-replica behavior of always sweeping.
	haCoordinator *HACoordinator

	// now is overridden in tests for deterministic "time has passed since
	// the last push" checks (mirrors HACoordinator's own now field).
	now func() time.Time

	stop chan struct{}
	once sync.Once
}

// renewalAgentSweepIntervalFromEnv reads AGENT_RENEWAL_SWEEP_MINUTES
// (default 15). Deliberately shorter than RENEWAL_POLL_HOURS
// (renewal_scheduler.go's daily owner-notification scan): this driver exists
// to catch drift between an agent's inventory-push cadence and the renewal
// threshold, so it has to tick faster than "once a day" to actually close
// that gap.
func renewalAgentSweepIntervalFromEnv() time.Duration {
	minutes := 15
	if raw := strings.TrimSpace(os.Getenv("AGENT_RENEWAL_SWEEP_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			minutes = n
		}
	}
	return time.Duration(minutes) * time.Minute
}

// NewRenewalAgentDriverFromEnv creates a RenewalAgentDriver using
// AGENT_RENEWAL_SWEEP_MINUTES (default 15).
//
// Wired into cmd/kryptkeeper/main.go by S-35: startAgentRenewalDriver builds
// this driver from NewAgentStoreFromEnv and Start()/Stop()s it alongside
// renewalScheduler, postureScheduler and evidenceScheduler, so it runs in the
// built binary. It was shipped unwired by W4-05 — main.go was outside that
// ticket's write_scope — which meant a fully tested scheduler that never
// executed in production; this comment said so, and S-35 closed it.
//
// main.go builds its own AgentStore because handlers.go keeps its instance
// local. Both resolve the same DSN, so a configured deployment shares one
// database; only the no-database fallback diverges, and that path already logs
// its own unavailability.
func NewRenewalAgentDriverFromEnv(store AgentStore) *RenewalAgentDriver {
	return &RenewalAgentDriver{
		store:         store,
		pollInterval:  renewalAgentSweepIntervalFromEnv(),
		haCoordinator: newHACoordinatorFromEnvLogged(),
		now:           func() time.Time { return time.Now().UTC() },
		stop:          make(chan struct{}),
	}
}

// Start launches the sweep loop in a goroutine. Call Stop to shut it down.
func (d *RenewalAgentDriver) Start() {
	go func() {
		d.sweep()
		ticker := time.NewTicker(d.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.sweep()
			case <-d.stop:
				return
			}
		}
	}()
}

// Stop shuts down the sweep loop.
func (d *RenewalAgentDriver) Stop() {
	d.once.Do(func() { close(d.stop) })
}

// sweep runs one tick: re-evaluate every agent's stored inventory and assign
// any newly-eligible AgentRenewalTask.
func (d *RenewalAgentDriver) sweep() {
	if d.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// HA gate (W6-01/PE-9/D-048): see renewal_scheduler.go/posture_scheduler.go
	// for why a lock-check error fails closed (skip) rather than open — this
	// driver would otherwise double-assign identical tasks across replicas.
	if d.haCoordinator != nil {
		ok, err := d.haCoordinator.TryAcquire(ctx, haLockRenewalAgentDriver, 2*d.pollInterval)
		if err != nil {
			log.Printf("renewal agent driver: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	if added := d.store.sweepRenewals(d.now()); added > 0 {
		log.Printf("renewal agent driver: assigned %d renewal task(s) on scheduled sweep", added)
	}
}

// sweepRenewals implements AgentStore for the DB-backed store — closes the
// same on-push-only gap as memAgentStore.sweepRenewals (handlers_agents.go),
// one agent's rows at a time. Defined here rather than agent_store_db.go
// because that file sits outside W4-05's write_scope; a method may live in
// any file of its declaring type's package.
func (s *dbAgentStore) sweepRenewals(now time.Time) int {
	ctx := context.Background()
	added := 0
	for _, a := range s.list() {
		n, err := s.sweepAgentRenewals(ctx, a.ID, now)
		if err != nil {
			log.Printf("renewal agent driver: sweep failed for agent %s: %v", a.ID, err)
			continue
		}
		added += n
	}
	return added
}

// sweepAgentRenewals re-evaluates one agent's last-known inventory. The
// existing-tasks read and the new tasks' inserts happen inside a single
// transaction, but that transaction is NOT synchronized with the separate
// transaction submitInventory (agent_store_db.go) opens for the same
// agent_id from a concurrent request: a sweep racing a live agent's own
// inventory push for the same newly-eligible fingerprint can both read "no
// existing task" before either commits — matchRenewalTasks's own
// no-duplicate guarantee only holds within a single existingTasks snapshot,
// not across two independent transactions. FIXED (W4-05): a unique index on
// agent_tasks(agent_id, fingerprint) — created by EnsureSchema
// (agent_store_db.go, self-heal, since NewAgentStoreFromEnv resolves its
// own DSN and doesn't necessarily go through RunMigrations) and by
// migrations/{postgres,sqlite}/000041_agent_tasks_unique (for deployments
// that do) — plus insertTaskTx (agent_store_db.go) switched to INSERT ...
// ON CONFLICT DO NOTHING means the losing writer's insert is silently
// skipped rather than either creating a duplicate row or erroring the whole
// transaction (a plain unique-constraint violation here would abort
// submitInventory's transaction via its tx.Rollback() defer, turning
// "duplicate renewal task" into "agent inventory push discarded" — worse
// than the bug being fixed). See
// TestDBAgentStore_ConcurrentSubmitInventoryAndSweepAssignExactlyOneTask
// (agent_store_db_test.go) for the regression proof.
func (s *dbAgentStore) sweepAgentRenewals(ctx context.Context, agentID string, now time.Time) (int, error) {
	inventory, err := s.inventoryFor(ctx, agentID)
	if err != nil {
		return 0, fmt.Errorf("inventory: %w", err)
	}
	if len(inventory) == 0 {
		return 0, nil
	}
	endpoints := s.endpointsFor(agentID)
	results := s.resultsFor(agentID)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	existingTasks, err := s.tasksTx(ctx, tx, agentID)
	if err != nil {
		return 0, fmt.Errorf("existing tasks: %w", err)
	}

	newTasks := matchRenewalTasks(inventory, endpoints, existingTasks, results, s.thresholdDays, now, newRenewalTaskID)
	added := 0
	for _, t := range newTasks {
		inserted, err := s.insertTaskTx(ctx, tx, agentID, t)
		if err != nil {
			return 0, fmt.Errorf("insert task: %w", err)
		}
		if inserted {
			added++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, nil
}

// inventoryFor returns an agent's last-known discovered-cert inventory — the
// same rows submitInventory replaces on each push. No non-sweep caller needs
// this today (submitInventory works from the certs it was just handed), so
// there is no pre-existing reader to reuse.
func (s *dbAgentStore) inventoryFor(ctx context.Context, agentID string) ([]AgentDiscoveredCert, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		"SELECT fingerprint, subject, issuer, not_before, not_after, source, auto_renewable FROM agent_inventory WHERE agent_id = %s",
		s.ph(1)), agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentDiscoveredCert{}
	for rows.Next() {
		var c AgentDiscoveredCert
		var notBefore, notAfter string
		var autoRenewable int
		if err := rows.Scan(&c.Fingerprint, &c.Subject, &c.Issuer, &notBefore, &notAfter, &c.Source, &autoRenewable); err != nil {
			return nil, err
		}
		c.NotBefore = parseTimeOrZero(notBefore)
		c.NotAfter = parseTimeOrZero(notAfter)
		c.AutoRenewable = autoRenewable != 0
		out = append(out, c)
	}
	return out, rows.Err()
}
