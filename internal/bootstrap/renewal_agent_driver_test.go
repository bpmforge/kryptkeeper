// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// TestRenewalAgentDriverSweep_AssignsTaskForCertThatAgedIntoThresholdWithoutNewPush
// is the core W4-05 acceptance-1 regression: a cert that was NOT yet within
// the renewal threshold at inventory-push time (so submitInventory's own
// on-push match assigned nothing) becomes eligible purely because wall-clock
// time has advanced, with no new push from the agent. Only a scheduled
// re-evaluation — not the on-push trigger — can catch this.
func TestRenewalAgentDriverSweep_AssignsTaskForCertThatAgedIntoThresholdWithoutNewPush(t *testing.T) {
	store := NewAgentStore()
	realNow := time.Now().UTC()
	// 35 days out: outside the default 30-day threshold at push time.
	notAfter := realNow.AddDate(0, 0, 35)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, notAfter)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)
	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("setup: expected 0 tasks at push time (cert not yet in window), got %d", len(tasks))
	}

	// No new push happens. Sweep as if 10 days later — the cert has now
	// aged into the 30-day window even though the store's inventory row is
	// unchanged since the original push.
	later := realNow.AddDate(0, 0, 10)
	d := &RenewalAgentDriver{store: store, now: func() time.Time { return later }}
	d.sweep()

	tasks, err := store.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected sweep to assign 1 task once the cert aged into the window, got %d", len(tasks))
	}
	tk := tasks[0]
	if tk.Fingerprint != "fp1" || tk.Action != "renew" {
		t.Errorf("task basics wrong: %+v", tk)
	}
	if tk.CertPath != "/etc/nginx/ssl/shop.crt" || tk.ServerType != "nginx" {
		t.Errorf("install hints not populated — sweep must reuse matchRenewalTasks, not a stub: %+v", tk)
	}
}

// TestRenewalAgentDriverSweep_NoOpWhenStillOutsideThresholdEvenLater is the
// boundary case for the same gap: even after time advances, a cert that
// still hasn't reached the threshold must not be tasked.
func TestRenewalAgentDriverSweep_NoOpWhenStillOutsideThresholdEvenLater(t *testing.T) {
	store := NewAgentStore()
	realNow := time.Now().UTC()
	notAfter := realNow.AddDate(0, 0, 60)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, notAfter)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)

	// threshold at the later sweep time is realNow+10d+30d = realNow+40d;
	// the cert at realNow+60d is still outside it.
	later := realNow.AddDate(0, 0, 10)
	d := &RenewalAgentDriver{store: store, now: func() time.Time { return later }}
	d.sweep()

	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("expected 0 tasks, cert still outside the threshold even at the later sweep time, got %d", len(tasks))
	}
}

// TestRenewalAgentDriverSweep_IdempotentAcrossMultipleSweeps proves the
// driver relies on matchRenewalTasks's own dedup rather than any separate
// assignment logic of its own (W4-05 acceptance 1).
func TestRenewalAgentDriverSweep_IdempotentAcrossMultipleSweeps(t *testing.T) {
	store := NewAgentStore()
	realNow := time.Now().UTC()
	notAfter := realNow.AddDate(0, 0, 35)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, notAfter)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)

	later := realNow.AddDate(0, 0, 10)
	d := &RenewalAgentDriver{store: store, now: func() time.Time { return later }}
	d.sweep()
	d.sweep() // second sweep at the same "later" instant must not duplicate

	tasks, _ := store.getTasks(id, token)
	if len(tasks) != 1 {
		t.Fatalf("expected sweeping twice to still leave exactly 1 task, got %d", len(tasks))
	}
}

// TestRenewalAgentDriverSweep_NilStoreNoPanic mirrors the nil-guard tests
// already established for PostureScheduler/RenewalScheduler.
func TestRenewalAgentDriverSweep_NilStoreNoPanic(t *testing.T) {
	(&RenewalAgentDriver{}).sweep()
}

// TestRenewalAgentDriverSweep_SkipsWhenNotLeader and RunsWhenLeader are the
// same HA-gate regression pattern as
// TestPostureSchedulerCaptureSkipsWhenNotLeader/RunsWhenLeader — on >=2
// replicas racing the same tick, only the lease holder may sweep, so two
// replicas can't both assign a task for the same newly-eligible fingerprint.
func TestRenewalAgentDriverSweep_SkipsWhenNotLeader(t *testing.T) {
	store := NewAgentStore()
	realNow := time.Now().UTC()
	notAfter := realNow.AddDate(0, 0, 35)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, notAfter)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)

	db := newTestHADB(t)
	haNow := time.Now().UTC()
	peer := newTestHACoordinatorAt(t, db, "replica-peer", haNow)
	if ok, err := peer.TryAcquire(context.Background(), haLockRenewalAgentDriver, 5*time.Minute); err != nil || !ok {
		t.Fatalf("setup: peer acquire ok=%v err=%v", ok, err)
	}
	self := newTestHACoordinatorAt(t, db, "replica-self", haNow)

	later := realNow.AddDate(0, 0, 10)
	d := &RenewalAgentDriver{store: store, pollInterval: time.Hour, haCoordinator: self, now: func() time.Time { return later }}
	d.sweep()

	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("expected non-leader sweep to skip, got %d task(s)", len(tasks))
	}
}

func TestRenewalAgentDriverSweep_RunsWhenLeader(t *testing.T) {
	store := NewAgentStore()
	realNow := time.Now().UTC()
	notAfter := realNow.AddDate(0, 0, 35)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, notAfter)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)

	db := newTestHADB(t)
	self := newTestHACoordinatorAt(t, db, "replica-self", time.Now().UTC())

	later := realNow.AddDate(0, 0, 10)
	d := &RenewalAgentDriver{store: store, pollInterval: time.Hour, haCoordinator: self, now: func() time.Time { return later }}
	d.sweep()

	if tasks, _ := store.getTasks(id, token); len(tasks) != 1 {
		t.Fatalf("expected leader sweep to assign the task, got %d", len(tasks))
	}
}

// TestDBAgentStoreSweepRenewals_AssignsTaskForStaleInventory is the
// DB-backed-store equivalent of the core mem-store gap test above.
func TestDBAgentStoreSweepRenewals_AssignsTaskForStaleInventory(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, err := s.register("agent-1", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	realNow := time.Now().UTC()
	notAfter := realNow.AddDate(0, 0, 35)
	certs := []AgentDiscoveredCert{{Fingerprint: "fp1", Subject: "CN=shop", Source: "/etc/nginx/ssl/shop.crt", NotAfter: notAfter, AutoRenewable: true}}
	eps := []AgentEndpoint{{ServerType: "nginx", CertPath: "/etc/nginx/ssl/shop.crt", KeyPath: "/etc/nginx/ssl/shop.key", ServerName: "shop.example.com", ListenPort: 443}}
	if err := s.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory: %v", err)
	}
	if tasks, _ := s.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("setup: expected 0 tasks at push time, got %d", len(tasks))
	}

	later := realNow.AddDate(0, 0, 10)
	added := s.sweepRenewals(later)
	if added != 1 {
		t.Fatalf("expected sweepRenewals to report 1 new task, got %d", added)
	}

	tasks, err := s.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	if len(tasks) != 1 || tasks[0].CertPath != "/etc/nginx/ssl/shop.crt" {
		t.Fatalf("task not persisted correctly: %+v", tasks)
	}
}

// TestDBAgentStoreSweepRenewals_IdempotentAndNoOpWithoutInventory covers two
// edge cases for the DB-backed sweep: an agent with no stored inventory must
// not error, and sweeping twice must not duplicate a task.
func TestDBAgentStoreSweepRenewals_IdempotentAndNoOpWithoutInventory(t *testing.T) {
	s := newTestDBAgentStore(t)

	if _, _, err := s.register("agent-empty", AgentTypeLinux); err != nil {
		t.Fatalf("register: %v", err)
	}
	if added := s.sweepRenewals(time.Now().UTC()); added != 0 {
		t.Fatalf("expected 0 for agent with no inventory, got %d", added)
	}

	id, token, err := s.register("agent-1", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	realNow := time.Now().UTC()
	// Subject must carry a CN that parses as a hostname (W19-13): matchRenewalTasks
	// skips queuing a task with no usable ACME identifier.
	certs := []AgentDiscoveredCert{{Fingerprint: "fp1", Subject: "CN=host", Source: "/c.crt", NotAfter: realNow.AddDate(0, 0, 35), AutoRenewable: true}}
	eps := []AgentEndpoint{{ServerType: "nginx", CertPath: "/c.crt", KeyPath: "/c.key", ServerName: "x", ListenPort: 443}}
	if err := s.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory: %v", err)
	}

	later := realNow.AddDate(0, 0, 10)
	if added := s.sweepRenewals(later); added != 1 {
		t.Fatalf("expected 1 new task on first sweep, got %d", added)
	}
	if added := s.sweepRenewals(later); added != 0 {
		t.Fatalf("expected 0 new tasks on second sweep (already tasked), got %d", added)
	}
	if tasks, _ := s.getTasks(id, token); len(tasks) != 1 {
		t.Fatalf("expected exactly 1 task after two sweeps, got %d", len(tasks))
	}
}

// TestRenewalAgentDriverSweep_DBBackedStoreViaDriver proves the driver works
// end-to-end against the production (DB-backed) store, not only the
// in-memory one used by the tests above.
func TestRenewalAgentDriverSweep_DBBackedStoreViaDriver(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, err := s.register("agent-1", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	realNow := time.Now().UTC()
	// Subject must carry a CN that parses as a hostname (W19-13): matchRenewalTasks
	// skips queuing a task with no usable ACME identifier.
	certs := []AgentDiscoveredCert{{Fingerprint: "fp1", Subject: "CN=host", Source: "/c.crt", NotAfter: realNow.AddDate(0, 0, 35), AutoRenewable: true}}
	eps := []AgentEndpoint{{ServerType: "nginx", CertPath: "/c.crt", KeyPath: "/c.key", ServerName: "x", ListenPort: 443}}
	if err := s.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory: %v", err)
	}

	later := realNow.AddDate(0, 0, 10)
	d := &RenewalAgentDriver{store: s, now: func() time.Time { return later }}
	d.sweep()

	tasks, err := s.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected driver sweep against DB-backed store to assign 1 task, got %d", len(tasks))
	}
}

// TestRenewalAgentDriverStart_SweepsImmediatelyWithoutWaitingForFirstTick is
// the S-35 wiring regression. Every other test in this file calls d.sweep()
// directly, which proves the sweep logic and says nothing about Start() — the
// method main.go actually calls. A driver whose Start() only swept on the
// first ticker tick would pass all of them and still do nothing for the first
// AGENT_RENEWAL_SWEEP_MINUTES (default 15) after every boot, which is exactly
// the window a restart-heavy deployment spends most of its life in.
//
// pollInterval is deliberately an hour: it is longer than this test can
// possibly run, so the ONLY thing that can assign a task here is the
// pre-ticker sweep inside Start(). Shorten it and the test would pass on a
// tick instead, quietly losing the property it exists to pin.
func TestRenewalAgentDriverStart_SweepsImmediatelyWithoutWaitingForFirstTick(t *testing.T) {
	store := NewAgentStore()
	realNow := time.Now().UTC()
	notAfter := realNow.AddDate(0, 0, 35) // outside the 30-day window at push time
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, notAfter)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)
	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("setup: expected 0 tasks at push time, got %d", len(tasks))
	}

	later := realNow.AddDate(0, 0, 10) // now inside the window, with no new push
	d := &RenewalAgentDriver{
		store:        store,
		now:          func() time.Time { return later },
		pollInterval: time.Hour,
		stop:         make(chan struct{}),
	}
	d.Start()
	defer d.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for {
		tasks, err := store.getTasks(id, token)
		if err != nil {
			t.Fatalf("getTasks: %v", err)
		}
		if len(tasks) == 1 {
			if tasks[0].Fingerprint != "fp1" || tasks[0].Action != "renew" {
				t.Errorf("Start()'s sweep assigned a task, but not the expected one: %+v", tasks[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Start() did not sweep within 3s — got %d task(s); the driver only sweeps on the first tick, so it does nothing for a whole poll interval after boot", len(tasks))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRenewalAgentDriverStop_IsIdempotent covers main.go's shape: Stop is
// reached through `defer stopAgentRenewalDriver()`, and a second call (a
// re-entrant shutdown path, or a test calling it after the deferred one) must
// not panic on a closed channel. sync.Once is what makes that true; this fails
// loudly if it is ever removed.
func TestRenewalAgentDriverStop_IsIdempotent(t *testing.T) {
	// `now` is required, not decorative: Start() sweeps immediately in a
	// goroutine and sweep() calls d.now(), so a zero-value field is a nil
	// dereference inside that goroutine. It panics the whole test binary
	// asynchronously — which a -run filter on this test can outrun and the
	// full suite cannot. Constructed here the way every other test in this
	// file does, via NewRenewalAgentDriverFromEnv's own defaults.
	d := &RenewalAgentDriver{
		store:        NewAgentStore(),
		now:          func() time.Time { return time.Now().UTC() },
		pollInterval: time.Hour,
		stop:         make(chan struct{}),
	}
	d.Start()
	d.Stop()
	d.Stop() // must not panic
}
