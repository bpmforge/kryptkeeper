// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openAgentDB(t *testing.T, path string) *dbAgentStore {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbAgentStore{db: db, ph: sqlitePlaceholder, thresholdDays: 30}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return s
}

func newTestDBAgentStore(t *testing.T) *dbAgentStore {
	return openAgentDB(t, filepath.Join(t.TempDir(), "agents.db"))
}

func TestDBAgentStore_RegisterAndAuth(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, err := s.register("agent-1", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.heartbeat(id, token); err != nil {
		t.Fatalf("heartbeat with valid token: %v", err)
	}
	if err := s.heartbeat(id, "wrong"); err != ErrAgentUnauthorized {
		t.Fatalf("expected unauthorized with wrong token, got %v", err)
	}
	agents := s.list()
	if len(agents) != 1 || agents[0].Name != "agent-1" {
		t.Fatalf("list wrong: %+v", agents)
	}
}

func TestDBAgentStore_TokenStoredHashedNotPlaintext(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, err := s.register("agent-1", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	var storedToken, storedHash string
	if err := s.db.QueryRow("SELECT token, token_hash FROM agents WHERE id = ?", id).Scan(&storedToken, &storedHash); err != nil {
		t.Fatalf("query: %v", err)
	}
	if storedToken != "" {
		t.Fatalf("expected plaintext token column empty, got %q", storedToken)
	}
	if storedHash == "" || storedHash == token {
		t.Fatalf("expected token_hash to be a non-empty hash distinct from the raw token, got %q", storedHash)
	}
	if storedHash != hashAgentToken(token) {
		t.Fatalf("stored hash does not match hashAgentToken(token)")
	}
}

func TestDBAgentStore_MigratesLegacyPlaintextToken(t *testing.T) {
	s := newTestDBAgentStore(t)

	// Simulate a pre-W2-09 row: plaintext token, empty token_hash.
	const legacyToken = "legacy-plaintext-token-value"
	if _, err := s.db.Exec(
		"INSERT INTO agents (id, name, type, token, token_hash, registered_at, inventory_count) VALUES (?,?,?,?,?,?,0)",
		"legacy-agent", "legacy", string(AgentTypeLinux), legacyToken, "", time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema (should migrate legacy token): %v", err)
	}

	var storedToken, storedHash string
	if err := s.db.QueryRow("SELECT token, token_hash FROM agents WHERE id = ?", "legacy-agent").Scan(&storedToken, &storedHash); err != nil {
		t.Fatalf("query: %v", err)
	}
	if storedToken != "" {
		t.Fatalf("expected legacy plaintext token cleared after migration, got %q", storedToken)
	}
	if storedHash != hashAgentToken(legacyToken) {
		t.Fatalf("expected migrated hash to match hashAgentToken(legacyToken)")
	}

	// The original plaintext token must still authenticate post-migration.
	if err := s.heartbeat("legacy-agent", legacyToken); err != nil {
		t.Fatalf("heartbeat with migrated legacy token: %v", err)
	}
}

func TestAgentTokenMatches(t *testing.T) {
	hash := hashAgentToken("correct-token")
	if !agentTokenMatches(hash, "correct-token") {
		t.Error("expected match for correct token")
	}
	if agentTokenMatches(hash, "wrong-token") {
		t.Error("expected no match for wrong token")
	}
	if agentTokenMatches("", "correct-token") {
		t.Error("expected no match against an empty stored hash")
	}
}

func TestDBAgentStore_InventoryAssignsTask(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, _ := s.register("agent-1", AgentTypeLinux)
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	certs := []AgentDiscoveredCert{
		{Fingerprint: "fp1", Subject: "CN=shop", Source: "/etc/nginx/ssl/shop.crt", NotAfter: soon, AutoRenewable: true},
	}
	eps := []AgentEndpoint{
		{ServerType: "nginx", CertPath: "/etc/nginx/ssl/shop.crt", KeyPath: "/etc/nginx/ssl/shop.key", ServerName: "shop.example.com", ListenPort: 443},
	}
	if err := s.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory: %v", err)
	}

	tasks, err := s.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	tk := tasks[0]
	if tk.CertPath != "/etc/nginx/ssl/shop.crt" || tk.KeyPath != "/etc/nginx/ssl/shop.key" ||
		tk.ServerType != "nginx" || tk.VerifyHostPort != "shop.example.com:443" {
		t.Fatalf("install hints not persisted: %+v", tk)
	}
	// W19-13: Identifiers must round-trip through the DB (agent_tasks.identifiers),
	// not just survive in the in-process matchRenewalTasks return value.
	if len(tk.Identifiers) != 1 || tk.Identifiers[0] != "shop" {
		t.Fatalf("Identifiers not persisted across DB round trip: %+v", tk.Identifiers)
	}
	if n, err := s.endpointCount(); err != nil || n != 1 {
		t.Errorf("endpointCount: got %d, err %v", n, err)
	}
	if eps := s.endpointsFor(id); len(eps) != 1 {
		t.Errorf("endpointsFor: got %d", len(eps))
	}

	// Idempotent: re-submit must not duplicate.
	if err := s.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory 2: %v", err)
	}
	if tasks, _ := s.getTasks(id, token); len(tasks) != 1 {
		t.Fatalf("expected 1 task after re-inventory, got %d", len(tasks))
	}
}

func TestDBAgentStore_ResultClearsTaskAndRecords(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, _ := s.register("agent-1", AgentTypeLinux)
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	// Subject must carry a CN that parses as a hostname (W19-13): matchRenewalTasks
	// now skips queuing a task with no usable ACME identifier rather than one
	// that could never validate.
	certs := []AgentDiscoveredCert{{Fingerprint: "fp1", Subject: "CN=host", Source: "/c.crt", NotAfter: soon, AutoRenewable: true}}
	eps := []AgentEndpoint{{ServerType: "nginx", CertPath: "/c.crt", KeyPath: "/c.key", ServerName: "x", ListenPort: 443}}
	_ = s.submitInventory(id, token, certs, eps)
	tasks, _ := s.getTasks(id, token)

	if err := s.submitRenewalResult(id, token, AgentRenewalResult{
		TaskID: tasks[0].TaskID, Fingerprint: "fp1", Outcome: "installed_verified",
	}); err != nil {
		t.Fatalf("submitRenewalResult: %v", err)
	}
	if tasks, _ := s.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("expected task cleared, got %d", len(tasks))
	}
	if res := s.resultsFor(id); len(res) != 1 || res[0].Outcome != "installed_verified" {
		t.Fatalf("resultsFor wrong: %+v", res)
	}
	if all := s.allResults(); len(all) != 1 || all[0].AgentID != id {
		t.Fatalf("allResults wrong: %+v", all)
	}

	// Verified cert is not re-tasked on next inventory.
	_ = s.submitInventory(id, token, certs, eps)
	if tasks, _ := s.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("verified cert should not be re-tasked, got %d", len(tasks))
	}
}

func TestDBAgentStore_SurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agents.db")
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	certs := []AgentDiscoveredCert{{Fingerprint: "fp1", Subject: "CN=shop", Source: "/c.crt", NotAfter: soon, AutoRenewable: true}}
	eps := []AgentEndpoint{{ServerType: "nginx", CertPath: "/c.crt", KeyPath: "/c.key", ServerName: "shop", ListenPort: 443}}

	// First "process": register + inventory + a result.
	var id, token string
	{
		s1 := openAgentDB(t, dbPath)
		var err error
		id, token, err = s1.register("agent-1", AgentTypeLinux)
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if err := s1.submitInventory(id, token, certs, eps); err != nil {
			t.Fatalf("submitInventory: %v", err)
		}
	}

	// Second "process" over the SAME database file — Hub restarted.
	s2 := openAgentDB(t, dbPath)

	// Agent identity survives: same token still authenticates.
	if err := s2.heartbeat(id, token); err != nil {
		t.Fatalf("heartbeat after restart: %v", err)
	}
	// Pending task survives.
	tasks, err := s2.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks after restart: %v", err)
	}
	if len(tasks) != 1 || tasks[0].CertPath != "/c.crt" {
		t.Fatalf("task did not survive restart: %+v", tasks)
	}
	// Endpoints + agent registry survive.
	if len(s2.endpointsFor(id)) != 1 {
		t.Errorf("endpoints did not survive restart")
	}
	if total, _ := s2.agentCounts(); total != 1 {
		t.Errorf("agent registry did not survive restart: total=%d", total)
	}
}

func TestDBAgentStore_ResultHistoryCapped(t *testing.T) {
	s := newTestDBAgentStore(t)
	id, token, _ := s.register("agent-1", AgentTypeLinux)
	for i := 0; i < maxAgentResults+10; i++ {
		ts := time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if err := s.submitRenewalResult(id, token, AgentRenewalResult{
			Fingerprint: "fp", Outcome: "verify_failed", RolledBack: true, ReportedAt: ts,
		}); err != nil {
			t.Fatalf("submitRenewalResult %d: %v", i, err)
		}
	}
	if got := len(s.resultsFor(id)); got > maxAgentResults {
		t.Fatalf("result history not capped: got %d, want <= %d", got, maxAgentResults)
	}
}

// TestDBAgentStore_InsertTaskTxOnConflictSkipsDuplicateWithoutError is the
// regression proof for W4-05: a second, independent transaction inserting
// for an (agent_id, fingerprint) pair a first transaction already committed
// must neither error nor create a second row -- it must silently no-op and
// report inserted=false. This forces the exact interleaving (first
// transaction fully committed before the second even begins) via two manual
// transactions rather than goroutine timing.
//
// A goroutine-based version literally racing submitInventory against
// sweepRenewals (the board note's own wording) was tried first and dropped:
// red-checked with the fix reverted across 1300+ runs (-race and not,
// several batches), it never once observed the duplicate-row outcome the
// bug produces -- SQLite's own writer serialization (even in WAL mode)
// closes the read-then-write window between two real goroutines far more
// reliably than it closes it between two application-level transactions
// that don't have to wait on Go's scheduler, so the test never discriminated
// pass from fail and would have shipped as theater. The two-manual-
// transaction proof below exercises the identical insertTaskTx code path
// deterministically instead.
func TestDBAgentStore_InsertTaskTxOnConflictSkipsDuplicateWithoutError(t *testing.T) {
	s := newTestDBAgentStore(t)
	if _, _, err := s.register("agent-1", AgentTypeLinux); err != nil {
		t.Fatalf("register: %v", err)
	}
	ctx := context.Background()
	task := AgentRenewalTask{TaskID: "task-1", Fingerprint: "fp-race", Subject: "CN=race", Action: "renew"}

	tx1, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	inserted1, err := s.insertTaskTx(ctx, tx1, "agent-1", task)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if !inserted1 {
		t.Fatal("expected the first insert to report inserted=true")
	}
	if err := tx1.Commit(); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}

	tx2, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	task2 := task
	task2.TaskID = "task-2" // different task_id -- only (agent_id, fingerprint) must collide
	inserted2, err := s.insertTaskTx(ctx, tx2, "agent-1", task2)
	if err != nil {
		t.Fatalf("second insert must not error (ON CONFLICT DO NOTHING), got: %v", err)
	}
	if inserted2 {
		t.Fatal("expected the second insert for the same (agent_id, fingerprint) to be skipped, but it reported inserted=true")
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit tx2: %v", err)
	}

	tasks, err := s.tasksTx(ctx, s.db, "agent-1")
	if err != nil {
		t.Fatalf("tasksTx: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected exactly 1 task after the conflicting insert, got %d: %+v", len(tasks), tasks)
	}
}

// TestNewAgentStoreFromEnv_FallbackIsSharedAcrossCallers is the S-35 follow-up
// regression. NewAgentStoreFromEnv has two production callers — handlers.go for
// the HTTP handlers, and cmd/kryptkeeper/main.go for the scheduled renewal
// driver. With a DSN configured both resolve the same database, so they agree.
// With NO database configured each call used to return a separate in-memory
// map, so an agent registered through the handlers was invisible to the driver:
// it swept an empty store forever and assigned nothing, which is indist-
// inguishable from "no certs are due".
//
// Registering through the first handle and reading through the second is the
// only assertion that catches it; comparing interface values would pass on two
// stores that merely happen to be the same TYPE.
func TestNewAgentStoreFromEnv_FallbackIsSharedAcrossCallers(t *testing.T) {
	// Force the no-database fallback: postgres mode with no DSN of any kind, so
	// newDBProviderState returns postgresMissingErr and both calls fall back.
	// KRYPTKEEPER_DB_MODE is the switch (dbModeEnv) — an invented name like
	// DB_DRIVER is silently ignored, leaves the default sqlite mode in place,
	// and quietly tests the DB path against a shared file instead. That is how
	// the first version of this test passed for the wrong reason.
	t.Setenv("KRYPTKEEPER_DB_MODE", "postgres")
	t.Setenv("APP_AUDIT_DB_DSN", "")
	t.Setenv("KRYPTKEEPER_DB_DSN", "")
	t.Setenv("DATABASE_URL", "")

	// sharedFallbackAgentStore is a sync.Once-guarded process singleton by
	// design (S-35: it must be the SAME store across callers in production).
	// That means it also persists across repeated invocations of this test
	// within one test binary process — go test -count=N reruns this func in
	// the same process, and without a reset the second run's register()
	// lands in a store that already holds "agent-a" from the first, so
	// agentCounts() reports 2 instead of 1 and the assertion below flakes.
	// Resetting the package vars around this test doesn't touch the
	// production sharing behavior (still one instance per real process); it
	// only gives each test iteration a fresh singleton to observe.
	origOnce, origStore := fallbackAgentStoreOnce, fallbackAgentStore
	fallbackAgentStoreOnce = new(sync.Once)
	fallbackAgentStore = nil
	t.Cleanup(func() {
		fallbackAgentStoreOnce = origOnce
		fallbackAgentStore = origStore
	})

	// Prove we are actually on the fallback path before asserting anything
	// about it — otherwise this test silently becomes a DB-path test again.
	if _, isMem := NewAgentStoreFromEnv().(*memAgentStore); !isMem {
		t.Fatalf("setup: expected the in-memory fallback, got a DB-backed store — this test is not exercising the path it describes")
	}

	handlersStore := NewAgentStoreFromEnv()
	driverStore := NewAgentStoreFromEnv()

	id, token, err := handlersStore.register("agent-a", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register through the handlers' store: %v", err)
	}

	// The driver's handle must see the agent the handlers registered.
	if _, err := driverStore.getTasks(id, token); err != nil {
		t.Fatalf("the driver's store cannot see an agent registered through the handlers' store — the in-memory fallback is not shared: %v", err)
	}
	total, _ := driverStore.agentCounts()
	if total != 1 {
		t.Fatalf("expected the driver's store to report the 1 agent registered through the handlers' store, got %d", total)
	}
}

// S-63: endpointCount distinguishes a failed query from a genuine zero.
func TestEndpointCountDistinguishesFailureFromZero(t *testing.T) {
	s := newTestDBAgentStore(t)
	n, err := s.endpointCount()
	if err != nil || n != 0 {
		t.Fatalf("fresh store: want 0 endpoints and no error, got %d, %v", n, err)
	}
	// Break the store: drop the table out from under it.
	if _, err := s.db.Exec("ALTER TABLE agent_endpoints RENAME TO agent_endpoints_gone"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := s.endpointCount(); err == nil {
		t.Fatal("a failed query must return an error, not a genuine-looking zero")
	}
}
