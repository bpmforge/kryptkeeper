// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// W16-04: cluster-atomic canary rollout — ordering, halt-before-fleet,
// atomic rollback, maintenance window, and happy path.

func rolloutContains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func rolloutGroup() RolloutGroup {
	return RolloutGroup{
		Name: "web-cluster",
		Nodes: []RolloutNode{
			{ID: "canary-1", IsCanary: true},
			{ID: "node-2"},
			{ID: "node-3"},
		},
	}
}

func outcomeByID(res RolloutResult) map[string]NodeOutcome {
	m := map[string]NodeOutcome{}
	for _, o := range res.NodeResults {
		m[o.NodeID] = o
	}
	return m
}

func TestRolloutHappyPath(t *testing.T) {
	var installed []string
	install := func(_ context.Context, n RolloutNode) (bool, string) {
		installed = append(installed, n.ID)
		return true, ""
	}
	rollback := func(context.Context, RolloutNode) error { t.Fatal("no rollback on success"); return nil }

	res := RunRolloutGroup(context.Background(), rolloutGroup(), install, rollback, time.Now())
	if res.Halted || res.Deferred {
		t.Fatalf("clean run must not halt/defer: %+v", res)
	}
	// Canary installs FIRST.
	if installed[0] != "canary-1" {
		t.Fatalf("canary must install first, order was %v", installed)
	}
	for _, o := range res.NodeResults {
		if o.Outcome != "installed" {
			t.Fatalf("all nodes must be installed: %+v", o)
		}
	}
}

func TestCanaryFailureHaltsBeforeFleet(t *testing.T) {
	var touched []string
	install := func(_ context.Context, n RolloutNode) (bool, string) {
		touched = append(touched, n.ID)
		if n.ID == "canary-1" {
			return false, "verify mismatch"
		}
		return true, ""
	}
	var rolledBack []string
	rollback := func(_ context.Context, n RolloutNode) error {
		rolledBack = append(rolledBack, n.ID)
		return nil
	}

	res := RunRolloutGroup(context.Background(), rolloutGroup(), install, rollback, time.Now())
	if !res.Halted {
		t.Fatal("a failing canary must halt the group")
	}
	// The fleet was never touched.
	for _, id := range touched {
		if id == "node-2" || id == "node-3" {
			t.Fatalf("fleet must not be touched after a canary failure: %v", touched)
		}
	}
	byID := outcomeByID(res)
	if byID["canary-1"].Outcome != "failed" {
		t.Fatalf("canary should be failed: %+v", byID["canary-1"])
	}
	if byID["node-2"].Outcome != "skipped" || byID["node-3"].Outcome != "skipped" {
		t.Fatalf("fleet nodes must be skipped: %+v", byID)
	}
	if res.HaltReason == "" {
		t.Fatal("halt reason must name the canary")
	}
}

func TestFleetFailureRollsBackCluster(t *testing.T) {
	install := func(_ context.Context, n RolloutNode) (bool, string) {
		if n.ID == "node-3" {
			return false, "reload failed"
		}
		return true, ""
	}
	var rolledBack []string
	rollback := func(_ context.Context, n RolloutNode) error {
		rolledBack = append(rolledBack, n.ID)
		return nil
	}

	res := RunRolloutGroup(context.Background(), rolloutGroup(), install, rollback, time.Now())
	if !res.Halted {
		t.Fatal("a fleet failure must halt")
	}
	// Cluster-atomic: the canary AND node-2 (both flipped) roll back.
	if len(rolledBack) != 2 || !rolloutContains(rolledBack, "canary-1") || !rolloutContains(rolledBack, "node-2") {
		t.Fatalf("every flipped node must roll back (cluster-atomic): %v", rolledBack)
	}
	byID := outcomeByID(res)
	if byID["canary-1"].Outcome != "rolled_back" || byID["node-2"].Outcome != "rolled_back" {
		t.Fatalf("flipped nodes must report rolled_back: %+v", byID)
	}
	if byID["node-3"].Outcome != "failed" {
		t.Fatalf("the failing node must report failed: %+v", byID["node-3"])
	}
}

func TestRollbackFailureIsRecorded(t *testing.T) {
	install := func(_ context.Context, n RolloutNode) (bool, string) {
		return n.ID != "node-3", "reload failed"
	}
	rollback := func(_ context.Context, n RolloutNode) error {
		if n.ID == "canary-1" {
			return context.DeadlineExceeded
		}
		return nil
	}
	res := RunRolloutGroup(context.Background(), rolloutGroup(), install, rollback, time.Now())
	if outcomeByID(res)["canary-1"].Outcome != "rollback_failed" {
		t.Fatalf("a failed rollback must be recorded, not swallowed: %+v", outcomeByID(res)["canary-1"])
	}
}

func TestMaintenanceWindowDefers(t *testing.T) {
	g := rolloutGroup()
	g.Window = MaintenanceWindow{StartHour: 2, EndHour: 4} // 02:00-04:00 UTC
	called := false
	install := func(context.Context, RolloutNode) (bool, string) { called = true; return true, "" }
	rollback := func(context.Context, RolloutNode) error { return nil }

	// 12:00 UTC is outside the window.
	res := RunRolloutGroup(context.Background(), g, install, rollback,
		time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC))
	if !res.Deferred || called {
		t.Fatalf("outside the window the run must defer without installing: %+v called=%v", res, called)
	}
	// 03:00 UTC is inside the window.
	res = RunRolloutGroup(context.Background(), g, install, rollback,
		time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC))
	if res.Deferred || !called {
		t.Fatalf("inside the window the run must proceed: %+v", res)
	}
}

// Review fix (concurrency challenger #4): a multi-node group with NO
// designated canary must still gate on an implicit canary — a failure
// on the first (promoted) node must halt before the rest are touched.
func TestRolloutZeroCanaryPromotesImplicitGate(t *testing.T) {
	g := RolloutGroup{Name: "no-canary", Nodes: []RolloutNode{{ID: "n1"}, {ID: "n2"}, {ID: "n3"}}}
	var touched []string
	install := func(_ context.Context, n RolloutNode) (bool, string) {
		touched = append(touched, n.ID)
		if n.ID == "n1" {
			return false, "verify mismatch"
		}
		return true, ""
	}
	rollback := func(context.Context, RolloutNode) error { return nil }
	res := RunRolloutGroup(context.Background(), g, install, rollback, time.Now())
	if !res.Halted {
		t.Fatal("implicit canary failure must halt")
	}
	for _, id := range touched {
		if id == "n2" || id == "n3" {
			t.Fatalf("fleet must not be touched after the implicit-canary failure: %v", touched)
		}
	}
}
