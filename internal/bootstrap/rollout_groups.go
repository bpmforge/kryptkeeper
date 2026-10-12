// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"time"
)

// W16-04: coordinated rollout groups. Multi-node LB/cluster renewals —
// where several nodes serve the SAME certificate — are a top operator
// complaint the incumbents leave manual: flip one node and the load
// balancer serves a mismatched pair. This flips a cluster together —
// canary first, verify, then the fleet — with a maintenance window and
// CLUSTER-ATOMIC rollback: on any failure, every already-flipped node
// is rolled back so the cluster is all-new or all-old, never split.

// RolloutNode is one target in a cluster serving a shared certificate.
type RolloutNode struct {
	ID       string `json:"id"`
	IsCanary bool   `json:"is_canary"`
}

// MaintenanceWindow bounds when a rollout may run (UTC hours, [start,
// end)). A zero window (both 0) means "any time".
type MaintenanceWindow struct {
	StartHour int `json:"start_hour"`
	EndHour   int `json:"end_hour"`
}

func (w MaintenanceWindow) allows(now time.Time) bool {
	if w.StartHour == 0 && w.EndHour == 0 {
		return true
	}
	h := now.UTC().Hour()
	if w.StartHour <= w.EndHour {
		return h >= w.StartHour && h < w.EndHour
	}
	// Window wraps midnight (e.g. 22->4).
	return h >= w.StartHour || h < w.EndHour
}

// RolloutGroup is a cluster whose nodes flip together.
type RolloutGroup struct {
	Name   string            `json:"name"`
	Nodes  []RolloutNode     `json:"nodes"`
	Window MaintenanceWindow `json:"window"`
}

// NodeOutcome is one node's result.
type NodeOutcome struct {
	NodeID   string `json:"node_id"`
	IsCanary bool   `json:"is_canary"`
	Outcome  string `json:"outcome"` // installed | rolled_back | skipped | failed | rollback_failed
	Detail   string `json:"detail,omitempty"`
}

// RolloutResult reports the whole group's outcome — partial state is
// never invisible (the S-50 rule).
type RolloutResult struct {
	Group       string        `json:"group"`
	Deferred    bool          `json:"deferred"`
	Halted      bool          `json:"halted"`
	HaltReason  string        `json:"halt_reason,omitempty"`
	NodeResults []NodeOutcome `json:"node_results"`
}

// InstallFunc installs the renewed cert on one node and verifies it,
// returning ok + detail. RollbackFunc reverts a node via the
// installer's existing rollback.
type (
	InstallFunc  func(ctx context.Context, node RolloutNode) (ok bool, detail string)
	RollbackFunc func(ctx context.Context, node RolloutNode) error
)

// RunRolloutGroup executes a cluster-atomic canary rollout. install and
// rollback are injected so this stays transport-agnostic (the executor
// supplies the real push/verify + installer rollback).
func RunRolloutGroup(ctx context.Context, group RolloutGroup, install InstallFunc, rollback RollbackFunc, now time.Time) RolloutResult {
	res := RolloutResult{Group: group.Name}

	if !group.Window.allows(now) {
		res.Deferred = true
		for _, n := range group.Nodes {
			res.NodeResults = append(res.NodeResults, NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: "skipped", Detail: "outside maintenance window"})
		}
		return res
	}

	var canaries, fleet []RolloutNode
	for _, n := range group.Nodes {
		if n.IsCanary {
			canaries = append(canaries, n)
		} else {
			fleet = append(fleet, n)
		}
	}
	// A multi-node group with NO designated canary would flip its whole
	// fleet with no verified-canary gate — the safety property this
	// exists for. Promote the first node to an implicit canary so a
	// cluster always proves one node before the rest. Single-node
	// groups need no canary.
	if len(canaries) == 0 && len(fleet) >= 2 {
		promoted := fleet[0]
		promoted.IsCanary = true
		canaries = []RolloutNode{promoted}
		fleet = fleet[1:]
	}

	// flipped tracks every node we installed onto, for atomic rollback.
	var flipped []RolloutNode
	outcome := map[string]*NodeOutcome{}
	record := func(n RolloutNode, oc, detail string) {
		o := &NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: oc, Detail: detail}
		outcome[n.ID] = o
	}

	// haltAndRollback reverts every flipped node and marks the reason.
	haltAndRollback := func(reason string, remaining []RolloutNode) RolloutResult {
		res.Halted = true
		res.HaltReason = reason
		for _, n := range flipped {
			if err := rollback(ctx, n); err != nil {
				outcome[n.ID] = &NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: "rollback_failed", Detail: err.Error()}
			} else {
				outcome[n.ID] = &NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: "rolled_back"}
			}
		}
		for _, n := range remaining {
			if _, done := outcome[n.ID]; !done {
				record(n, "skipped", "halted before this node")
			}
		}
		res.NodeResults = orderedOutcomes(group.Nodes, outcome)
		return res
	}

	// Canary phase: any canary failure halts BEFORE the fleet.
	for i, n := range canaries {
		ok, detail := install(ctx, n)
		if !ok {
			record(n, "failed", detail)
			return haltAndRollback("canary "+n.ID+" failed: "+detail, append(append([]RolloutNode{}, canaries[i+1:]...), fleet...))
		}
		record(n, "installed", "")
		flipped = append(flipped, n)
	}

	// Fleet phase: any failure rolls back EVERY flipped node.
	for i, n := range fleet {
		ok, detail := install(ctx, n)
		if !ok {
			record(n, "failed", detail)
			return haltAndRollback(fmt.Sprintf("fleet node %s failed: %s", n.ID, detail), fleet[i+1:])
		}
		record(n, "installed", "")
		flipped = append(flipped, n)
	}

	res.NodeResults = orderedOutcomes(group.Nodes, outcome)
	return res
}

// orderedOutcomes returns per-node outcomes in the group's node order.
func orderedOutcomes(nodes []RolloutNode, outcome map[string]*NodeOutcome) []NodeOutcome {
	out := make([]NodeOutcome, 0, len(nodes))
	for _, n := range nodes {
		if o, ok := outcome[n.ID]; ok {
			out = append(out, *o)
		} else {
			out = append(out, NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: "skipped"})
		}
	}
	return out
}
