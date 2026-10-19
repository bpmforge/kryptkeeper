// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net"
	"time"

	"kryptkeeper/internal/agentinstall"
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
	Group string `json:"group"`
	// Mode is "staged" (two-phase stage-then-flip, ssh nodes) or
	// "sequential" (install node by node; succeeded nodes cannot be reverted).
	Mode string `json:"mode"`
	// NewFingerprint is the SHA-256 of the one renewed leaf every node
	// received (W27-16/17 consume it).
	NewFingerprint string        `json:"new_fingerprint,omitempty"`
	Deferred       bool          `json:"deferred"`
	Halted         bool          `json:"halted"`
	HaltReason     string        `json:"halt_reason,omitempty"`
	NodeResults    []NodeOutcome `json:"node_results"`
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
	if !group.Window.allows(now) {
		return deferredResult(group, RolloutModeSequential)
	}
	res := RolloutResult{Group: group.Name, Mode: RolloutModeSequential}

	// A multi-node group with NO designated canary would flip its whole
	// fleet with no verified-canary gate — the safety property this
	// exists for; splitCanary promotes the first node to an implicit
	// canary so a cluster always proves one node before the rest.
	canaries, fleet := splitCanary(group.Nodes)

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

// --- W27-15: staged (two-phase) rollout, D09-1 ---

// Rollout modes reported in RolloutResult.Mode.
const (
	RolloutModeStaged     = "staged"
	RolloutModeSequential = "sequential"
)

// StagedNodeOps are the per-node operations of a two-phase rollout. Flip
// includes reload and verify and, on error, the node has ALREADY restored
// itself; Restore undoes a node whose Flip succeeded; Commit drops the
// host-side predecessor copy; Discard drops staged files.
type StagedNodeOps struct {
	Stage   func(ctx context.Context, n RolloutNode) (detail string, err error)
	Flip    func(ctx context.Context, n RolloutNode) (detail string, err error)
	Restore func(ctx context.Context, n RolloutNode) error
	Commit  func(ctx context.Context, n RolloutNode) error
	Discard func(ctx context.Context, n RolloutNode) error
}

// splitCanary separates canaries from the fleet and promotes the first node
// of a multi-node group with no canary (see RunRolloutGroup).
func splitCanary(nodes []RolloutNode) (canaries, fleet []RolloutNode) {
	for _, n := range nodes {
		if n.IsCanary {
			canaries = append(canaries, n)
		} else {
			fleet = append(fleet, n)
		}
	}
	if len(canaries) == 0 && len(fleet) >= 2 {
		promoted := fleet[0]
		promoted.IsCanary = true
		canaries = []RolloutNode{promoted}
		fleet = fleet[1:]
	}
	return canaries, fleet
}

// deferredResult reports a group held back by its maintenance window: every
// node skipped, nothing called.
func deferredResult(group RolloutGroup, mode string) RolloutResult {
	res := RolloutResult{Group: group.Name, Mode: mode, Deferred: true}
	for _, n := range group.Nodes {
		res.NodeResults = append(res.NodeResults, NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: "skipped", Detail: "outside maintenance window"})
	}
	return res
}

// RunStagedRolloutGroup stages the new certificate on EVERY node first (live
// files untouched), then flips canary-first. Any failure returns every node to
// the old certificate: nodes not yet flipped discard their staged files,
// flipped nodes restore. All nodes end on the old OR all on the new material.
func RunStagedRolloutGroup(ctx context.Context, group RolloutGroup, ops StagedNodeOps, now time.Time) RolloutResult {
	if !group.Window.allows(now) {
		return deferredResult(group, RolloutModeStaged)
	}
	res := RolloutResult{Group: group.Name, Mode: RolloutModeStaged}
	canaries, fleet := splitCanary(group.Nodes)
	order := append(append([]RolloutNode{}, canaries...), fleet...)

	outcome := map[string]*NodeOutcome{}
	record := func(n RolloutNode, oc, detail string) {
		outcome[n.ID] = &NodeOutcome{NodeID: n.ID, IsCanary: n.IsCanary, Outcome: oc, Detail: detail}
	}
	finish := func(reason string) RolloutResult {
		res.Halted, res.HaltReason = true, reason
		res.NodeResults = orderedOutcomes(group.Nodes, outcome)
		return res
	}
	// discard drops staged files on nodes that never flipped.
	discard := func(nodes []RolloutNode) {
		for _, n := range nodes {
			if err := ops.Discard(ctx, n); err != nil {
				record(n, "rollback_failed", "discarding staged files failed: "+err.Error())
				continue
			}
			record(n, "skipped", "staged files discarded; nothing was changed")
		}
	}
	skipRest := func(nodes []RolloutNode) {
		for _, n := range nodes {
			record(n, "skipped", "halted before this node")
		}
	}

	// Phase 1: stage everywhere. Live files are untouched until Phase 2.
	for i, n := range order {
		detail, err := ops.Stage(ctx, n)
		if err != nil {
			msg := stagedDetail(detail, err)
			record(n, "failed", msg)
			discard(order[:i])
			skipRest(order[i+1:])
			return finish("stage failed on " + n.ID + ": " + msg)
		}
	}

	// Phase 2: flip canary-first.
	for i, n := range order {
		detail, err := ops.Flip(ctx, n)
		if err != nil {
			msg := stagedDetail(detail, err)
			record(n, "failed", msg)
			for _, f := range order[:i] {
				if rerr := ops.Restore(ctx, f); rerr != nil {
					record(f, "rollback_failed", rerr.Error())
				} else {
					record(f, "rolled_back", "")
				}
			}
			discard(order[i+1:])
			return finish("flip failed on " + n.ID + ": " + msg)
		}
	}

	for _, n := range order {
		d := ""
		if err := ops.Commit(ctx, n); err != nil {
			d = "commit warning: " + err.Error()
			logging.Warnf("ALERT rollout.commit_failed node=%s group=%s: a predecessor key copy may remain on that host", n.ID, group.Name)
		}
		record(n, "installed", d)
	}
	res.NodeResults = orderedOutcomes(group.Nodes, outcome)
	return res
}

func stagedDetail(detail string, err error) string {
	if detail != "" {
		return detail
	}
	return err.Error()
}

// dialSSHTarget opens an SSH executor to target using its stored credential,
// with the same host-key pin and mismatch handling as ExecuteRenewal. It
// duplicates that block because renewal_executor.go is outside W27-15's
// write_scope; fold the two together when that file is next opened.
func (e *RenewalExecutor) dialSSHTarget(ctx context.Context, target ManagedTarget) (agentinstall.Executor, func() error, error) {
	if target.CredentialRef == "" {
		return nil, nil, errRenewalNoCredential
	}
	if e.creds == nil {
		return nil, nil, errors.New("outbound credential store not configured")
	}
	payload, err := e.resolveSSHCredential(ctx, target.CredentialRef)
	if err != nil {
		return nil, nil, err
	}
	signer, hostKey, err := payload.parse()
	if err != nil {
		return nil, nil, err
	}
	port := payload.Port
	if port == 0 {
		port = 22
	}
	pinned := pinnedHostKeyFor(target, hostKey)
	executor, closeConn, err := e.dial(ctx, agentinstall.SSHTarget{
		Host:              target.Host,
		Port:              port,
		User:              payload.User,
		Signer:            signer,
		HostKeyCallback:   agentinstall.PinnedHostKeyCallback(pinned),
		HostKeyAlgorithms: hostKeyAlgorithmsFor(pinned),
	})
	if err != nil {
		var mm *agentinstall.HostKeyMismatchError
		if errors.As(err, &mm) {
			recordHostKeyMismatch(ctx, e.pluginAudit, target.ID, mm)
		}
		return nil, nil, err
	}
	return executor, closeConn, nil
}

// stagedConn is one node's open SSH session and its in-flight staged/flipped state.
type stagedConn struct {
	inst    *agentinstall.Installer
	closeFn func() error
	st      *agentinstall.StagedInstall
	fl      *agentinstall.FlippedInstall
}

// sshStagedRollout adapts agentinstall's Stage/Flip API to StagedNodeOps. One
// SSH connection per node stays open across both phases; closeAll must be
// deferred by the caller.
type sshStagedRollout struct {
	e        *RenewalExecutor
	targets  map[string]ManagedTarget
	profiles map[string]RenewalInstallProfile
	chainPEM []byte
	keyPEM   []byte
	leafFP   string
	conns    map[string]*stagedConn
}

func (a *sshStagedRollout) conn(id string) (*stagedConn, error) {
	c, ok := a.conns[id]
	if !ok {
		return nil, fmt.Errorf("node %s has no open session", id)
	}
	return c, nil
}

func (a *sshStagedRollout) closeAll() {
	for _, c := range a.conns {
		_ = c.closeFn() // best-effort teardown; outcomes are already recorded
	}
}

func (a *sshStagedRollout) ops() StagedNodeOps {
	return StagedNodeOps{
		Stage: func(ctx context.Context, n RolloutNode) (string, error) {
			target, profile := a.targets[n.ID], a.profiles[n.ID]
			executor, closeConn, err := a.e.dialSSHTarget(ctx, target)
			if err != nil {
				return "", err
			}
			inst := agentinstall.New(executor)
			if a.e.verifier != nil {
				inst = inst.WithVerifier(a.e.verifier)
			}
			verifyHostPort := profile.VerifyHostPort
			if verifyHostPort == "" {
				verifyHostPort = net.JoinHostPort(target.Host, "443")
			}
			st, res, err := inst.Stage(ctx, agentinstall.InstallRequest{
				ServerType: profile.ServerType, CertPath: profile.CertPath, KeyPath: profile.KeyPath,
				CertPEM: a.chainPEM, KeyPEM: a.keyPEM, ReloadMethod: profile.ReloadMethod,
				VerifyHostPort: verifyHostPort, ExpectedFingerprint: a.leafFP,
			})
			if err != nil {
				_ = closeConn() // best-effort; the stage error is the one reported
				return res.Detail, err
			}
			a.conns[n.ID] = &stagedConn{inst: inst, closeFn: closeConn, st: st}
			return res.Detail, nil
		},
		Flip: func(ctx context.Context, n RolloutNode) (string, error) {
			c, err := a.conn(n.ID)
			if err != nil {
				return "", err
			}
			fl, res, err := c.inst.Flip(ctx, c.st)
			if err != nil {
				return res.Outcome + ": " + err.Error(), err
			}
			c.fl = fl
			return res.Outcome, nil
		},
		Restore: func(ctx context.Context, n RolloutNode) error {
			c, err := a.conn(n.ID)
			if err != nil {
				return err
			}
			if c.fl == nil {
				return fmt.Errorf("node %s was not flipped", n.ID)
			}
			return c.inst.Restore(ctx, c.fl)
		},
		Commit: func(ctx context.Context, n RolloutNode) error {
			c, err := a.conn(n.ID)
			if err != nil {
				return err
			}
			return c.inst.Commit(ctx, c.fl)
		},
		Discard: func(ctx context.Context, n RolloutNode) error {
			c, err := a.conn(n.ID)
			if err != nil {
				return err
			}
			return c.inst.Discard(ctx, c.st)
		},
	}
}
