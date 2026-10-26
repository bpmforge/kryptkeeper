// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/trustpush"
)

// trustStorePushEnv is the agent's opt-in (D-319): the agent has no YAML
// config, its env file (or the Windows service settings file) is the config
// file, so `trust_store_push: true` is this key set to "true". Off by default,
// so a compromised hub cannot add roots to a host that never asked for it.
const trustStorePushEnv = "KRYPTKEEPER_TRUST_STORE_PUSH"

// trustRetryAfter spaces re-applies of a failed bundle; the hub keeps
// offering it until it is applied.
const trustRetryAfter = 15 * time.Minute

func trustStorePushEnabled(getenv func(string) string) bool {
	return strings.EqualFold(strings.TrimSpace(getenv(trustStorePushEnv)), "true")
}

type trustHub interface {
	GetTrustTasks(ctx context.Context) ([]agentclient.TrustTask, error)
	PostTrustResult(ctx context.Context, r agentclient.TrustResult) error
}

// trustPusher applies queued trust bundles, honouring the local opt-in.
type trustPusher struct {
	enabled bool
	applier *trustpush.Applier
	now     func() time.Time

	mu   sync.Mutex
	last map[string]trustAttempt // bundle id -> what this process last reported
}

type trustAttempt struct {
	outcome string
	at      time.Time
}

func newTrustPusher(enabled bool, a *trustpush.Applier) *trustPusher {
	return &trustPusher{enabled: enabled, applier: a, now: time.Now, last: map[string]trustAttempt{}}
}

// poll fetches this agent's trust tasks and acts on each. A hub older than
// W40-03 answers 404; that is silent by design.
func (p *trustPusher) poll(ctx context.Context, hub trustHub) {
	tasks, err := hub.GetTrustTasks(ctx)
	if err != nil {
		if !strings.Contains(err.Error(), "returned 404") {
			logging.Infof("trust tasks: %v", err)
		}
		return
	}
	for _, t := range tasks {
		p.handle(ctx, hub, t)
	}
}

func (p *trustPusher) handle(ctx context.Context, hub trustHub, t agentclient.TrustTask) {
	p.mu.Lock()
	prev, seen := p.last[t.BundleID]
	p.mu.Unlock()
	if seen {
		switch {
		case prev.outcome == trustpush.OutcomeRefused:
			return // opt-in cannot change without a restart; do not re-report every poll
		case prev.outcome == trustpush.OutcomeApplied:
			return
		case p.now().Sub(prev.at) < trustRetryAfter:
			return
		}
	}
	var res trustpush.Result
	if !p.enabled {
		res = trustpush.Result{Outcome: trustpush.OutcomeRefused, Detail: "this agent has not opted in to trust store push (" + trustStorePushEnv + ")"}
	} else {
		// Validate before dispatch so a malformed or hostile task never reaches
		// the privileged helper; the helper validates again on its side.
		act := trustpush.Action(t.Action)
		if !act.Valid() {
			res = trustpush.Result{Outcome: trustpush.OutcomeFailed, Detail: fmt.Sprintf("unknown action %q", t.Action)}
		} else if _, err := trustpush.ParseCAs(t.CertPEM, p.now(), act == trustpush.ActionAdd); err != nil {
			res = trustpush.Result{Outcome: trustpush.OutcomeFailed, Detail: "bundle refused: " + err.Error()}
		} else {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			res = p.applier.Dispatch(cctx, trustpush.Request{Action: act, CertPEM: t.CertPEM})
			cancel()
		}
	}
	logging.Infof("trust bundle %s (%s): %s %s", t.BundleID, t.Action, res.Outcome, res.Detail)
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := hub.PostTrustResult(rctx, agentclient.TrustResult{BundleID: t.BundleID, Outcome: res.Outcome, Detail: res.Detail}); err != nil {
		logging.Infof("report trust result %s: %v", t.BundleID, err)
		return // unreported: retry on the next poll
	}
	p.mu.Lock()
	p.last[t.BundleID] = trustAttempt{outcome: res.Outcome, at: p.now()}
	p.mu.Unlock()
}

// execRunner runs real commands for the Applier.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- name and args come from the fixed command table in internal/trustpush, never from the hub
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	return cmd.CombinedOutput()
}

func newTrustApplier(goos string) *trustpush.Applier {
	return &trustpush.Applier{GOOS: goos, StatePath: trustpush.DefaultStatePath(goos, os.Getenv), Runner: execRunner{}}
}

// runTrustStoreHelper is the root half, reached only through the one sudoers
// rule `kryptkeeper-agent --trust-store-apply` (D-319). It reads a Request
// from stdin and prints a Result as JSON; the applier re-validates the bundle,
// so the agent account is not trusted to have done it.
func runTrustStoreHelper(stdin io.Reader, stdout io.Writer, a *trustpush.Applier) int {
	raw, err := io.ReadAll(io.LimitReader(stdin, trustpush.MaxPEMBytes+4096))
	var req trustpush.Request
	var res trustpush.Result
	if err != nil || json.Unmarshal(raw, &req) != nil {
		res = trustpush.Result{Outcome: trustpush.OutcomeFailed, Detail: "unreadable request"}
	} else {
		res = a.ApplyLocal(context.Background(), req)
	}
	_ = json.NewEncoder(stdout).Encode(res)
	if res.Outcome == trustpush.OutcomeApplied {
		return 0
	}
	return 1
}

// trustStoreSudoers is the opt-in drop-in for trust store push. It is its own
// file (--generate-trust-store-sudoers, installed as
// /etc/sudoers.d/kryptkeeper-agent-truststore) so regenerating the
// renewal-autopilot drop-in never widens privilege invisibly (D-114). One exact
// command, no wildcard: sudoers matches arguments literally when none is
// written.
func trustStoreSudoers(user string) string {
	return fmt.Sprintf(`# Kryptkeeper Agent - trust store push privilege (W40-03, D-319). Opt-in.
#
# Install:   kryptkeeper-agent --generate-trust-store-sudoers | sudo tee /etc/sudoers.d/kryptkeeper-agent-truststore
# Secure:    sudo chmod 0440 /etc/sudoers.d/kryptkeeper-agent-truststore
# Validate:  sudo visudo -cf /etc/sudoers.d/kryptkeeper-agent-truststore
#
# This is the ONLY privilege it adds: the root half of the agent, with exactly
# one argument, reading its request on stdin. It validates every certificate
# itself (CA:TRUE, no key blocks) and only ever touches files named
# kryptkeeper-<sha256>.crt in the distribution's anchor directory, or the System
# keychain on macOS. The binary MUST be owned by root and not writable by %[1]s,
# or this rule is a root shell.
Defaults:%[1]s !requiretty
Cmnd_Alias KK_TRUSTSTORE = %[2]s %[3]s
%[1]s ALL=(root) NOPASSWD: KK_TRUSTSTORE
`, user, trustpush.HelperPath, trustpush.HelperArg)
}
