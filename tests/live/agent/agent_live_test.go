// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package agent_test gates the W19-04 live UAT behind an env switch, per the
// ticket's acceptance criteria ("gated live test tests/live/agent/*_live_test.go
// with an env switch"). The actual orchestration (build hub + agent, drive a
// podman container, assert enrol/inventory/renewal-task steps) lives in
// run.sh, not in Go: it needs podman lifecycle management (build, run, logs,
// rm) that a Go test would just be re-implementing os/exec calls around. This
// test is a thin, CI-usable wrapper — the same shape as
// internal/agentdiscovery/live_winrm_test.go and
// internal/bootstrap/winrm_discovery_live_test.go, which gate real-host
// acceptance behind KK_LIVE_WINRM rather than reimplementing WinRM calls
// inline.
//
// Skipped unless KK_LIVE_AGENT=1. Requires podman (no docker) and a podman
// machine already running. As of the 2026-09-10 rerun all steps pass end to
// end (enrol, inventory, ACME renewal, install, hub-side outcome recording,
// and a changed leaf on the TLS vhost) — see README.md for the three
// compounding defects that had to clear to get there and docs/STATUS.md for
// full per-step evidence.
package agent_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAgentLiveUAT(t *testing.T) {
	if os.Getenv("KK_LIVE_AGENT") != "1" {
		t.Skip("set KK_LIVE_AGENT=1 to run the W19-04 agent-mode UAT against a real podman container (needs podman, no docker)")
	}

	scriptPath, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatalf("resolve run.sh path: %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("run.sh not found next to this test: %v", err)
	}

	cmd := exec.Command("bash", scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// run.sh's own PASS/FAIL log (already streamed above) carries the
		// per-step detail; a nonzero exit here means at least one step
		// failed -- as of 2026-09-10 that is a regression, not a known gap.
		t.Fatalf("tests/live/agent/run.sh exited non-zero: %v", err)
	}
}
