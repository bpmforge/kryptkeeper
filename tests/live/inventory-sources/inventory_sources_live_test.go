// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package inventorysources_test gates the W24-28 inventory-source UAT behind
// KK_LIVE_INVSRC=1. Orchestration (hub, fixture server, DigiCert sandbox) lives
// in run.sh; this wrapper only runs it and fails on a non-zero exit. Same shape
// as tests/live/mesh/mesh_live_test.go. See README.md.
package inventorysources_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInventorySourcesLive(t *testing.T) {
	if os.Getenv("KK_LIVE_INVSRC") != "1" {
		t.Skip("set KK_LIVE_INVSRC=1 to run the W24-28 inventory-source UAT (optional KK_DIGICERT_API_KEY for the DigiCert sandbox; needs openssl, python3 and a private NIC for the fixture vendors)")
	}

	scriptPath, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatalf("resolve run.sh path: %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("run.sh not found next to this test: %v", err)
	}

	cmd := exec.Command("bash", scriptPath)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	t.Logf("run.sh output:\n%s", out)
	if err != nil {
		t.Fatalf("tests/live/inventory-sources/run.sh exited non-zero: %v", err)
	}
}
