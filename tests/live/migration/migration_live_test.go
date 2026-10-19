// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMigrationLive gates the W33-19 seeded-200-cert verification behind
// KK_LIVE_MIGRATION=1. Orchestration lives in run.sh. See README.md.
func TestMigrationLive(t *testing.T) {
	if os.Getenv("KK_LIVE_MIGRATION") != "1" {
		t.Skip("set KK_LIVE_MIGRATION=1 to run the W33-19 migration verification (needs openssl and python3)")
	}
	scriptPath, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatalf("resolve run.sh path: %v", err)
	}
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	t.Logf("run.sh output:\n%s", out)
	if err != nil {
		t.Fatalf("tests/live/migration/run.sh exited non-zero: %v", err)
	}
}
