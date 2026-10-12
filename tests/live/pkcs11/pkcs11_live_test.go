// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package pkcs11_test gates the W19-08 live UAT behind an env switch, per
// the ticket's acceptance criteria ("gated live test
// tests/live/pkcs11/*_live_test.go with an env switch"). The actual
// orchestration (init a SoftHSM2 token, build the hub with -tags pkcs11,
// drive it, verify with pkcs11-tool/openssl) lives in run.sh, not in Go: it
// needs cgo build tags and native tool lifecycle management (softhsm2-util,
// pkcs11-tool) that a Go test would just be re-implementing os/exec calls
// around. This test is a thin, CI-usable wrapper — the same shape as
// tests/live/agent/agent_live_test.go and tests/live/ad-ldap/adldap_live_test.go.
//
// Skipped unless KK_LIVE_PKCS11=1. Requires softhsm2-util + libsofthsm2.so
// (brew install softhsm), pkcs11-tool (brew install opensc), and
// CGO_ENABLED=1. See README.md for the two hub defects this run found and
// fixed, and the two it found and deliberately left unfixed.
package pkcs11_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPKCS11LiveUAT(t *testing.T) {
	if os.Getenv("KK_LIVE_PKCS11") != "1" {
		t.Skip("set KK_LIVE_PKCS11=1 to run the W19-08 PKCS#11 UAT against a real SoftHSM2 token (needs softhsm2-util, pkcs11-tool, CGO_ENABLED=1)")
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
		// failed.
		t.Fatalf("tests/live/pkcs11/run.sh exited non-zero: %v", err)
	}
}
