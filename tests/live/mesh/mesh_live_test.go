// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package mesh_test gates the W19-09 live UAT behind an env switch, per
// the ticket's acceptance criteria ("gated live test
// tests/live/mesh/*_live_test.go with an env switch"). Orchestration
// (kind cluster, linkerd/istioctl installers, RBAC, hub lifecycle) lives
// in run.sh, not Go: it needs kind/kubectl/linkerd/istioctl process
// lifecycle management a Go test would just be re-implementing os/exec
// calls around. Same shape as tests/live/pkcs11/pkcs11_live_test.go and
// tests/live/ad-ldap/adldap_live_test.go.
//
// Skipped unless KK_LIVE_MESH=1. Requires kind, kubectl, linkerd,
// istioctl, and rootless podman (KIND_EXPERIMENTAL_PROVIDER=podman, set
// by run.sh itself). See README.md for results and the hub defect this
// run found and fixed (W19-20: mesh discovery had no K8s API-server CA
// trust).
package mesh_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMeshDiscoveryLiveUAT(t *testing.T) {
	if os.Getenv("KK_LIVE_MESH") != "1" {
		t.Skip("set KK_LIVE_MESH=1 to run the W19-09 service-mesh discovery UAT against a real kind cluster (needs kind, kubectl, linkerd, istioctl, rootless podman)")
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
		t.Fatalf("tests/live/mesh/run.sh exited non-zero: %v", err)
	}
}
