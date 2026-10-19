// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import (
	"fmt"
	"os"
	"testing"
)

// TestTenantIDOR is the suite itself. It runs only when scripts/test (run.sh)
// has booted a hub and exported KK_IDOR_BASE_URL; under plain `go test ./...`
// it skips. With KK_IDOR_LEAK_FIXTURE=1 it targets an in-process hub with a
// seeded leak instead, which run.sh uses to prove the suite fails closed.
func TestTenantIDOR(t *testing.T) {
	var res Result
	engine := os.Getenv("KK_IDOR_ENGINE")
	var skipped []string
	if os.Getenv("KK_IDOR_LEAK_FIXTURE") == "1" {
		engine = "leak-fixture"
		res = runAgainstLeakyHub(t)
	} else {
		base := os.Getenv("KK_IDOR_BASE_URL")
		if base == "" {
			t.Skip("KK_IDOR_BASE_URL not set; run via scripts/test/run.sh --suite tenant-idor")
		}
		routes, err := LoadRoutes(os.Getenv("KK_IDOR_ROUTES"))
		if err != nil {
			t.Fatalf("routes: %v", err)
		}
		raw, err := os.ReadFile("allowlist.txt")
		if err != nil {
			t.Fatalf("allowlist: %v", err)
		}
		al, err := ParseAllowlist(raw)
		if err != nil {
			t.Fatal(err)
		}
		c := newClient(base)
		f, err := Seed(c, os.Getenv("KK_IDOR_BOOTSTRAP_TOKEN"))
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		skipped = f.Skipped
		for _, s := range skipped {
			t.Log(s)
		}
		if len(f.Victim.IDs) == 0 {
			t.Fatal("no victim data was seeded; the run would be vacuous")
		}
		t.Logf("seeded %d victim ids across %d collections", len(f.Victim.IDs), len(f.Collections))
		res = Run(c, f, routes, al, t.Logf)
	}
	line := fmt.Sprintf("routes=%d requests=%d leaks=%d elapsed=%.1f", res.Routes, res.Requests, len(res.Leaks), res.Elapsed.Seconds())
	if p := os.Getenv("KK_IDOR_SUMMARY_FILE"); p != "" {
		_ = os.WriteFile(p, []byte(line+"\n"), 0o600)
	}
	t.Logf("engine=%s %s", engine, line)
	for _, l := range res.Leaks {
		t.Error(l.String())
	}
	if len(res.Leaks) > 0 {
		t.Fatalf("%d cross-tenant leak(s) on %s", len(res.Leaks), engine)
	}
}
