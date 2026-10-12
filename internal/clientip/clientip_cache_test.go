// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package clientip

import "testing"

func TestFromEnv_ReusesParseUntilEnvChanges(t *testing.T) {
	t.Setenv(EnvTrustedProxyCIDRs, "10.0.0.0/24")
	first := FromEnv()
	if FromEnv() != first {
		t.Fatal("unchanged env must reuse the parsed resolver")
	}
	if allocs := testing.AllocsPerRun(100, func() { FromEnv() }); allocs > 0 {
		t.Fatalf("FromEnv allocates %v per call on an unchanged env", allocs)
	}
	t.Setenv(EnvTrustedProxyCIDRs, "192.168.0.0/16")
	if FromEnv() == first || FromEnv().PeerTrusted("10.0.0.5:1") || !FromEnv().PeerTrusted("192.168.1.1:1") {
		t.Fatal("changed env must be re-parsed")
	}
}
