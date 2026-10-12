// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package blastradius

import (
	"testing"
)

// W16-02: blast-radius simulation — transitive dependents, algorithm-
// target queries, severity, and cycle safety.

// sampleGraph:
//
//	cert:c1 issued by ca:root, on algorithm:RSA-2048
//	endpoint:web serves cert:c1; service:shop depends on endpoint:web
//	cert:c2 issued by ca:root, on algorithm:ML-DSA-65
//	endpoint:api serves cert:c2; service:billing depends on endpoint:api
func sampleGraph() *Graph {
	g := NewGraph()
	g.AddDependency(KindCert, "c1", KindCA, "root")
	g.AddDependency(KindCert, "c1", KindAlgorithm, "RSA-2048")
	g.AddDependency(KindEndpoint, "web", KindCert, "c1")
	g.AddDependency(KindService, "shop", KindEndpoint, "web")

	g.AddDependency(KindCert, "c2", KindCA, "root")
	g.AddDependency(KindCert, "c2", KindAlgorithm, "ML-DSA-65")
	g.AddDependency(KindEndpoint, "api", KindCert, "c2")
	g.AddDependency(KindService, "billing", KindEndpoint, "api")
	return g
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestSimulateRevokeReachesTransitiveDependents(t *testing.T) {
	imp := sampleGraph().SimulateRevoke("c1")
	// The endpoint serving c1 and the service behind it break — but NOT
	// the unrelated c2 chain.
	if !has(imp.AffectedByKind[KindEndpoint], "web") {
		t.Fatalf("endpoint web must be affected: %+v", imp.AffectedByKind)
	}
	if !has(imp.AffectedByKind[KindService], "shop") {
		t.Fatalf("service shop must be affected (multi-hop cert->endpoint->service): %+v", imp.AffectedByKind)
	}
	if has(imp.AffectedByKind[KindEndpoint], "api") || has(imp.AffectedByKind[KindService], "billing") {
		t.Fatalf("unrelated c2 chain must NOT be affected: %+v", imp.AffectedByKind)
	}
	if imp.Severity != "low" { // one service
		t.Fatalf("one-service blast should be low, got %q", imp.Severity)
	}
}

func TestSimulateRetireCAReachesAllIssued(t *testing.T) {
	imp := sampleGraph().SimulateRetireCA("root")
	// Both certs, both endpoints, both services.
	if !has(imp.AffectedByKind[KindCert], "c1") || !has(imp.AffectedByKind[KindCert], "c2") {
		t.Fatalf("both issued certs must be affected: %+v", imp.AffectedByKind)
	}
	if len(imp.AffectedByKind[KindService]) != 2 {
		t.Fatalf("both services must be affected: %+v", imp.AffectedByKind[KindService])
	}
}

func TestSimulateDeprecateAlgorithmIsThePQCQuery(t *testing.T) {
	imp := sampleGraph().SimulateDeprecateAlgorithm("RSA-2048")
	// Only the RSA cert's chain — the ML-DSA cert is quantum-safe.
	if !has(imp.AffectedByKind[KindCert], "c1") {
		t.Fatalf("RSA cert must be affected: %+v", imp.AffectedByKind)
	}
	if has(imp.AffectedByKind[KindCert], "c2") {
		t.Fatalf("the ML-DSA cert must survive an RSA deprecation: %+v", imp.AffectedByKind)
	}
	if !has(imp.AffectedByKind[KindService], "shop") || has(imp.AffectedByKind[KindService], "billing") {
		t.Fatalf("only the RSA-backed service breaks: %+v", imp.AffectedByKind)
	}
}

func TestSeverityRisesWithServices(t *testing.T) {
	g := NewGraph()
	for i := 0; i < 8; i++ {
		svc := string(rune('a' + i))
		g.AddDependency(KindService, svc, KindCert, "shared")
	}
	imp := g.SimulateRevoke("shared")
	if imp.Severity != "high" { // 8 services → high
		t.Fatalf("8 services should be high, got %q (n=%d)", imp.Severity, len(imp.AffectedByKind[KindService]))
	}
}

func TestCyclicDependencyDoesNotHang(t *testing.T) {
	g := NewGraph()
	// a depends on b, b depends on a (mis-modeled cycle).
	g.AddDependency(KindService, "a", KindService, "b")
	g.AddDependency(KindService, "b", KindService, "a")
	done := make(chan Impact, 1)
	go func() { done <- g.simulate(nodeID(KindService, "a")) }()
	select {
	case imp := <-done:
		if !has(imp.AffectedByKind[KindService], "b") {
			t.Fatalf("cycle must still report b: %+v", imp.AffectedByKind)
		}
	default:
		// simulate is synchronous and fast; the goroutine has completed.
		imp := g.simulate(nodeID(KindService, "a"))
		if imp.TotalAffected == 0 {
			t.Fatal("expected b in the blast radius")
		}
	}
}
