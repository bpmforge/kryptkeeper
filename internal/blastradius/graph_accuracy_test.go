// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package blastradius

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The oracle is built from the seed maps, never from the graph under test.
func TestRetireCAListsEveryChainedCertAndService(t *testing.T) {
	g := NewGraph()
	parent := map[string]string{"X": "R", "X1": "X", "Y": "R"}
	for child, p := range parent {
		g.AddDependency(KindCA, child, KindCA, p)
	}
	g.AddNode(KindCA, "R")

	wantCerts := map[string]bool{}
	wantServices := map[string]bool{}
	yCerts := map[string]bool{}
	yOnlyServices := map[string]bool{}
	xServices := map[string]bool{}
	seed := func(ca string, n int) {
		for i := 0; i < n; i++ {
			fp := fmt.Sprintf("%s-cert-%d", ca, i)
			g.AddDependency(KindCert, fp, KindCA, ca)
			for s := 0; s <= i%3; s++ {
				svc := fmt.Sprintf("%s-svc-%d-%d", ca, i, s)
				// two services are shared between an X cert and a Y cert
				if ca == "Y" && i < 2 && s == 0 {
					svc = fmt.Sprintf("X-svc-%d-0", i)
				}
				g.AddDependency(KindService, svc, KindCert, fp)
				switch ca {
				case "X", "X1":
					wantServices[svc] = true
					xServices[svc] = true
				case "Y":
					yOnlyServices[svc] = true
				}
			}
			switch ca {
			case "X", "X1":
				wantCerts[fp] = true
			case "Y":
				yCerts[fp] = true
			}
		}
	}
	seed("X", 200)
	seed("X1", 60)
	seed("Y", 50)

	imp := g.SimulateRetireCA("X")
	gotCerts := map[string]bool{}
	for _, c := range imp.AffectedByKind[KindCert] {
		gotCerts[c] = true
	}
	gotServices := map[string]bool{}
	for _, s := range imp.AffectedByKind[KindService] {
		gotServices[s] = true
	}
	if len(wantCerts) != 260 {
		t.Fatalf("oracle seed wrong: %d", len(wantCerts))
	}
	if !reflect.DeepEqual(sortedKeys(gotCerts), sortedKeys(wantCerts)) {
		t.Fatalf("certs mismatch: got %d want %d", len(gotCerts), len(wantCerts))
	}
	if !reflect.DeepEqual(sortedKeys(gotServices), sortedKeys(wantServices)) {
		t.Fatalf("services mismatch: got %d want %d", len(gotServices), len(wantServices))
	}
	if got := imp.AffectedByKind[KindCA]; !reflect.DeepEqual(got, []string{"X1"}) {
		t.Fatalf("CA kind must list exactly X1, got %v", got)
	}
	for c := range yCerts {
		if gotCerts[c] {
			t.Fatalf("Y's exclusive cert %s leaked into X's radius", c)
		}
	}
	shared := 0
	for s := range yOnlyServices {
		if xServices[s] {
			shared++
			continue // shared services are conservatively reported
		}
		if gotServices[s] {
			t.Fatalf("Y's exclusive service %s leaked", s)
		}
	}
	if shared != 2 {
		t.Fatalf("expected 2 shared services, got %d", shared)
	}
}

func TestSimulateCyclesTerminate(t *testing.T) {
	g := NewGraph()
	g.AddDependency(KindCA, "A", KindCA, "B")
	g.AddDependency(KindCA, "B", KindCA, "A")
	imp := g.SimulateRetireCA("A")
	if imp.TotalAffected != 1 || !reflect.DeepEqual(imp.AffectedByKind[KindCA], []string{"B"}) {
		t.Fatalf("cycle result: %+v", imp)
	}
}

func TestHasNode(t *testing.T) {
	g := NewGraph()
	g.AddDependency(KindCert, "fp", KindCA, "ca")
	if !g.HasNode(KindCert, "fp") || !g.HasNode(KindCA, "ca") {
		t.Fatal("present nodes not found")
	}
	if g.HasNode(KindCert, "nope") {
		t.Fatal("absent node found")
	}
	if g.HasNode(KindCA, "fp") {
		t.Fatal("wrong kind must not match")
	}
}

func TestCoverageCounts(t *testing.T) {
	g := NewGraph()
	for i := 0; i < 10; i++ {
		fp := fmt.Sprintf("c%d", i)
		g.AddNode(KindCert, fp)
		if i < 7 {
			g.AddDependency(KindCert, fp, KindCA, "ca")
		}
		if i >= 3 && i < 7 { // 4 certs with services
			g.AddDependency(KindService, "svc"+fp, KindCert, fp)
		}
		g.AddDependency(KindCert, fp, KindAlgorithm, "RSA-2048")
	}
	want := Coverage{CertsTotal: 10, CertsWithCAEdge: 7, CertsWithServiceEdge: 4}
	if got := g.Coverage(); got != want {
		t.Fatalf("coverage = %+v, want %+v", got, want)
	}
}
