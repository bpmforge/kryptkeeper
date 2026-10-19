// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// W31-13: a deterministic 500-cert corpus checked against an oracle that
// is written out from the policy doc, not derived from Matches.

type corpusKind struct {
	alg  string
	bits int
}

// Index i uses kinds[i%10].
var corpusKinds = [10]corpusKind{
	{"RSA", 1024}, {"RSA", 2048}, {"RSA", 3072}, {"RSA", 4096},
	{"ECDSA", 256}, {"ECDSA", 384}, {"Ed25519", 256}, {"ML-DSA", 0},
	{"RSA", 0}, {"ECDSA", 0},
}

func corpusCN(i int) string {
	switch i % 3 {
	case 0:
		return fmt.Sprintf("test-%d.example.com", i)
	case 1:
		return fmt.Sprintf("svc%d.corp", i)
	default:
		return fmt.Sprintf("www%d.example.com", i)
	}
}

func corpusCerts() []CertRecord {
	out := make([]CertRecord, 0, 500)
	for i := 0; i < 500; i++ {
		k := corpusKinds[i%10]
		out = append(out, CertRecord{
			Fingerprint: fmt.Sprintf("fp%03d", i),
			CommonName:  corpusCN(i),
			Algorithm:   k.alg,
			KeySize:     k.bits,
		})
	}
	return out
}

type corpusPolicy struct {
	name string
	pol  DeprecationPolicy
	want int // independently counted from the kinds table
}

func corpusPolicies() []corpusPolicy {
	return []corpusPolicy{
		{"P1", DeprecationPolicy{Name: "P1", Algorithms: []string{"RSA"}, MaxKeyBits: 2048}, 150},
		{"P2", DeprecationPolicy{Name: "P2", Algorithms: []string{"RSA"}}, 250},
		{"P3", DeprecationPolicy{Name: "P3", Algorithms: []string{"ECDSA"}, MaxKeyBits: 256}, 100},
		{"P4", DeprecationPolicy{Name: "P4", Algorithms: []string{"ECDSA", "ML-DSA"}}, 200},
		{"P5", DeprecationPolicy{Name: "P5", MaxKeyBits: 2048}, 250},
	}
}

// wantMatch is the doc-derived oracle: algorithm substring (case-insensitive),
// then the size bound, where an unknown size (0) is never excluded by a
// bound but a size-only policy cannot match an unknown-size cert at all.
func wantMatch(c CertRecord, algs []string, maxBits int) bool {
	if len(algs) == 0 {
		return maxBits > 0 && c.KeySize > 0 && c.KeySize <= maxBits
	}
	hit := false
	for _, a := range algs {
		if strings.Contains(strings.ToLower(c.Algorithm), strings.ToLower(a)) {
			hit = true
		}
	}
	if !hit {
		return false
	}
	if maxBits > 0 && c.KeySize > 0 {
		return c.KeySize <= maxBits
	}
	return true
}

func flattenFPs(rm AgilityRoadmap) []string {
	var got []string
	for _, items := range rm.ByWave {
		for _, it := range items {
			got = append(got, it.Fingerprint)
		}
	}
	sort.Strings(got)
	return got
}

func TestAgilityCorpusMembershipExact(t *testing.T) {
	certs := corpusCerts()
	now := time.Now()
	for _, cp := range corpusPolicies() {
		want := map[string]bool{}
		for _, c := range certs {
			if wantMatch(c, cp.pol.Algorithms, cp.pol.MaxKeyBits) {
				want[c.Fingerprint] = true
			}
		}
		if len(want) != cp.want {
			t.Fatalf("%s: oracle size %d != hand count %d", cp.name, len(want), cp.want)
		}
		rm := DeriveAgilityRoadmap(certs, cp.pol, now)
		got := flattenFPs(rm)
		gotSet := map[string]bool{}
		for _, fp := range got {
			gotSet[fp] = true
		}
		fn, fp := 0, 0
		for w := range want {
			if !gotSet[w] {
				fn++
			}
		}
		for g := range gotSet {
			if !want[g] {
				fp++
			}
		}
		if fn != 0 || fp != 0 {
			t.Errorf("%s: false negatives=%d false positives=%d", cp.name, fn, fp)
		}
		if len(got) != len(gotSet) {
			t.Errorf("%s: duplicate fingerprints in roadmap", cp.name)
		}
		if rm.TotalMatched != len(want) {
			t.Errorf("%s: TotalMatched=%d want %d", cp.name, rm.TotalMatched, len(want))
		}
	}
}

func TestAgilityCorpusProgressHits100OnlyAtZero(t *testing.T) {
	pol := DeprecationPolicy{Name: "P2", Algorithms: []string{"RSA"}}
	remaining := corpusCerts()
	now := time.Now()
	for {
		p := Progress(remaining, pol, now)
		if p.MatchedRemaining == 0 {
			if p.PercentMigrated != 100 {
				t.Fatalf("zero matched must be 100%%, got %d", p.PercentMigrated)
			}
			break
		}
		if p.PercentMigrated >= 100 {
			t.Fatalf("%d matched still remain but percent=%d", p.MatchedRemaining, p.PercentMigrated)
		}
		// Drop the last matching cert, keeping non-matching ones.
		idx := -1
		for i := len(remaining) - 1; i >= 0; i-- {
			if pol.Matches(remaining[i]) {
				idx = i
				break
			}
		}
		remaining = append(remaining[:idx:idx], remaining[idx+1:]...)
	}

	// 1 matching cert among 500 total -> floor(499*100/500) = 99.
	one := []CertRecord{{Fingerprint: "x", Algorithm: "RSA", KeySize: 2048}}
	one = append(one, corpusCerts()[4:5]...) // ECDSA
	for i := 0; i < 498; i++ {
		one = append(one, CertRecord{Fingerprint: fmt.Sprintf("e%d", i), Algorithm: "ECDSA", KeySize: 256})
	}
	if len(one) != 500 {
		t.Fatalf("setup: %d", len(one))
	}
	if got := Progress(one, pol, now).PercentMigrated; got != 99 {
		t.Fatalf("1 of 500 remaining = 99%%, got %d", got)
	}
}

func TestAgilityCorpusPQCAndUnknownSize(t *testing.T) {
	certs := corpusCerts()
	p1 := corpusPolicies()[0].pol
	p3 := corpusPolicies()[2].pol
	p5 := corpusPolicies()[4].pol
	rsaUnknown := certs[8]
	pqc := certs[7]
	if pqc.Algorithm != "ML-DSA" || rsaUnknown.Algorithm != "RSA" || rsaUnknown.KeySize != 0 {
		t.Fatalf("corpus layout changed")
	}
	if p1.Matches(pqc) || p3.Matches(pqc) {
		t.Fatal("ML-DSA must never match an RSA/ECDSA policy")
	}
	if !p1.Matches(rsaUnknown) {
		t.Fatal("RSA with unknown size falls back to the algorithm match (documented)")
	}
	// D3: a size-only policy must not sweep up PQC / unknown-size certs.
	for _, c := range []CertRecord{pqc, rsaUnknown, certs[9]} {
		if p5.Matches(c) {
			t.Fatalf("size-only policy matched unknown-size cert %s/%d", c.Algorithm, c.KeySize)
		}
	}
	if !p5.Matches(certs[1]) {
		t.Fatal("size-only policy must still match a known RSA-2048")
	}
}

func TestAgilityCorpusKeySizeLabel(t *testing.T) {
	certs := corpusCerts()
	pol := DeprecationPolicy{Name: "Sunset", Algorithms: []string{"RSA", "ML-DSA"}}
	rm := DeriveAgilityRoadmap(certs, pol, time.Now())
	reasons := map[string]string{}
	for _, items := range rm.ByWave {
		for _, it := range items {
			reasons[it.Fingerprint] = it.Reason
		}
	}
	if got := reasons["fp001"]; got != "Sunset: RSA (2048-bit)" {
		t.Errorf("RSA-2048 reason = %q", got)
	}
	for _, fp := range []string{"fp007", "fp008"} {
		got := reasons[fp]
		if got == "" || strings.Contains(got, "-bit") {
			t.Errorf("%s reason %q must exist with no -bit suffix", fp, got)
		}
	}
}

func TestAgilityCorpusDeadline(t *testing.T) {
	certs := corpusCerts()
	now := time.Now()
	past := now.Add(-24 * time.Hour)

	pol := DeprecationPolicy{Name: "late", Algorithms: []string{"RSA"}, Deadline: past}
	if !Progress(certs, pol, now).Overdue {
		t.Error("past deadline with matches must be overdue")
	}

	pol.Algorithms = []string{"NoSuchAlg"}
	p := Progress(certs, pol, now)
	if p.Overdue || p.PercentMigrated != 100 {
		t.Errorf("past deadline with zero matches: overdue=%v pct=%d", p.Overdue, p.PercentMigrated)
	}

	pol = DeprecationPolicy{Name: "none", Algorithms: []string{"RSA"}}
	if Progress(certs, pol, now).Overdue {
		t.Error("zero deadline must never be overdue")
	}
}
