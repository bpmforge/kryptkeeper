// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"testing"
	"time"
)

// US-030's "weak key" example is the 30-point WEAK_SIGNATURE flag
// (SHA-1/MD5), not WEAK_RSA_KEY (35). An unknown key algorithm (PQC readiness
// not_applicable; since D-173 Ed25519 counts as classical) keeps PQC_VULNERABLE
// (+10) out of the exact-70 case; IsCA keeps SELF_SIGNED/NO_OCSP_URL/NO_CRL_DP out.
func TestRiskScoreUS030(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	t.Run("expired plus weak signature is 70 grade D", func(t *testing.T) {
		cert := &x509.Certificate{
			IsCA: true, PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm, SignatureAlgorithm: x509.SHA1WithRSA,
			NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day),
		}
		flags := computeRiskFlags(cert, false, now)
		got := append([]string(nil), flags...)
		sort.Strings(got)
		if want := []string{"EXPIRED", "WEAK_SIGNATURE"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("flags = %v, want %v", got, want)
		}
		score := computeRiskScore(cert, now)
		if score != 70 {
			t.Errorf("score = %d, want 70", score)
		}
		if g := computeGrade(score); g != "D" {
			t.Errorf("grade = %q, want D", g)
		}
	})

	t.Run("no flags is 0 grade A", func(t *testing.T) {
		cert := &x509.Certificate{
			IsCA: true, PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm, SignatureAlgorithm: x509.SHA256WithRSA,
			NotBefore: now.Add(-30 * day), NotAfter: now.Add(300 * day),
		}
		if flags := computeRiskFlags(cert, false, now); len(flags) != 0 {
			t.Fatalf("flags = %v, want none", flags)
		}
		score := computeRiskScore(cert, now)
		if score != 0 {
			t.Errorf("score = %d, want 0", score)
		}
		if g := computeGrade(score); g != "A" {
			t.Errorf("grade = %q, want A", g)
		}
	})

	t.Run("weights over 100 clamp to 100 grade F", func(t *testing.T) {
		cert := &x509.Certificate{
			IsCA: true, PublicKeyAlgorithm: x509.RSA, SignatureAlgorithm: x509.SHA1WithRSA,
			PublicKey: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537},
			NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day),
		}
		raw := 0
		for _, f := range computeRiskFlags(cert, false, now) {
			raw += riskFlagWeights[f]
		}
		if raw <= 100 {
			t.Fatalf("raw weight sum = %d, want > 100", raw)
		}
		score := computeRiskScore(cert, now)
		if score != 100 {
			t.Errorf("score = %d, want 100", score)
		}
		if g := computeGrade(score); g != "F" {
			t.Errorf("grade = %q, want F", g)
		}
	})

	t.Run("untrusted chain adds 25 capped at 100", func(t *testing.T) {
		if got := adjustRiskForChain(70, false); got != 95 {
			t.Errorf("adjustRiskForChain(70,false) = %d, want 95", got)
		}
		if got := adjustRiskForChain(90, false); got != 100 {
			t.Errorf("adjustRiskForChain(90,false) = %d, want 100", got)
		}
		if got := adjustRiskForChain(70, true); got != 70 {
			t.Errorf("adjustRiskForChain(70,true) = %d, want 70", got)
		}
	})
}

func TestRiskGradeCutoffs(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "A"}, {10, "A"}, {11, "B"}, {30, "B"}, {31, "C"},
		{50, "C"}, {51, "D"}, {70, "D"}, {71, "F"}, {100, "F"},
	}
	for _, tc := range cases {
		if got := computeGrade(tc.score); got != tc.want {
			t.Errorf("computeGrade(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// The published guide is buyer-facing; it must not drift from the code.
func TestRiskScoringDocMatchesCode(t *testing.T) {
	raw, err := os.ReadFile("../../docs/guides/RISK_SCORING.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	docWeights := map[string]int{}
	weightRow := regexp.MustCompile("(?m)^\\|\\s*`([A-Z0-9_]+)`\\s*\\|\\s*(\\d+)\\s*\\|")
	for _, m := range weightRow.FindAllStringSubmatch(doc, -1) {
		n, _ := strconv.Atoi(m[2])
		docWeights[m[1]] = n
	}
	if !reflect.DeepEqual(docWeights, riskFlagWeights) {
		for flag, pts := range riskFlagWeights {
			got, ok := docWeights[flag]
			if !ok {
				t.Errorf("flag %s is in code but missing from the doc", flag)
			} else if got != pts {
				t.Errorf("flag %s: doc says %d points, code says %d", flag, got, pts)
			}
		}
		for flag := range docWeights {
			if _, ok := riskFlagWeights[flag]; !ok {
				t.Errorf("flag %s is in the doc but missing from code", flag)
			}
		}
	}

	gradeRow := regexp.MustCompile(`(?m)^\|\s*([A-F])\s*\|\s*(\d+)-(\d+)\s*\|`)
	rows := gradeRow.FindAllStringSubmatch(doc, -1)
	if len(rows) != 5 {
		t.Fatalf("grade rows in doc = %d, want 5", len(rows))
	}
	for _, m := range rows {
		g := m[1]
		lo, _ := strconv.Atoi(m[2])
		hi, _ := strconv.Atoi(m[3])
		if got := computeGrade(lo); got != g {
			t.Errorf("grade %s: computeGrade(%d) = %s", g, lo, got)
		}
		if got := computeGrade(hi); got != g {
			t.Errorf("grade %s: computeGrade(%d) = %s", g, hi, got)
		}
		if g != "F" {
			if got := computeGrade(hi + 1); got == g {
				t.Errorf("grade %s: computeGrade(%d) still %s, range upper bound wrong", g, hi+1, g)
			}
		}
	}
}
