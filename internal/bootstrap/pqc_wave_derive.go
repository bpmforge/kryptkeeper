// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"regexp"
	"strings"
)

// derivedWave is an auto-generated migration wave with its assigned members.
type derivedWave struct {
	Name    string
	Owner   string
	Members []MigrationWaveMember
}

var (
	reTestEnv     = regexp.MustCompile(`(?i)\b(test|staging|stg|dev|sandbox|qa|uat)\b`)
	reInternalTLD = regexp.MustCompile(`(?i)\.(local|internal|corp|lan|intranet)\.?$`)
)

// labelSet lowercases a cert's labels for membership checks.
func labelSet(labels []string) map[string]bool {
	out := make(map[string]bool, len(labels))
	for _, l := range labels {
		out[strings.ToLower(strings.TrimSpace(l))] = true
	}
	return out
}

// classifyWave decides which migration wave a vulnerable cert belongs to:
// "Test", "Customer-Facing", or "Internal" — from naming, SANs, and labels.
func classifyWave(c CertificateItem) string {
	labels := labelSet(c.Labels)
	hay := strings.ToLower(c.CommonName + " " + strings.Join(c.SubjectAltNames, " "))

	if labels["test"] || labels["dev"] || labels["staging"] || reTestEnv.MatchString(hay) {
		return "Test"
	}
	if labels["prod"] || labels["public"] || labels["customer"] || labels["external"] || isPublicFacing(c) {
		return "Customer-Facing"
	}
	return "Internal"
}

// isPublicFacing reports whether any SAN looks like a public FQDN (a dotted name
// that isn't an internal-only TLD).
func isPublicFacing(c CertificateItem) bool {
	for _, san := range c.SubjectAltNames {
		s := strings.ToLower(strings.TrimSpace(san))
		if !strings.Contains(s, ".") {
			continue
		}
		if reInternalTLD.MatchString(s) {
			continue
		}
		return true
	}
	return false
}

// derivePQCWaves groups the still-vulnerable certs into ordered migration waves
// (Test → Internal → Customer-Facing). Non-vulnerable certs need no migration
// and are skipped. Each wave's owner is the most common owner team among its
// members. Order reflects a safe rollout sequence.
func derivePQCWaves(certs []CertificateItem) []derivedWave {
	order := []string{"Test", "Internal", "Customer-Facing"}
	byWave := map[string][]MigrationWaveMember{}
	teamVotes := map[string]map[string]int{}

	for _, c := range activeCertificates(certs) {
		if c.PQCReadiness != "vulnerable" {
			continue
		}
		w := classifyWave(c)
		byWave[w] = append(byWave[w], MigrationWaveMember{
			Fingerprint: c.FingerprintSHA256,
			CommonName:  c.CommonName,
		})
		if c.OwnerTeam != "" {
			if teamVotes[w] == nil {
				teamVotes[w] = map[string]int{}
			}
			teamVotes[w][c.OwnerTeam]++
		}
	}

	var out []derivedWave
	for _, name := range order {
		members := byWave[name]
		if len(members) == 0 {
			continue
		}
		out = append(out, derivedWave{
			Name:    name,
			Owner:   topTeam(teamVotes[name]),
			Members: members,
		})
	}
	return out
}

// topTeam returns the most-voted team, or "" if none.
func topTeam(votes map[string]int) string {
	best, bestN := "", 0
	for team, n := range votes {
		if n > bestN {
			best, bestN = team, n
		}
	}
	return best
}
