// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// W7-04 (D-058), rules-first: issuance-anomaly detection and
// natural-language policy drafting, both deterministic. No LLM
// dependency exists in this repo and none is added — a future LLM
// front-end drives these same seams, and its drafts inherit the same
// never-auto-active guarantee.

// IssuanceEvent is the minimal issuance fact the detector consumes.
type IssuanceEvent struct {
	Subject     string
	CAID        string
	RequestedBy string
	IssuedAt    time.Time
}

// AnomalyFinding is one detected pattern.
type AnomalyFinding struct {
	Kind     string    `json:"kind"` // volume_spike | subject_churn | requester_burst
	Severity string    `json:"severity"`
	Detail   string    `json:"detail"`
	Evidence []string  `json:"evidence"`
	At       time.Time `json:"at"`
}

// AnomalyDetector holds tunable thresholds — struct fields, not buried
// constants, so ops can tune without a rebuild.
type AnomalyDetector struct {
	// SpikeFactor: last-24h count > SpikeFactor × trailing-30d daily
	// average flags a CA. MinSample mirrors the S-45 report's guard so
	// the report and the detector agree on when data is meaningful.
	SpikeFactor float64
	MinSample   int
	// SubjectChurnLimit: same subject issued more than this many times
	// within 24h.
	SubjectChurnLimit int
	// RequesterBurstLimit: one requester minting for more than this
	// many DISTINCT subjects within 1h.
	RequesterBurstLimit int
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{SpikeFactor: 2.0, MinSample: 5, SubjectChurnLimit: 3, RequesterBurstLimit: 10}
}

// Scan is pure: events in, findings out. Wiring an inventory adapter
// and a notifier is follow-up outside this ticket's scope.
func (d *AnomalyDetector) Scan(events []IssuanceEvent, now time.Time) []AnomalyFinding {
	var findings []AnomalyFinding

	// volume_spike per CA.
	perCA24h := map[string]int{}
	perCA30d := map[string]int{}
	for _, e := range events {
		age := now.Sub(e.IssuedAt)
		if age < 0 || age > 30*24*time.Hour {
			continue
		}
		perCA30d[e.CAID]++
		if age <= 24*time.Hour {
			perCA24h[e.CAID]++
		}
	}
	for caID, last24 := range perCA24h {
		if last24 < d.MinSample {
			continue
		}
		dailyAvg := float64(perCA30d[caID]) / 30.0
		if dailyAvg > 0 && float64(last24) > d.SpikeFactor*dailyAvg {
			findings = append(findings, AnomalyFinding{
				Kind: "volume_spike", Severity: "high", At: now,
				Detail:   fmt.Sprintf("CA %s issued %d certificates in 24h vs a %.1f/day 30d average", caID, last24, dailyAvg),
				Evidence: []string{caID},
			})
		}
	}

	// subject_churn within 24h.
	perSubject := map[string]int{}
	for _, e := range events {
		if age := now.Sub(e.IssuedAt); age >= 0 && age <= 24*time.Hour {
			perSubject[e.Subject]++
		}
	}
	for subject, n := range perSubject {
		if n > d.SubjectChurnLimit {
			findings = append(findings, AnomalyFinding{
				Kind: "subject_churn", Severity: "medium", At: now,
				Detail:   fmt.Sprintf("subject %q issued %d times within 24h (limit %d)", subject, n, d.SubjectChurnLimit),
				Evidence: []string{subject},
			})
		}
	}

	// requester_burst: distinct subjects per requester within 1h.
	perRequester := map[string]map[string]bool{}
	for _, e := range events {
		if age := now.Sub(e.IssuedAt); age >= 0 && age <= time.Hour {
			if perRequester[e.RequestedBy] == nil {
				perRequester[e.RequestedBy] = map[string]bool{}
			}
			perRequester[e.RequestedBy][e.Subject] = true
		}
	}
	for requester, subjects := range perRequester {
		if len(subjects) > d.RequesterBurstLimit {
			ev := make([]string, 0, len(subjects))
			for s := range subjects {
				ev = append(ev, s)
			}
			sort.Strings(ev)
			findings = append(findings, AnomalyFinding{
				Kind: "requester_burst", Severity: "high", At: now,
				Detail:   fmt.Sprintf("requester %q minted certificates for %d distinct subjects within 1h (limit %d)", requester, len(subjects), d.RequesterBurstLimit),
				Evidence: ev,
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Kind < findings[j].Kind })
	return findings
}

// --- NL policy drafting -------------------------------------------------

var (
	reMaxValidity = regexp.MustCompile(`(?i)(?:valid(?:ity)?[^.\d]{0,20}|max(?:imum)? validity[^.\d]{0,10})(\d+)\s*(day|d\b)`)
	reRSABits     = regexp.MustCompile(`(?i)rsa[^.\d]{0,20}(\d{4})\s*(?:bits?)?`)
	reAllowCA     = regexp.MustCompile(`(?i)allow\s+ca\s+cert`)
	reOnlyAlgs    = regexp.MustCompile(`(?i)only\s+([a-z0-9, ]+?)(?:\s+(?:keys|algorithms|certs)|[.;]|$)`)
)

var knownAlgorithms = map[string]string{
	"rsa": "rsa", "ecdsa": "ecdsa", "ed25519": "ed25519",
}

// DraftPolicyFromNL turns an operator's natural-language request into a
// PROPOSED (never active) issuance policy on the real W5-05 rule
// schema. Deterministic phrase extraction; unrecognized text errors
// with what IS understood rather than yielding a silently-empty policy.
// The explanation names every extracted rule — the reviewer must see
// exactly what the text became.
func DraftPolicyFromNL(name, text string) (ca.IssuancePolicy, []string, error) {
	rules := ca.PolicyRules{}
	var explanation []string

	if m := reMaxValidity.FindStringSubmatch(text); m != nil {
		days, err := strconv.Atoi(m[1])
		if err == nil && days > 0 {
			rules.MaxValidityDays = days
			explanation = append(explanation, fmt.Sprintf("max validity %d days", days))
		}
	}
	if m := reRSABits.FindStringSubmatch(text); m != nil {
		bits, err := strconv.Atoi(m[1])
		if err == nil && bits >= 2048 {
			rules.MinRSABits = bits
			explanation = append(explanation, fmt.Sprintf("minimum RSA key size %d bits", bits))
		}
	}
	if reAllowCA.MatchString(text) {
		rules.AllowCACerts = true
		explanation = append(explanation, "CA certificates allowed through the leaf path (explicit opt-in)")
	}
	if m := reOnlyAlgs.FindStringSubmatch(text); m != nil {
		var algs []string
		for _, part := range strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' }) {
			p := strings.ToLower(strings.TrimSpace(part))
			if p == "and" || p == "or" || p == "" {
				continue
			}
			if canonical, ok := knownAlgorithms[p]; ok {
				algs = append(algs, canonical)
			}
		}
		if len(algs) > 0 {
			rules.AllowedAlgorithms = algs
			explanation = append(explanation, "allowed algorithms: "+strings.Join(algs, ", "))
		}
	}

	if len(explanation) == 0 {
		return ca.IssuancePolicy{}, nil, fmt.Errorf(
			"no policy rules recognized in %q — understood phrases: validity limits (\"valid for at most 90 days\"), RSA floors (\"rsa at least 3072 bits\"), algorithm restrictions (\"only ecdsa and ed25519\"), CA-cert opt-in (\"allow ca certificates\")", text)
	}

	// Proposed, never active: Enabled is false at construction and
	// SubmitPolicyDraft forces it false again. NL text asking for
	// activation ("enable it now") is deliberately not honored.
	return ca.IssuancePolicy{Name: name, Enabled: false, Rules: rules}, explanation, nil
}

// SubmitPolicyDraft persists a draft as a DISABLED policy row. The
// force is structural: even a caller who flipped Enabled on the draft
// lands a disabled row. A human enables it through the existing policy
// surface — the LLM/NL path proposes, never activates (D-058).
func SubmitPolicyDraft(engine *ca.PolicyEngine, draft ca.IssuancePolicy) (ca.IssuancePolicy, error) {
	if engine == nil {
		return ca.IssuancePolicy{}, fmt.Errorf("policy engine unavailable")
	}
	draft.Enabled = false
	return engine.UpsertPolicy(draft)
}
