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
	"unicode"

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
	Fingerprint string
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
		// Imported, discovered and synced certificates carry no issuing CA of
		// this hub; pooling them under "" produced a finding about a CA with
		// an empty id (CB-09).
		if e.CAID == "" {
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
		// Unknown requesters (imported/discovered/protocol-issued certs)
		// must not be pooled into one synthetic bucket.
		if e.RequestedBy == "" {
			continue
		}
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
	reMaxValidity = regexp.MustCompile(`(?i)(?:valid(?:ity)?[^.\d]{0,20}|max(?:imum)? validity[^.\d]{0,10})(\d+)\s*(?:days?\b|d\b)`)
	// reMaxValidityAlt covers "max 90 days"; consulted only when reMaxValidity
	// does not match so one phrase is never counted twice.
	reMaxValidityAlt = regexp.MustCompile(`(?i)\bmax(?:imum)?\s+(?:of\s+)?(\d+)\s*days?\b`)
	reRSABits        = regexp.MustCompile(`(?i)rsa[^.,;\d]{0,40}?(\d{4})\s*(?:bits?)?`)
	reAllowCA        = regexp.MustCompile(`(?i)allow\s+ca\s+cert(?:ificate)?s?`)
	reOnlyAlgs       = regexp.MustCompile(`(?i)only\s+([a-z0-9, ]+?)(?:\s+(?:keys|algorithms|certs)|[.;]|$)`)
	reDraftSplit     = regexp.MustCompile(`[.;,\n]`)
)

var knownAlgorithms = map[string]string{
	"rsa": "rsa", "ecdsa": "ecdsa", "ed25519": "ed25519",
}

// draftStopwords are connective fragments left over once the recognised
// phrases are blanked out; they carry no policy intent so they are not
// reported as unrecognised.
var draftStopwords = map[string]bool{
	"and": true, "or": true, "then": true, "also": true, "please": true, "the": true, "a": true, "an": true,
	"all": true, "any": true, "cert": true, "certs": true, "certificate": true, "certificates": true,
	"key": true, "keys": true, "algorithm": true, "algorithms": true, "must": true, "should": true,
	"be": true, "have": true, "use": true,
}

// PolicyDraftResult is the outcome of parsing operator text. Unrecognized
// holds every clause no rule consumed, verbatim: text is reported, never
// silently dropped.
type PolicyDraftResult struct {
	Policy       ca.IssuancePolicy
	Explanation  []string
	Unrecognized []string
}

// ParsePolicyDraft turns an operator's natural-language request into a
// PROPOSED (never active) issuance policy on the real W5-05 rule schema.
// Deterministic phrase extraction, no LLM and no network (D-058). It never
// errors and Policy.Enabled is always false: NL text asking for activation
// ("enable it now") is deliberately not honored, it surfaces as Unrecognized.
func ParsePolicyDraft(name, text string) PolicyDraftResult {
	rules := ca.PolicyRules{}
	var explanation, unrecognized []string
	var spans [][2]int

	if loc := reMaxValidity.FindStringSubmatchIndex(text); loc != nil {
		if days, err := strconv.Atoi(text[loc[2]:loc[3]]); err == nil && days > 0 {
			rules.MaxValidityDays = days
			explanation = append(explanation, fmt.Sprintf("max validity %d days", days))
			spans = append(spans, [2]int{loc[0], loc[1]})
		}
	} else if loc := reMaxValidityAlt.FindStringSubmatchIndex(text); loc != nil {
		if days, err := strconv.Atoi(text[loc[2]:loc[3]]); err == nil && days > 0 {
			rules.MaxValidityDays = days
			explanation = append(explanation, fmt.Sprintf("max validity %d days", days))
			spans = append(spans, [2]int{loc[0], loc[1]})
		}
	}
	if loc := reRSABits.FindStringSubmatchIndex(text); loc != nil {
		if bits, err := strconv.Atoi(text[loc[2]:loc[3]]); err == nil && bits >= 2048 {
			rules.MinRSABits = bits
			explanation = append(explanation, fmt.Sprintf("minimum RSA key size %d bits", bits))
			spans = append(spans, [2]int{loc[0], loc[1]})
		}
	}
	if loc := reAllowCA.FindStringIndex(text); loc != nil {
		rules.AllowCACerts = true
		explanation = append(explanation, "CA certificates allowed through the leaf path (explicit opt-in)")
		spans = append(spans, [2]int{loc[0], loc[1]})
	}
	if loc := reOnlyAlgs.FindStringSubmatchIndex(text); loc != nil {
		var algs, unknown []string
		seen := map[string]bool{}
		for _, part := range strings.FieldsFunc(text[loc[2]:loc[3]], func(r rune) bool { return r == ',' || r == ' ' }) {
			p := strings.ToLower(strings.TrimSpace(part))
			if p == "and" || p == "or" || p == "" {
				continue
			}
			canonical, ok := knownAlgorithms[p]
			switch {
			case !ok:
				unknown = append(unknown, part)
			case !seen[canonical]:
				seen[canonical] = true
				algs = append(algs, canonical)
			}
		}
		if len(algs) > 0 {
			rules.AllowedAlgorithms = algs
			explanation = append(explanation, "allowed algorithms: "+strings.Join(algs, ", "))
			spans = append(spans, [2]int{loc[0], loc[1]})
			for _, u := range unknown {
				unrecognized = append(unrecognized, "algorithm not supported: "+u)
			}
		}
	}

	// Blank consumed spans so only clauses no rule understood remain.
	rest := []byte(text)
	for _, sp := range spans {
		for i := sp[0]; i < sp[1]; i++ {
			rest[i] = ' '
		}
	}
	var leftovers []string
	for _, frag := range reDraftSplit.Split(string(rest), -1) {
		frag = strings.TrimSpace(frag)
		if frag == "" || !strings.ContainsFunc(frag, unicode.IsLetter) || draftStopwords[strings.ToLower(frag)] {
			continue
		}
		leftovers = append(leftovers, frag)
	}
	unrecognized = append(leftovers, unrecognized...)

	return PolicyDraftResult{
		Policy:       ca.IssuancePolicy{Name: name, Enabled: false, Rules: rules},
		Explanation:  explanation,
		Unrecognized: unrecognized,
	}
}

// DraftPolicyFromNL is ParsePolicyDraft for callers that want an error when
// nothing was understood; the error names what IS understood.
func DraftPolicyFromNL(name, text string) (ca.IssuancePolicy, []string, error) {
	res := ParsePolicyDraft(name, text)
	if len(res.Explanation) == 0 {
		return ca.IssuancePolicy{}, nil, fmt.Errorf(
			"no policy rules recognized in %q — understood phrases: validity limits (\"valid for at most 90 days\"), RSA floors (\"rsa at least 3072 bits\"), algorithm restrictions (\"only ecdsa and ed25519\"), CA-cert opt-in (\"allow ca certificates\")", text)
	}
	return res.Policy, res.Explanation, nil
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
