// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"kryptkeeper/internal/discovery/scanner"
)

// riskyScoreThreshold is the numeric half of the "risky endpoint" rule.
const riskyScoreThreshold = 70

// A discovered endpoint is RISKY when any of these holds:
//
//  1. a currently-active certificate on it scores >= riskyScoreThreshold,
//     counting what serving it THERE adds (certificate score + the link's
//     endpoint_risk_score);
//  2. such a certificate carries a high-severity flag: one of its own
//     (scanner.HighSeverityCertFlags: EXPIRED, SELF_SIGNED, WEAK_KEY,
//     WEAK_SIGNATURE) or an endpoint-scoped one recorded on this endpoint's
//     link (scanner.HighSeverityEndpointCertFlags: HOSTNAME_MISMATCH,
//     UNTRUSTED_ROOT). A certificate served under the wrong name makes that
//     endpoint risky, and only that endpoint (owner policy, 2026-10);
//  3. the endpoint itself has a high-severity finding
//     (scanner.HighSeverityEndpointFindings: DEPRECATED_TLS_VERSION, NOT_TLS,
//     TLS_HANDSHAKE_FAILED, POSTGRES_TLS_DISABLED). An open port on which no
//     working TLS protects the service is a finding whichever way it fails;
//     such an endpoint scores scanner.EndpointFindingScore on its own.
//
// The score alone is not enough: scores are sums, and an expired or self-signed
// certificate can score 40-60 depending on how the flags add up, so it used to
// fall under the threshold and disappear from "Risky only" and the dashboard.
// The same rule drives the summary count, the risky_only filter and the
// per-endpoint `risky` field, so the three can never disagree.

// riskyEndpointSQL is the rule above as a predicate over an `endpoints e` row.
// activeLiteral is the dialect's TRUE ("1" on sqlite, "true" on postgres).
// risk_flags is matched through CAST(... AS TEXT) so it works whether the
// column holds a JSON array (sqlite, the discovery mirror) or a TEXT[]
// (migrated postgres); no flag code is a substring of another, so an unquoted
// match is exact. The finding match is anchored on the opening quote of the
// JSON string in endpoints.issues.
func riskyEndpointSQL(activeLiteral string) string {
	certConds := []string{"(c.risk_score + COALESCE(ce.endpoint_risk_score, 0)) >= " + strconv.Itoa(riskyScoreThreshold)}
	for _, f := range scanner.HighSeverityCertFlags {
		certConds = append(certConds, "CAST(c.risk_flags AS TEXT) LIKE '%"+f+"%'")
	}
	for _, f := range scanner.HighSeverityEndpointCertFlags {
		certConds = append(certConds, "COALESCE(ce.endpoint_flags, '') LIKE '%\""+f+"\"%'")
	}
	endpointConds := make([]string, 0, len(scanner.HighSeverityEndpointFindings))
	for _, f := range scanner.HighSeverityEndpointFindings {
		endpointConds = append(endpointConds, `COALESCE(e.issues, '') LIKE '%"`+f+`%'`)
	}
	return `(e.id IN (
			SELECT ce.endpoint_id FROM certificate_endpoints ce
			JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
			WHERE ce.currently_active = ` + activeLiteral + ` AND (` + strings.Join(certConds, " OR ") + `)
		) OR ` + strings.Join(endpointConds, " OR ") + `)`
}

// endpointIsRisky is the in-Go form of riskyEndpointSQL for an endpoint whose
// MappedCerts and Issues are already loaded.
func endpointIsRisky(ep DiscoveryEndpoint) bool {
	if ep.RiskScore >= riskyScoreThreshold {
		return true
	}
	for _, mc := range ep.MappedCerts {
		if mc.RiskScore >= riskyScoreThreshold {
			return true
		}
		if slices.ContainsFunc(mc.RiskFlags, isHighSeverityFlag) {
			return true
		}
	}
	return slices.ContainsFunc(ep.Issues, func(issue string) bool {
		return slices.Contains(scanner.HighSeverityEndpointFindings, scanner.FindingCode(issue))
	})
}

func isHighSeverityFlag(f string) bool {
	return slices.Contains(scanner.HighSeverityCertFlags, f) || slices.Contains(scanner.HighSeverityEndpointCertFlags, f)
}

// parseRiskFlagsText reads certificates.risk_flags however it was stored: a
// JSON array (sqlite) or a Postgres array literal like {A,B} (a migrated
// TEXT[] column scanned into a string).
func parseRiskFlagsText(raw string) []string {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "", raw == "[]", raw == "{}":
		return nil
	case strings.HasPrefix(raw, "["):
		var flags []string
		_ = json.Unmarshal([]byte(raw), &flags) // best-effort: malformed stored JSON yields no flags
		return flags
	case strings.HasPrefix(raw, "{"):
		var flags []string
		for _, f := range strings.Split(strings.Trim(raw, "{}"), ",") {
			if f = strings.Trim(strings.TrimSpace(f), `"`); f != "" {
				flags = append(flags, f)
			}
		}
		return flags
	}
	return nil
}

// certFlagFindings returns the flags of a certificate that count as findings
// (scanner.FindingCertFlags), in stored order.
func certFlagFindings(flags []string) []string {
	var out []string
	for _, f := range flags {
		if slices.Contains(scanner.FindingCertFlags, f) {
			out = append(out, f)
		}
	}
	return out
}

// markRiskyEndpoints sets Risky on a page of endpoints whose MappedCerts and
// Issues are loaded.
func markRiskyEndpoints(eps []DiscoveryEndpoint) {
	for i := range eps {
		// The listing's SQL score is the bare certificate maximum; the mapped
		// certs already carry the endpoint-adjusted score.
		for _, mc := range eps[i].MappedCerts {
			eps[i].RiskScore = max(eps[i].RiskScore, mc.RiskScore)
		}
		eps[i].RiskScore = max(eps[i].RiskScore, scanner.EndpointFindingsScore(eps[i].Issues))
		eps[i].Risky = endpointIsRisky(eps[i])
	}
}
