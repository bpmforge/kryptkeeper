// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"slices"
	"testing"

	"kryptkeeper/internal/discovery/scanner"
)

func flaggedCert(fp string, score int, flags ...string) scanner.DiscoveredCert {
	c := testDiscoveredCert(fp, score)
	c.RiskFlags = flags
	// A chain flag only reaches the link from a classified chain, as in
	// production where ApplyTrust sets both together.
	if slices.Contains(flags, scanner.FlagUntrustedRoot) || slices.Contains(flags, scanner.FlagIncompleteChain) {
		c.Served, c.TrustClass = true, scanner.TrustPrivateOther
	}
	return c
}

// seedRiskCases covers the cases from the lab: certs scored 60 or less that
// are expired, self-signed or weakly signed used to be hidden from "Risky
// only", and the Findings widget stayed at 0.
func seedRiskCases(t *testing.T, s *sqliteDiscoveryStore) map[string]bool {
	t.Helper()
	cases := []struct {
		host  string
		ep    scanner.DiscoveredEndpoint
		risky bool
	}{
		{"selfsigned.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-ss", 40, "SELF_SIGNED", "PQC_VULNERABLE")}}, true},
		{"expired.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-exp", 50, "EXPIRED", "PQC_VULNERABLE")}}, true},
		{"weakkey.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-wk", 40, "WEAK_KEY")}}, true},
		{"weaksig.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-ws", 60, "WEAK_SIGNATURE", "PQC_VULNERABLE")}}, true},
		{"untrusted.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-ur", 30, "UNTRUSTED_ROOT")}}, true},
		{"highscore.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-hs", 80, "HOSTNAME_MISMATCH")}}, true},
		{"nottls.test", scanner.DiscoveredEndpoint{Reachable: true, Error: "not a TLS service", Findings: []string{"NOT_TLS: plain"}}, true},
		{"oldtls.test", scanner.DiscoveredEndpoint{Reachable: true, Findings: []string{"DEPRECATED_TLS_VERSION: TLSv1.0"}}, true},
		// A cert served under a name it does not vouch for makes THAT endpoint
		// risky (owner policy), even when the score alone would not.
		{"mismatch.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-hm", 30, "HOSTNAME_MISMATCH")}}, true},
		// Not risky: a healthy cert (the informational PQC flag only), an
		// expiring-soon one, and an incomplete chain alone. A failed handshake
		// on an open port IS risky (same rule as NOT_TLS).
		{"healthy.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-ok", 10, "PQC_VULNERABLE")}}, false},
		{"expiring.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-ex30", 25, "EXPIRING_30_DAYS")}}, false},
		{"incomplete.test", scanner.DiscoveredEndpoint{Certs: []scanner.DiscoveredCert{flaggedCert("fp-ic", 25, "INCOMPLETE_CHAIN")}}, false},
		{"hsfail.test", scanner.DiscoveredEndpoint{Reachable: true, Error: "tls handshake: EOF", Findings: []string{"TLS_HANDSHAKE_FAILED: EOF"}}, true},
		{"pgplain.test", scanner.DiscoveredEndpoint{Reachable: true, Error: "server does not offer TLS", Findings: []string{"POSTGRES_TLS_DISABLED: x"}}, true},
	}
	want := map[string]bool{}
	var results []scanner.DiscoveredEndpoint
	for _, c := range cases {
		c.ep.Host, c.ep.Port, c.ep.Protocol = c.host, 443, "https"
		results = append(results, c.ep)
		want[c.host] = c.risky
	}
	if _, err := s.upsertScanResults(context.Background(), results); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return want
}

func TestRiskyRuleIsOneRuleAcrossSummaryFilterAndEndpointField(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	ctx := context.Background()
	want := seedRiskCases(t, s)
	wantRisky := 0
	for _, r := range want {
		if r {
			wantRisky++
		}
	}

	summary, err := s.GetSummary(ctx)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.RiskyEndpoints != wantRisky {
		t.Errorf("summary risky_endpoints = %d, want %d (the dashboard reads this)", summary.RiskyEndpoints, wantRisky)
	}

	filtered, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{RiskyOnly: true, Limit: 100})
	if err != nil {
		t.Fatalf("ListEndpoints risky: %v", err)
	}
	if filtered.Total != wantRisky {
		t.Errorf("risky_only total = %d, want %d", filtered.Total, wantRisky)
	}
	all, err := s.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	inFilter := map[string]bool{}
	for _, ep := range filtered.Endpoints {
		inFilter[ep.Hostname] = true
	}
	for _, ep := range all.Endpoints {
		if ep.Risky != want[ep.Hostname] {
			t.Errorf("%s: risky field = %v, want %v (score %d, issues %v)", ep.Hostname, ep.Risky, want[ep.Hostname], ep.RiskScore, ep.Issues)
		}
		if inFilter[ep.Hostname] != ep.Risky {
			t.Errorf("%s: risky_only filter (%v) disagrees with the risky field (%v)", ep.Hostname, inFilter[ep.Hostname], ep.Risky)
		}
	}
}

func TestFindingsFunnelCountsCertificateFlags(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	seedRiskCases(t, s)
	findings, err := s.ListEndpointFindings(context.Background())
	if err != nil {
		t.Fatalf("ListEndpointFindings: %v", err)
	}
	funnel := computeDiscoveryFindingFunnel(findings, nil)
	// 5 high-severity cert flags + HOSTNAME_MISMATCH x2 + EXPIRING_30_DAYS +
	// INCOMPLETE_CHAIN = 9 flag findings (PQC_VULNERABLE is informational and
	// never counted), plus NOT_TLS, DEPRECATED_TLS_VERSION and
	// TLS_HANDSHAKE_FAILED and POSTGRES_TLS_DISABLED.
	if funnel.Raw != 13 || funnel.Effective != 13 {
		t.Fatalf("funnel = %+v, want raw=13: the widget read 0 while flags existed", funnel)
	}

	// An accepted-risk exception on the certificate for that flag suppresses it.
	suppressed := computeDiscoveryFindingFunnel(findings, []FindingException{
		{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-ss", FindingCode: "SELF_SIGNED"},
	})
	if suppressed.Raw != 13 || suppressed.Suppressed != 1 || suppressed.Effective != 12 {
		t.Fatalf("suppressed funnel = %+v, want raw=13 suppressed=1 effective=12", suppressed)
	}
}

func TestParseRiskFlagsTextAcceptsJSONAndPostgresArray(t *testing.T) {
	for in, want := range map[string][]string{
		`["EXPIRED","SELF_SIGNED"]`: {"EXPIRED", "SELF_SIGNED"},
		`{EXPIRED,SELF_SIGNED}`:     {"EXPIRED", "SELF_SIGNED"},
		`{"EXPIRED"}`:               {"EXPIRED"},
		`[]`:                        nil,
		`{}`:                        nil,
		``:                          nil,
	} {
		if got := parseRiskFlagsText(in); !slices.Equal(got, want) {
			t.Errorf("parseRiskFlagsText(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEndpointIsRiskyRule(t *testing.T) {
	cases := map[string]struct {
		ep   DiscoveryEndpoint
		want bool
	}{
		"empty":                   {DiscoveryEndpoint{}, false},
		"score at 70":             {DiscoveryEndpoint{RiskScore: 70}, true},
		"score at 69":             {DiscoveryEndpoint{RiskScore: 69}, false},
		"expired at 40":           {DiscoveryEndpoint{MappedCerts: []DiscoveryMappedCert{{RiskScore: 40, RiskFlags: []string{"EXPIRED"}}}}, true},
		"hostname mismatch alone": {DiscoveryEndpoint{MappedCerts: []DiscoveryMappedCert{{RiskScore: 30, RiskFlags: []string{"HOSTNAME_MISMATCH"}}}}, true},
		"incomplete chain alone":  {DiscoveryEndpoint{MappedCerts: []DiscoveryMappedCert{{RiskScore: 25, RiskFlags: []string{"INCOMPLETE_CHAIN"}}}}, false},
		"pqc only":                {DiscoveryEndpoint{MappedCerts: []DiscoveryMappedCert{{RiskScore: 10, RiskFlags: []string{"PQC_VULNERABLE"}}}}, false},
		"not tls":                 {DiscoveryEndpoint{Issues: []string{"NOT_TLS: x"}}, true},
		"deprecated tls":          {DiscoveryEndpoint{Issues: []string{"DEPRECATED_TLS_VERSION: TLSv1.1"}}, true},
		"handshake failed":        {DiscoveryEndpoint{Issues: []string{"TLS_HANDSHAKE_FAILED: EOF"}}, true},
		"postgres tls disabled":   {DiscoveryEndpoint{Issues: []string{"POSTGRES_TLS_DISABLED: x"}}, true},
		"cipheraudit text":        {DiscoveryEndpoint{Issues: []string{"Weak cipher: RC4"}}, false},
	}
	for name, c := range cases {
		if got := endpointIsRisky(c.ep); got != c.want {
			t.Errorf("%s: endpointIsRisky = %v, want %v", name, got, c.want)
		}
	}
}

func TestOpenPortFindingsScoreNonZero(t *testing.T) {
	s := newFreshDiscoveryStore(t)
	seedRiskCases(t, s)
	all, err := s.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	for _, ep := range all.Endpoints {
		switch ep.Hostname {
		case "nottls.test", "hsfail.test", "pgplain.test":
			if ep.RiskScore != scanner.EndpointFindingScore || !ep.Risky {
				t.Errorf("%s: risk_score=%d risky=%v, want %d/true", ep.Hostname, ep.RiskScore, ep.Risky, scanner.EndpointFindingScore)
			}
		}
	}
}
