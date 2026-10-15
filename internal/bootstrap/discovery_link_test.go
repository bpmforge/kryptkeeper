// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/discovery/scanner"
)

// pgq rewrites the ?-placeholders of a sqlite statement into $n for Postgres.
func pgq(postgres bool, q string) string {
	if !postgres {
		return q
	}
	n := 0
	var b strings.Builder
	for _, r := range q {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestPerEndpointCertificateState(t *testing.T) {
	db := setupIntegrationDB(t)
	store := migratedDiscoveryStore(t, db)
	runPerEndpointCase(t, db, false, store, func(f func() (*x509.CertPool, error)) { store.trust.systemRoots = f })
}

// Postgres twin on the real migrated schema (native BOOLEAN link columns).
func TestPerEndpointCertificateState_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres integration test")
	}
	freshPostgresForTest(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	store := &postgresDiscoveryStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("discovery EnsureSchema on migrated db: %v", err)
	}
	runPerEndpointCase(t, db, true, store, func(f func() (*x509.CertPool, error)) { store.trust.systemRoots = f })
}

// One certificate on several endpoints: hostname match, served-chain
// completeness and the derived flags are facts about each (certificate,
// endpoint) pair, so they must not depend on which endpoint was scanned last,
// and the certificate row must carry only what is true of the certificate.
func runPerEndpointCase(t *testing.T, db *sql.DB, postgres bool, store trustTestStore, setSystem func(func() (*x509.CertPool, error))) {
	t.Helper()
	stubEndpointAudit(t)
	ctx := context.Background()

	hubRoot := trustIssue(t, nil, "Hub Root", true)
	hubInt := trustIssue(t, hubRoot, "Hub Issuing", true)
	// One leaf for the hostname scenario, another for the chain scenario, a
	// third for the managed-on-the-network scenario, so no scenario can mask
	// another through the shared row.
	nameLeaf := trustIssue(t, hubInt, "app.hub.test", false)
	chainLeaf := trustIssue(t, hubInt, "chain.hub.test", false)
	managedLeaf := trustIssue(t, hubInt, "managed.hub.test", false)
	otherRoot := trustIssue(t, nil, "Other Root", true)
	otherLeaf := trustIssue(t, trustIssue(t, otherRoot, "Other Issuing", true), "svc.other.test", false)

	setSystem(func() (*x509.CertPool, error) { return x509.NewCertPool(), nil })
	store.SetHubCASource(func(context.Context) ([]*x509.Certificate, error) {
		return []*x509.Certificate{hubRoot.cert, hubInt.cert}, nil
	})

	type linkRow struct {
		flags    string
		score    int
		complete sql.NullBool
	}
	link := func(c *x509.Certificate, host string) linkRow {
		t.Helper()
		var l linkRow
		err := db.QueryRow(pgq(postgres, `SELECT ce.endpoint_flags, ce.endpoint_risk_score, ce.chain_complete
FROM certificate_endpoints ce JOIN endpoints e ON e.id = ce.endpoint_id
WHERE ce.certificate_fingerprint = ? AND e.ip_address = ?`), fingerprintOf(c), host).Scan(&l.flags, &l.score, &l.complete)
		if err != nil {
			t.Fatalf("link %s@%s: %v", c.Subject.CommonName, host, err)
		}
		return l
	}
	certRow := func(c *x509.Certificate) (flags string, score int) {
		t.Helper()
		col := "risk_flags"
		if postgres {
			col = "risk_flags::text"
		}
		if err := db.QueryRow(pgq(postgres, `SELECT `+col+`, risk_score FROM certificates WHERE fingerprint_sha256 = ?`), fingerprintOf(c)).Scan(&flags, &score); err != nil {
			t.Fatalf("cert row %s: %v", c.Subject.CommonName, err)
		}
		return flags, score
	}
	scan := func(eps ...scanner.DiscoveredEndpoint) {
		t.Helper()
		if _, err := store.upsertScanResults(ctx, eps); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	mappedFor := func(host string) map[string]DiscoveryMappedCert {
		t.Helper()
		res, err := store.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, ep := range res.Endpoints {
			if ep.Hostname == host {
				m := map[string]DiscoveryMappedCert{}
				for _, mc := range ep.MappedCerts {
					m[mc.Fingerprint] = mc
				}
				return m
			}
		}
		t.Fatalf("endpoint %s not listed", host)
		return nil
	}
	riskyHosts := func() []string {
		t.Helper()
		res, err := store.ListEndpoints(ctx, DiscoveryEndpointQuery{RiskyOnly: true, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		var hosts []string
		for _, ep := range res.Endpoints {
			hosts = append(hosts, ep.Hostname)
		}
		slices.Sort(hosts)
		return hosts
	}

	// --- hostname: the same certificate under a matching and a wrong name ---
	good, bad := servedEndpoint("app.hub.test", nameLeaf, hubInt), servedEndpoint("alias.hub.test", nameLeaf, hubInt)
	for i, order := range [][]scanner.DiscoveredEndpoint{{good, bad}, {bad, good}, {good, bad}} {
		scan(order...)
		if l := link(nameLeaf.cert, "app.hub.test"); strings.Contains(l.flags, "HOSTNAME_MISMATCH") || l.score != 0 {
			t.Fatalf("order %d: matching endpoint carries a mismatch: %+v", i, l)
		}
		if l := link(nameLeaf.cert, "alias.hub.test"); !strings.Contains(l.flags, "HOSTNAME_MISMATCH") || l.score != scanner.EndpointFlagScore("HOSTNAME_MISMATCH") {
			t.Fatalf("order %d: wrong-name endpoint lost its mismatch: %+v", i, l)
		}
		if flags, _ := certRow(nameLeaf.cert); strings.Contains(flags, "HOSTNAME_MISMATCH") {
			t.Fatalf("order %d: the certificate row carries an endpoint flag: %s", i, flags)
		}
	}
	okMapped, badMapped := mappedFor("app.hub.test")[fingerprintOf(nameLeaf.cert)], mappedFor("alias.hub.test")[fingerprintOf(nameLeaf.cert)]
	if slices.Contains(okMapped.RiskFlags, "HOSTNAME_MISMATCH") || !slices.Contains(badMapped.RiskFlags, "HOSTNAME_MISMATCH") || badMapped.RiskScore != okMapped.RiskScore+20 {
		t.Fatalf("mapped certs must carry per-endpoint flags/score: ok=%+v bad=%+v", okMapped, badMapped)
	}
	// Policy: a mismatch makes THAT endpoint risky, and only that one.
	if got := riskyHosts(); !slices.Equal(got, []string{"alias.hub.test"}) {
		t.Fatalf("risky endpoints = %v, want only the wrong-name endpoint", got)
	}
	// The findings funnel counts the mismatch once, on the endpoint it applies to.
	findings, err := store.ListEndpointFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mismatches := 0
	for _, f := range findings {
		for _, issue := range f.Issues {
			if issue == "HOSTNAME_MISMATCH" {
				mismatches++
			}
		}
	}
	if mismatches != 1 {
		t.Fatalf("HOSTNAME_MISMATCH findings = %d, want 1 (only alias.hub.test)", mismatches)
	}

	// --- chain: served with its intermediate on one endpoint, alone on another ---
	withInt, alone := servedEndpoint("192.0.2.10", chainLeaf, hubInt), servedEndpoint("192.0.2.11", chainLeaf)
	for i, order := range [][]scanner.DiscoveredEndpoint{{withInt, alone}, {alone, withInt}} {
		scan(order...)
		l1, l2 := link(chainLeaf.cert, "192.0.2.10"), link(chainLeaf.cert, "192.0.2.11")
		if !l1.complete.Valid || !l1.complete.Bool || strings.Contains(l1.flags, "INCOMPLETE_CHAIN") {
			t.Fatalf("order %d: leaf served with its intermediate must be complete: %+v", i, l1)
		}
		if !l2.complete.Valid || l2.complete.Bool || !strings.Contains(l2.flags, "INCOMPLETE_CHAIN") {
			t.Fatalf("order %d: leaf served alone must be incomplete on that endpoint only: %+v", i, l2)
		}
		if flags, _ := certRow(chainLeaf.cert); strings.Contains(flags, "INCOMPLETE_CHAIN") {
			t.Fatalf("order %d: certificate row carries INCOMPLETE_CHAIN: %s", i, flags)
		}
	}
	if c := mappedFor("192.0.2.10")[fingerprintOf(chainLeaf.cert)]; c.ChainComplete == nil || !*c.ChainComplete {
		t.Fatalf("mapped chain_complete for the complete endpoint = %v", c.ChainComplete)
	}
	if c := mappedFor("192.0.2.11")[fingerprintOf(chainLeaf.cert)]; c.ChainComplete == nil || *c.ChainComplete {
		t.Fatalf("mapped chain_complete for the incomplete endpoint = %v", c.ChainComplete)
	}

	// A private leaf+intermediate whose issuer the hub does not hold cannot be
	// judged: unknown (NULL), and no flag.
	scan(servedEndpoint("192.0.2.12", otherLeaf, trustIssue(t, otherRoot, "Other Issuing 2", true)))
	if l := link(otherLeaf.cert, "192.0.2.12"); l.complete.Valid || strings.Contains(l.flags, "INCOMPLETE_CHAIN") {
		t.Fatalf("an unjudgeable private chain must be unknown, not incomplete: %+v", l)
	}

	// An unclassified sighting of the SAME endpoint (e.g. a WinRM probe) must
	// not erase the chain verdict an earlier TLS scan established there.
	dc := scanner.CertToDiscovered(chainLeaf.cert, "192.0.2.11", true)
	scan(scanner.DiscoveredEndpoint{Host: "192.0.2.11", Port: 443, Protocol: "tls", Certs: []scanner.DiscoveredCert{dc}})
	if l := link(chainLeaf.cert, "192.0.2.11"); !strings.Contains(l.flags, "INCOMPLETE_CHAIN") || !l.complete.Valid || l.complete.Bool {
		t.Fatalf("unclassified sighting erased the endpoint's chain verdict: %+v", l)
	}

	// --- a hub-issued cert found on the network ---
	scan(servedEndpoint("192.0.2.20", managedLeaf, hubInt), servedEndpoint("192.0.2.21", managedLeaf, hubInt))
	if _, err := db.Exec(pgq(postgres, `UPDATE certificates SET management_state = 'managed' WHERE fingerprint_sha256 = ?`), fingerprintOf(managedLeaf.cert)); err != nil {
		t.Fatal(err)
	}
	scan(servedEndpoint("192.0.2.20", managedLeaf, hubInt), servedEndpoint("192.0.2.21", managedLeaf, hubInt)) // a rescan must not disturb it
	for _, host := range []string{"192.0.2.20", "192.0.2.21"} {
		if mc := mappedFor(host)[fingerprintOf(managedLeaf.cert)]; mc.TrustClass != "managed" {
			t.Fatalf("%s: managed cert mapped with trust_class %q, want managed", host, mc.TrustClass)
		}
	}
	sum, err := store.GetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.TrustClasses.Managed != 3 { // nameLeaf, chainLeaf, managedLeaf: each counted once however many endpoints serve it
		t.Errorf("managed = %d, want 3 distinct certificates (not one per endpoint)", sum.TrustClasses.Managed)
	}
	tc := sum.TrustClasses
	if total := tc.Managed + tc.Public + tc.PrivateOther + tc.SelfSigned + tc.Unknown; total != sum.MappedCertificates {
		t.Errorf("trust breakdown sums to %d, mapped certificates = %d: the strip must equal the distinct certs seen on the network", total, sum.MappedCertificates)
	}
}

func TestEndpointFlagSplit(t *testing.T) {
	certFlags, epFlags, score := scanner.SplitEndpointFlags([]string{"EXPIRED", "HOSTNAME_MISMATCH", "PQC_VULNERABLE", "INCOMPLETE_CHAIN", "HOSTNAME_MISMATCH"})
	if !slices.Equal(certFlags, []string{"EXPIRED", "PQC_VULNERABLE"}) || !slices.Equal(epFlags, []string{"HOSTNAME_MISMATCH", "INCOMPLETE_CHAIN"}) || score != 35 {
		t.Fatalf("split = %v / %v / %d", certFlags, epFlags, score)
	}
	// A pre-link row still carrying an endpoint flag must not leak it through
	// the certificate-level view.
	if got := mergeLinkFlags([]string{"EXPIRED", "HOSTNAME_MISMATCH"}, nil); !slices.Equal(got, []string{"EXPIRED"}) {
		t.Fatalf("legacy endpoint flag leaked: %v", got)
	}
}
