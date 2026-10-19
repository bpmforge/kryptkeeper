// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestFindingIdentityStore(t *testing.T) *sqlFindingIdentityStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "finding-identities.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqlFindingIdentityStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Idempotent: the self-heal runs on every start.
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema not idempotent: %v", err)
	}
	return s
}

func TestIdentityStableAcrossThreeScans(t *testing.T) {
	s := newTestFindingIdentityStore(t)
	ctx := context.Background()
	key := FindingKey{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", Code: "WEAK_RSA_KEY"}
	id := key.id()

	exc := FindingException{TargetType: key.TargetType, TargetID: key.TargetID, FindingCode: key.Code}
	if exc.IdentityID(key.Tenant) != id {
		t.Fatalf("exception identity %q != finding identity %q", exc.IdentityID(key.Tenant), id)
	}
	idx := findingExceptionIndex([]FindingException{exc})

	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, at := range []time.Time{t0, t0.Add(2 * time.Hour), t0.Add(4 * time.Hour)} {
		if err := s.Observe(ctx, []FindingKey{key}, at); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		if !idx[findingExceptionKey(key.TargetType, key.TargetID, key.Code)] {
			t.Fatalf("scan %d: the one exception no longer matches the finding", i)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM finding_identities`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d (err %v), want 1", n, err)
	}
	got, ok, err := s.Get(ctx, id)
	if err != nil || !ok {
		t.Fatalf("get: %v %v", ok, err)
	}
	if got.FirstSeen != t0.Format(time.RFC3339) {
		t.Errorf("first_seen moved to %s", got.FirstSeen)
	}
	if got.LastSeen != t0.Add(4*time.Hour).Format(time.RFC3339) {
		t.Errorf("last_seen = %s, want the third scan", got.LastSeen)
	}
}

func TestObserveThrottle(t *testing.T) {
	s := newTestFindingIdentityStore(t)
	ctx := context.Background()
	key := FindingKey{TargetType: "certificate", TargetID: "fp-a", Code: "SAN_SPRAWL"}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	_ = s.Observe(ctx, []FindingKey{key}, t0)
	_ = s.Observe(ctx, []FindingKey{key}, t0.Add(30*time.Minute))
	got, _, _ := s.Get(ctx, key.id())
	if got.LastSeen != t0.Format(time.RFC3339) {
		t.Fatalf("last_seen bumped inside the throttle window: %s", got.LastSeen)
	}
	_ = s.Observe(ctx, []FindingKey{key}, t0.Add(61*time.Minute))
	got, _, _ = s.Get(ctx, key.id())
	if got.LastSeen != t0.Add(61*time.Minute).Format(time.RFC3339) {
		t.Fatalf("last_seen not bumped after the window: %s", got.LastSeen)
	}
}

func TestIdentityIncludesTenant(t *testing.T) {
	a := FindingIdentityID("acme", "certificate", "fp", "X")
	b := FindingIdentityID("globex", "certificate", "fp", "X")
	if a == b || !strings.HasPrefix(a, "fnd-") || len(a) != len("fnd-")+32 {
		t.Fatalf("tenant must separate identities: %s %s", a, b)
	}
	s := newTestFindingIdentityStore(t)
	ctx := context.Background()
	t0 := time.Now()
	_ = s.Observe(ctx, []FindingKey{{"acme", "certificate", "fp", "X"}, {"globex", "certificate", "fp", "X"}}, t0)
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM finding_identities`).Scan(&n)
	if n != 2 {
		t.Fatalf("two tenants, same cert flaw: rows = %d, want 2", n)
	}
	got, ok, _ := s.Get(ctx, a)
	if !ok || got.Tenant != "acme" {
		t.Fatalf("tenant not persisted: %+v", got)
	}
}

func TestFunnelBuilderStages(t *testing.T) {
	b := newFunnelBuilder()
	b.Add("", "certificate", "fp-a", "X", false)
	b.Add("", "certificate", "fp-a", "X", false) // repeat
	b.Add("", "certificate", "fp-a", "Y", true)
	b.Add("", "certificate", "fp-b", "X", false)
	b.Add("", "certificate", "fp-b", "X", false) // repeat
	got := b.Summary()
	want := FindingFunnelSummary{Raw: 5, Deduped: 3, InScope: 3, Effective: 2, Suppressed: 1}
	if got != want {
		t.Fatalf("funnel = %+v, want %+v", got, want)
	}
	if !(got.Raw >= got.Deduped && got.Deduped >= got.InScope && got.InScope >= got.Effective) || got.Effective+got.Suppressed != got.InScope {
		t.Fatalf("invariants broken: %+v", got)
	}
	if len(b.Identities()) != 3 {
		t.Fatalf("identities = %d, want 3", len(b.Identities()))
	}
}

func TestDiscoveryDuplicateEndpointsCollapse(t *testing.T) {
	eps := []discoveryEndpointFindings{
		{Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
		{Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
		{Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-z", "fp-a"}}, // smallest fp wins
	}
	got := computeDiscoveryFindingFunnel(eps, nil)
	if got.Raw != 3 || got.Deduped != 1 || got.Effective != 1 {
		t.Fatalf("funnel = %+v, want raw 3 deduped 1", got)
	}
	// Endpoints that present no certificate are never merged.
	got = computeDiscoveryFindingFunnel([]discoveryEndpointFindings{
		{Issues: []string{"TLS10"}}, {Issues: []string{"TLS10"}},
	}, nil)
	if got.Raw != 2 || got.Deduped != 2 {
		t.Fatalf("certless endpoints merged: %+v", got)
	}
}

// Two tenants that each serve the same flawed certificate are two findings.
func TestDiscoveryFunnelKeepsTenantsApart(t *testing.T) {
	eps := []discoveryEndpointFindings{
		{Tenant: "acme", Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
		{Tenant: "globex", Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
	}
	b := discoveryFindingFunnel(eps, nil)
	if s := b.Summary(); s.Raw != 2 || s.Deduped != 2 {
		t.Fatalf("funnel = %+v, want deduped 2", s)
	}
	keys := b.Identities()
	if len(keys) != 2 || keys[0].Tenant == keys[1].Tenant {
		t.Fatalf("identities = %+v", keys)
	}
}

func TestDiscoverySuppressionStillCollapses(t *testing.T) {
	eps := []discoveryEndpointFindings{
		{Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
		{Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
	}
	exc := []FindingException{{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", FindingCode: "WEAK_KEY"}}
	got := computeDiscoveryFindingFunnel(eps, exc)
	want := FindingFunnelSummary{Raw: 2, Deduped: 1, InScope: 1, Effective: 0, Suppressed: 1}
	if got != want {
		t.Fatalf("funnel = %+v, want %+v", got, want)
	}
}

func TestPostureFunnelFiveStages(t *testing.T) {
	certs := []CertificateItem{
		{FingerprintSHA256: "fp-1", RiskFlags: []string{"WEAK_RSA_KEY", "WEAK_RSA_KEY", "SAN_SPRAWL"}},
		{FingerprintSHA256: "fp-2", RiskFlags: []string{"WEAK_RSA_KEY"}},
	}
	exc := []FindingException{{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-2", FindingCode: "WEAK_RSA_KEY"}}
	report := computeCryptoPostureReport(certs, exc)
	want := FindingFunnelSummary{Raw: 4, Deduped: 3, InScope: 3, Effective: 2, Suppressed: 1}
	if report.Findings != want {
		t.Fatalf("funnel = %+v, want %+v", report.Findings, want)
	}
	if len(report.findingKeys) != 3 {
		t.Fatalf("findingKeys = %d, want 3", len(report.findingKeys))
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Findings map[string]int `json:"findings"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"raw", "deduped", "in_scope", "effective", "suppressed"} {
		if _, ok := wire.Findings[field]; !ok {
			t.Errorf("response findings lacks %q: %s", field, raw)
		}
	}
	if strings.Contains(string(raw), "findingKeys") {
		t.Error("finding keys leaked onto the wire")
	}
}

func TestObserveFindingIdentitiesIsBestEffort(t *testing.T) {
	observeFindingIdentities(context.Background(), nil, []FindingKey{{TargetType: "certificate"}}) // nil store: no panic
	s := newTestFindingIdentityStore(t)
	s.db.Close()
	observeFindingIdentities(context.Background(), s, []FindingKey{{TargetType: "certificate", TargetID: "x", Code: "y"}}) // error swallowed
}

// GetSummary is the discovery observation point: after a summary read the
// funnel's identities are persisted, and a second read adds none.
func TestDiscoverySummaryPersistsIdentities(t *testing.T) {
	db := setupDiscoveryTestDB(t)
	if _, err := db.Exec(`UPDATE endpoints SET issues = '["Weak cipher: RC4"]', tenant = 'acme' WHERE id = 'ep-2'`); err != nil {
		t.Fatal(err)
	}
	ids := newTestFindingIdentityStore(t)
	p := &dbDiscoveryProvider{store: &sqliteDiscoveryStore{db: db}, findingIdentityStore: ids}
	for i := 0; i < 2; i++ {
		sum, err := p.GetSummary(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if sum.Findings.Raw == 0 || sum.Findings.Deduped == 0 {
			t.Fatalf("scan %d: funnel = %+v", i, sum.Findings)
		}
	}
	var n int
	var tenant string
	if err := ids.db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(tenant),'') FROM finding_identities WHERE finding_code = 'Weak cipher: RC4'`).Scan(&n, &tenant); err != nil {
		t.Fatal(err)
	}
	if n != 1 || tenant != "acme" {
		t.Fatalf("persisted rows = %d tenant %q, want 1 acme", n, tenant)
	}
}
