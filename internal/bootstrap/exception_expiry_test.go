// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

type fakeExpiryChannel struct {
	name string
	mu   sync.Mutex
	sent []delivery.Event
}

func (c *fakeExpiryChannel) Name() string { return c.name }
func (c *fakeExpiryChannel) Send(_ context.Context, ev delivery.Event) error {
	c.mu.Lock()
	c.sent = append(c.sent, ev)
	c.mu.Unlock()
	return nil
}

var expiryT0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func seedException(t *testing.T, s FindingExceptionStore, id, fp, code string, expires time.Time) {
	t.Helper()
	if err := s.Create(context.Background(), FindingException{
		ID: id, TargetType: FindingExceptionTargetCertificate, TargetID: fp, FindingCode: code,
		JustificationCode: JustificationRiskAccepted, CreatedBy: "alice",
		CreatedAt: expiryT0.Add(-24 * time.Hour).Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
}

func newExpiryScanner(t *testing.T) (*ExceptionExpiryScanner, *sqliteFindingExceptionStore, *fakeExpiryChannel, *expiryAudit) {
	t.Helper()
	store := newFreshFindingExceptionStore(t)
	if err := store.EnsureTenantSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	ch := &fakeExpiryChannel{name: "email"}
	audit := &expiryAudit{}
	certs := exceptionCerts{reportCertProvider: &reportCertProvider{}, byFP: map[string]CertificateItem{
		"fp-owned":  {FingerprintSHA256: "fp-owned", OwnerTeam: "payments", OwnerEmail: "pay@example.com"},
		"fp-orphan": {FingerprintSHA256: "fp-orphan"},
	}}
	s := NewExceptionExpiryScannerFromEnv(store, certs, audit, ch, "ops@example.com")
	s.haCoordinator = nil // single replica; HA is covered by ClaimEvent
	return s, store, ch, audit
}

func TestWarnsOnceAt14Days(t *testing.T) {
	s, store, ch, _ := newExpiryScanner(t)
	seedException(t, store, "exc-a", "fp-owned", "WEAK_RSA_KEY", expiryT0.Add(14*24*time.Hour))
	seedException(t, store, "exc-b", "fp-owned", "SAN_SPRAWL", expiryT0.Add(15*24*time.Hour))
	seedException(t, store, "exc-c", "fp-orphan", "NO_SAN", expiryT0.Add(10*24*time.Hour))
	ctx := context.Background()

	s.tick(ctx, expiryT0)
	if len(ch.sent) != 2 {
		t.Fatalf("sent %d events, want 2 (exc-a and exc-c): %+v", len(ch.sent), ch.sent)
	}
	byID := map[string]delivery.Event{}
	for _, ev := range ch.sent {
		byID[ev.ID] = ev
	}
	a := byID["exception-expiring-exc-a"]
	if a.Target != "pay@example.com" || a.Priority != "medium" || a.Subject != "exception.expiring: WEAK_RSA_KEY on fp-owned" {
		t.Fatalf("owner warning = %+v", a)
	}
	if c := byID["exception-expiring-exc-c"]; c.Target != "ops@example.com" {
		t.Fatalf("unowned warning must go to the fallback target: %+v", c)
	}

	s.tick(ctx, expiryT0.Add(time.Hour))
	if len(ch.sent) != 2 {
		t.Fatalf("repeat warning sent: %d", len(ch.sent))
	}
	// exc-b enters the window one day later and is warned then, once.
	s.tick(ctx, expiryT0.Add(24*time.Hour))
	if len(ch.sent) != 3 {
		t.Fatalf("exc-b not warned at T+1d: %d", len(ch.sent))
	}
	s.tick(ctx, expiryT0.Add(25*time.Hour))
	if len(ch.sent) != 3 {
		t.Fatalf("exc-b warned twice: %d", len(ch.sent))
	}
}

func TestWarnFallbackForNonEmailChannel(t *testing.T) {
	s, store, ch, _ := newExpiryScanner(t)
	ch.name = "slack"
	seedException(t, store, "exc-a", "fp-owned", "WEAK_RSA_KEY", expiryT0.Add(5*24*time.Hour))
	s.tick(context.Background(), expiryT0)
	if len(ch.sent) != 1 || ch.sent[0].Target != "ops@example.com" {
		t.Fatalf("sent = %+v", ch.sent)
	}
}

func TestExpireAuditedOnce(t *testing.T) {
	s, store, _, audit := newExpiryScanner(t)
	exp := expiryT0.Add(24 * time.Hour)
	seedException(t, store, "exc-a", "fp-owned", "WEAK_RSA_KEY", exp)
	ctx := context.Background()

	s.tick(ctx, exp.Add(-time.Minute))
	if audit.count("exception.expire", AuditOutcomeSuccess) != 0 {
		t.Fatal("expire audited before expiry")
	}
	s.tick(ctx, exp.Add(time.Second))
	s.tick(ctx, exp.Add(time.Hour))
	if n := audit.count("exception.expire", AuditOutcomeSuccess); n != 1 {
		t.Fatalf("exception.expire rows = %d, want 1", n)
	}
	e, _ := audit.find("exception.expire")
	if e.ActorType != "system" || e.ActorID != "exception-expiry-scanner" || e.ResourceID != "exc-a" {
		t.Fatalf("audit row = %+v", e)
	}
	// The lapsed row is kept: the evidence pack and audit history need it.
	if _, err := store.Get(ctx, "exc-a"); err != nil {
		t.Fatalf("lapsed exception was removed: %v", err)
	}
}

func TestExpireAuditCarriesExceptionTenant(t *testing.T) {
	s, store, _, audit := newExpiryScanner(t)
	exp := expiryT0.Add(time.Hour)
	exc := FindingException{ID: "exc-t", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-owned", FindingCode: "X",
		JustificationCode: JustificationRiskAccepted, CreatedBy: "alice", CreatedAt: expiryT0.Format(time.RFC3339), ExpiresAt: exp.Format(time.RFC3339)}
	if err := store.CreateWithTenant(context.Background(), exc, "acme"); err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), exp.Add(time.Minute))
	if e, ok := audit.find("exception.expire"); !ok || e.Tenant != "acme" {
		t.Fatalf("audit = %+v ok=%v", e, ok)
	}
}

func TestLapsedExceptionCountsAgain(t *testing.T) {
	store := newFreshFindingExceptionStore(t)
	exp := expiryT0.Add(24 * time.Hour)
	seedException(t, store, "exc-a", "fp-weak", "WEAK_RSA_KEY", exp)
	seedException(t, store, "exc-d", "fp-ep", "TLS10", exp)
	ctx := context.Background()
	endpoints := []discoveryEndpointFindings{{Issues: []string{"TLS10"}, CertFingerprints: []string{"fp-ep"}}}

	before, _ := store.ListActive(ctx, exp.Add(-time.Minute))
	if r := computeCryptoPostureReport(findingFunnelTestCerts(), before); r.Findings.Suppressed != 1 {
		t.Fatalf("posture suppressed before expiry = %d", r.Findings.Suppressed)
	}
	if f := computeDiscoveryFindingFunnel(endpoints, before); f.Suppressed != 1 {
		t.Fatalf("discovery suppressed before expiry = %d", f.Suppressed)
	}
	after, _ := store.ListActive(ctx, exp)
	if r := computeCryptoPostureReport(findingFunnelTestCerts(), after); r.Findings.Suppressed != 0 || r.Findings.Effective != r.Findings.Raw {
		t.Fatalf("posture after expiry: %+v", r.Findings)
	}
	if f := computeDiscoveryFindingFunnel(endpoints, after); f.Suppressed != 0 || f.Effective != 1 {
		t.Fatalf("discovery after expiry: %+v", f)
	}
}

func TestReissueCountsAgain(t *testing.T) {
	store := newFreshFindingExceptionStore(t)
	seedException(t, store, "exc-a", "fp-A", "WEAK_RSA_KEY", expiryT0.Add(30*24*time.Hour))
	active, _ := store.ListActive(context.Background(), expiryT0)
	// fp-B is the renewed certificate: a new fingerprint carrying the same flag.
	certs := []CertificateItem{
		{FingerprintSHA256: "fp-A", RiskFlags: []string{"WEAK_RSA_KEY"}},
		{FingerprintSHA256: "fp-B", RiskFlags: []string{"WEAK_RSA_KEY"}},
	}
	r := computeCryptoPostureReport(certs, active)
	if r.Findings.Raw != 2 || r.Findings.Suppressed != 1 || r.Findings.Effective != 1 {
		t.Fatalf("funnel = %+v; the re-issued certificate must still count", r.Findings)
	}
	eps := []discoveryEndpointFindings{{Issues: []string{"WEAK_RSA_KEY"}, CertFingerprints: []string{"fp-B"}}}
	if f := computeDiscoveryFindingFunnel(eps, active); f.Suppressed != 0 {
		t.Fatalf("discovery suppressed the re-issued certificate: %+v", f)
	}
}

func claimEventContract(t *testing.T, s findingExceptionLifecycleStore) {
	t.Helper()
	ctx := context.Background()
	if err := s.EnsureLifecycleSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureLifecycleSchema(ctx); err != nil {
		t.Fatalf("EnsureLifecycleSchema must be idempotent: %v", err)
	}
	now := time.Now()
	for _, tc := range []struct {
		id, kind string
		want     bool
	}{
		{"exc-1", exceptionEventExpiring, true},
		{"exc-1", exceptionEventExpiring, false},
		{"exc-1", exceptionEventExpired, true},
		{"exc-2", exceptionEventExpiring, true},
		{"exc-1", exceptionEventExpired, false},
	} {
		got, err := s.ClaimEvent(ctx, tc.id, tc.kind, now)
		if err != nil || got != tc.want {
			t.Fatalf("ClaimEvent(%s,%s) = %v, %v; want %v", tc.id, tc.kind, got, err, tc.want)
		}
	}
	if _, err := s.ClaimEvent(ctx, "exc-3", "bogus", now); err == nil {
		t.Fatal("unknown kind must be rejected by the CHECK")
	}
}

func TestClaimEventIdempotentSQLite(t *testing.T) {
	claimEventContract(t, newFreshFindingExceptionStore(t))
}

func TestClaimEventIdempotentPostgres(t *testing.T) {
	migratedPostgresForTest(t)
	s, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ls, ok := s.(findingExceptionLifecycleStore)
	if !ok {
		t.Fatal("postgres store lacks lifecycle support")
	}
	claimEventContract(t, ls)
}

func TestListAllIncludesLapsed(t *testing.T) {
	store := newFreshFindingExceptionStore(t)
	seedException(t, store, "exc-old", "fp-1", "A", expiryT0.Add(-time.Hour))
	seedException(t, store, "exc-new", "fp-1", "B", expiryT0.Add(time.Hour))
	all, err := store.ListAll(context.Background())
	if err != nil || len(all) != 2 {
		t.Fatalf("ListAll = %+v %v", all, err)
	}
	if act, _ := store.ListActive(context.Background(), expiryT0); len(act) != 1 {
		t.Fatalf("ListActive = %d", len(act))
	}
}

func TestScannerDisabledWithoutLifecycleStore(t *testing.T) {
	s := NewExceptionExpiryScannerFromEnv(noLifecycleStore{}, nil, &expiryAudit{}, nil, "")
	s.tick(context.Background(), expiryT0) // must not panic
}

type noLifecycleStore struct{ FindingExceptionStore }

// An exception created in one tenant must not suppress another tenant's
// finding on the same certificate fingerprint (discovery endpoints are
// per-tenant rows).
func TestExceptionDoesNotSuppressOtherTenantsFinding(t *testing.T) {
	exc := []FindingException{{ID: "e1", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", FindingCode: "WEAK_KEY", Tenant: "acme"}}
	eps := []discoveryEndpointFindings{
		{Tenant: "acme", Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
		{Tenant: "globex", Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
		{Tenant: "", Issues: []string{"WEAK_KEY"}, CertFingerprints: []string{"fp-a"}},
	}
	got := computeDiscoveryFindingFunnel(eps, exc)
	if got.Raw != 3 || got.Suppressed != 1 || got.Effective != 2 {
		t.Fatalf("funnel = %+v; only acme's finding may be suppressed", got)
	}
	// Default-tenant stamp ("default") matches default-tenant endpoints ("").
	def := []FindingException{{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", FindingCode: "WEAK_KEY", Tenant: DefaultTenant}}
	if g := computeDiscoveryFindingFunnel(eps, def); g.Suppressed != 1 {
		t.Fatalf("default-tenant exception: %+v", g)
	}
}

func TestActiveFindingExceptionsCarryTenantStamp(t *testing.T) {
	store := newFreshFindingExceptionStore(t)
	exc := FindingException{ID: "e1", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", FindingCode: "X",
		JustificationCode: JustificationRiskAccepted, CreatedBy: "a", CreatedAt: expiryT0.Format(time.RFC3339), ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}
	if err := store.EnsureTenantSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWithTenant(context.Background(), exc, "acme"); err != nil {
		t.Fatal(err)
	}
	got := activeFindingExceptions(context.Background(), store)
	if len(got) != 1 || got[0].Tenant != "acme" {
		t.Fatalf("active = %+v", got)
	}
}
