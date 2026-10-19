// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/itsm"
)

type failingRenewalRunner struct{ calls int }

func (r *failingRenewalRunner) ExecuteRenewal(context.Context, string, ManagedTarget, RenewalInstallProfile) (RenewalExecuteResult, error) {
	r.calls++
	return RenewalExecuteResult{}, errors.New("install refused")
}

func itsmRows(t *testing.T, svc *itsm.Service, class string) []itsm.EventRow {
	t.Helper()
	all, err := svc.Store().ListEvents(context.Background(), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	var out []itsm.EventRow
	for _, r := range all {
		if r.Class == class {
			out = append(out, r)
		}
	}
	return out
}

func itsmRoutingFixture(t *testing.T) (*itsm.Service, *itsmRoutingProvider) {
	t.Helper()
	svc := newItsmService(t)
	return svc, &itsmRoutingProvider{delivers: true, channel: itsm.Channel{Svc: svc}, rules: []NotificationRule{
		{ID: "r1", Channel: "itsm", Target: "conn-1", Enabled: true, Tenant: "default"},
		{ID: "r2", Channel: "email", Target: "a@b.example", Enabled: true, Tenant: "default"},
		{ID: "r3", Channel: "itsm", Target: "conn-1", Enabled: false, Tenant: "default"},
	}}
}

func TestRenewalFailed_TerminalFailureOpensOneTicketKeyedByFingerprint(t *testing.T) {
	svc, prov := itsmRoutingFixture(t)
	cert := soonCert("fp-fail", "fail.ex.com")
	cert.SerialNumber = "0A1B"
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "fail.ex.com"))
	f.sched.notifProvider = prov
	runner := &failingRenewalRunner{}
	f.sched.WithRenewalRunner(runner)
	pol := retryPolicy{base: time.Minute, retryCap: time.Hour, poll: time.Hour}
	ctx := context.Background()
	now := time.Now().UTC()
	prior := now.Add(-time.Hour)

	// Not the last allowed attempt: no ticket.
	f.sched.tryAutoRenew(ctx, cert, armedTarget("t1", "fail.ex.com"), now, installAttemptState{failures: 1, lastFailure: prior.Add(-48 * time.Hour)}, pol)
	if rows := itsmRows(t, svc, "renewal_failed"); len(rows) != 0 {
		t.Fatalf("non-terminal failure opened a ticket: %+v", rows)
	}

	// Terminal failure, announced twice (retry of the same episode).
	st := installAttemptState{failures: renewalInstallMaxAttempts - 1, lastFailure: prior}
	for i := 0; i < 2; i++ {
		out := f.sched.tryAutoRenew(ctx, cert, armedTarget("t1", "fail.ex.com"), now, st, pol)
		if !out.gaveUp {
			t.Fatalf("attempt %d: want gave up, got %+v", i, out)
		}
	}
	rows := itsmRows(t, svc, "renewal_failed")
	if len(rows) != 1 {
		t.Fatalf("want one ticket for the episode, got %+v", rows)
	}
	if rows[0].Fingerprint != "fp-fail" || !strings.HasPrefix(rows[0].EventID, "renewal_failed:fp-fail:") {
		t.Fatalf("row %+v", rows[0])
	}
	for _, want := range []string{`"cn":"fail.ex.com"`, `"serial":"0A1B"`, `"risk":"high"`, `"not_after":"`} {
		if !strings.Contains(rows[0].Payload, want) {
			t.Errorf("payload missing %s: %s", want, rows[0].Payload)
		}
	}

	// A later failure episode (operator retry) is a new event.
	st.lastFailure = prior.Add(-3 * time.Hour)
	f.sched.tryAutoRenew(ctx, cert, armedTarget("t1", "fail.ex.com"), now, st, pol)
	if rows := itsmRows(t, svc, "renewal_failed"); len(rows) != 2 {
		t.Fatalf("new episode should open its own ticket: %+v", rows)
	}
}

func TestRenewalFailed_SilentWhenProviderDoesNotDeliverOrTenantHidden(t *testing.T) {
	svc, prov := itsmRoutingFixture(t)
	cert := soonCert("fp-q", "q.ex.com")
	prov.delivers = false
	announceRenewalFailed(context.Background(), prov, cert, time.Now(), time.Now())
	if len(prov.delivered) != 0 || len(itsmRows(t, svc, "renewal_failed")) != 0 {
		t.Fatalf("record-only provider announced: %v", prov.delivered)
	}

	prov.delivers = true
	t.Setenv("MULTI_TENANCY", "on")
	tenants := newTestTenantStore(t)
	for _, tn := range []string{"default", "globex"} {
		if _, err := tenants.CreateTenant(context.Background(), tn, tn); err != nil {
			t.Fatal(err)
		}
	}
	if err := tenants.SetCATenant(context.Background(), "ca-1", "globex"); err != nil {
		t.Fatal(err)
	}
	setActiveTenantStore(tenants)
	t.Cleanup(func() { setActiveTenantStore(nil) })
	announceRenewalFailed(context.Background(), prov, cert, time.Now(), time.Now())
	if len(prov.delivered) != 0 {
		t.Fatalf("another tenant's certificate reached a default-tenant connection: %v", prov.delivered)
	}
}

func TestExpiryNoOwner_OncePerCertPerWindow(t *testing.T) {
	svc, prov := itsmRoutingFixture(t)
	orphan := soonCert("fp-orphan", "orphan.ex.com")
	owned := soonCert("fp-owned", "owned.ex.com")
	owned.OwnerEmail = "owner@ex.com"
	teamed := soonCert("fp-teamed", "teamed.ex.com")
	teamed.OwnerTeam = "platform"
	f := newBindingSweepFixture(t, []CertificateItem{orphan, owned, teamed})
	f.sched.notifProvider = prov

	for i := 0; i < 3; i++ { // hourly sweeps
		f.sched.runScan()
	}
	rows := itsmRows(t, svc, "expiry_no_owner")
	if len(rows) != 1 || rows[0].Fingerprint != "fp-orphan" || rows[0].EventID != "expiry_no_owner:fp-orphan:conn-1" {
		t.Fatalf("want one ticket for the ownerless cert only, got %+v", rows)
	}

	// A restarted hub (fresh in-memory set) re-announces; the store dedupes.
	var fresh noOwnerAnnouncer
	fresh.announce(context.Background(), prov, orphan, time.Now())
	if got := itsmRows(t, svc, "expiry_no_owner"); len(got) != 1 {
		t.Fatalf("restart duplicated the ticket: %+v", got)
	}
}

func TestExpiryNoOwner_CertOutsideWindowIsIgnored(t *testing.T) {
	svc, prov := itsmRoutingFixture(t)
	far := soonCert("fp-far", "far.ex.com")
	far.ValidUntil = time.Now().UTC().Add(300 * 24 * time.Hour).Format(time.RFC3339)
	f := newBindingSweepFixture(t, []CertificateItem{far})
	f.sched.notifProvider = prov
	f.sched.runScan()
	if rows := itsmRows(t, svc, "expiry_no_owner"); len(rows) != 0 {
		t.Fatalf("cert outside its expiry window produced a ticket: %+v", rows)
	}
}

func TestItsmCertRisk(t *testing.T) {
	now := time.Now().UTC()
	at := func(d time.Duration) CertificateItem {
		return CertificateItem{ValidUntil: now.Add(d).Format(time.RFC3339)}
	}
	for _, tc := range []struct {
		c    CertificateItem
		want string
	}{{at(3 * 24 * time.Hour), "critical"}, {at(20 * 24 * time.Hour), "high"}, {at(90 * 24 * time.Hour), "medium"}, {CertificateItem{}, "medium"}} {
		if got := itsmCertRisk(tc.c, now); got != tc.want {
			t.Errorf("risk(%s) = %s, want %s", tc.c.ValidUntil, got, tc.want)
		}
	}
}

// chainedCertProvider reports fp-orig as already renewed once (successor
// fp-tail), as after an earlier failed install.
type chainedCertProvider struct{ tailCertProvider }

func (p chainedCertProvider) GetCertificate(ctx context.Context, fp string) (CertificateDetail, bool, error) {
	d, ok, err := p.tailCertProvider.GetCertificate(ctx, fp)
	if fp == "fp-orig" {
		succ := "fp-tail"
		d.CertificateItem = soonCert("fp-orig", "orig.ex.com")
		d.SuccessorFP, ok = &succ, true
	}
	return d, ok, err
}

func TestAutoRenewSuccessAfterChainMoveAlsoClosesTicketsOfOriginalFingerprint(t *testing.T) {
	cert := soonCert("fp-orig", "orig.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "orig.ex.com"))
	f.sched.certProvider = chainedCertProvider{tailCertProvider{&reportCertProvider{items: []CertificateItem{cert, soonCert("fp-tail", "orig.ex.com")}}}}
	var got []string
	SetRenewalVerifiedHook(func(_ context.Context, pred, _ string) { got = append(got, pred) })
	t.Cleanup(func() { SetRenewalVerifiedHook(nil) })
	// The recording runner stands in for the executor, which would itself
	// report the tail it renewed; here only the scheduler's extra report fires.
	pol := retryPolicy{base: time.Minute, retryCap: time.Hour, poll: time.Hour}
	out := f.sched.tryAutoRenew(context.Background(), cert, armedTarget("t1", "orig.ex.com"), time.Now(), installAttemptState{}, pol)
	if !out.renewed {
		t.Fatalf("want renewed, got %+v", out)
	}
	if len(got) != 1 || got[0] != "fp-orig" {
		t.Fatalf("hook predecessors = %v, want [fp-orig]", got)
	}
}
