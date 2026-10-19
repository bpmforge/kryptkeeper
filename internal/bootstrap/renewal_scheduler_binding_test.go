// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// W27-02: the sweep renews a certificate only onto targets an operator bound
// to it. These tests drive runScan with a recording runner instead of the
// SSH-installing engine, so "which targets were renewed" is directly visible.

type bindingRunnerCall struct{ fingerprint, targetID string }

type recordingRenewalRunner struct {
	mu    sync.Mutex
	calls []bindingRunnerCall
}

func (r *recordingRenewalRunner) ExecuteRenewal(_ context.Context, fp string, target ManagedTarget, _ RenewalInstallProfile) (RenewalExecuteResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, bindingRunnerCall{fp, target.ID})
	return RenewalExecuteResult{
		PredecessorFingerprint: fp, NewFingerprint: fmt.Sprintf("new-%s-%d", target.ID, len(r.calls)),
		Renewed: true, InstallOutcome: "installed_verified", Verified: true,
	}, nil
}

func (r *recordingRenewalRunner) targets() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, c.targetID)
	}
	sort.Strings(out)
	return out
}

// tailCertProvider serves GetCertificate for renewalTail: every certificate is
// the head of its chain.
type tailCertProvider struct{ *reportCertProvider }

func (p tailCertProvider) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	for _, it := range p.items {
		if it.FingerprintSHA256 == fp {
			return CertificateDetail{CertificateItem: it}, true, nil
		}
	}
	return CertificateDetail{}, false, nil
}

func armedTarget(id, host string) ManagedTarget {
	t := mkTarget(id, host)
	t.InstallMode, t.AutoRenew, t.AutoRenewSetBy, t.CredentialRef = "keychain", true, "admin-1", "cred"
	return t
}

type bindingSweepFixture struct {
	sched    *RenewalScheduler
	runner   *recordingRenewalRunner
	bindings *sqlCertTargetBindingStore
	audit    *recordingAuditProvider
}

func newBindingSweepFixture(t *testing.T, certs []CertificateItem, targets ...ManagedTarget) *bindingSweepFixture {
	t.Helper()
	store := newFreshManagedTargetStore(t)
	for _, tg := range targets {
		if _, err := store.Create(context.Background(), tg); err != nil {
			t.Fatalf("create target %s: %v", tg.ID, err)
		}
	}
	f := &bindingSweepFixture{
		runner:   &recordingRenewalRunner{},
		bindings: newFreshBindingStore(t),
		audit:    &recordingAuditProvider{},
	}
	f.sched = (&RenewalScheduler{
		certProvider:  tailCertProvider{&reportCertProvider{items: certs}},
		auditProvider: f.audit,
		thresholdDays: 30,
		pollInterval:  time.Hour,
		cooldown:      time.Hour,
		targetStore:   store,
	}).WithRenewalRunner(f.runner).WithBindingStore(f.bindings)
	return f
}

func soonCert(fp, cn string, sans ...string) CertificateItem {
	return CertificateItem{
		FingerprintSHA256: fp, CommonName: cn, SubjectAltNames: sans, CAID: "ca-1",
		ValidFrom:  time.Now().UTC().Add(-80 * 24 * time.Hour).Format(time.RFC3339),
		ValidUntil: time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339),
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func bindTo(t *testing.T, f *bindingSweepFixture, fp string, targetIDs ...string) {
	t.Helper()
	for _, id := range targetIDs {
		if _, err := f.bindings.Create(context.Background(), CertTargetBinding{CertFingerprint: fp, TargetID: id}); err != nil {
			t.Fatalf("bind %s -> %s: %v", fp, id, err)
		}
	}
	if err := f.bindings.MarkBackfillDone(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAutoRenewBindingWildcardAndMultiSANRenewExactlyBoundTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		cert CertificateItem
	}{
		{"wildcard", soonCert("fp-wild", "*.ex.com", "*.ex.com")},
		{"multi-san", soonCert("fp-multi", "multi.ex.com", "multi.ex.com", "a.ex.com", "b.ex.com", "c.ex.com", "d.ex.com")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBindingSweepFixture(t, []CertificateItem{tc.cert},
				armedTarget("t1", "b.ex.com"), armedTarget("t2", "c.ex.com"), armedTarget("t3", "d.ex.com"),
				// t4's host is covered by the certificate but nobody bound it.
				armedTarget("t4", "a.ex.com"))
			bindTo(t, f, tc.cert.FingerprintSHA256, "t1", "t2", "t3")

			f.sched.runScan()

			if got := strings.Join(f.runner.targets(), ","); got != "t1,t2,t3" {
				t.Fatalf("renewed targets = %q, want exactly t1,t2,t3", got)
			}
			if st := f.sched.Status(); st.LastAutoRenewTriggers != 3 {
				t.Fatalf("triggers = %d, want 3", st.LastAutoRenewTriggers)
			}
			// Each target now serves its own successor.
			binds, _ := f.bindings.ListAll(context.Background())
			for _, b := range binds {
				if !strings.HasPrefix(b.ServedFingerprint, "new-"+b.TargetID+"-") {
					t.Fatalf("binding %s/%s served %q", b.CertFingerprint, b.TargetID, b.ServedFingerprint)
				}
			}
		})
	}
}

func TestAutoRenewHeuristicMatchWithoutBindingIsSkippedAndLogged(t *testing.T) {
	logs := captureLog(t)
	cert := soonCert("fp-nobind", "web.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "web.ex.com"))
	if err := f.bindings.MarkBackfillDone(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.sched.runScan()
	f.sched.runScan() // the log is deduped, the verdict is not

	if n := len(f.runner.calls); n != 0 {
		t.Fatalf("executor called %d time(s) for an unbound cert", n)
	}
	if !strings.Contains(logs.String(), "has no binding") || !strings.Contains(logs.String(), "fp-nobind") {
		t.Fatalf("skip reason not logged: %q", logs.String())
	}
	if c := strings.Count(logs.String(), "has no binding"); c != 1 {
		t.Fatalf("no-binding log repeated %d times in one day", c)
	}
}

func TestAutoRenewWithoutBindingStoreExecutesNothing(t *testing.T) {
	cert := soonCert("fp-nostore", "web.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "web.ex.com"))
	f.sched.bindingStore = nil

	f.sched.runScan()

	if n := len(f.runner.calls); n != 0 {
		t.Fatalf("a missing binding store fell back to host matching: %d call(s)", n)
	}
}

func TestAutoRenewBackfillCreatesBindingsOnce(t *testing.T) {
	cert := soonCert("fp-bf", "web.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "web.ex.com"))
	ctx := context.Background()

	f.sched.runScan()

	binds, _ := f.bindings.ListByTarget(ctx, "t1")
	if len(binds) != 1 || binds[0].Source != bindingSourceBackfill || binds[0].CertFingerprint != "fp-bf" {
		t.Fatalf("backfill bindings = %+v", binds)
	}
	if len(f.runner.calls) != 1 {
		t.Fatalf("the migrated match was not renewed: %d call(s)", len(f.runner.calls))
	}
	if err := f.bindings.Delete(ctx, "t1", "fp-bf"); err != nil {
		t.Fatal(err)
	}

	f.sched.runScan()

	if binds, _ := f.bindings.ListAll(ctx); len(binds) != 0 {
		t.Fatalf("a deleted binding was recreated: %+v", binds)
	}
	if len(f.runner.calls) != 1 {
		t.Fatalf("renewed again after the operator unbound the cert: %d call(s)", len(f.runner.calls))
	}
}

func TestAutoRenewBackfillSkippedWhenTargetListFails(t *testing.T) {
	cert := soonCert("fp-bf2", "web.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "web.ex.com"))
	f.sched.targetStore = failingTargetList{f.sched.targetStore}

	f.sched.runScan()

	if done, _ := f.bindings.BackfillDone(context.Background()); done {
		t.Fatal("backfill marked done although the target list failed: live renewals would be forfeited")
	}
}

type failingTargetList struct{ ManagedTargetStore }

func (failingTargetList) List(context.Context) ([]ManagedTarget, error) {
	return nil, fmt.Errorf("db down")
}

func TestAutoRenewServedFingerprintAdvances(t *testing.T) {
	cert := soonCert("fp-adv", "web.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{cert}, armedTarget("t1", "web.ex.com"))
	bindTo(t, f, "fp-adv", "t1")

	f.sched.runScan()

	binds, _ := f.bindings.ListByTarget(context.Background(), "t1")
	want := f.runner.calls[0]
	if len(binds) != 1 || binds[0].ServedFingerprint != "new-t1-1" || want.fingerprint != "fp-adv" {
		t.Fatalf("binding after success = %+v (call %+v)", binds, want)
	}

	// The successor is not in the window yet, and the old cert is no longer
	// what the target serves: nothing more to do.
	f.sched.runScan()
	if len(f.runner.calls) != 1 {
		t.Fatalf("renewed again on the next tick: %d call(s)", len(f.runner.calls))
	}
}

func TestAutoRenewBindingTenantMismatchDenied(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tenants.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ts := &dbTenantStore{db: db, ph: sqlitePlaceholder}
	ctx := context.Background()
	if err := ts.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"tenant-a", "tenant-b"} {
		if _, err := ts.CreateTenant(ctx, id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.SetCATenant(ctx, "ca-1", "tenant-b"); err != nil {
		t.Fatal(err)
	}
	prev := activeTenantStore
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(prev) })

	cert := soonCert("fp-ten", "web.ex.com")
	tg := armedTarget("t1", "web.ex.com")
	tg.Tenant = "tenant-a"
	f := newBindingSweepFixture(t, []CertificateItem{cert}, tg)
	bindTo(t, f, "fp-ten", "t1")

	f.sched.runScan()

	if n := len(f.runner.calls); n != 0 {
		t.Fatalf("key pushed across a tenant boundary: %d call(s)", n)
	}
	denied := false
	for _, e := range f.audit.entries {
		if e.Action == "certificate.renew_execute_denied" && e.Outcome == AuditOutcomeDenied {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("no denied audit row: %+v", f.audit.entries)
	}
}

type fixedHistoryAudit struct {
	stubAuditProvider
	entries []AuditEntry
}

func (p fixedHistoryAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: p.entries}, nil
}

func TestInstallStateIsScopedToTheTarget(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	fail := func(target string) AuditEntry {
		return AuditEntry{Action: "certificate.renew_execute_failed", Timestamp: now, ChangeSummary: "target_id=" + target + " attempt=1/5 boom"}
	}
	ok := AuditEntry{Action: "certificate.renew_execute", Timestamp: now, ChangeSummary: "new_fingerprint=x install=installed target_id=t2 target=n attempt=1"}
	s := &RenewalScheduler{auditProvider: fixedHistoryAudit{entries: []AuditEntry{ok, fail("t1"), fail("t1"), fail("t10")}}}
	cert := CertificateItem{FingerprintSHA256: "fp"}

	if st, _ := s.installState(context.Background(), cert, "t1"); st.failures != 2 {
		t.Fatalf("t1 failures = %d, want 2 (t10 and t2 rows are not its own)", st.failures)
	}
	if st, _ := s.installState(context.Background(), cert, "t2"); st.failures != 0 {
		t.Fatalf("t2 failures = %d, want 0", st.failures)
	}
	if st, _ := s.installState(context.Background(), cert, "t3"); st.failures != 0 {
		t.Fatalf("t3 failures = %d, want 0", st.failures)
	}
}
