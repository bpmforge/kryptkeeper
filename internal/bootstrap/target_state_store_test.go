// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

func TestComputeTargetBlock(t *testing.T) {
	auto := ManagedTarget{AutoRenew: true, InstallCertPath: "/etc/nginx/ssl/a.pem", InstallKeyPath: "/etc/nginx/ssl/a.key"}
	cases := []struct {
		name     string
		t        ManagedTarget
		st       TargetState
		mode     string
		known    bool
		wantKind string
	}{
		{"needs root, no sudo, auto-renew", auto, TargetState{RenewalPrivilegeRequired: true}, "none", true, BlockKindPrivilege},
		{"needs root but the credential has helper mode", auto, TargetState{RenewalPrivilegeRequired: true}, "helper", true, ""},
		{"credential unreadable never blocks", auto, TargetState{RenewalPrivilegeRequired: true}, "", false, ""},
		{"manual renewal is not blocked on privilege", ManagedTarget{}, TargetState{RenewalPrivilegeRequired: true}, "none", true, ""},
		{"nothing needs root", auto, TargetState{}, "none", true, ""},
		{"failed rollback blocks regardless of mode", ManagedTarget{}, TargetState{BlockedKind: BlockKindRollback, BlockedReason: "renewal rollback failed"}, "helper", true, BlockKindRollback},
	}
	for _, c := range cases {
		b := computeTargetBlock(c.t, c.st, c.mode, c.known)
		got := ""
		if b != nil {
			got = b.Kind
		}
		if got != c.wantKind {
			t.Errorf("%s: kind %q, want %q", c.name, got, c.wantKind)
		}
		if b != nil && (b.Reason == "" || b.Fix == "") {
			t.Errorf("%s: a Blocked state must carry its reason and fix: %+v", c.name, b)
		}
	}
	b := computeTargetBlock(auto, TargetState{RenewalPrivilegeRequired: true}, "none", true)
	if !strings.Contains(b.Fix, "chown <service-user> /etc/nginx/ssl/a.pem /etc/nginx/ssl/a.key") || !strings.Contains(b.Fix, "chmod 600 /etc/nginx/ssl/a.key") {
		t.Errorf("recipe should name the install paths: %s", b.Fix)
	}
}

func TestTargetStateStoreSQLite(t *testing.T)   { runTargetStateStoreCase(t, false) }
func TestTargetStateStorePostgres(t *testing.T) { runTargetStateStoreCase(t, true) }

func runTargetStateStoreCase(t *testing.T, postgres bool) {
	_, db := migratedLinkStore(t, postgres)
	ctx := context.Background()
	var store ManagedTargetStore = &sqliteManagedTargetStore{db: db}
	if postgres {
		store = &postgresManagedTargetStore{db: db}
	}
	if _, err := store.Create(ctx, ManagedTarget{ID: "t1", Name: "n", Host: "h", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", Tenant: "default"}); err != nil {
		t.Fatal(err)
	}
	ss := store.(targetStateStore)
	if err := ss.RecordTargetScan(ctx, "t1", "helper", 4, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetTargetBlocked(ctx, "t1", BlockKindRollback, "renewal rollback failed"); err != nil {
		t.Fatal(err)
	}
	st, err := ss.TargetStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := st["t1"]
	if got.LastPrivilegeMode != "helper" || got.UnreadableCount != 4 || got.LastScannedAt == "" || got.BlockedKind != BlockKindRollback || got.BlockedAt == "" || got.RenewalPrivilegeRequired {
		t.Fatalf("%+v", got)
	}
	if err := ss.ClearTargetBlocked(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if st, _ = ss.TargetStates(ctx); st["t1"].BlockedKind != "" || st["t1"].BlockedReason != "" {
		t.Fatalf("not cleared: %+v", st["t1"])
	}
	if err := ss.SetTargetBlocked(ctx, "nope", BlockKindRollback, "x"); err == nil {
		t.Fatal("unknown id must fail")
	}

	// A host scan records its mode and unreadable count through the discovery path.
	obs := &scanner.HostObservations{TargetID: "t1", PrivilegeMode: "none", UnreadableCount: 7}
	recordTargetScanState(ctx, db, postgres, obs)
	if st, _ = ss.TargetStates(ctx); st["t1"].LastPrivilegeMode != "none" || st["t1"].UnreadableCount != 7 {
		t.Fatalf("scan state not recorded: %+v", st["t1"])
	}
	// The renewal executor's blocker adapter marks a rollback block.
	if err := (targetStateBlocker{store}).BlockTarget(ctx, "t1", "renewal rollback failed"); err != nil {
		t.Fatal(err)
	}
	if st, _ = ss.TargetStates(ctx); st["t1"].BlockedKind != BlockKindRollback {
		t.Fatalf("BlockTarget did not block: %+v", st["t1"])
	}
}

// The sweep refuses a target that needs root while its credential has no sudo
// mode, audits the transition once, and lets it through again when the
// credential gains a mode.
func TestSchedulerRefusesPrivilegeBlockedTargetAndAuditsTransitionsOnce(t *testing.T) {
	targets, creds := winrmTestStores(t)
	ctx := context.Background()
	mk := func(id, mode string) {
		extra := map[string]string{}
		if mode != "" {
			extra["sudo_mode"] = mode
			if mode == "helper" {
				extra["helper_sha256"] = strings.Repeat("a", 64)
			}
		}
		if _, err := creds.Create(ctx, id, id, CredentialTypeSSHKey, "", sshPayloadWithPrivilege(t, extra)); err != nil {
			t.Fatal(err)
		}
	}
	mk("c-none", "")
	mk("c-helper", "helper")
	target := ManagedTarget{ID: "t1", Name: "web", Host: "10.0.0.5", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual",
		CredentialRef: "c-none", AutoRenew: true, AutoRenewSetBy: "u1", InstallServerType: "nginx",
		InstallCertPath: "/etc/nginx/ssl/a.pem", InstallKeyPath: "/etc/nginx/ssl/a.key"}
	if _, err := targets.Create(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err := targets.db.Exec(`UPDATE managed_targets SET renewal_privilege_required = 1 WHERE id = 't1'`); err != nil {
		t.Fatal(err)
	}
	audit := &sshRecordingAudit{}
	s := &RenewalScheduler{targetStore: targets, credStore: creds, auditProvider: audit}
	tick := func() int {
		list, err := targets.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return len(s.withoutBlockedTargets(ctx, eligibleAutoRenewTargets(list)))
	}
	count := func(action string) int {
		n := 0
		for _, e := range audit.entries {
			if e.Action == action && e.ResourceID == "t1" {
				n++
			}
		}
		return n
	}
	if tick() != 0 || tick() != 0 || tick() != 0 {
		t.Fatal("a target that needs root with no sudo mode must not be scheduled")
	}
	if count("target.renewal.blocked") != 1 {
		t.Fatalf("blocked must be audited once per transition, got %d", count("target.renewal.blocked"))
	}
	cred := "c-helper"
	if _, err := targets.Update(ctx, "t1", ManagedTargetUpdate{CredentialRef: &cred}); err != nil {
		t.Fatal(err)
	}
	if tick() != 1 || tick() != 1 {
		t.Fatal("a credential with helper mode must clear the block")
	}
	if count("target.renewal.unblocked") != 1 || count("target.renewal.blocked") != 1 {
		t.Fatalf("transitions: blocked=%d unblocked=%d", count("target.renewal.blocked"), count("target.renewal.unblocked"))
	}
	// A rollback block persists across ticks until an operator clears it.
	if err := (targetStateBlocker{targets}).BlockTarget(ctx, "t1", "renewal rollback failed"); err != nil {
		t.Fatal(err)
	}
	if tick() != 0 {
		t.Fatal("a rollback-blocked target must not be scheduled")
	}
	if err := targets.ClearTargetBlocked(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if tick() != 1 {
		t.Fatal("unblock must let the target through")
	}
}

func TestTargetsAPIShowsBlockedCoverageAndUnblock(t *testing.T) {
	f := newPreflightFixture(t, nil, true)
	ctx := context.Background()
	if _, err := f.targets.db.Exec(`UPDATE managed_targets SET renewal_privilege_required = 1 WHERE id = 'target-pf'`); err != nil {
		t.Fatal(err)
	}
	if err := f.targets.RecordTargetScan(ctx, "target-pf", "none", 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	get := func() ManagedTarget {
		rec := doTargetsRequest(f.mux, http.MethodGet, "/api/v1/targets/target-pf", f.admin, "")
		var out struct{ Data ManagedTarget }
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return out.Data
	}
	got := get()
	if got.Blocked == nil || got.Blocked.Kind != BlockKindPrivilege || got.LastPrivilegeMode != "none" || got.UnreadableCount != 3 || !got.RenewalPrivilegeRequired {
		t.Fatalf("GET: %+v", got)
	}
	rec := doTargetsRequest(f.mux, http.MethodGet, "/api/v1/targets", f.admin, "")
	if !strings.Contains(rec.Body.String(), `"blocked":{"kind":"privilege"`) {
		t.Fatalf("list lacks blocked: %s", rec.Body)
	}

	// Unblock: permission, tenant, method gates; a privilege block is derived, so it stays.
	if rec := doTargetsRequest(f.mux, http.MethodPost, "/api/v1/targets/target-pf/unblock", f.viewer, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d", rec.Code)
	}
	if rec := doTargetsRequest(f.mux, http.MethodPost, "/api/v1/targets/target-pf/unblock", f.other, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("other tenant: %d", rec.Code)
	}
	if rec := doTargetsRequest(f.mux, http.MethodGet, "/api/v1/targets/target-pf/unblock", f.admin, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
	if rec := doTargetsRequest(f.mux, http.MethodPost, "/api/v1/targets/nope/unblock", f.admin, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rec.Code)
	}
	if err := (targetStateBlocker{f.targets}).BlockTarget(ctx, "target-pf", "renewal rollback failed"); err != nil {
		t.Fatal(err)
	}
	if b := get().Blocked; b == nil || b.Kind != BlockKindRollback {
		t.Fatalf("rollback block must win: %+v", b)
	}
	if rec := doTargetsRequest(f.mux, http.MethodPost, "/api/v1/targets/target-pf/unblock", f.admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("unblock: %d %s", rec.Code, rec.Body)
	}
	if b := get().Blocked; b == nil || b.Kind != BlockKindPrivilege {
		t.Fatalf("after unblock the derived privilege block remains: %+v", b)
	}
	var denied, ok bool
	for _, e := range f.audit.entries {
		if e.Action == "target.renewal.unblock" && e.Outcome == AuditOutcomeDenied {
			denied = true
		}
		if e.Action == "target.renewal.unblock" && e.Outcome == AuditOutcomeSuccess {
			ok = true
		}
	}
	if !denied || !ok {
		t.Fatalf("unblock must be audited: %+v", f.audit.entries)
	}
}

func TestApplyInsufficientPrivilege(t *testing.T) {
	mk := func(findings ...string) *scanner.ScanResult {
		return &scanner.ScanResult{Endpoints: []scanner.DiscoveredEndpoint{{Findings: findings, HostObs: &scanner.HostObservations{TargetID: "t"}}}}
	}
	denied := func(p string) string {
		return "UNREADABLE_PATH: h:" + p + ": ssh executor: read " + p + ": permission denied"
	}

	r := mk(denied("/opt/tomcat/conf/keystore.jks"), "UNREADABLE_PATH: h:/etc/ssl/bad.p12: not a PKCS#12 keystore", "KEY_WORLD_READABLE: path=/k", needsPasswordForTest)
	applyInsufficientPrivilege(r, "1001", "kkscan", "none")
	ep := r.Endpoints[0]
	if len(ep.Findings) != 3 || !strings.HasPrefix(ep.Findings[0], "INSUFFICIENT_PRIVILEGE: uid=1001; user=kkscan; mode=none; unreadable=1; paths=/opt/tomcat/conf/keystore.jks; fix=") {
		t.Fatalf("%v", ep.Findings)
	}
	if !strings.HasPrefix(ep.Findings[1], "UNREADABLE_PATH: h:/etc/ssl/bad.p12") || !strings.HasPrefix(ep.Findings[2], "KEY_WORLD_READABLE") {
		t.Fatalf("non-permission findings must survive in order: %v", ep.Findings)
	}
	if strings.Contains(strings.Join(ep.Findings, "|"), "NEEDS_PASSWORD") {
		t.Fatal("NEEDS_PASSWORD folds into the fix text")
	}
	if ep.HostObs.PrivilegeMode != "none" || ep.HostObs.UnreadableCount != 1 {
		t.Fatalf("%+v", ep.HostObs)
	}

	var many []string
	for i := 0; i < 14; i++ {
		many = append(many, denied(fmt.Sprintf("/srv/k/%d.jks", i)), denied(fmt.Sprintf("/srv/k/%d.jks", i))) // duplicates collapse
	}
	r = mk(many...)
	applyInsufficientPrivilege(r, "", "kkscan", "nopasswd")
	f := r.Endpoints[0].Findings[0]
	if !strings.Contains(f, "uid=unknown") || !strings.Contains(f, "unreadable=14") || !strings.Contains(f, "(+4 more)") || strings.Count(f, ".jks") != 10 {
		t.Fatalf("cap/total/dedupe: %s", f)
	}

	for mode, want := range map[string]string{
		"helper":   "never private keys",
		"nopasswd": "NOPASSWD:",
		"password": "remove NOPASSWD",
		"none":     "privilege helper",
	} {
		r = mk(denied("/etc/x/a.jks"))
		applyInsufficientPrivilege(r, "1", "u", mode)
		if !strings.Contains(r.Endpoints[0].Findings[0], want) {
			t.Errorf("%s fix should mention %q: %s", mode, want, r.Endpoints[0].Findings[0])
		}
	}

	r = mk("KEY_WORLD_READABLE: path=/k")
	applyInsufficientPrivilege(r, "1", "u", "helper")
	if len(r.Endpoints[0].Findings) != 1 || r.Endpoints[0].HostObs.UnreadableCount != 0 || r.Endpoints[0].HostObs.PrivilegeMode != "helper" {
		t.Fatalf("a clean scan adds no finding but still records its mode: %+v", r.Endpoints[0])
	}
}

const needsPasswordForTest = "NEEDS_PASSWORD: legacy hint"
