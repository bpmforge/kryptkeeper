// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

// waveFakeTargets serves a fixed target list; every other method panics via
// the nil embedded interface, which keeps the fake honest about what the
// executor is allowed to call.
type waveFakeTargets struct {
	ManagedTargetStore
	list []ManagedTarget
}

func (f waveFakeTargets) List(context.Context) ([]ManagedTarget, error) { return f.list, nil }

// waveFakeDeliverer models a target that serves `served` and, like the UC-D01
// installer, restores the previous file when the post-install verify does not
// see the new fingerprint. files stands in for the target's cert path.
type waveFakeDeliverer struct {
	files       map[string]string
	certPath    string
	verifyFails bool
	delivered   int
}

func (d *waveFakeDeliverer) Supports(ManagedTarget) (bool, string) { return true, "" }

func (d *waveFakeDeliverer) Deliver(_ context.Context, _ ManagedTarget, oldFP, newFP string) (waveDelivery, error) {
	d.delivered++
	backup := d.files[d.certPath]
	d.files[d.certPath] = newFP
	served := d.files[d.certPath]
	if d.verifyFails {
		served = "" // reloaded server never presented the new cert
	}
	if served == newFP {
		return waveDelivery{Outcome: waveDeliveryOK, Detail: "served fingerprint matches", Verified: true}, nil
	}
	d.files[d.certPath] = backup
	if d.files[d.certPath] != oldFP {
		return waveDelivery{Outcome: waveDeliveryFailed, Detail: "rollback did not restore old cert"}, nil
	}
	return waveDelivery{Outcome: waveDeliveryRolledBack, Detail: "served fingerprint != new"}, nil
}

func waveTestMember(t *testing.T, fx *waveExecuteTestFixture, cn string) (string, MigrationWave) {
	t.Helper()
	ctx := context.Background()
	csr := generateTestCSRPEM(t, cn, cn)
	issued, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: getFirstCAID(t, fx.engine), TemplateID: "tpl-classical", CSRPEM: csr, TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	wave, err := fx.waveStore.CreateWave(ctx, MigrationWave{Name: "w-" + cn})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	if err := fx.waveStore.AddMember(ctx, wave.ID, MigrationWaveMember{Fingerprint: issued.FingerprintSHA256}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	waves, _ := fx.waveStore.ListWaves(ctx)
	for _, w := range waves {
		if w.ID == wave.ID {
			return issued.FingerprintSHA256, w
		}
	}
	t.Fatal("wave vanished")
	return "", MigrationWave{}
}

func waveStatusOf(t *testing.T, fx *waveExecuteTestFixture, id string) string {
	t.Helper()
	waves, _ := fx.waveStore.ListWaves(context.Background())
	for _, w := range waves {
		if w.ID == id {
			return w.Status
		}
	}
	t.Fatalf("wave %s not found", id)
	return ""
}

func TestWave_DeliveryVerifyFailureRollsBack(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	oldFP, wave := waveTestMember(t, fx, "rollback.example.com")
	deliver := &waveFakeDeliverer{files: map[string]string{"/etc/tls/c.crt": oldFP}, certPath: "/etc/tls/c.crt", verifyFails: true}
	var memberHook []migrateWaveMemberResult
	var outcomeHook *migrateWaveExecutionResult
	hooks := waveHooks{
		MemberResult: func(_ string, r migrateWaveMemberResult) { memberHook = append(memberHook, r) },
		WaveOutcome:  func(_ string, res migrateWaveExecutionResult) { outcomeHook = &res },
	}
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Name: "web", Host: "rollback.example.com"}}}, deliver: deliver, waves: fx.waveStore}

	res := runWaveMigration(context.Background(), d, wave, "ML-DSA-65", hooks)

	if len(res.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(res.Results))
	}
	r := res.Results[0]
	if r.Status != "failed" || r.Delivery != "failed" || r.Reason == "" {
		t.Fatalf("member = %+v, want failed/failed with a reason", r)
	}
	if r.OldSerialServed == nil || !*r.OldSerialServed {
		t.Fatalf("OldSerialServed = %v, want true", r.OldSerialServed)
	}
	if deliver.files[deliver.certPath] != oldFP {
		t.Fatalf("target file = %q, want old fingerprint %q still served", deliver.files[deliver.certPath], oldFP)
	}
	if res.Failed != 1 || res.Migrated != 0 || !res.Regressed || res.WaveStatus != waveStatusRegressed {
		t.Fatalf("result = %+v, want failed=1 migrated=0 regressed", res)
	}
	if got := waveStatusOf(t, fx, wave.ID); got != waveStatusRegressed {
		t.Fatalf("stored wave status = %q, want regressed", got)
	}
	if len(memberHook) != 1 || outcomeHook == nil || !outcomeHook.Regressed {
		t.Fatalf("hooks not invoked: member=%d outcome=%v", len(memberHook), outcomeHook)
	}
}

func TestWave_DeliveryVerifiedMigrates(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	oldFP, wave := waveTestMember(t, fx, "ok.example.com")
	deliver := &waveFakeDeliverer{files: map[string]string{"/p": oldFP}, certPath: "/p"}
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Host: "ok.example.com"}}}, deliver: deliver, waves: fx.waveStore}

	res := runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{})

	if res.Migrated != 1 || res.Regressed || res.Results[0].Delivery != "verified" {
		t.Fatalf("result = %+v, want migrated with verified delivery", res)
	}
	if deliver.files["/p"] != res.Results[0].NewFingerprint {
		t.Fatalf("target serves %q, want new fingerprint", deliver.files["/p"])
	}
}

func TestWave_UnsupportedTargetReported(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	_, wave := waveTestMember(t, fx, "unsupported.example.com")
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Host: "unsupported.example.com"}}}, deliver: unsupportedWaveDeliverer{}, waves: fx.waveStore}

	res := runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{})

	r := res.Results[0]
	if r.Status != "delivery_unsupported" || r.Delivery != "unsupported" || r.Reason != waveDeliveryUnsupportedReason {
		t.Fatalf("member = %+v, want delivery_unsupported with the manual-install reason", r)
	}
	if res.Unsupported != 1 || res.Migrated != 0 || res.Failed != 0 || res.Regressed {
		t.Fatalf("result = %+v, want unsupported=1 only", res)
	}
}

func TestWave_NoTargetMigratedDeliveryNone(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	_, wave := waveTestMember(t, fx, "unbound.example.com")
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Host: "other.example.com"}}}, deliver: unsupportedWaveDeliverer{}, waves: fx.waveStore}

	res := runWaveMigration(context.Background(), d, wave, "ML-DSA-65", waveHooks{})

	if res.Migrated != 1 || res.Results[0].Status != "migrated" || res.Results[0].Delivery != "none" {
		t.Fatalf("result = %+v, want migrated with delivery none", res)
	}
}

func TestWave_MidWaveRenewedMemberSkipped(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	ctx := context.Background()
	oldFP, wave := waveTestMember(t, fx, "midwave.example.com")
	if _, err := fx.certs.RenewCertificate(ctx, oldFP, CertificateRenewRequest{CSRPEM: generateTestCSRPEM(t, "midwave.example.com", "midwave.example.com")}); err != nil {
		t.Fatalf("renew by another path: %v", err)
	}
	d := waveDeps{certs: fx.certs, keys: fx.keys, targets: waveFakeTargets{}, deliver: unsupportedWaveDeliverer{}, waves: fx.waveStore}

	res := runWaveMigration(ctx, d, wave, "ML-DSA-65", waveHooks{})

	r := res.Results[0]
	if r.Status != "skipped" || r.Reason == "" || r.NewFingerprint != "" || res.Skipped != 1 {
		t.Fatalf("result = %+v, want skipped with reason and no issuance", res)
	}
}

func TestWaveCurrentReadiness_FollowsSuccessorChainAndCycleSafe(t *testing.T) {
	s := func(v string) *string { return &v }
	items := []CertificateItem{
		{FingerprintSHA256: "a", PQCReadiness: "vulnerable", SuccessorFP: s("b")},
		{FingerprintSHA256: "b", PQCReadiness: "vulnerable", SuccessorFP: s("c")},
		{FingerprintSHA256: "c", PQCReadiness: "quantum_safe_leaf_only"},
		{FingerprintSHA256: "x", PQCReadiness: "vulnerable", SuccessorFP: s("y")},
		{FingerprintSHA256: "y", PQCReadiness: "migration_ready", SuccessorFP: s("x")},
		{FingerprintSHA256: "dangling", PQCReadiness: "vulnerable", SuccessorFP: s("missing")},
		{FingerprintSHA256: "blank"},
	}
	got := waveCurrentReadiness(items)
	if got["a"] != "quantum_safe_leaf_only" || got["b"] != "quantum_safe_leaf_only" || got["c"] != "quantum_safe_leaf_only" {
		t.Fatalf("chain tail not followed: %v", got)
	}
	if got["x"] != "migration_ready" || got["y"] != "vulnerable" {
		t.Fatalf("cycle must stop at the last distinct cert: %v", got)
	}
	if got["dangling"] != "vulnerable" {
		t.Fatalf("missing successor must fall back to own label: %v", got)
	}
	if _, ok := got["blank"]; ok {
		t.Fatal("empty labels must never be stored")
	}
}

func TestWaveProgress_EqualsPQCCurrentCerts(t *testing.T) {
	s := func(v string) *string { return &v }
	items := []CertificateItem{
		{FingerprintSHA256: "rsa", PQCReadiness: "vulnerable", SuccessorFP: s("mldsa")},
		{FingerprintSHA256: "mldsa", PQCReadiness: "quantum_safe"},
		{FingerprintSHA256: "still", PQCReadiness: "vulnerable"},
	}
	wave := MigrationWave{ID: "w", Members: []MigrationWaveMember{{Fingerprint: "rsa"}, {Fingerprint: "still"}, {Fingerprint: "deleted"}}}
	p := computeWaveProgress([]MigrationWave{wave}, waveCurrentReadiness(items))[0]
	if p.Total != 3 || p.Migrated != 1 || p.ProgressPercent != 33 {
		t.Fatalf("progress = %+v, want 1/3 (renewed-to-PQC counted, vulnerable and deleted not)", p)
	}
}

func TestWaveProgress_LeafOnlyNeverDone(t *testing.T) {
	ctx := context.Background()
	store := newTestWaveStore(t)
	w, err := store.CreateWave(ctx, MigrationWave{Name: "leafy", Members: []MigrationWaveMember{{Fingerprint: "l1"}, {Fingerprint: "l2"}}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.UpdateWaveStatus(ctx, w.ID, waveStatusInProgress); err != nil {
		t.Fatalf("status: %v", err)
	}
	waves, _ := store.ListWaves(ctx)
	current := map[string]string{"l1": "quantum_safe_leaf_only", "l2": "quantum_safe_leaf_only"}

	got := syncWaveStatuses(ctx, store, waves, current)[0]

	if got.ProgressPercent != 100 || got.LeafOnly != 2 {
		t.Fatalf("progress = %+v, want 100%% with 2 leaf-only", got)
	}
	if got.Status == waveStatusDone || waveStatusOf2(ctx, store, w.ID) == waveStatusDone {
		t.Fatalf("status = %q, a wave with leaf-only members must never be done", got.Status)
	}

	// Once the chain is fully PQC the same wave may complete.
	waves, _ = store.ListWaves(ctx)
	current = map[string]string{"l1": "quantum_safe", "l2": "quantum_safe"}
	if got := syncWaveStatuses(ctx, store, waves, current)[0]; got.Status != waveStatusDone {
		t.Fatalf("full-chain wave status = %q, want done", got.Status)
	}
}

func waveStatusOf2(ctx context.Context, store MigrationWaveStore, id string) string {
	waves, _ := store.ListWaves(ctx)
	for _, w := range waves {
		if w.ID == id {
			return w.Status
		}
	}
	return ""
}
