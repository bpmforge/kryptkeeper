// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/pqc"
)

// mldsaWaveSetup issues a classical leaf from an ML-DSA issuing CA and wraps it
// in a one-member wave, so the successor the wave issues is a full-chain
// quantum_safe cert (the case the leaf_only cap does not catch).
func mldsaWaveSetup(t *testing.T, cn string) (CertificateProvider, keystore.Store, *dbMigrationWaveStore, MigrationWave, string) {
	t.Helper()
	ctx := context.Background()
	provider, engine, keys := newTestMLDSACAProvider(t)
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: getFirstCAID(t, engine), TemplateID: "tpl-tls", CSRPEM: generateTestCSRPEM(t, cn, cn), TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue classical leaf: %v", err)
	}
	store := newTestWaveStore(t)
	wave, err := store.CreateWave(ctx, MigrationWave{Name: "w-" + cn, Members: []MigrationWaveMember{{Fingerprint: issued.FingerprintSHA256}}})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	if err := store.UpdateWaveStatus(ctx, wave.ID, waveStatusInProgress); err != nil {
		t.Fatalf("status: %v", err)
	}
	waves, _ := store.ListWaves(ctx)
	return provider, keys, store, waves[0], issued.FingerprintSHA256
}

func waveProgressNow(t *testing.T, provider CertificateProvider, store MigrationWaveStore) WaveProgress {
	t.Helper()
	ctx := context.Background()
	waves, err := store.ListWaves(ctx)
	if err != nil {
		t.Fatalf("list waves: %v", err)
	}
	all, err := listAllCertificates(ctx, provider, CertificateListQuery{})
	if err != nil {
		t.Fatalf("list certs: %v", err)
	}
	return syncWaveStatuses(ctx, store, waves, waveCurrentReadiness(all.Items))[0]
}

func TestWaveProgress_UndeliveredMemberNotMigratedUnderMLDSACA(t *testing.T) {
	ctx := context.Background()
	provider, keys, store, wave, oldFP := mldsaWaveSetup(t, "undelivered.example.com")
	d := waveDeps{certs: provider, keys: keys, deliver: unsupportedWaveDeliverer{}, waves: store,
		targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Host: "undelivered.example.com"}}}}

	res := runWaveMigration(ctx, d, wave, "ML-DSA-65", waveHooks{})
	if res.Unsupported != 1 || res.Results[0].NewFingerprint == "" {
		t.Fatalf("result = %+v, want one delivery_unsupported member with an issued successor", res)
	}

	// Control: the inventory alone reads the successor as fully quantum_safe,
	// which is exactly what used to make this member count as migrated.
	all, _ := listAllCertificates(ctx, provider, CertificateListQuery{})
	if got := waveCurrentReadiness(all.Items)[oldFP]; got != "quantum_safe" {
		t.Fatalf("precondition: current readiness = %q, want quantum_safe (full chain)", got)
	}
	bare := computeWaveProgress([]MigrationWave{{ID: wave.ID, Members: []MigrationWaveMember{{Fingerprint: oldFP}}}}, waveCurrentReadiness(all.Items))[0]
	if bare.Migrated != 1 || bare.ProgressPercent != 100 {
		t.Fatalf("control (no delivery record) = %+v, want 1/100%%", bare)
	}

	got := waveProgressNow(t, provider, store)
	if got.Migrated != 0 || got.Undelivered != 1 || got.ProgressPercent != 0 {
		t.Fatalf("progress = %+v, want migrated=0 undelivered=1 0%%", got)
	}
	if got.Status == waveStatusDone || waveStatusOf2(ctx, store, wave.ID) == waveStatusDone {
		t.Fatalf("status = %q, an undelivered wave must not be done", got.Status)
	}
	if got.Members[0].DeliveryStatus != pqc.MemberDeliveryUnsupported {
		t.Fatalf("member delivery_status = %q, want delivery_unsupported", got.Members[0].DeliveryStatus)
	}
}

func TestWaveProgress_UnboundMemberMigratedUnderMLDSACA(t *testing.T) {
	ctx := context.Background()
	provider, keys, store, wave, _ := mldsaWaveSetup(t, "unbound.example.com")
	d := waveDeps{certs: provider, keys: keys, deliver: unsupportedWaveDeliverer{}, waves: store,
		targets: waveFakeTargets{list: []ManagedTarget{{ID: "t1", Host: "other.example.com"}}}}

	res := runWaveMigration(ctx, d, wave, "ML-DSA-65", waveHooks{})
	if res.Migrated != 1 {
		t.Fatalf("result = %+v, want migrated=1", res)
	}

	got := waveProgressNow(t, provider, store)
	if got.Migrated != 1 || got.Undelivered != 0 || got.ProgressPercent != 100 || got.Status != waveStatusDone {
		t.Fatalf("progress = %+v, want migrated=1 undelivered=0 100%% done", got)
	}
}

func TestWaveProgress_FailedDeliveryNotMigratedAndMigratedResultClears(t *testing.T) {
	ctx := context.Background()
	store := newTestWaveStore(t)
	w, err := store.CreateWave(ctx, MigrationWave{Name: "w", Members: []MigrationWaveMember{{Fingerprint: "old"}}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	d := waveDeps{waves: store}
	current := map[string]string{"old": "quantum_safe"}
	progress := func() WaveProgress {
		waves, _ := store.ListWaves(ctx)
		return computeWaveProgress(waves, current)[0]
	}

	d.recordMemberDelivery(ctx, w.ID, migrateWaveMemberResult{Fingerprint: "old", Status: pqc.MemberFailed, NewFingerprint: "new", Delivery: "failed"})
	if p := progress(); p.Migrated != 0 || p.Undelivered != 1 {
		t.Fatalf("failed delivery progress = %+v, want migrated=0 undelivered=1", p)
	}
	// A skipped or pre-issuance failure leaves the earlier mark alone.
	d.recordMemberDelivery(ctx, w.ID, migrateWaveMemberResult{Fingerprint: "old", Status: pqc.MemberSkipped})
	d.recordMemberDelivery(ctx, w.ID, migrateWaveMemberResult{Fingerprint: "old", Status: pqc.MemberFailed})
	if p := progress(); p.Undelivered != 1 {
		t.Fatalf("progress = %+v, want mark kept", p)
	}
	d.recordMemberDelivery(ctx, w.ID, migrateWaveMemberResult{Fingerprint: "old", Status: pqc.MemberMigrated, NewFingerprint: "new", Delivery: "verified"})
	if p := progress(); p.Migrated != 1 || p.Undelivered != 0 {
		t.Fatalf("verified delivery progress = %+v, want migrated=1 undelivered=0", p)
	}
}
