// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// Second sweep of live-Postgres round trips (see db_providers_postgres_test.go
// for the rationale): every remaining store that has a Postgres branch. Each
// test migrates first (the "ca" boot order) and exercises create/read/update/
// delete or the closest equivalents.

func TestApprovalStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s, err := newApprovalStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	req := ApprovalRequest{ID: "apr-1", TemplateID: "tpl", CAID: "ca-1", Requester: "alice", Status: "pending",
		CSRPEM: "csr", RequestedAt: now}
	if err := s.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, "apr-1")
	if err != nil || got.Requester != "alice" {
		t.Fatalf("Get: %+v %v", got, err)
	}
	list, total, err := s.List(ctx, "pending", 10, 0)
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("List: %+v %d %v", list, total, err)
	}
	if err := s.Decide(ctx, "apr-1", "bob", "approved", ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if err := s.SetIssued(ctx, "apr-1", "fp"); err != nil {
		t.Fatalf("SetIssued: %v", err)
	}
	got, err = s.Get(ctx, "apr-1")
	if err != nil || got.Status != "approved" || got.DecidedBy == nil || got.IssuedFingerprint == nil {
		t.Fatalf("after decide: %+v %v", got, err)
	}
}

func TestConfigStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "pg-test-passphrase-32-bytes-long!!")
	s := newConfigStoreFromEnv()
	ctx := context.Background()
	if err := s.Set(ctx, "discovery.provider", "scanner", "tester"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set(ctx, "discovery.provider", "db", "tester"); err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	e, ok, err := s.Get(ctx, "discovery.provider")
	if err != nil || !ok || e.Value != "db" {
		t.Fatalf("Get: %+v ok=%v err=%v", e, ok, err)
	}
	if l, err := s.List(ctx); err != nil || len(l) == 0 {
		t.Fatalf("List: %+v %v", l, err)
	}
}

func TestConnectorStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := newConnectorStoreFromEnv()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	rec, err := s.Create(ctx, ConnectorRecord{ID: "con-1", Name: "internal", Type: "internal", ConfigJSON: "{}",
		Tenant: "default", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := s.Get(ctx, rec.ID); err != nil || got.Name != "internal" {
		t.Fatalf("Get: %+v %v", got, err)
	}
	if l, err := s.List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	if err := s.Delete(ctx, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestFindingExceptionStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	exc := FindingException{ID: "fe-1", TargetType: "certificate", TargetID: "fp-1", FindingCode: "WEAK_KEY",
		JustificationCode: "risk_accepted", JustificationNote: "n", CreatedBy: "alice",
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339)}
	if err := s.Create(ctx, exc); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := s.Get(ctx, "fe-1"); err != nil || got.FindingCode != "WEAK_KEY" {
		t.Fatalf("Get: %+v %v", got, err)
	}
	if l, err := s.ListForTarget(ctx, "certificate", "fp-1"); err != nil || len(l) != 1 {
		t.Fatalf("ListForTarget: %+v %v", l, err)
	}
	if l, err := s.ListActive(ctx, now); err != nil || len(l) != 1 {
		t.Fatalf("ListActive: %+v %v", l, err)
	}
}

func TestTenantStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewTenantStoreFromEnv()
	ctx := context.Background()
	if _, err := s.CreateTenant(ctx, "acme", "Acme"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if l, err := s.ListTenants(ctx); err != nil || len(l) == 0 {
		t.Fatalf("ListTenants: %+v %v", l, err)
	}
	if ok, err := s.TenantExists(ctx, "acme"); err != nil || !ok {
		t.Fatalf("TenantExists: %v %v", ok, err)
	}
	if err := s.SetCATenant(ctx, "ca-1", "acme"); err != nil {
		t.Fatalf("SetCATenant: %v", err)
	}
	if id, err := s.CATenant(ctx, "ca-1"); err != nil || id != "acme" {
		t.Fatalf("CATenant: %q %v", id, err)
	}
	if m, err := s.CAIDsForTenant(ctx, "acme"); err != nil || !m["ca-1"] {
		t.Fatalf("CAIDsForTenant: %v %v", m, err)
	}
}

func TestSCIMGroupStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := newSCIMGroupStoreFromEnv()
	ctx := context.Background()
	if _, err := s.Create(ctx, "grp-1", "Admins", time.Now().UTC()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g, ok, err := s.Get(ctx, "grp-1"); err != nil || !ok || g.DisplayName != "Admins" {
		t.Fatalf("Get: %+v ok=%v err=%v", g, ok, err)
	}
	if err := s.AddMember(ctx, "grp-1", "usr-1"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if m, err := s.Members(ctx, "grp-1"); err != nil || len(m) != 1 {
		t.Fatalf("Members: %v %v", m, err)
	}
	if l, err := s.List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	if err := s.RemoveMember(ctx, "grp-1", "usr-1"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := s.Delete(ctx, "grp-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestOutboundCredentialStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "pg-test-passphrase-32-bytes-long!!")
	s := newOutboundCredentialStoreFromEnv()
	if s == nil {
		t.Fatal("nil outbound credential store")
	}
	ctx := context.Background()
	meta, err := s.Create(ctx, "cred-1", "ssh key", "ssh_key", "default", []byte("secret"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := s.Get(ctx, meta.ID); err != nil || got.Name != "ssh key" {
		t.Fatalf("Get: %+v %v", got, err)
	}
	if l, err := s.List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	if err := s.Delete(ctx, meta.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestNHIStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewNHIStoreFromEnv()
	ctx := context.Background()
	n, err := s.Create(ctx, NHIIdentity{ID: "nhi-1", Name: "svc", Kind: "workload", SPIFFEID: "spiffe://x/y",
		Scopes: []string{"a"}, Status: "pending", CreatedBy: "alice", CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Decide(ctx, n.ID, "approved", "bob"); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got, ok, err := s.Get(ctx, n.ID)
	if err != nil || !ok || got.Status != "approved" || len(got.Scopes) != 1 {
		t.Fatalf("Get: %+v ok=%v err=%v", got, ok, err)
	}
	if l, err := s.List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
}

func TestEvidenceScheduleStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewEvidenceScheduleStoreFromEnv()
	ctx := context.Background()
	es, err := s.Create(ctx, EvidenceSchedule{ID: "ev-1", Framework: "pci", Cadence: "weekly",
		Recipients: []string{"a@example.com"}, Enabled: true, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkSent(ctx, es.ID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	l, err := s.List(ctx)
	if err != nil || len(l) != 1 || !l[0].Enabled || l[0].LastSentAt == "" {
		t.Fatalf("List: %+v %v", l, err)
	}
	if err := s.Delete(ctx, es.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestMigrationWaveStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewMigrationWaveStoreFromEnv()
	ctx := context.Background()
	w, err := s.CreateWave(ctx, MigrationWave{ID: "w-1", Name: "wave", Owner: "alice",
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Status: "proposed"})
	if err != nil {
		t.Fatalf("CreateWave: %v", err)
	}
	if err := s.AddMember(ctx, w.ID, MigrationWaveMember{Fingerprint: "fp1", CommonName: "a"}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := s.UpdateWaveStatus(ctx, w.ID, "accepted"); err != nil {
		t.Fatalf("UpdateWaveStatus: %v", err)
	}
	l, err := s.ListWaves(ctx)
	if err != nil || len(l) != 1 || l[0].Status != "accepted" || len(l[0].Members) != 1 {
		t.Fatalf("ListWaves: %+v %v", l, err)
	}
	if err := s.RemoveMember(ctx, w.ID, "fp1"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := s.DeleteWave(ctx, w.ID); err != nil {
		t.Fatalf("DeleteWave: %v", err)
	}
	if err := s.DeleteAllWaves(ctx); err != nil {
		t.Fatalf("DeleteAllWaves: %v", err)
	}
}

func TestPostureSnapshotStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s, err := NewPostureSnapshotStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	at := time.Now().UTC().Format(time.RFC3339)
	if err := s.Save(ctx, PostureSnapshot{ID: "psn-1", CapturedAt: at, TotalCerts: 3, PQCScorePercent: 10}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if l, err := s.List(ctx, "", 10); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	if l, err := s.List(ctx, "2000-01-01T00:00:00Z", 10); err != nil || len(l) != 1 {
		t.Fatalf("List since: %+v %v", l, err)
	}
	if snap, ok, err := s.Latest(ctx); err != nil || !ok || snap.TotalCerts != 3 {
		t.Fatalf("Latest: %+v ok=%v err=%v", snap, ok, err)
	}
}

func TestInventorySourceStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := newInventorySourceStoreFromEnv()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	rec, err := s.Create(ctx, InventorySourceRecord{ID: "inv-1", Name: "src", Type: "digicert", ConfigJSON: "{}",
		ScheduleMinutes: 60, Tenant: "default", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.RecordSync(ctx, rec.ID, now, "ok"); err != nil {
		t.Fatalf("RecordSync: %v", err)
	}
	got, err := s.Get(ctx, rec.ID)
	if err != nil || got.LastSyncResult != "ok" {
		t.Fatalf("Get: %+v %v", got, err)
	}
	if l, err := s.List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	if err := s.Delete(ctx, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestNotificationSilenceStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s, err := newNotificationSilenceStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Create(ctx, NotificationSilence{ID: "sil-1", TargetType: "certificate", TargetID: "fp-1",
		CreatedBy: "alice", CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ok, err := s.IsSilenced(ctx, "certificate", "fp-1"); err != nil || !ok {
		t.Fatalf("IsSilenced: %v %v", ok, err)
	}
	if l, err := s.ListForTarget(ctx, "certificate", "fp-1"); err != nil || len(l) != 1 {
		t.Fatalf("ListForTarget: %+v %v", l, err)
	}
	if err := s.Delete(ctx, "sil-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestRenewalAlertCooldownStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s, err := newRenewalAlertCooldownStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, ok, err := s.LastAlertedAt(ctx, "fp-1"); err != nil || ok {
		t.Fatalf("LastAlertedAt empty: ok=%v err=%v", ok, err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := s.RecordAlerted(ctx, "fp-1", at); err != nil {
		t.Fatalf("RecordAlerted: %v", err)
	}
	if err := s.RecordAlerted(ctx, "fp-1", at.Add(time.Minute)); err != nil {
		t.Fatalf("RecordAlerted (upsert): %v", err)
	}
	got, ok, err := s.LastAlertedAt(ctx, "fp-1")
	if err != nil || !ok || !got.Equal(at.Add(time.Minute)) {
		t.Fatalf("LastAlertedAt: %v ok=%v err=%v", got, ok, err)
	}
}

func TestCustomRoleStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewCustomRoleStoreFromEnv()
	if s == nil {
		t.Fatal("nil custom role store")
	}
	if _, err := s.CreateRole(CustomRole{Name: "auditor-plus", Description: "d", Permissions: []string{"certificate.read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if r, ok, err := s.GetRole("auditor-plus"); err != nil || !ok || len(r.Permissions) != 1 {
		t.Fatalf("GetRole: %+v ok=%v err=%v", r, ok, err)
	}
	if ok, err := s.RoleHasPermission("auditor-plus", "certificate.read"); err != nil || !ok {
		t.Fatalf("RoleHasPermission: %v %v", ok, err)
	}
	if l, err := s.ListRoles(); err != nil || len(l) != 1 {
		t.Fatalf("ListRoles: %+v %v", l, err)
	}
	if err := s.DeleteRole("auditor-plus"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
}

func TestSSHCertStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := newSSHCertStoreFromEnv()
	if s == nil {
		t.Fatal("nil ssh cert store")
	}
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	rec := SSHCertRecord{Serial: "1", CertType: "user", KeyID: "kid", Principals: []string{"alice"},
		ValidAfter: now, ValidBefore: now, SubjectFingerprint: "sfp", AuthorityFingerprint: "afp",
		CertificateLine: "ssh-ed25519-cert-v01@openssh.com AAAA", Tenant: "default", CreatedAt: now, TemplateID: "tpl"}
	if err := s.insert(ctx, rec); err != nil {
		t.Fatalf("insert: %v", err)
	}
	l, err := s.list(ctx, "sfp")
	if err != nil || len(l) != 1 || l[0].TemplateID != "tpl" || len(l[0].Principals) != 1 {
		t.Fatalf("list: %+v %v", l, err)
	}
}
