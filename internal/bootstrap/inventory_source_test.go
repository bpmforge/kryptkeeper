// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// W11-05: inventory sync — ADCS export files and the DigiCert CertCentral
// adapter (fixtures in the vendor-documented shape), idempotent by
// fingerprint, upstream revocation propagated. All through the production
// import path; zero live network.

func TestADCSExportSyncEndToEndAndIdempotent(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("export-%d.pem", i)),
			[]byte(estateTestCertPEM(t)), 0o600); err != nil {
			t.Fatalf("write export: %v", err)
		}
	}

	source, err := buildInventorySource(ctx, InventorySourceRecord{
		ID: "invsrc-adcs", Type: "adcs_export",
		ConfigJSON: `{"export_path":"` + dir + `"}`,
	}, nil)
	if err != nil {
		t.Fatalf("build source: %v", err)
	}

	result, err := syncInventorySource(ctx, source, "invsrc-adcs", provider)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if result.Synced != 2 || result.Skipped != 0 || len(result.Failed) != 0 {
		t.Fatalf("first sync wrong: %+v", result)
	}

	// Synced certs are origin=synced / management_state=external — the
	// upstream CA manages them until a takeover says otherwise.
	listed, err := provider.ListCertificates(ctx, CertificateListQuery{Origin: "synced", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if listed.Total != 2 || listed.Items[0].ManagementState != "external" {
		t.Fatalf("estate stamp wrong: total=%d %+v", listed.Total, listed.Items[0])
	}
	if listed.Items[0].IssuerCN == "" {
		t.Fatal("issuer metadata lost in sync")
	}

	// Re-sync: everything already known by fingerprint — idempotent.
	result2, err := syncInventorySource(ctx, source, "invsrc-adcs", provider)
	if err != nil {
		t.Fatalf("re-sync: %v", err)
	}
	if result2.Synced != 0 || result2.Skipped != 2 {
		t.Fatalf("re-sync not idempotent: %+v", result2)
	}
}

// newDigicertFixtureServer serves the CertCentral shapes the vendor docs
// describe (dev.digicert.com, fetched 2026-08-18): the order listing and the
// per-certificate PEM download, gated on the X-DC-DEVKEY header.
func newDigicertFixtureServer(t *testing.T, issuedPEM, revokedPEM string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	requireKey := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-DC-DEVKEY") != "fixture-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("/services/v2/order/certificate", func(w http.ResponseWriter, r *http.Request) {
		if !requireKey(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"orders":[
			{"id":101,"status":"issued","certificate":{"id":9001,"common_name":"issued.example.com"}},
			{"id":102,"status":"revoked","certificate":{"id":9002,"common_name":"revoked.example.com"}},
			{"id":103,"status":"pending","certificate":{"id":0}}
		]}`))
	})
	mux.HandleFunc("/services/v2/certificate/9001/download/format/pem", func(w http.ResponseWriter, r *http.Request) {
		if !requireKey(w, r) {
			return
		}
		_, _ = w.Write([]byte(issuedPEM))
	})
	mux.HandleFunc("/services/v2/certificate/9002/download/format/pem", func(w http.ResponseWriter, r *http.Request) {
		if !requireKey(w, r) {
			return
		}
		_, _ = w.Write([]byte(revokedPEM))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestDigicertSyncPropagatesUpstreamRevocation(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issuedPEM := estateTestCertPEM(t)
	revokedPEM := estateTestCertPEM(t)
	ts := newDigicertFixtureServer(t, issuedPEM, revokedPEM)

	creds := &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-dc", CredentialType: CredentialTypeAPIToken},
		payload: []byte("fixture-api-key"),
	}
	source, err := buildInventorySource(ctx, InventorySourceRecord{
		ID: "invsrc-dc", Type: "digicert",
		ConfigJSON:    `{"base_url":"` + ts.URL + `"}`,
		CredentialRef: "cred-dc",
	}, creds)
	if err != nil {
		t.Fatalf("build source: %v", err)
	}

	result, err := syncInventorySource(ctx, source, "invsrc-dc", provider)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// Two issued certs synced (the pending order has no certificate id and
	// is skipped upstream of import); one carries upstream revocation.
	if result.Synced != 2 || result.RevokedMarked != 1 {
		t.Fatalf("digicert sync wrong: %+v", result)
	}

	revokedFP := agentFingerprintOfPEM(revokedPEM)
	item, ok, err := provider.GetCertificate(ctx, revokedFP)
	if err != nil || !ok {
		t.Fatalf("revoked cert not in inventory: ok=%v err=%v", ok, err)
	}
	if item.RenewalStatus != "revoked" || item.Origin != "synced" || item.ManagementState != "external" {
		t.Fatalf("upstream revocation not propagated: status=%q origin=%q state=%q",
			item.RenewalStatus, item.Origin, item.ManagementState)
	}
}

func TestDigicertSourceRequiresCredential(t *testing.T) {
	_, err := buildInventorySource(context.Background(), InventorySourceRecord{
		ID: "invsrc-x", Type: "digicert", ConfigJSON: `{}`,
	}, nil)
	if err == nil {
		t.Fatal("digicert source without a credential must be unbuildable")
	}
}

func TestInventorySourceStoreRoundTrip(t *testing.T) {
	store := newInventorySourceTestStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, InventorySourceRecord{
		ID: "invsrc-1", Name: "Corp ADCS", Type: "adcs_export",
		ConfigJSON: `{"export_path":"/exports"}`, ScheduleMinutes: 60,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.RecordSync(ctx, created.ID, "2026-08-18T00:00:00Z", `{"synced":3}`); err != nil {
		t.Fatalf("record sync: %v", err)
	}
	got, err := store.Get(ctx, created.ID)
	if err != nil || got.LastSyncAt != "2026-08-18T00:00:00Z" || got.LastSyncResult != `{"synced":3}` || got.ScheduleMinutes != 60 {
		t.Fatalf("round-trip wrong: %+v %v", got, err)
	}
	if _, err := store.Create(ctx, InventorySourceRecord{ID: "invsrc-2", Name: "x", Type: "nope"}); err == nil {
		t.Fatal("invalid type accepted")
	}
}

func newInventorySourceTestStore(t *testing.T) InventorySourceStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "inventory-sources.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := newInventorySourceStore(db, false)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return store
}

// --- W24-29: HA lock + scale ------------------------------------------------

type countingSyncSource struct {
	mu      sync.Mutex
	fetches int
	certs   []SyncedCertificate
}

func (c *countingSyncSource) Fetch(context.Context) ([]SyncedCertificate, error) {
	c.mu.Lock()
	c.fetches++
	c.mu.Unlock()
	return c.certs, nil
}

func (c *countingSyncSource) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches
}

// fakeSyncProvider embeds a nil interface on purpose: only the two methods
// below may be called; anything else panics, signalling that
// syncInventorySource grew a new dependency.
type fakeSyncProvider struct {
	CertificateProvider
	mu   sync.Mutex
	seen map[string]bool
}

func newFakeSyncProvider() *fakeSyncProvider { return &fakeSyncProvider{seen: map[string]bool{}} }

func (p *fakeSyncProvider) ImportCertificate(_ context.Context, r CertificateImportRequest) (CertificateIssueResult, error) {
	fp := agentFingerprintOfPEM(r.CertificatePEM)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[fp] {
		return CertificateIssueResult{}, errCertificateConflict
	}
	p.seen[fp] = true
	return CertificateIssueResult{CertificateItem: CertificateItem{FingerprintSHA256: fp}}, nil
}

func (p *fakeSyncProvider) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	return CertificateDetail{CertificateItem: CertificateItem{FingerprintSHA256: fp, ManagementState: "external"}}, true, nil
}

func (p *fakeSyncProvider) UpdateEstate(context.Context, string, EstateUpdate) (CertificateItem, error) {
	return CertificateItem{}, nil
}

// staleListStore returns a snapshot taken before another replica synced, so
// the source still looks due and only the lock can stop a second sync.
type staleListStore struct {
	InventorySourceStore
	snapshot []InventorySourceRecord
}

func (s staleListStore) List(context.Context) ([]InventorySourceRecord, error) {
	return s.snapshot, nil
}

func syncTestCerts(t *testing.T, n int) []SyncedCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	out := make([]SyncedCertificate, n)
	for i := range out {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i) + 1),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("sync-%d.example.com", i)},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("create cert %d: %v", i, err)
		}
		out[i] = SyncedCertificate{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), UpstreamStatus: "active"}
	}
	return out
}

func withSyncSource(t *testing.T, src InventorySource) {
	t.Helper()
	orig := newInventorySourceForSync
	newInventorySourceForSync = func(context.Context, InventorySourceRecord, OutboundCredentialStore) (InventorySource, error) {
		return src, nil
	}
	t.Cleanup(func() { newInventorySourceForSync = orig })
}

func seedSyncSources(t *testing.T, store InventorySourceStore, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if _, err := store.Create(context.Background(), InventorySourceRecord{ID: id, Name: id, Type: "adcs_export", ScheduleMinutes: 60}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
}

func twoReplicaSchedulers(t *testing.T, ha bool, ids ...string) (*InventorySyncScheduler, *InventorySyncScheduler, InventorySourceStore) {
	t.Helper()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	store := newInventorySourceTestStore(t)
	seedSyncSources(t, store, ids...)
	snapshot, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	provider := newFakeSyncProvider()
	s1 := &InventorySyncScheduler{store: store, provider: provider, now: func() time.Time { return at }}
	s2 := &InventorySyncScheduler{store: staleListStore{InventorySourceStore: store, snapshot: snapshot}, provider: provider, now: func() time.Time { return at }}
	if ha {
		db := newTestHADB(t)
		s1.haCoordinator = newTestHACoordinatorAt(t, db, "r1", at)
		s2.haCoordinator = newTestHACoordinatorAt(t, db, "r2", at)
	}
	return s1, s2, store
}

func TestInventorySyncSchedulersShareOneSyncPerInterval(t *testing.T) {
	for _, ids := range [][]string{{"src-a"}, {"src-a", "src-b"}} {
		src := &countingSyncSource{certs: syncTestCerts(t, 1)}
		withSyncSource(t, src)
		s1, s2, store := twoReplicaSchedulers(t, true, ids...)
		s1.runDue(context.Background())
		s2.runDue(context.Background())
		if got := src.count(); got != len(ids) {
			t.Fatalf("%d sources: %d fetches, want exactly one per source", len(ids), got)
		}
		for _, id := range ids {
			rec, err := store.Get(context.Background(), id)
			if err != nil || rec.LastSyncAt == "" || rec.LastSyncResult == "" {
				t.Fatalf("RecordSync not populated for %s: %+v %v", id, rec, err)
			}
		}
	}

	// Control: without a coordinator both replicas sync (the bug being fixed).
	src := &countingSyncSource{certs: syncTestCerts(t, 1)}
	withSyncSource(t, src)
	s1, s2, _ := twoReplicaSchedulers(t, false, "src-a")
	s1.runDue(context.Background())
	s2.runDue(context.Background())
	if got := src.count(); got != 2 {
		t.Fatalf("control (no lock): %d fetches, want 2", got)
	}
}

func TestInventorySyncSchedulerNilCoordinatorStillRuns(t *testing.T) {
	src := &countingSyncSource{certs: syncTestCerts(t, 1)}
	withSyncSource(t, src)
	s1, _, _ := twoReplicaSchedulers(t, false, "src-a")
	s1.runDue(context.Background())
	if src.count() != 1 {
		t.Fatalf("fetches=%d, want 1", src.count())
	}
}

func TestInventorySyncSchedulerLockErrorFailsClosed(t *testing.T) {
	src := &countingSyncSource{certs: syncTestCerts(t, 1)}
	withSyncSource(t, src)
	s1, _, _ := twoReplicaSchedulers(t, true, "src-a")
	db := newTestHADB(t)
	s1.haCoordinator = newTestHACoordinatorAt(t, db, "r1", time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC))
	db.Close()
	s1.runDue(context.Background())
	if src.count() != 0 {
		t.Fatalf("lock error must fail closed, fetches=%d", src.count())
	}
}

func TestInventorySync10kSecondSyncAddsNoDuplicates(t *testing.T) {
	src := &countingSyncSource{certs: syncTestCerts(t, 10000)}
	provider := newFakeSyncProvider()
	ctx := context.Background()

	start := time.Now()
	first, err := syncInventorySource(ctx, src, "src-10k", provider)
	if err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	if first.Synced != 10000 || first.Skipped != 0 || len(first.Failed) != 0 {
		t.Fatalf("sync 1: %+v", first)
	}
	second, err := syncInventorySource(ctx, src, "src-10k", provider)
	if err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	elapsed := time.Since(start)
	if second.Synced != 0 || second.Skipped != 10000 {
		t.Fatalf("sync 2: %+v", second)
	}
	if len(provider.seen) != 10000 {
		t.Fatalf("distinct certs imported: %d", len(provider.seen))
	}
	if elapsed >= 10*time.Minute {
		t.Fatalf("10k double sync took %s", elapsed)
	}
	t.Logf("10k fake-provider sync x2: %s", elapsed)
}

func TestInventorySync1kRealProviderRate(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	src := &countingSyncSource{certs: syncTestCerts(t, 1000)}
	ctx := context.Background()

	start := time.Now()
	first, err := syncInventorySource(ctx, src, "src-1k", provider)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	if first.Synced != 1000 || len(first.Failed) != 0 {
		t.Fatalf("sync 1: %+v", first)
	}
	if elapsed >= 60*time.Second {
		t.Fatalf("1k real-provider sync took %s", elapsed)
	}
	t.Logf("1k real-provider sync: %s = %.1f certs/sec; projected 10k: %s",
		elapsed, 1000/elapsed.Seconds(), time.Duration(float64(elapsed)*10))
	second, err := syncInventorySource(ctx, src, "src-1k", provider)
	if err != nil || second.Synced != 0 {
		t.Fatalf("sync 2: %+v %v", second, err)
	}
}

// B3 (ADCS cutover rehearsal): a re-sync must never undo a takeover. A
// certificate the operator took over stays managed; only new or unmanaged
// rows are stamped external.
func TestInventoryResyncKeepsTakenOverCertificateManaged(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("export-%d.pem", i)), []byte(estateTestCertPEM(t)), 0o600); err != nil {
			t.Fatalf("write export: %v", err)
		}
	}
	source, err := buildInventorySource(ctx, InventorySourceRecord{ID: "invsrc-adcs", Type: "adcs_export",
		ConfigJSON: `{"export_path":"` + dir + `"}`}, nil)
	if err != nil {
		t.Fatalf("build source: %v", err)
	}
	if _, err := syncInventorySource(ctx, source, "invsrc-adcs", provider); err != nil {
		t.Fatalf("sync: %v", err)
	}
	listed, err := provider.ListCertificates(ctx, CertificateListQuery{Origin: "synced", Limit: 10})
	if err != nil || listed.Total != 2 {
		t.Fatalf("list: %v %+v", err, listed)
	}
	taken, other := listed.Items[0].FingerprintSHA256, listed.Items[1].FingerprintSHA256
	if _, err := provider.UpdateEstate(ctx, taken, EstateUpdate{ManagementState: "managed", RenewalMethod: "api"}); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if _, err := provider.UpdateEstate(ctx, other, EstateUpdate{ManagementState: "unmanaged"}); err != nil {
		t.Fatalf("unmanage: %v", err)
	}

	if _, err := syncInventorySource(ctx, source, "invsrc-adcs", provider); err != nil {
		t.Fatalf("re-sync: %v", err)
	}
	state := func(fp string) string {
		d, ok, err := provider.GetCertificate(ctx, fp)
		if err != nil || !ok {
			t.Fatalf("get %s: %v %v", fp, ok, err)
		}
		return d.ManagementState
	}
	if got := state(taken); got != "managed" {
		t.Fatalf("re-sync reverted a taken-over certificate to %q", got)
	}
	if got := state(other); got != "external" {
		t.Fatalf("unmanaged synced certificate: %q, want external", got)
	}
}
