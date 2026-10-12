// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
