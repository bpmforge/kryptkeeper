// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
)

// haPair is two hub replicas on one database: the HA topology the in-memory
// inventory used to break (a certificate written by one never reached the
// other until it restarted).
type haPair struct {
	a, b *caCertificateProvider
	caID string
	db   *sql.DB
	pg   bool
}

func newHAPair(t *testing.T, db *sql.DB, postgres bool) haPair {
	t.Helper()
	keysA, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engineA := ca.NewEngine(keysA, ca.NewDBStore(db, postgres))
	root, err := engineA.CreateRootCA("HA Root", pkix.Name{CommonName: "HA Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	t.Cleanup(func() {
		if postgres {
			_, _ = db.Exec(`DELETE FROM certificates WHERE ca_id = $1`, root.ID)
			_, _ = db.Exec(`DELETE FROM certificate_authorities WHERE id = $1`, root.ID)
		}
	})
	// B is a separate process with its own keystore; it never signs here.
	keysB, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engineB := ca.NewEngine(keysB, ca.NewDBStore(db, postgres))

	mk := func(e *ca.Engine) *caCertificateProvider {
		p := NewCACertificateProvider(e, ca.NewDBRevocationStore(db, postgres), db, postgres).(*caCertificateProvider)
		p.discoveryRefreshEvery = 0
		return p
	}
	// Both providers hydrate before anything is issued, as two replicas that
	// have been up for a while would.
	return haPair{a: mk(engineA), b: mk(engineB), caID: root.ID, db: db, pg: postgres}
}

func (h haPair) issueOnA(t *testing.T, cn string) CertificateItem {
	t.Helper()
	res, err := h.a.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: h.caID, CSRPEM: generateTestCSRPEM(t, cn, cn), TemplateID: "tpl-ha", TeamID: "team-ha",
	})
	if err != nil {
		t.Fatalf("issue on A: %v", err)
	}
	return res.CertificateItem
}

func (h haPair) ph(n int) string {
	if h.pg {
		return "$" + string(rune('0'+n))
	}
	return "?"
}

func runHAPeerVisibilityCase(t *testing.T, db *sql.DB, postgres bool) {
	h := newHAPair(t, db, postgres)
	ctx := context.Background()
	query := CertificateListQuery{TeamID: "team-ha"}

	// Both replicas hydrated empty: this is the state the bug lives in.
	if got, _ := h.b.ListCertificates(ctx, query); got.Total != 0 {
		t.Fatalf("precondition: B should be empty, has %d", got.Total)
	}

	t.Run("issue on A lists on B without restart", func(t *testing.T) {
		issued := h.issueOnA(t, "list.example.com")
		res, err := h.b.ListCertificates(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		if findCertByFingerprint(res.Items, issued.FingerprintSHA256) == nil {
			t.Fatalf("B does not list the certificate A issued: %+v", res)
		}
	})

	t.Run("issue on A is served by fingerprint on B before any refresh", func(t *testing.T) {
		issued := h.issueOnA(t, "readthrough.example.com")
		fp := issued.FingerprintSHA256
		// A hour-long throttle with a refresh just done proves the lookup
		// below did not ride on the periodic refresh.
		h.b.discoveryRefreshEvery = time.Hour
		h.b.lastTableRefresh = time.Now()
		defer func() { h.b.discoveryRefreshEvery = 0 }()

		got, found, err := h.b.GetCertificate(ctx, fp)
		if err != nil || !found || got.CommonName != "readthrough.example.com" {
			t.Fatalf("GetCertificate on B: found=%v err=%v item=%+v", found, err, got.CertificateItem)
		}
		chain, found, err := h.b.GetCertificateChain(ctx, fp)
		if err != nil || !found || chain.CurrentFingerprint != fp {
			t.Fatalf("GetCertificateChain on B: found=%v err=%v", found, err)
		}
		dl, err := h.b.DownloadCertificate(ctx, fp, "pem", false)
		if err != nil || len(dl.Body) == 0 {
			t.Fatalf("DownloadCertificate on B: err=%v", err)
		}
		if _, found, _ := h.b.GetCertificate(ctx, "00ff"); found {
			t.Fatal("unknown fingerprint must still be not found")
		}
	})

	t.Run("revoke on A shows revoked on B", func(t *testing.T) {
		issued := h.issueOnA(t, "revoke.example.com")
		fp := issued.FingerprintSHA256
		if _, found, _ := h.b.GetCertificate(ctx, fp); !found {
			t.Fatal("B should have loaded the certificate")
		}
		// Issue and revoke land in the same second, so the revoked row's
		// updated_at can equal B's copy: revocation must win regardless.
		if _, err := h.a.RevokeCertificate(ctx, fp, CertificateRevokeRequest{ReasonCode: 1}); err != nil {
			t.Fatalf("revoke on A: %v", err)
		}
		got, _, _ := h.b.GetCertificate(ctx, fp)
		if got.RevokedAt == nil || got.RenewalStatus != string(RenewalStatusRevoked) {
			t.Fatalf("B still shows the certificate as live: revoked_at=%v status=%q", got.RevokedAt, got.RenewalStatus)
		}
		if _, err := h.b.RevokeCertificate(ctx, fp, CertificateRevokeRequest{ReasonCode: 1}); !errors.Is(err, errCertificateConflict) {
			t.Fatalf("second revoke via B = %v, want conflict", err)
		}
		active, _ := h.b.ActiveCertCountsByCA(ctx)
		if active[h.caID] != 2 { // two earlier subtests issued; this one is issued then revoked
			t.Errorf("active count on B = %d, want 2 (index must follow the replaced copy)", active[h.caID])
		}
	})

	t.Run("peer ownership edit replaces an older copy", func(t *testing.T) {
		issued := h.issueOnA(t, "owner.example.com")
		fp := issued.FingerprintSHA256
		_, _, _ = h.b.GetCertificate(ctx, fp)
		// A's edit must carry a later updated_at than B's copy.
		time.Sleep(1100 * time.Millisecond)
		if _, err := h.a.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerEmail: "ops@example.com", ServiceName: "svc"}); err != nil {
			t.Fatal(err)
		}
		got, _, _ := h.b.GetCertificate(ctx, fp)
		if got.OwnerEmail != "ops@example.com" || got.ServiceName != "svc" {
			t.Fatalf("B did not pick up A's ownership edit: %+v", got.CertificateItem)
		}
	})

	t.Run("renewal on A marks the predecessor renewed on B", func(t *testing.T) {
		issued := h.issueOnA(t, "renew.example.com")
		_, _, _ = h.b.GetCertificate(ctx, issued.FingerprintSHA256)
		time.Sleep(1100 * time.Millisecond)
		renewed, err := h.a.RenewCertificate(ctx, issued.FingerprintSHA256, CertificateRenewRequest{CSRPEM: generateTestCSRPEM(t, "renew.example.com", "renew.example.com")})
		if err != nil {
			t.Fatalf("renew on A: %v", err)
		}
		pred, _, _ := h.b.GetCertificate(ctx, issued.FingerprintSHA256)
		if pred.RenewalStatus != string(RenewalStatusRenewed) || pred.SuccessorFP == nil || *pred.SuccessorFP != renewed.FingerprintSHA256 {
			t.Fatalf("B's predecessor not linked: status=%q successor=%v", pred.RenewalStatus, pred.SuccessorFP)
		}
		succ, found, _ := h.b.GetCertificate(ctx, renewed.FingerprintSHA256)
		if !found || succ.PredecessorFP == nil || *succ.PredecessorFP != issued.FingerprintSHA256 {
			t.Fatalf("B's successor not linked: found=%v pred=%v", found, succ.PredecessorFP)
		}
		_, err = h.b.RenewCertificate(ctx, issued.FingerprintSHA256, CertificateRenewRequest{CSRPEM: generateTestCSRPEM(t, "renew.example.com", "renew.example.com")})
		if !errors.Is(err, errCertificateConflict) {
			t.Fatalf("second renewal via B = %v, want conflict", err)
		}
	})

	t.Run("discovery row never replaces a managed certificate", func(t *testing.T) {
		issued := h.issueOnA(t, "managed.example.com")
		fp := issued.FingerprintSHA256
		_, _, _ = h.b.GetCertificate(ctx, fp)
		time.Sleep(1100 * time.Millisecond)
		upd := `UPDATE certificates SET source='discovery_network', management_state='unmanaged', origin='discovered', owner_team=` + h.ph(1) + `, updated_at=` + h.ph(2) + ` WHERE fingerprint_sha256=` + h.ph(3)
		if _, err := db.Exec(upd, "scanner", time.Now().UTC().Add(time.Minute).Format(time.RFC3339), fp); err != nil {
			t.Fatalf("simulate discovery rewrite: %v", err)
		}
		h.b.refreshFromTable()
		got, _, _ := h.b.GetCertificate(ctx, fp)
		if got.ManagementState != "managed" || got.OwnerTeam == "scanner" || got.Source == "discovery_network" {
			t.Fatalf("discovery demoted a managed certificate on B: %+v", got.CertificateItem)
		}
	})

	t.Run("stale row does not overwrite a newer in-memory copy", func(t *testing.T) {
		issued := h.issueOnA(t, "stale.example.com")
		fp := issued.FingerprintSHA256
		if _, err := h.b.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerEmail: "new@example.com"}); err != nil {
			t.Fatal(err)
		}
		rows, err := h.b.queryCerts(" WHERE fingerprint_sha256 = "+h.ph(1), fp)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read row: %v (%d)", err, len(rows))
		}
		stale := rows[0]
		stale.item.OwnerEmail = "stale@example.com"
		stale.item.UpdatedAt = "2001-01-01T00:00:00Z"
		h.b.mergeRows([]*storedCert{stale})
		got, _, _ := h.b.GetCertificate(ctx, fp)
		if got.OwnerEmail != "new@example.com" {
			t.Fatalf("stale row overwrote a newer copy: owner=%q", got.OwnerEmail)
		}
	})
}

func TestHA_PeerVisibility_SQLite(t *testing.T) {
	runHAPeerVisibilityCase(t, setupIntegrationDB(t), false)
}

func TestHA_PeerVisibility_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	runHAPeerVisibilityCase(t, db, true)
}

func TestRowSupersedes(t *testing.T) {
	rev := "2026-01-01T00:00:00Z"
	cases := []struct {
		name         string
		existing, in CertificateItem
		want         bool
	}{
		{"newer wins", CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z"}, CertificateItem{UpdatedAt: "2026-01-01T00:00:01Z"}, true},
		{"tie keeps local", CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z"}, CertificateItem{UpdatedAt: "2026-01-01T00:00:00.000Z"}, false},
		{"fractional vs whole second", CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z"}, CertificateItem{UpdatedAt: "2026-01-01T00:00:00.500Z"}, true},
		{"older loses", CertificateItem{UpdatedAt: "2026-01-01T00:00:05Z"}, CertificateItem{UpdatedAt: "2026-01-01T00:00:01Z"}, false},
		{"revocation beats an equal timestamp", CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z"}, CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z", RevokedAt: &rev}, true},
		{"discovery cannot demote managed",
			CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z", ManagementState: "managed"},
			CertificateItem{UpdatedAt: "2027-01-01T00:00:00Z", Source: "discovery_network", ManagementState: "unmanaged"}, false},
		{"discovery cannot revoke-replace managed",
			CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z", ManagementState: "managed"},
			CertificateItem{UpdatedAt: "2027-01-01T00:00:00Z", Source: "discovery_network", ManagementState: "unmanaged", RevokedAt: &rev}, false},
		{"peer managed row replaces",
			CertificateItem{UpdatedAt: "2026-01-01T00:00:00Z", ManagementState: "managed"},
			CertificateItem{UpdatedAt: "2026-01-01T00:00:09Z", Source: "api", ManagementState: "managed"}, true},
	}
	for _, c := range cases {
		if got := rowSupersedes(&c.existing, &c.in); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// W30-25/26: a refresh window that covers rows B already holds must fetch none
// of them in full, but must still fetch a peer's new row and a peer's revocation
// of a row with an equal updated_at.
func TestQueryChangedCerts_SkipsRowsAlreadyHeld(t *testing.T) {
	db := setupIntegrationDB(t)
	h := newHAPair(t, db, false)
	ctx := context.Background()

	first := h.issueOnA(t, "held.example.com")
	h.b.refreshFromTable()
	if _, found, _ := h.b.GetCertificate(ctx, first.FingerprintSHA256); !found {
		t.Fatal("B should hold the first certificate after a refresh")
	}

	got, err := h.b.queryChangedCerts(discoveryEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("all-time window refetched %d rows B already holds, want 0", len(got))
	}

	second := h.issueOnA(t, "new.example.com")
	got, err = h.b.queryChangedCerts(discoveryEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].item.FingerprintSHA256 != second.FingerprintSHA256 {
		t.Fatalf("want exactly the peer's new row, got %d rows", len(got))
	}

	h.b.refreshFromTable()
	if _, err := h.a.RevokeCertificate(ctx, first.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 1}); err != nil {
		t.Fatal(err)
	}
	got, err = h.b.queryChangedCerts(discoveryEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].item.FingerprintSHA256 != first.FingerprintSHA256 || got[0].item.RevokedAt == nil {
		t.Fatalf("want exactly the revoked row, got %d rows", len(got))
	}
}

// A refresh scan must not wait for p.mu while its cursor holds the only
// connection of a MaxOpenConns=1 sqlite pool: writers (UpdateEstate,
// UpdateOwnership) hold p.mu across their db.Exec, so that was a lock-order
// deadlock that hung every write on the hub (storm smoke seeding, 2026-10-18).
func TestQueryChangedCerts_NoConnHeldWhileWaitingForProviderLock(t *testing.T) {
	db := setupIntegrationDB(t)
	db.SetMaxOpenConns(1)
	h := newHAPair(t, db, false)
	h.issueOnA(t, "dl.example.com")

	// Stand-in for a writer that is mid-UpdateEstate: it owns p.mu and is
	// about to need the connection.
	h.b.mu.Lock()
	scanned := make(chan error, 1)
	go func() {
		_, err := h.b.queryChangedCerts(discoveryEpoch)
		scanned <- err
	}()
	time.Sleep(300 * time.Millisecond) // the scan is now parked on p.mu.RLock

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, execErr := db.ExecContext(ctx, `SELECT 1`)
	h.b.mu.Unlock()
	if execErr != nil {
		t.Fatalf("writer could not get a connection while the scan waited for p.mu (deadlock): %v", execErr)
	}
	select {
	case err := <-scanned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan never finished after p.mu was released")
	}
}

// A refresh that fetched a row before a local write and merges it after must
// not revert that write. Seen as ~1 in 500 storm certificates losing their
// takeover (managed + connector) in memory only, then renewing through the hub
// CA ("ca not found"): UpdateOwnership and UpdateEstate stamped second-resolution
// updated_at, the row trigger turned the second same-second write into a
// millisecond stamp, and the stale full row then outranked the live copy.
func TestStaleRefreshRowDoesNotRevertTakeover(t *testing.T) {
	db := setupIntegrationDB(t)
	h := newHAPair(t, db, false)
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		certPEM, _ := selfSignedPair(t, false)
		imp, err := h.a.ImportCertificate(ctx, CertificateImportRequest{CertificatePEM: certPEM})
		if err != nil {
			t.Fatal(err)
		}
		fp := imp.FingerprintSHA256
		if _, err := h.a.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerTeam: "storm"}); err != nil {
			t.Fatal(err)
		}
		// What a concurrent refresh holds when it read the table between the
		// ownership write and the takeover.
		stale, err := h.a.queryCerts(" WHERE fingerprint_sha256 = ?", fp)
		if err != nil || len(stale) != 1 {
			t.Fatalf("stale row: %v (%d)", err, len(stale))
		}
		if _, err := h.a.UpdateEstate(ctx, fp, EstateUpdate{ManagementState: "managed", RenewalMethod: "acme", RenewalConnectorID: "conn-x"}); err != nil {
			t.Fatal(err)
		}
		h.a.mergeRows(stale)
		got, _, _ := h.a.GetCertificate(ctx, fp)
		if got.ManagementState != "managed" || got.RenewalConnectorID != "conn-x" {
			t.Fatalf("iteration %d: stale refresh row reverted the takeover: state=%q connector=%q", i, got.ManagementState, got.RenewalConnectorID)
		}
	}
}
