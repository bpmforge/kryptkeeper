// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/discovery/scanner"
	"kryptkeeper/internal/keystore"
)

// newSelfSignedForDiscovery builds a real CA:TRUE self-signed cert, the shape
// `openssl req -x509` produces and the lab test discovered.
func newSelfSignedForDiscovery(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// dbDiscoveryStoreUpserter is the slice of the sqlite/postgres discovery stores
// the inventory case needs.
type dbDiscoveryStoreUpserter interface {
	upsertScanResults(ctx context.Context, results []scanner.DiscoveredEndpoint) (upsertOutcome, error)
}

// migratedDiscoveryStore mirrors production boot order: real migrations first,
// then the discovery store's own EnsureSchema widening.
func migratedDiscoveryStore(t *testing.T, db *sql.DB) *sqliteDiscoveryStore {
	t.Helper()
	s := &sqliteDiscoveryStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("discovery EnsureSchema on migrated db: %v", err)
	}
	return s
}

func discoveredFromX509(c *x509.Certificate, host string) scanner.DiscoveredEndpoint {
	return scanner.DiscoveredEndpoint{
		Host: host, Port: 443, Protocol: "tls",
		Certs: []scanner.DiscoveredCert{scanner.CertToDiscovered(c, host, true)},
	}
}

func fingerprintOf(c *x509.Certificate) string {
	return scanner.CertToDiscovered(c, "", false).Fingerprint
}

// Root cause 1a: discovery wrote NULL issuer_cn / key_size_bits / key usage
// columns that the loader scanned into plain values, so every discovered row
// was skipped on load. This inserts exactly the row shape discovery used to
// write and asserts the loader still serves it.
func TestLoadCertsFromDB_ToleratesNullableColumns(t *testing.T) {
	db := setupIntegrationDB(t)
	if _, err := db.Exec(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names, issuer_dn,
		 valid_from, valid_until, public_key_algorithm, signature_algorithm, risk_score, risk_flags,
		 raw_cert_b64, updated_at, source, origin, management_state)
		VALUES ('fp-null-cols','1','CN=n',NULL,NULL,'CN=i','2026-01-01T00:00:00Z','2027-01-01T00:00:00Z',
		        'ECDSA','ECDSA-SHA256',10,'[]',NULL,'2026-01-01T00:00:00Z','discovery_network','discovered','unmanaged')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	provider, _ := newIntegrationCAProvider(t, db)
	res, err := provider.ListCertificates(context.Background(), CertificateListQuery{ManagementState: "unmanaged"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || res.Items[0].FingerprintSHA256 != "fp-null-cols" {
		t.Fatalf("row with NULL nullable columns must load, got %+v", res)
	}
}

// Root causes 1a-1c end to end on the real migrated schema: a discovery
// upsert is listed by the certificate provider with NO restart, carries the
// issuer/key facts, stays unmanaged, and survives a provider restart.
func TestDiscoveredCertAppearsInInventoryWithoutRestart(t *testing.T) {
	db := setupIntegrationDB(t)
	runDiscoveredInventoryCase(t, db, false, migratedDiscoveryStore(t, db))
}

// Postgres twin: same case on the real migrated Postgres schema (TEXT[]
// columns, native BOOLEAN), skipped unless KRYPTKEEPER_TEST_POSTGRES_DSN is set.
func TestDiscoveredCertAppearsInInventoryWithoutRestart_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres integration test")
	}
	freshPostgresForTest(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	store := &postgresDiscoveryStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("discovery EnsureSchema on migrated db: %v", err)
	}
	runDiscoveredInventoryCase(t, db, true, store)
}

func runDiscoveredInventoryCase(t *testing.T, db *sql.DB, postgres bool, store dbDiscoveryStoreUpserter) {
	t.Helper()
	stubEndpointAudit(t)
	newProvider := func() CertificateProvider {
		keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
		if err != nil {
			t.Fatal(err)
		}
		engine := ca.NewEngine(keys, ca.NewDBStore(db, postgres))
		p := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, postgres), db, postgres)
		p.(*caCertificateProvider).discoveryRefreshEvery = 0
		return p
	}
	provider := newProvider()
	ctx := context.Background()

	before, err := provider.ListCertificates(ctx, CertificateListQuery{ManagementState: "unmanaged"})
	if err != nil || before.Total != 0 {
		t.Fatalf("precondition: no unmanaged certs, got %+v err=%v", before, err)
	}

	c := newSelfSignedForDiscovery(t, "lab.example.com")
	if _, err := store.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{discoveredFromX509(c, "lab.example.com")}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	fp := fingerprintOf(c)
	check := func(p CertificateProvider, label string) {
		t.Helper()
		res, err := p.ListCertificates(ctx, CertificateListQuery{ManagementState: "unmanaged"})
		if err != nil {
			t.Fatalf("%s: list: %v", label, err)
		}
		if res.Total != 1 || res.Items[0].FingerprintSHA256 != fp {
			t.Fatalf("%s: discovered cert missing from inventory: %+v", label, res)
		}
		it := res.Items[0]
		if it.ManagementState != "unmanaged" || it.Origin != "discovered" || it.Source != "discovery_network" {
			t.Errorf("%s: provenance wrong: state=%q origin=%q source=%q", label, it.ManagementState, it.Origin, it.Source)
		}
		if it.IssuerCN != "lab.example.com" {
			t.Errorf("%s: issuer_cn = %q", label, it.IssuerCN)
		}
		if it.KeySizeBits != 256 || it.PublicKeyAlgorithm != "ECDSA" {
			t.Errorf("%s: key facts wrong: %d %q", label, it.KeySizeBits, it.PublicKeyAlgorithm)
		}
		if !slices.Contains(it.RiskFlags, "SELF_SIGNED") {
			t.Errorf("%s: risk flags %v missing SELF_SIGNED", label, it.RiskFlags)
		}
		managed, err := p.ListCertificates(ctx, CertificateListQuery{ManagementState: "managed"})
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range managed.Items {
			if m.FingerprintSHA256 == fp {
				t.Errorf("%s: discovered cert must never become managed", label)
			}
		}
	}
	check(provider, "live provider")

	// A re-scan that changes the stored row is picked up too (updated_at based).
	bump := `UPDATE certificates SET risk_score = 77, updated_at = '2999-01-01T00:00:00Z' WHERE fingerprint_sha256 = ?`
	if postgres {
		bump = `UPDATE certificates SET risk_score = 77, updated_at = '2999-01-01T00:00:00Z' WHERE fingerprint_sha256 = $1`
	}
	if _, err := db.Exec(bump, fp); err != nil {
		t.Fatal(err)
	}
	res, err := provider.ListCertificates(ctx, CertificateListQuery{ManagementState: "unmanaged"})
	if err != nil || res.Total != 1 || res.Items[0].RiskScore != 77 {
		t.Fatalf("refresh must pick up an updated row, got %+v err=%v", res, err)
	}

	check(newProvider(), "restarted provider")
}

// A discovery scan must never rewrite the risk of a cert the hub manages: the
// hub scores those with richer rules, and the scan target (IP vs name)
// changing the number made it flap 10 -> 30.
func TestDiscoveryUpsertDoesNotOverwriteManagedCertRisk(t *testing.T) {
	stubEndpointAudit(t)
	db := setupIntegrationDB(t)
	store := migratedDiscoveryStore(t, db)
	c := newSelfSignedForDiscovery(t, "managed.example.com")
	ep := discoveredFromX509(c, "managed.example.com")
	if _, err := store.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatal(err)
	}
	fp := fingerprintOf(c)
	if _, err := db.Exec(`UPDATE certificates SET management_state='managed', risk_score=10, risk_flags='[]' WHERE fingerprint_sha256=?`, fp); err != nil {
		t.Fatal(err)
	}
	if _, err := store.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatal(err)
	}
	var score int
	if err := db.QueryRow(`SELECT risk_score FROM certificates WHERE fingerprint_sha256=?`, fp).Scan(&score); err != nil {
		t.Fatal(err)
	}
	if score != 10 {
		t.Fatalf("managed cert risk overwritten by discovery: %d", score)
	}
}

// A discovered certificate's chain verdict is an endpoint fact. The
// certificates.chain_complete column is a stale default (0) for those rows, so
// the inventory used to report chain_complete=false for certs whose endpoint
// view said "unknown". It must be absent for discovered certs and unchanged
// for hub-issued ones.
func TestInventoryOmitsCertLevelChainForDiscoveredCerts(t *testing.T) {
	db := setupIntegrationDB(t)
	for _, r := range []struct{ fp, origin, state, source string }{
		{"fp-chain-disc", "discovered", "unmanaged", "discovery_network"},
		{"fp-chain-int", "internal", "managed", "api"},
	} {
		if _, err := db.Exec(`INSERT INTO certificates
			(fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names, issuer_dn,
			 valid_from, valid_until, public_key_algorithm, signature_algorithm, risk_score, risk_flags,
			 chain_complete, chain_trusted, raw_cert_b64, updated_at, source, origin, management_state)
			VALUES (?,'1','CN=n','n','[]','CN=i','2026-01-01T00:00:00Z','2027-01-01T00:00:00Z',
			        'ECDSA','ECDSA-SHA256',10,'[]',?,?,NULL,'2026-01-01T00:00:00Z',?,?,?)`,
			r.fp, boolArg(r.origin != "discovered", false), boolArg(r.origin != "discovered", false), r.source, r.origin, r.state); err != nil {
			t.Fatalf("seed %s: %v", r.fp, err)
		}
	}
	provider, _ := newIntegrationCAProvider(t, db)
	res, err := provider.ListCertificates(context.Background(), CertificateListQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byFP := map[string]CertificateItem{}
	for _, it := range res.Items {
		byFP[it.FingerprintSHA256] = it
	}
	disc, ok := byFP["fp-chain-disc"]
	if !ok {
		t.Fatalf("discovered cert not listed: %+v", res.Items)
	}
	if disc.ChainComplete != nil || disc.ChainTrusted != nil {
		t.Errorf("discovered cert chain = %v/%v, want nil/nil (judged per endpoint)", disc.ChainComplete, disc.ChainTrusted)
	}
	raw, err := json.Marshal(disc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("chain_complete")) || bytes.Contains(raw, []byte("chain_trusted")) {
		t.Errorf("discovered cert JSON must omit chain fields: %s", raw)
	}
	if in := byFP["fp-chain-int"]; !boolVal(in.ChainComplete) || !boolVal(in.ChainTrusted) {
		t.Errorf("hub-held cert keeps its issuance chain verdict, got %v/%v", in.ChainComplete, in.ChainTrusted)
	}
}
