// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/crl"
	"kryptkeeper/internal/db"
	"kryptkeeper/internal/ocsp"

	_ "modernc.org/sqlite"
)

const syncTestCAID = "ca-sync-1"

func openSharedSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func insertSyncCert(t *testing.T, d *sql.DB, fp string, serial *big.Int) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, ca_id, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm)
		VALUES (?, ?, 'CN=x', 'CN=ca', ?, '2026-01-01T00:00:00Z', '2036-01-01T00:00:00Z', 'ECDSA', 'ecdsa-with-SHA256')`,
		fp, serial.String(), syncTestCAID); err != nil {
		t.Fatalf("insert cert: %v", err)
	}
}

func migratedSyncDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	d := openSharedSQLite(t, path)
	if err := db.RunMigrations(d, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status)
		VALUES (?, 'sync', 'Sync', 'root', 'software', 'active')`, syncTestCAID); err != nil {
		t.Fatalf("seed ca: %v", err)
	}
	return d
}

func TestRevocationStampChangesOnRevoke(t *testing.T) {
	d := migratedSyncDB(t, filepath.Join(t.TempDir(), "stamp.db"))
	serial := big.NewInt(4242)
	insertSyncCert(t, d, "fp-stamp", serial)

	ctx := context.Background()
	before, err := revocationStamp(ctx, d)
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if err := ca.NewDBRevocationStore(d, false).Revoke(serial, syncTestCAID, 1, time.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	after, err := revocationStamp(ctx, d)
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if before == after {
		t.Fatalf("stamp unchanged by a revoke: %q", after)
	}
}

func TestRevocationSyncIntervalParsing(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":      5 * time.Second,
		"bogus": 5 * time.Second,
		"-3s":   5 * time.Second,
		"10ms":  time.Second, // floor
		"30s":   30 * time.Second,
	} {
		t.Setenv("KRYPTKEEPER_REVOCATION_SYNC_INTERVAL", in)
		if got := revocationSyncInterval(); got != want {
			t.Errorf("interval(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestRevocationSyncNoopWithoutDB(t *testing.T) {
	startRevocationSync(context.Background(), nil) // must not panic or start a poller
}

type syncReplica struct {
	gen   *crl.Generator
	resp  *ocsp.Responder
	store *ca.DBRevocationStore
}

func newSyncReplica(t *testing.T, d *sql.DB, caCert *x509.Certificate, caKey crypto.Signer) *syncReplica {
	t.Helper()
	store := ca.NewDBRevocationStore(d, false)
	gen := crl.NewGenerator(
		func(caID string) ([]crl.RevokedCert, error) {
			entries, err := store.ListRevoked(caID)
			if err != nil {
				return nil, err
			}
			out := make([]crl.RevokedCert, len(entries))
			for i, e := range entries {
				out[i] = crl.RevokedCert{SerialNumber: e.Serial, RevokedAt: e.RevokedAt, ReasonCode: e.ReasonCode}
			}
			return out, nil
		},
		func(caID string) (*x509.Certificate, crypto.Signer, error) {
			if caID != syncTestCAID {
				return nil, nil, fmt.Errorf("unknown CA")
			}
			return caCert, caKey, nil
		},
		24*time.Hour,
	)
	resp := ocsp.NewResponder(
		func(serial *big.Int, _ *x509.Certificate) (bool, time.Time, int, error) {
			return store.IsRevoked(serial, syncTestCAID)
		},
		func([]byte) (*x509.Certificate, crypto.Signer, error) { return caCert, caKey, nil },
		24*time.Hour, 100,
	)
	return &syncReplica{gen: gen, resp: resp, store: store}
}

func (r *syncReplica) crlListsSerial(t *testing.T, serial *big.Int) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	r.gen.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/"+syncTestCAID+".crl", nil))
	list, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	for _, e := range list.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func (r *syncReplica) ocspStatus(t *testing.T, req []byte, issuer *x509.Certificate) int {
	t.Helper()
	rec := httptest.NewRecorder()
	r.resp.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(string(req))))
	parsed, err := goocsp.ParseResponse(rec.Body.Bytes(), issuer)
	if err != nil {
		t.Fatalf("parse OCSP: %v", err)
	}
	return parsed.Status
}

// W23-26 acceptance 1: a revoke on replica A shows in replica B's CRL and
// OCSP through the shared DB stamp, with no direct call into B.
func TestCrossReplicaRevocationVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	dbA := migratedSyncDB(t, path)
	dbB := openSharedSQLite(t, path)

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Sync CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := big.NewInt(777001)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	ocspReq, err := goocsp.CreateRequest(leaf, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}
	insertSyncCert(t, dbA, "fp-sync-leaf", serial)

	a := newSyncReplica(t, dbA, caCert, caKey)
	b := newSyncReplica(t, dbB, caCert, caKey)

	// Record the baseline stamp before any cache is primed, as startup does.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, r := range []struct {
		d *sql.DB
		s *syncReplica
	}{{dbA, a}, {dbB, b}} {
		stamp, err := revocationStamp(ctx, r.d)
		if err != nil {
			t.Fatal(err)
		}
		r.s.gen.SyncVersion(stamp)
		r.s.resp.SyncVersion(stamp)
	}

	// Prime both replicas' caches with the "good" state.
	for name, r := range map[string]*syncReplica{"A": a, "B": b} {
		if r.crlListsSerial(t, serial) {
			t.Fatalf("%s: serial listed before revocation", name)
		}
		if st := r.ocspStatus(t, ocspReq, caCert); st != goocsp.Good {
			t.Fatalf("%s: OCSP status %d before revocation, want Good", name, st)
		}
	}

	go runRevocationSync(ctx, dbA, 50*time.Millisecond, a.gen, a.resp)
	go runRevocationSync(ctx, dbB, 50*time.Millisecond, b.gen, b.resp)

	// Revoke on A only, with A's local invalidation as in production.
	if err := a.store.Revoke(serial, syncTestCAID, 1, time.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	a.gen.InvalidateCache(serial)
	a.resp.InvalidateCache(serial)

	deadline := time.Now().Add(5 * time.Second)
	for {
		crlSeen := b.crlListsSerial(t, serial)
		ocspSeen := b.ocspStatus(t, ocspReq, caCert) == goocsp.Revoked
		if crlSeen && ocspSeen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replica B never saw A's revocation (crl=%v ocsp=%v)", crlSeen, ocspSeen)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
