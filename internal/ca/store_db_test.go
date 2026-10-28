// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"database/sql"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"kryptkeeper/internal/db"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
CREATE TABLE certificate_authorities (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    display_name TEXT NOT NULL,
    type         TEXT NOT NULL,
    key_storage_type TEXT NOT NULL DEFAULT 'software',
    key_id       TEXT,
    cert_pem     TEXT,
    csr_pem      TEXT,
    status       TEXT NOT NULL DEFAULT 'active',
    parent_ca_id TEXT,
    connector_id TEXT,
    external_trust_pem TEXT,
    crl_distribution_points TEXT,
    ocsp_service_url TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
)`)
	if err != nil {
		t.Fatalf("create ca table: %v", err)
	}

	_, err = db.Exec(`
CREATE TABLE certificates (
    fingerprint_sha256  TEXT PRIMARY KEY,
    serial_number       TEXT NOT NULL,
    subject_dn          TEXT NOT NULL,
    common_name         TEXT,
    subject_alt_names   TEXT,
    issuer_dn           TEXT NOT NULL DEFAULT '',
    issuer_cn           TEXT,
    ca_id               TEXT,
    valid_from          TEXT NOT NULL,
    valid_until         TEXT NOT NULL,
    public_key_algorithm TEXT NOT NULL DEFAULT 'ECDSA',
    key_size_bits       INTEGER,
    signature_algorithm TEXT NOT NULL DEFAULT 'ECDSA-SHA256',
    extended_key_usage  TEXT,
    key_usage           TEXT,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    risk_flags          TEXT NOT NULL DEFAULT '[]',
    grade               TEXT NOT NULL DEFAULT 'A',
    renewal_status      TEXT DEFAULT 'active',
    revoked_at          TEXT,
    revocation_reason   INTEGER,
    chain_complete      INTEGER NOT NULL DEFAULT 0,
    chain_trusted       INTEGER NOT NULL DEFAULT 0,
    pqc_vulnerable      INTEGER NOT NULL DEFAULT 0,
    source              TEXT NOT NULL DEFAULT 'api',
    raw_cert_b64        TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)`)
	if err != nil {
		t.Fatalf("create certificates table: %v", err)
	}

	_, err = db.Exec(`
CREATE TABLE ca_key_rotations (
    id          TEXT PRIMARY KEY,
    ca_id       TEXT NOT NULL,
    old_key_id  TEXT NOT NULL,
    new_key_id  TEXT NOT NULL,
    new_cert_sn TEXT NOT NULL,
    method      TEXT NOT NULL,
    rotated_at  TEXT NOT NULL,
    old_cert_pem TEXT NOT NULL DEFAULT ''
)`)
	if err != nil {
		t.Fatalf("create ca_key_rotations table: %v", err)
	}
	return db
}

// --- DBStore ---

func TestDBStoreSaveAndLoad(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	ca := &CA{
		ID:     "ca-test-1",
		Name:   "Test Root CA",
		Type:   "root",
		Status: "active",
		KeyID:  "key-1",
	}
	if err := store.Save(ca); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load("ca-test-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ID != "ca-test-1" {
		t.Errorf("ID mismatch: got %s", loaded.ID)
	}
	if loaded.Status != "active" {
		t.Errorf("Status mismatch: got %s", loaded.Status)
	}
}

// TestDBStoreSaveAndLoadRoundTripsKeyStorageType is the regression test for
// W19-08: Save previously wrote the literal "software" into the
// key_storage_type column no matter what CA.KeyStorageType held, and Load's
// query didn't even select the column back -- an HSM-held CA key was
// misreported as software custody by the persistence layer itself.
func TestDBStoreSaveAndLoadRoundTripsKeyStorageType(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	ca := &CA{
		ID:             "ca-pkcs11-1",
		Name:           "HSM Root CA",
		Type:           "root",
		Status:         "active",
		KeyID:          "key-1",
		KeyStorageType: "pkcs11",
	}
	if err := store.Save(ca); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load("ca-pkcs11-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.KeyStorageType != "pkcs11" {
		t.Errorf("expected KeyStorageType=pkcs11 round-trip, got %q", loaded.KeyStorageType)
	}
}

// TestDBStoreSaveDefaultsKeyStorageTypeToSoftware covers CAs constructed
// without going through ca.Engine (e.g. older callers, ImportCA), where
// KeyStorageType is empty -- the DB row must still fall back to "software"
// rather than persisting an empty/misleading value.
func TestDBStoreSaveDefaultsKeyStorageTypeToSoftware(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	ca := &CA{ID: "ca-imported-1", Name: "Imported Root CA", Type: "root", Status: "active"}
	if err := store.Save(ca); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load("ca-imported-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.KeyStorageType != "software" {
		t.Errorf("expected default KeyStorageType=software, got %q", loaded.KeyStorageType)
	}
}

func TestDBStoreSaveUpsert(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	ca := &CA{ID: "ca-upsert", Name: "Upsert CA", Type: "root", Status: "active", KeyID: "k1"}
	if err := store.Save(ca); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	ca.Status = "suspended"
	if err := store.Save(ca); err != nil {
		t.Fatalf("Save upsert: %v", err)
	}

	loaded, err := store.Load("ca-upsert")
	if err != nil {
		t.Fatalf("Load after upsert: %v", err)
	}
	if loaded.Status != "suspended" {
		t.Errorf("expected suspended after upsert, got %s", loaded.Status)
	}
}

func TestDBStoreRoundTripsEditableMetadata(t *testing.T) {
	d := newTestDB(t)
	store := NewDBStore(d, false)

	// Defaults: display_name falls back to name; CRL/OCSP read back empty, not an error.
	if err := store.Save(&CA{ID: "m1", Name: "Meta", Type: "root", Status: "active"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load("m1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DisplayName != "Meta" || len(got.CRLDistributionPoints) != 0 || got.OCSPServiceURL != "" {
		t.Fatalf("defaults wrong: %+v", got)
	}

	got.DisplayName = "Pretty"
	got.CRLDistributionPoints = []string{"http://a/x.crl", "https://b/y.crl"}
	got.OCSPServiceURL = "http://ocsp.example"
	got.Name = "must-not-change"
	if err := store.Save(got); err != nil {
		t.Fatalf("Save upsert: %v", err)
	}
	var name string
	if err := d.QueryRow(`SELECT name FROM certificate_authorities WHERE id = 'm1'`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Meta" {
		t.Fatalf("upsert rewrote the immutable name: %q", name)
	}
	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v, %d", err, len(list))
	}
	if g := list[0]; g.DisplayName != "Pretty" || g.OCSPServiceURL != "http://ocsp.example" ||
		len(g.CRLDistributionPoints) != 2 || g.CRLDistributionPoints[1] != "https://b/y.crl" {
		t.Fatalf("round trip wrong: %+v", g)
	}

	// Clearing writes NULL, which must read back as empty.
	got.CRLDistributionPoints, got.OCSPServiceURL = nil, ""
	if err := store.Save(got); err != nil {
		t.Fatal(err)
	}
	cleared, _ := store.Load("m1")
	if len(cleared.CRLDistributionPoints) != 0 || cleared.OCSPServiceURL != "" {
		t.Fatalf("clear failed: %+v", cleared)
	}
}

func TestDBStoreLoadNotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	_, err := store.Load("nonexistent")
	if err != ErrCANotFound {
		t.Errorf("expected ErrCANotFound, got %v", err)
	}
}

func TestDBStoreList(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	list, err := store.List()
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}

	store.Save(&CA{ID: "ca-1", Name: "CA 1", Type: "root", Status: "active", KeyID: "k1"})
	store.Save(&CA{ID: "ca-2", Name: "CA 2", Type: "root", Status: "active", KeyID: "k2"})

	list, err = store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 CAs, got %d", len(list))
	}
}

func TestDBStoreUpdateStatus(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	store.Save(&CA{ID: "ca-status", Name: "Status CA", Type: "root", Status: "active", KeyID: "k1"})

	if err := store.UpdateStatus("ca-status", "suspended"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	loaded, _ := store.Load("ca-status")
	if loaded.Status != "suspended" {
		t.Errorf("expected suspended, got %s", loaded.Status)
	}
}

func TestDBStoreUpdateStatusNotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	if err := store.UpdateStatus("missing", "suspended"); err != ErrCANotFound {
		t.Errorf("expected ErrCANotFound, got %v", err)
	}
}

func TestDBStoreIntermediateType(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	// Create root first since parent_ca_id is NOT enforced in our minimal test schema.
	store.Save(&CA{ID: "root-1", Name: "Root", Type: "root", Status: "active", KeyID: "k0"})

	inter := &CA{
		ID:         "inter-1",
		Name:       "Intermediate CA",
		Type:       "intermediate",
		Status:     "active",
		KeyID:      "k2",
		ParentCAID: "root-1",
	}
	if err := store.Save(inter); err != nil {
		t.Fatalf("Save intermediate: %v", err)
	}

	loaded, err := store.Load("inter-1")
	if err != nil {
		t.Fatalf("Load intermediate: %v", err)
	}
	if loaded.Type != "intermediate" {
		t.Errorf("expected intermediate, got %s", loaded.Type)
	}
}

func TestCATypeMapping(t *testing.T) {
	if got := caTypeForDB("intermediate"); got != "issuing" {
		t.Errorf("caTypeForDB(intermediate) = %q, want issuing", got)
	}
	if got := caTypeForDB("root"); got != "root" {
		t.Errorf("caTypeForDB(root) = %q, want root", got)
	}
	if got := caTypeFromDB("issuing"); got != "intermediate" {
		t.Errorf("caTypeFromDB(issuing) = %q, want intermediate", got)
	}
	if got := caTypeFromDB("root"); got != "root" {
		t.Errorf("caTypeFromDB(root) = %q, want root", got)
	}
}

// --- ca_key_rotations ledger (W9-04/G-35) ---

func TestDBStoreRecordAndListKeyRotations(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)

	store.Save(&CA{ID: "ca-1", Name: "CA 1", Type: "root", Status: "active", KeyID: "key-ca-1"})

	r1 := KeyRotation{ID: "rot-1", CAID: "ca-1", OldKeyID: "key-ca-1-retired-1", NewKeyID: "key-ca-1", NewCertSN: "111", Method: "rekey_reissue", RotatedAt: time.Now().UTC().Truncate(time.Second), OldCertPEM: []byte("-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n")}
	if err := store.RecordKeyRotation(r1); err != nil {
		t.Fatalf("RecordKeyRotation: %v", err)
	}
	r2 := KeyRotation{ID: "rot-2", CAID: "ca-1", OldKeyID: "key-ca-1-retired-2", NewKeyID: "key-ca-1", NewCertSN: "222", Method: "rekey_reissue", RotatedAt: r1.RotatedAt.Add(time.Hour)}
	if err := store.RecordKeyRotation(r2); err != nil {
		t.Fatalf("RecordKeyRotation: %v", err)
	}

	rotations, err := store.ListKeyRotations("ca-1")
	if err != nil {
		t.Fatalf("ListKeyRotations: %v", err)
	}
	if len(rotations) != 2 {
		t.Fatalf("got %d rotations, want 2", len(rotations))
	}
	// Newest first.
	if rotations[0].ID != "rot-2" || rotations[1].ID != "rot-1" {
		t.Errorf("unexpected order: %+v", rotations)
	}
	if rotations[0].NewCertSN != "222" {
		t.Errorf("NewCertSN = %q, want 222", rotations[0].NewCertSN)
	}
	if string(rotations[1].OldCertPEM) != string(r1.OldCertPEM) || len(rotations[0].OldCertPEM) != 0 {
		t.Errorf("OldCertPEM round-trip: got %q / %q", rotations[1].OldCertPEM, rotations[0].OldCertPEM)
	}
	if !rotations[0].RotatedAt.Equal(r2.RotatedAt) {
		t.Errorf("RotatedAt round-trip mismatch: got %v, want %v", rotations[0].RotatedAt, r2.RotatedAt)
	}
}

func TestDBStoreListKeyRotationsEmpty(t *testing.T) {
	db := newTestDB(t)
	store := NewDBStore(db, false)
	rotations, err := store.ListKeyRotations("no-such-ca")
	if err != nil {
		t.Fatalf("ListKeyRotations: %v", err)
	}
	if len(rotations) != 0 {
		t.Fatalf("got %d rotations, want 0", len(rotations))
	}
}

// --- DBRevocationStore ---

func TestDBRevocationStore(t *testing.T) {
	db := newTestDB(t)
	rs := NewDBRevocationStore(db, false)

	caID := "ca-rev-1"
	serial := big.NewInt(12345)
	now := time.Now().UTC().Truncate(time.Second)

	// Not revoked initially.
	revoked, _, _, err := rs.IsRevoked(serial, caID)
	if err != nil {
		t.Fatalf("IsRevoked (empty): %v", err)
	}
	if revoked {
		t.Error("expected not revoked")
	}

	// Insert a certificate row so the UPDATE in Revoke affects a row.
	_, err = db.Exec(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, ca_id, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"fp-1", serial.String(), "CN=test", caID,
		now.Format(time.RFC3339), now.Add(365*24*time.Hour).Format(time.RFC3339),
		"ECDSA", "ECDSA-SHA256")
	if err != nil {
		t.Fatalf("insert cert: %v", err)
	}

	if err := rs.Revoke(serial, caID, 0, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, revokedAt, reason, err := rs.IsRevoked(serial, caID)
	if err != nil {
		t.Fatalf("IsRevoked after revoke: %v", err)
	}
	if !revoked {
		t.Error("expected revoked=true")
	}
	if revokedAt.IsZero() {
		t.Error("expected non-zero revokedAt")
	}
	_ = reason

	list, err := rs.ListRevoked(caID)
	if err != nil {
		t.Fatalf("ListRevoked: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 revoked, got %d", len(list))
	}
	if list[0].Serial.Cmp(serial) != 0 {
		t.Errorf("serial mismatch: got %s", list[0].Serial)
	}
}

func TestDBRevocationStoreEmpty(t *testing.T) {
	db := newTestDB(t)
	rs := NewDBRevocationStore(db, false)

	list, err := rs.ListRevoked("nonexistent-ca")
	if err != nil {
		t.Fatalf("ListRevoked empty: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

// --- DBRevocationStore.Revoke's zero-row behavior (W1-15/G-92) -------------
//
// Prior to this fix, Revoke's UPDATE matching zero rows (no certificates row
// for serial_number+ca_id) still returned a nil error: sql.Exec succeeds
// whether or not any row matched, and the old code never checked
// RowsAffected. That is exactly what happened for every ACME-issued
// certificate, since ACME finalize never inserts one.

func TestDBRevocationStoreRevokeErrorsWithNoRowAndNoMeta(t *testing.T) {
	db := newTestDB(t)
	rs := NewDBRevocationStore(db, false)

	caID := "ca-no-row"
	serial := big.NewInt(999)

	// No CertMeta supplied -- mirrors bootstrap.caCertificateProvider's
	// existing 4-arg call site, which always has a row already (writeCertToDB
	// runs at issuance) and so never legitimately hits this branch. Proving
	// the negative: this must now return an error instead of the old silent
	// nil.
	if err := rs.Revoke(serial, caID, 0, time.Now().UTC()); err == nil {
		t.Fatal("expected an error when no certificates row exists and no CertMeta is supplied, got nil")
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE serial_number = ? AND ca_id = ?`, serial.String(), caID).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Errorf("expected no certificates row to have been created, got %d", count)
	}
}

func TestDBRevocationStoreRevokeCreatesRowWithMeta(t *testing.T) {
	db := newTestDB(t)
	rs := NewDBRevocationStore(db, false)

	caID := "ca-acme-1"
	serial := big.NewInt(424242)
	now := time.Now().UTC().Truncate(time.Second)

	var before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE serial_number = ? AND ca_id = ?`, serial.String(), caID).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}
	if before != 0 {
		t.Fatalf("test setup: expected no pre-existing row, got %d", before)
	}

	meta := CertMeta{
		FingerprintSHA256:  "acme-fp-1",
		CommonName:         "acme-issued.example.com",
		SubjectDN:          "CN=acme-issued.example.com",
		SubjectAltNames:    []string{"acme-issued.example.com"},
		IssuerDN:           "CN=ACME Test Root CA",
		IssuerCN:           "ACME Test Root CA",
		NotBefore:          now,
		NotAfter:           now.Add(90 * 24 * time.Hour),
		PublicKeyAlgorithm: "ECDSA",
		KeySizeBits:        256,
		SignatureAlgorithm: "ECDSA-SHA256",
		ExtendedKeyUsage:   []string{"serverAuth"},
		KeyUsage:           []string{"digitalSignature", "keyEncipherment"},
		Source:             "acme",
		CertPEM:            []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"),
	}
	if err := rs.Revoke(serial, caID, 1, now, meta); err != nil {
		t.Fatalf("Revoke with meta: %v", err)
	}

	// Prove the created row is compatible with
	// bootstrap.caCertificateProvider.loadCertsFromDB's scan (out of
	// write_scope to change), which reads common_name, subject_alt_names,
	// issuer_cn, key_size_bits, extended_key_usage, and key_usage into
	// non-nullable Go types. A NULL in any of them would fail that Scan and
	// silently drop the certificate from the dashboard's list the next time
	// the provider restarts -- reproduced here directly against bare,
	// non-nullable receivers of the same shape.
	var commonName, subjectAltNames, issuerCN, extKeyUsage, keyUsageStr, rawCertB64 string
	var keySizeBits int
	if err := db.QueryRow(`SELECT common_name, subject_alt_names, issuer_cn, key_size_bits, extended_key_usage, key_usage, raw_cert_b64
		FROM certificates WHERE serial_number = ? AND ca_id = ?`, serial.String(), caID).
		Scan(&commonName, &subjectAltNames, &issuerCN, &keySizeBits, &extKeyUsage, &keyUsageStr, &rawCertB64); err != nil {
		t.Fatalf("scan bootstrap-compatible columns (bare, non-nullable types): %v", err)
	}
	if commonName != meta.CommonName {
		t.Errorf("common_name = %q, want %q", commonName, meta.CommonName)
	}
	if issuerCN != meta.IssuerCN {
		t.Errorf("issuer_cn = %q, want %q", issuerCN, meta.IssuerCN)
	}
	if rawCertB64 == "" {
		t.Error("expected raw_cert_b64 to be populated from meta.CertPEM")
	}

	// Rows-affected-equivalent assertion: query the table directly rather
	// than relying on IsRevoked, which could pass for the wrong reason (e.g.
	// an unrelated row, or a store that just always reports revoked=true).
	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE serial_number = ? AND ca_id = ?`, serial.String(), caID).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 1 {
		t.Fatalf("expected exactly 1 certificates row to be created, got %d", after)
	}

	var revokedAt sql.NullString
	var reason sql.NullInt64
	var subjectDN, source string
	err := db.QueryRow(`SELECT revoked_at, revocation_reason, subject_dn, source FROM certificates
		WHERE serial_number = ? AND ca_id = ?`, serial.String(), caID).
		Scan(&revokedAt, &reason, &subjectDN, &source)
	if err != nil {
		t.Fatalf("select created row: %v", err)
	}
	if !revokedAt.Valid || revokedAt.String == "" {
		t.Error("expected revoked_at to be set on the newly created row")
	}
	if !reason.Valid || reason.Int64 != 1 {
		t.Errorf("revocation_reason = %v, want 1", reason)
	}
	if subjectDN != meta.SubjectDN {
		t.Errorf("subject_dn = %q, want %q", subjectDN, meta.SubjectDN)
	}
	if source != "acme" {
		t.Errorf("source = %q, want acme", source)
	}

	// IsRevoked should also reflect it -- in addition to, not instead of,
	// the direct row assertions above.
	revoked, _, _, err := rs.IsRevoked(serial, caID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("expected IsRevoked to report revoked=true after Revoke created the row")
	}
}

// TestDBRevocationStoreRevokeInsertConflictUnderDifferentCAIDErrors proves
// insertRevokedCertificate does not repeat the exact bug this ticket exists
// to fix, one level down: a fingerprint_sha256 conflict against a row
// belonging to a DIFFERENT certificate (different serial_number/ca_id) must
// surface as an error, not a silent no-op via ON CONFLICT/OR IGNORE.
func TestDBRevocationStoreRevokeInsertConflictUnderDifferentCAIDErrors(t *testing.T) {
	db := newTestDB(t)
	rs := NewDBRevocationStore(db, false)

	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, ca_id, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"shared-fp", "111", "CN=other", "ca-other",
		now.Format(time.RFC3339), now.Add(24*time.Hour).Format(time.RFC3339),
		"ECDSA", "ECDSA-SHA256")
	if err != nil {
		t.Fatalf("seed conflicting row: %v", err)
	}

	serial := big.NewInt(222)
	caID := "ca-mine"
	meta := CertMeta{
		FingerprintSHA256:  "shared-fp", // same fingerprint, different serial/ca_id
		SubjectDN:          "CN=mine",
		IssuerDN:           "CN=issuer",
		NotBefore:          now,
		NotAfter:           now.Add(90 * 24 * time.Hour),
		PublicKeyAlgorithm: "ECDSA",
		SignatureAlgorithm: "ECDSA-SHA256",
		Source:             "acme",
	}
	if err := rs.Revoke(serial, caID, 1, now, meta); err == nil {
		t.Fatal("expected an error when the INSERT conflicts with an existing row under a different serial/ca_id, got nil")
	}

	revoked, _, _, err := rs.IsRevoked(serial, caID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("expected not revoked under caID=ca-mine -- the conflicting row belongs to a different certificate")
	}
}

// --- W23-25: UNIQUE(issuer CA, serial) ---

func openMigratedSQLite(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "serial.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := db.RunMigrations(d, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, id := range []string{"ca-1", "ca-2"} {
		if _, err := d.Exec(`INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status)
			VALUES (?, ?, ?, 'root', 'software', 'active')`, id, id, id); err != nil {
			t.Fatalf("seed ca: %v", err)
		}
	}
	return d
}

func insertSerialRow(d *sql.DB, fp, serial, caID string) error {
	_, err := d.Exec(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, ca_id, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm)
		VALUES (?, ?, 'CN=x', 'CN=ca', ?, '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'ECDSA', 'ecdsa-with-SHA256')`,
		fp, serial, caID)
	return err
}

func countSerial(t *testing.T, d *sql.DB, serial, caID string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM certificates WHERE serial_number = ? AND ca_id = ?`, serial, caID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestMigratedSchemaEnforcesIssuerSerialUnique(t *testing.T) {
	d := openMigratedSQLite(t)
	if err := insertSerialRow(d, "fp-a", "100", "ca-1"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := insertSerialRow(d, "fp-b", "100", "ca-1")
	if err == nil {
		t.Fatal("duplicate (ca_id, serial) must be rejected")
	}
	if !IsSerialCollision(err) {
		t.Fatalf("IsSerialCollision(%v) = false", err)
	}
	if n := countSerial(t, d, "100", "ca-1"); n != 1 {
		t.Fatalf("rows for (ca-1,100) = %d, want 1", n)
	}
	// Same serial under a different CA is legitimate.
	if err := insertSerialRow(d, "fp-c", "100", "ca-2"); err != nil {
		t.Fatalf("same serial, other CA must be allowed: %v", err)
	}
}

func TestMigrationRollbackKeepsUniqueIndex(t *testing.T) {
	d := openMigratedSQLite(t)
	if err := db.RollbackMigration(d, "sqlite", 78); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := insertSerialRow(d, "fp-a", "7", "ca-1"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := insertSerialRow(d, "fp-b", "7", "ca-1"); !IsSerialCollision(err) {
		t.Fatalf("index must survive rollback of later migrations, got %v", err)
	}
	if err := db.RunMigrations(d, "sqlite"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if err := insertSerialRow(d, "fp-c", "7", "ca-1"); !IsSerialCollision(err) {
		t.Fatalf("index must hold after re-apply, got %v", err)
	}
}

func TestIsSerialCollisionIgnoresOtherErrors(t *testing.T) {
	for name, err := range map[string]error{
		"nil":      nil,
		"no rows":  sql.ErrNoRows,
		"fk":       errors.New("FOREIGN KEY constraint failed"),
		"other uq": errors.New("UNIQUE constraint failed: certificates.fingerprint_sha256"),
	} {
		if IsSerialCollision(err) {
			t.Errorf("%s: IsSerialCollision = true, want false", name)
		}
	}
	if !IsSerialCollision(errors.New(`ERROR: duplicate key value violates unique constraint "idx_cert_serial_ca" (SQLSTATE 23505)`)) {
		t.Error("postgres duplicate-key text must match")
	}
}

func TestRetryOnSerialCollisionFreshSerial(t *testing.T) {
	d := openMigratedSQLite(t)
	if err := insertSerialRow(d, "fp-seed", "5", "ca-1"); err != nil {
		t.Fatal(err)
	}
	serials := []string{"5", "6"}
	calls := 0
	err := RetryOnSerialCollision(5, func(n int) error {
		calls++
		return insertSerialRow(d, "fp-new-"+serials[n], serials[n], "ca-1")
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	var total, dupes int
	_ = d.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&total)
	_ = d.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM certificates GROUP BY serial_number, ca_id HAVING COUNT(*) > 1)`).Scan(&dupes)
	if total != 2 || dupes != 0 {
		t.Fatalf("total=%d dupes=%d, want 2 and 0", total, dupes)
	}
}

func TestRetryOnSerialCollisionExhausts(t *testing.T) {
	d := openMigratedSQLite(t)
	if err := insertSerialRow(d, "fp-seed", "5", "ca-1"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := RetryOnSerialCollision(5, func(int) error {
		calls++
		return insertSerialRow(d, "fp-x", "5", "ca-1")
	})
	if !errors.Is(err, ErrSerialCollision) {
		t.Fatalf("err = %v, want ErrSerialCollision", err)
	}
	if calls != 5 {
		t.Fatalf("calls = %d, want 5", calls)
	}
	if n := countSerial(t, d, "5", "ca-1"); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

func TestRetryOnSerialCollisionPassesThroughOtherErrors(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := RetryOnSerialCollision(5, func(int) error { calls++; return sentinel })
	if err != sentinel || calls != 1 {
		t.Fatalf("err=%v calls=%d, want sentinel after 1 call", err, calls)
	}
}

func TestDBStoreSerialExists(t *testing.T) {
	d := openMigratedSQLite(t)
	if err := insertSerialRow(d, "fp-a", "42", "ca-1"); err != nil {
		t.Fatal(err)
	}
	store := NewDBStore(d, false)
	if ok, err := store.SerialExists("ca-1", big.NewInt(42)); err != nil || !ok {
		t.Fatalf("SerialExists(ca-1,42) = %v,%v", ok, err)
	}
	if ok, err := store.SerialExists("ca-2", big.NewInt(42)); err != nil || ok {
		t.Fatalf("SerialExists(ca-2,42) = %v,%v", ok, err)
	}
}
