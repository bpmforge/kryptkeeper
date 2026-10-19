// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// Approving a CA revoke records the intermediate's own certificate in its
// parent's revocation list by creating a certificates row. caCertMeta leaves
// subject_alt_names / extended_key_usage / key_usage nil, and the writer used
// to send json.Marshal(nil) = "null" to those TEXT[] columns, which Postgres
// rejects (SQLSTATE 22P02) -- the API returned 503. Also covers the ACME
// revoke-cert path, which reaches the same insert with populated lists.
func TestRevokeCA_RecordsCertificatesRow_Postgres(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, true))
	rev := ca.NewDBRevocationStore(db, true)

	root, err := engine.CreateRootCA("rv Root", pkix.Name{CommonName: "rv Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	inter, err := engine.CreateIntermediateCA("rv Intermediate", pkix.Name{CommonName: "rv Intermediate CA"},
		keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	out, err := ca.RevokeCA(engine, rev, inter.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("RevokeCA: %v", err)
	}
	revoked, _, reason, err := rev.IsRevoked(out.Serial, root.ID)
	if err != nil || !revoked || reason != 2 {
		t.Fatalf("IsRevoked(intermediate under root) = %v reason=%d err=%v", revoked, reason, err)
	}
	var sans, eku, ku string
	if err := db.QueryRow(`SELECT COALESCE(array_to_json(subject_alt_names)::text,'NULL'),
		COALESCE(array_to_json(extended_key_usage)::text,'NULL'), COALESCE(array_to_json(key_usage)::text,'NULL')
		FROM certificates WHERE serial_number = $1 AND ca_id = $2`, out.Serial.String(), root.ID).Scan(&sans, &eku, &ku); err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if sans != "[]" || eku != "[]" || ku != "[]" {
		t.Fatalf("empty lists must be stored as empty arrays, got san=%s eku=%s ku=%s", sans, eku, ku)
	}

	// ACME revoke-cert shape: populated lists on a fresh serial.
	now := time.Now().UTC()
	meta := ca.CertMeta{
		FingerprintSHA256: "acme-fp-0001", CommonName: "a.example.com", SubjectDN: "CN=a.example.com",
		SubjectAltNames: []string{"a.example.com", "10.0.0.1"}, IssuerDN: "CN=rv Intermediate CA", IssuerCN: "rv Intermediate CA",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), PublicKeyAlgorithm: "ECDSA", KeySizeBits: 256,
		SignatureAlgorithm: "ECDSAWithSHA256", ExtendedKeyUsage: []string{"serverAuth"}, KeyUsage: []string{"digitalSignature"},
		Source: "acme", CertPEM: []byte("pem"),
	}
	if err := rev.Revoke(big.NewInt(987654321), inter.ID, 1, now, meta); err != nil {
		t.Fatalf("acme-shaped Revoke: %v", err)
	}
	if err := db.QueryRow(`SELECT array_to_json(subject_alt_names)::text, array_to_json(extended_key_usage)::text, array_to_json(key_usage)::text
		FROM certificates WHERE fingerprint_sha256 = 'acme-fp-0001'`).Scan(&sans, &eku, &ku); err != nil {
		t.Fatalf("read back acme row: %v", err)
	}
	if sans != `["a.example.com","10.0.0.1"]` || eku != `["serverAuth"]` || ku != `["digitalSignature"]` {
		t.Fatalf("unexpected arrays san=%s eku=%s ku=%s", sans, eku, ku)
	}
}
