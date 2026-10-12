// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// Regression (rc.5, found by the Postgres sweep): certificate_authorities.status
// had a CHECK without 'pending_ceremony', so a root-CA key ceremony against the
// real migrated schema failed on BOTH engines after the CA was already created
// active. The ca package's ceremony tests use a store that never enforced it.
func TestRootCACeremonyAgainstMigratedSQLiteSchema(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	db, _, err := OpenCoreDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, false))
	cm, err := ca.NewCeremonyManager(db, false, engine)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cm.StartRootCACeremony(ca.RootCACeremonyParams{Name: "cer", CommonName: "Cer Root",
		Algorithm: keystore.ECDSAP256, ValidityDays: 365, Initiator: "alice",
		Approvers: []string{"bob", "carol"}, Quorum: 2})
	if err != nil {
		t.Fatalf("StartRootCACeremony: %v", err)
	}
	if _, err := cm.Approve(c.ID, "bob"); err != nil {
		t.Fatalf("Approve bob: %v", err)
	}
	done, err := cm.Approve(c.ID, "carol")
	if err != nil || done.Status != ca.CeremonyCompleted {
		t.Fatalf("Approve carol: %+v %v", done, err)
	}
	got, err := engine.GetCA(c.CAID)
	if err != nil || got.Status != "active" {
		t.Fatalf("CA after quorum: %+v %v", got, err)
	}
}
