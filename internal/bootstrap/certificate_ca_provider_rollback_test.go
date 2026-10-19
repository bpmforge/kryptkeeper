// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"errors"
	"io"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// A failed persist must leave memory matching the database, not ahead of it
// until the next restart reverts the change silently.
func TestFailedPersistLeavesEstateAndOwnershipUnchanged(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	res, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, CSRPEM: generateTestCSRPEM(t, "rb.example.com", "rb.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	fp := res.FingerprintSHA256
	before, _, _ := provider.GetCertificate(ctx, fp)

	if _, err := db.Exec(`DROP TABLE certificates`); err != nil {
		t.Fatal(err)
	}

	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{ManagementState: "external", RenewalStatus: "reissue_required", RenewalMethod: "manual"}); err == nil {
		t.Fatal("UpdateEstate must fail when the row cannot be written")
	}
	if _, err := provider.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerEmail: "x@example.com", OwnerTeam: "t", ServiceName: "svc"}); err == nil {
		t.Fatal("UpdateOwnership must fail when the row cannot be written")
	}
	// A rejected value mid-request must not leave earlier fields applied.
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{ManagementState: "external", Origin: "bogus"}); err == nil {
		t.Fatal("invalid origin must be rejected")
	}

	after, _, _ := provider.GetCertificate(ctx, fp)
	if after.ManagementState != before.ManagementState || after.RenewalStatus != before.RenewalStatus ||
		after.RenewalMethod != before.RenewalMethod || after.OwnerEmail != before.OwnerEmail ||
		after.OwnerTeam != before.OwnerTeam || after.ServiceName != before.ServiceName || after.Origin != before.Origin {
		t.Fatalf("memory diverged from the database after failed writes:\nbefore=%+v\nafter=%+v", before, after)
	}
}

// failingSignerStore wraps a real store and, once down is set, hands out a
// signer whose Sign fails like a removed HSM token.
type failingSignerStore struct {
	keystore.Store
	down bool
}

type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("pkcs11: token removed")
}

func (s *failingSignerStore) Signer(id string) (crypto.Signer, error) {
	sg, err := s.Store.Signer(id)
	if err != nil || !s.down {
		return sg, err
	}
	return failingSigner{sg}, nil
}

// Acceptance W23-12 #3: with the signing backend gone, issuance fails closed
// (503-class), records nothing, and raises keystore.backend_unavailable once.
func TestIssueFailsClosedWhenKeystoreBackendDown(t *testing.T) {
	db := setupIntegrationDB(t)
	soft, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	store := &failingSignerStore{Store: soft}
	engine := ca.NewEngine(store, ca.NewDBStore(db, false))
	if _, err := engine.CreateRootCA("Down Root", pkix.Name{CommonName: "Down Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	provider := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, false), db, false)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	var alerts []string
	orig := keystoreAlertHook
	keystoreAlertHook = func(code, id string, _ error) { alerts = append(alerts, code+":"+id) }
	t.Cleanup(func() { keystoreAlertHook = orig })

	countRows := func() int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	listed := func() int {
		res, err := provider.ListCertificates(ctx, CertificateListQuery{})
		if err != nil {
			t.Fatal(err)
		}
		return len(res.Items)
	}
	rowsBefore, listBefore := countRows(), listed()

	store.down = true
	_, err = provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, CSRPEM: generateTestCSRPEM(t, "down.example.com", "down.example.com")})
	if err == nil || !errors.Is(err, errKeystoreBackendUnavailable) {
		t.Fatalf("want errKeystoreBackendUnavailable, got %v", err)
	}
	if countRows() != rowsBefore || listed() != listBefore {
		t.Fatalf("certificates recorded despite backend failure: rows %d->%d list %d->%d", rowsBefore, countRows(), listBefore, listed())
	}
	if len(alerts) != 1 || alerts[0] != "keystore.backend_unavailable:"+caID {
		t.Fatalf("alerts = %v, want exactly one keystore.backend_unavailable", alerts)
	}

	// A client error must NOT be classified as a backend outage.
	alerts = nil
	_, err = provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: "no-such-ca", CSRPEM: generateTestCSRPEM(t, "x.example.com", "x.example.com")})
	if err == nil || errors.Is(err, errKeystoreBackendUnavailable) || len(alerts) != 0 {
		t.Fatalf("unknown CA misclassified as backend outage: err=%v alerts=%v", err, alerts)
	}
}
