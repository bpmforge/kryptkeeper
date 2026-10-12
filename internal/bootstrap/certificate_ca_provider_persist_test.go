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
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"

	_ "modernc.org/sqlite"
)

// S-50. TestIntegration_IssuedCertSurvivesProviderRestart already covered the
// happy path, and passed — the write works when the database cooperates. The
// gap was entirely the failure path, which was `_ = p.writeCertToDB(...)`:
// error discarded, 200 returned, certificate gone on the next restart with
// nothing logged. Observed in the running product: 3 certificates served by
// the API while the certificates table held none of them.

func TestIssuanceFailsWhenTheCertificateCannotBeRecorded(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	// Make persistence fail the way a real outage would.
	if _, err := db.Exec(`DROP TABLE certificates`); err != nil {
		t.Fatalf("drop certificates table: %v", err)
	}

	_, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:   caID,
		CSRPEM: generateTestCSRPEM(t, "unrecordable.example.com", "unrecordable.example.com"),
	})
	if err == nil {
		t.Fatal("issuance must fail when the certificate cannot be recorded: " +
			"reporting success hands the caller a credential the system can never " +
			"inventory, renew, expire or revoke")
	}
	if !strings.Contains(err.Error(), "could not be recorded") {
		t.Fatalf("error should say the record failed, got: %v", err)
	}
}

func TestAFailedPersistDoesNotLeaveTheCertInMemory(t *testing.T) {
	// If it isn't recorded it isn't issued — the in-memory map must not keep a
	// certificate the caller was told they did not get, or the two stores
	// disagree until the next restart silently resolves it.
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	if _, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:   caID,
		CSRPEM: generateTestCSRPEM(t, "good.example.com", "good.example.com"),
	}); err != nil {
		t.Fatalf("precondition: first issuance should succeed: %v", err)
	}

	if _, err := db.Exec(`DROP TABLE certificates`); err != nil {
		t.Fatalf("drop certificates table: %v", err)
	}
	_, _ = provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:   caID,
		CSRPEM: generateTestCSRPEM(t, "bad.example.com", "bad.example.com"),
	})

	list, err := provider.ListCertificates(ctx, CertificateListQuery{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Total != 1 {
		t.Fatalf("expected only the recorded certificate to remain, got %d", list.Total)
	}
	for _, c := range list.Items {
		if strings.HasPrefix(c.CommonName, "bad.") {
			t.Fatal("a certificate whose persist failed is still listed; " +
				"it will vanish on the next restart")
		}
	}
}

// TestRecordIssuedCertificateWritesARealRow is W18-16's DB-backed half of
// TestCACertificateProviderRecordIssuedCertificate (certificate_ca_provider_test.go),
// which only proves the in-memory p.certs cache was updated -- newTestCAProvider
// there passes db=nil, so writeCertToDB never actually runs. writeCertToDB's own
// comment warns that INSERT OR IGNORE / ON CONFLICT DO NOTHING swallows a CHECK
// violation as silently as a duplicate (see TestIssuanceFailsWhenTheCertificateCannotBeRecorded's
// history above), so passing here proves the row survived the real migrated
// schema's constraints (source='acme', origin='internal', management_state='managed',
// nullable template_id/team_id) -- not just that Go returned a nil error.
func TestRecordIssuedCertificateWritesARealRow(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	recorder, ok := provider.(interface {
		RecordIssuedCertificate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error
	})
	if !ok {
		t.Fatal("caCertificateProvider does not implement RecordIssuedCertificate")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "acme-db.example.com"},
		DNSNames: []string{"acme-db.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		DNSNames:    csrTmpl.DNSNames,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("issue via engine: %v", err)
	}

	if err := recorder.RecordIssuedCertificate(ctx, caID, issued.Certificate, issued.CertPEM, "acme"); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}

	var gotSource, gotCAID, gotSANs string
	row := db.QueryRow(`SELECT source, ca_id, subject_alt_names FROM certificates WHERE fingerprint_sha256 = ?`, issued.Fingerprint)
	if err := row.Scan(&gotSource, &gotCAID, &gotSANs); err != nil {
		t.Fatalf("row not found in certificates table (writeCertToDB's INSERT OR IGNORE silently dropped it): %v", err)
	}
	if gotSource != "acme" {
		t.Errorf("expected source=acme, got %s", gotSource)
	}
	if gotCAID != caID {
		t.Errorf("expected ca_id=%s, got %s", caID, gotCAID)
	}
	if !strings.Contains(gotSANs, "acme-db.example.com") {
		t.Errorf("expected subject_alt_names to contain the DNS SAN, got %s", gotSANs)
	}
}

// TestCMPAndTLSListenerSourcesPersist is W19-33's regression for the defect
// the W19-31 protocols fixture found: certificates.source's CHECK
// constraint (000042) never included "cmp" (internal/cmp/server.go, W18-18)
// or "tls-listener" (cmd/kryptkeeper/tls.go's tlsListenerSource, W19-21), so
// writeCertToDB's INSERT OR IGNORE silently dropped both -- CMP-issued and
// the hub's self-issued listener certificate never reached inventory.
// 000060_certificates_source_vocabulary widens the constraint; this proves
// both sources now write and read back through the real migrated schema.
func TestCMPAndTLSListenerSourcesPersist(t *testing.T) {
	for _, source := range []string{"cmp", "tls-listener"} {
		t.Run(source, func(t *testing.T) {
			db := setupIntegrationDB(t)
			provider, engine := newIntegrationCAProvider(t, db)
			ctx := context.Background()
			caID := getFirstCAID(t, engine)

			recorder, ok := provider.(interface {
				RecordIssuedCertificate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error
			})
			if !ok {
				t.Fatal("caCertificateProvider does not implement RecordIssuedCertificate")
			}

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			cn := source + ".example.com"
			csrTmpl := &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: cn},
				DNSNames: []string{cn},
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
			if err != nil {
				t.Fatalf("create CSR: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("parse CSR: %v", err)
			}

			issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
				CSR:         csr,
				Validity:    90 * 24 * time.Hour,
				DNSNames:    csrTmpl.DNSNames,
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				t.Fatalf("issue via engine: %v", err)
			}

			if err := recorder.RecordIssuedCertificate(ctx, caID, issued.Certificate, issued.CertPEM, source); err != nil {
				t.Fatalf("RecordIssuedCertificate(source=%q): %v", source, err)
			}

			var gotSource string
			row := db.QueryRow(`SELECT source FROM certificates WHERE fingerprint_sha256 = ?`, issued.Fingerprint)
			if err := row.Scan(&gotSource); err != nil {
				t.Fatalf("row not found in certificates table (CHECK constraint rejected source=%q): %v", source, err)
			}
			if gotSource != source {
				t.Errorf("expected source=%s, got %s", source, gotSource)
			}
		})
	}
}

// TestWriteCertToDBReportsRejectedSourceAsError proves the other half of
// W19-33: even when the vocabulary is later incomplete again (a future
// writer adds a source no migration has allowed yet), the rejection must
// come back as an error a caller can log -- never as a silent no-op the way
// "cmp" and "tls-listener" were dropped before 000060.
func TestWriteCertToDBReportsRejectedSourceAsError(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	recorder, ok := provider.(interface {
		RecordIssuedCertificate(ctx context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error
	})
	if !ok {
		t.Fatal("caCertificateProvider does not implement RecordIssuedCertificate")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "rejected-source.example.com"},
		DNSNames: []string{"rejected-source.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		DNSNames:    csrTmpl.DNSNames,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("issue via engine: %v", err)
	}

	const invalidSource = "not-a-real-source"
	err = recorder.RecordIssuedCertificate(ctx, caID, issued.Certificate, issued.CertPEM, invalidSource)
	if err == nil {
		t.Fatal("recording a certificate with a source outside the CHECK vocabulary must error, " +
			"not silently drop the row the way \"cmp\" and \"tls-listener\" did before W19-33")
	}
	if !strings.Contains(err.Error(), issued.Fingerprint) {
		t.Errorf("error should name the fingerprint %s, got: %v", issued.Fingerprint, err)
	}
	if !strings.Contains(err.Error(), invalidSource) {
		t.Errorf("error should name the rejected source %q, got: %v", invalidSource, err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE fingerprint_sha256 = ?`, issued.Fingerprint).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Errorf("expected the rejected row to be absent, found %d", count)
	}
}

func TestInventoryReportsAnErrorRatherThanEmptyWhenItCannotLoad(t *testing.T) {
	// The failure this prevents: a database hiccup at boot used to leave the
	// provider with an empty map, so every screen looked healthy and calmly
	// reported that there were no certificates at all.
	db := setupIntegrationDB(t)

	if _, err := db.Exec(`DROP TABLE certificates`); err != nil {
		t.Fatalf("drop certificates table: %v", err)
	}

	// Constructed after the drop, so its startup hydrate is the thing that
	// fails. Built directly (nil engine — hydrate and List never touch it):
	// the newIntegrationCAProvider helper creates a root CA first, which
	// itself needs the certificates table this test just removed.
	provider := NewCACertificateProvider(nil, nil, db, false)

	_, err := provider.ListCertificates(context.Background(), CertificateListQuery{})
	if err == nil {
		t.Fatal("an inventory that could not be loaded must report an error, " +
			"not an empty list — an empty list is a claim that no certificates exist")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("error should mark the inventory unavailable, got: %v", err)
	}
}

// W20-15: the template a protocol issuance was held to reaches the real
// certificates row, not just the in-memory cache (writeCertToDB is INSERT OR
// IGNORE, so a rejected row would otherwise pass silently).
func TestRecordIssuedCertificateWithTemplateWritesTemplateID(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	recorder, ok := provider.(ca.TemplateIssuedCertificateRecorder)
	if !ok {
		t.Fatal("caCertificateProvider does not implement ca.TemplateIssuedCertificateRecorder")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "wstep-db"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
		CSR: csr, Validity: 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	const templateID = "6f1c2d3e-4a5b-4c6d-8e7f-001122334455"
	if err := recorder.RecordIssuedCertificateWithTemplate(ctx, caID, issued.Certificate, issued.CertPEM, "wstep", templateID); err != nil {
		t.Fatalf("RecordIssuedCertificateWithTemplate: %v", err)
	}
	var gotSource, gotTemplate string
	if err := db.QueryRow(`SELECT source, template_id FROM certificates WHERE fingerprint_sha256 = ?`, issued.Fingerprint).Scan(&gotSource, &gotTemplate); err != nil {
		t.Fatalf("row not found in certificates table: %v", err)
	}
	if gotSource != "wstep" || gotTemplate != templateID {
		t.Errorf("row source=%q template_id=%q, want wstep and %s", gotSource, gotTemplate, templateID)
	}
}
