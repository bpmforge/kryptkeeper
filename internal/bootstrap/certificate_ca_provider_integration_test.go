// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/ocsp"
	_ "modernc.org/sqlite"
)

// setupIntegrationDB opens a fresh SQLite database and applies the real
// embedded migrations (S-51) instead of a hand-written CREATE TABLE, so a
// constraint present in production cannot be absent here -- this is exactly
// how a bug that made every certificate non-durable stayed invisible for as
// long as it did (see 000042_certificates_drop_nonauthoritative_fks and its
// ticket notes): the old hand-written certificates table declared
// template_id/team_id with no REFERENCES clause at all, so its FK behavior
// silently diverged from the migrated schema every real deployment runs.
// "?_fk=1" mirrors resolveSQLiteDSNFromEnv's production DSN
// (db_provider_helpers.go) so FK enforcement is actually on, not just
// declared. This also applies to ca_rotation_test.go's use of this helper --
// FK enforcement is now genuinely on for every caller, not just the tests in
// this file.
func setupIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "integration-test.db")
	db, err := sql.Open("sqlite", dbPath+"?_fk=1")
	if err != nil {
		t.Fatalf("open integration db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return db
}

func newIntegrationCAProvider(t *testing.T, db *sql.DB) (CertificateProvider, *ca.Engine) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	caStore := ca.NewDBStore(db, false)
	engine := ca.NewEngine(keys, caStore)

	_, err = engine.CreateRootCA("Integration Root", pkix.Name{
		CommonName: "Integration Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	revStore := ca.NewDBRevocationStore(db, false)
	provider := NewCACertificateProvider(engine, revStore, db, false)
	return provider, engine
}

// TestIntegration_IssuedCertSurvivesProviderRestart verifies that a cert
// issued to one provider instance is visible to a new provider instance
// backed by the same DB (S-51). Exercises the real migration schema (via
// setupIntegrationDB) with FK enforcement genuinely on, and issues with a
// real template_id and team_id -- neither one a row in certificate_templates
// or teams, matching the default configuration: templates are file-backed
// (never a DB row) and team_id is the issuing principal's identifier
// (handlers_certificates.go's authorizeCertificateMutationRequest), never a
// row in `teams` either. Before 000042 dropped those two FKs, this exact
// insert violated both of them and the write was never durable; listing
// scoped to the issuing principal's team_id (mirroring
// authorizeCertificateListQuery, which forces query.TeamID = principal for
// every non-bootstrap caller) is what GET /api/v1/certificates actually does.
func TestIntegration_IssuedCertSurvivesProviderRestart(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	caID := getFirstCAID(t, engine)
	csrPEM := generateTestCSRPEM(t, "restart-test.example.com", "restart-test.example.com")

	const principal = "team-restart-test"    // the issuing principal's identifier, not a `teams` row
	const templateID = "file-backed-default" // a file-backed template ID, not a `certificate_templates` row

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     csrPEM,
		TemplateID: templateID,
		TeamID:     principal,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	if issued.CertificateItem.TemplateID != templateID {
		t.Fatalf("issued cert template_id = %q, want %q", issued.CertificateItem.TemplateID, templateID)
	}
	if issued.CertificateItem.TeamID != principal {
		t.Fatalf("issued cert team_id = %q, want %q", issued.CertificateItem.TeamID, principal)
	}

	list1, err := provider.ListCertificates(ctx, CertificateListQuery{TeamID: principal})
	if err != nil || list1.Total != 1 {
		t.Fatalf("expected 1 cert before restart for principal %q, got %d (err=%v)", principal, list1.Total, err)
	}

	// Simulate process restart: new provider from the same DB (keys not needed for list).
	dir := t.TempDir()
	keys2, err := keystore.NewSoftwareStore(dir, []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("create second keystore: %v", err)
	}
	engine2 := ca.NewEngine(keys2, ca.NewDBStore(db, false))
	provider2 := NewCACertificateProvider(engine2, ca.NewDBRevocationStore(db, false), db, false)

	list2, err := provider2.ListCertificates(ctx, CertificateListQuery{TeamID: principal})
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	if list2.Total != 1 {
		t.Fatalf("cert must survive restart for the issuing principal %q: got %d certs", principal, list2.Total)
	}
	if list2.Items[0].CommonName != "restart-test.example.com" {
		t.Fatalf("unexpected CN after restart: %q", list2.Items[0].CommonName)
	}
	if list2.Items[0].TemplateID != templateID {
		t.Fatalf("template_id after restart = %q, want %q", list2.Items[0].TemplateID, templateID)
	}
	if list2.Items[0].TeamID != principal {
		t.Fatalf("team_id after restart = %q, want %q", list2.Items[0].TeamID, principal)
	}
}

// TestIntegration_IssueRevoke_OCSPAndCRL covers the full issue→revoke→OCSP→CRL path.
func TestIntegration_IssueRevoke_OCSPAndCRL(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	caID := getFirstCAID(t, engine)
	csrPEM := generateTestCSRPEM(t, "ocsp-test.example.com", "ocsp-test.example.com")

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:   caID,
		CSRPEM: csrPEM,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}

	fp := issued.CertificateItem.FingerprintSHA256
	serialStr := issued.CertificateItem.SerialNumber

	_, err = provider.RevokeCertificate(ctx, fp, CertificateRevokeRequest{ReasonCode: 1})
	if err != nil {
		t.Fatalf("revoke cert: %v", err)
	}

	revStore := ca.NewDBRevocationStore(db, false)

	// Parse serial string to *big.Int as IsRevoked requires.
	serial := new(big.Int)
	if _, ok := serial.SetString(serialStr, 10); !ok {
		t.Fatalf("parse serial %q as big.Int", serialStr)
	}

	// OCSP: IsRevoked must return true.
	revoked, _, _, err := revStore.IsRevoked(serial, caID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected cert to be revoked in DB")
	}

	// CRL: ListRevoked must include the serial.
	revList, err := revStore.ListRevoked(caID)
	if err != nil {
		t.Fatalf("ListRevoked: %v", err)
	}
	found := false
	for _, r := range revList {
		if r.Serial != nil && r.Serial.String() == serialStr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("serial %q not in CRL list (got %d entries)", serialStr, len(revList))
	}
}

// TestIntegration_RevokeInvalidatesOCSPCache is W19-01: found live against a
// real ACME client's revocation and independently true of this API's own
// RevokeCertificate -- ocsp.Responder caches each status response for its
// full validity window (24h default) and nothing ever called its own
// InvalidateCache, so a client that checked OCSP before revoking (a normal
// flow) kept getting "good" for the rest of that window even though this
// method's own comment claims OCSP "reflect[s] it immediately". Wires a real
// ocsp.Responder to the provider via SetOCSPCacheInvalidator, queries it
// (HTTP round trip, same as a real client) BEFORE revoking to populate the
// cache, then again after, and requires Good -> Revoked on that identical
// cached responder.
func TestIntegration_RevokeInvalidatesOCSPCache(t *testing.T) {
	db := setupIntegrationDB(t)
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	caStore := ca.NewDBStore(db, false)
	engine := ca.NewEngine(keys, caStore)
	caObj, err := engine.CreateRootCA("Integration Root", pkix.Name{
		CommonName: "Integration Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	revStore := ca.NewDBRevocationStore(db, false)
	provider := NewCACertificateProvider(engine, revStore, db, false)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "ocsp-cache-test.example.com", "ocsp-cache-test.example.com")
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:   caObj.ID,
		CSRPEM: csrPEM,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	cert := issued.CertificateItem
	serial := new(big.Int)
	if _, ok := serial.SetString(cert.SerialNumber, 10); !ok {
		t.Fatalf("parse serial %q as big.Int", cert.SerialNumber)
	}
	// goocsp.CreateRequest only reads cert.SerialNumber from this argument
	// (issuer name/key hash come from the issuer cert) -- CertificateItem
	// carries no PEM to parse a full leaf from, and none is needed here.
	leaf := &x509.Certificate{SerialNumber: serial}

	invalidatable, ok := provider.(interface {
		SetOCSPCacheInvalidator(ca.RevocationCacheInvalidator)
	})
	if !ok {
		t.Fatal("provider does not implement SetOCSPCacheInvalidator")
	}

	signer, err := keys.Signer(caObj.KeyID)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	ocspResponder := ocsp.NewResponder(
		func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
			return revStore.IsRevoked(serial, caObj.ID)
		},
		func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
			return caObj.Certificate, signer, nil
		},
		24*time.Hour, 100,
	)
	invalidatable.SetOCSPCacheInvalidator(ocspResponder)
	ocspServer := httptest.NewServer(ocspResponder.Handler())
	defer ocspServer.Close()

	queryOCSP := func() int {
		t.Helper()
		reqDER, err := goocsp.CreateRequest(leaf, caObj.Certificate, nil)
		if err != nil {
			t.Fatalf("create OCSP request: %v", err)
		}
		httpResp, err := http.Post(ocspServer.URL, "application/ocsp-request", bytes.NewReader(reqDER))
		if err != nil {
			t.Fatalf("OCSP POST: %v", err)
		}
		defer httpResp.Body.Close()
		respDER, err := io.ReadAll(httpResp.Body)
		if err != nil {
			t.Fatalf("read OCSP response: %v", err)
		}
		parsed, err := goocsp.ParseResponse(respDER, caObj.Certificate)
		if err != nil {
			t.Fatalf("parse OCSP response: %v", err)
		}
		return parsed.Status
	}

	if status := queryOCSP(); status != goocsp.Good {
		t.Fatalf("pre-revocation OCSP status = %d, want Good", status)
	}

	if _, err := provider.RevokeCertificate(ctx, cert.FingerprintSHA256, CertificateRevokeRequest{ReasonCode: 1}); err != nil {
		t.Fatalf("revoke cert: %v", err)
	}

	if status := queryOCSP(); status != goocsp.Revoked {
		t.Fatalf("post-revocation OCSP status = %d, want Revoked -- OCSP cache was not invalidated on revoke", status)
	}
}

// TestIntegration_TemplatePolicyRejectsDisallowedAlgorithm verifies that issuance
// fails with ErrPolicyViolation when the CSR uses an algorithm not allowed by the template.
func TestIntegration_TemplatePolicyRejectsDisallowedAlgorithm(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	caID := getFirstCAID(t, engine)

	templates := &integrationMemTemplateProvider{templates: map[string]TemplateItem{
		"rsa-only": {
			ID:                "rsa-only",
			Name:              "RSA Only",
			Active:            true,
			AllowedAlgorithms: []string{"RSA"},
			ValidityPeriod:    "720h",
		},
	}}
	provider = WithTemplateProvider(provider, templates)

	// ECDSA CSR against an RSA-only template must be rejected.
	csrPEM := generateTestCSRPEM(t, "policy-test.example.com")
	_, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "rsa-only",
		CSRPEM:     csrPEM,
	})
	if err == nil {
		t.Fatal("expected policy violation, got nil")
	}
}

// integrationMemTemplateProvider is a minimal in-memory TemplateProvider for tests.
type integrationMemTemplateProvider struct {
	templates map[string]TemplateItem
}

func (m *integrationMemTemplateProvider) ListTemplates(_ context.Context, _ TemplateListQuery) (TemplateListResult, error) {
	items := make([]TemplateItem, 0, len(m.templates))
	for _, t := range m.templates {
		items = append(items, t)
	}
	return TemplateListResult{Items: items, Total: len(items), Limit: 25}, nil
}

func (m *integrationMemTemplateProvider) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	t, ok := m.templates[id]
	return t, ok, nil
}

func (m *integrationMemTemplateProvider) CreateTemplate(_ context.Context, _ TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, nil
}

func (m *integrationMemTemplateProvider) ReplaceTemplate(_ context.Context, _ string, _ TemplateUpsertRequest, _ int) (TemplateItem, error) {
	return TemplateItem{}, nil
}

func (m *integrationMemTemplateProvider) PatchTemplate(_ context.Context, _ string, _ TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, nil
}

func (m *integrationMemTemplateProvider) CloneTemplate(_ context.Context, _ string, _ TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, nil
}

func (m *integrationMemTemplateProvider) DeleteTemplate(_ context.Context, _ string) error {
	return nil
}

// S-50 follow-up, found 2026-08-20 while wiring the UI horizon (which
// reads renewal_method): RenewCertificate stamped RenewalMethod
// "renewal", but certificates.renewal_method's CHECK only admits
// acme|est|scep|api|manual. Against a DB-backed provider the INSERT was
// therefore rejected and the renewal — already SIGNED, its serial already
// burned — could not be recorded.
//
// The existing renewal tests never caught it because newTestCAProvider
// has no db, so writeCertToDB is never reached. This one is DB-backed on
// purpose; that is the whole point of it.
func TestRenewCertificatePersistsAgainstTheSchemaCheck(t *testing.T) {
	ctx := context.Background()
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	caID := getFirstCAID(t, engine)

	original, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "renew-persist.example.com", "renew-persist.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-renew",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	renewed, err := provider.RenewCertificate(ctx, original.CertificateItem.FingerprintSHA256,
		CertificateRenewRequest{
			CSRPEM: generateTestCSRPEM(t, "renew-persist.example.com", "renew-persist.example.com"),
		})
	if err != nil {
		t.Fatalf("renewal was signed but not recorded — the serial is burned and the row is gone: %v", err)
	}

	// It must actually be in the table, not merely in memory: the S-50
	// family of bugs is precisely "looked fine until restart".
	var stored string
	if err := db.QueryRow(
		`SELECT renewal_method FROM certificates WHERE fingerprint_sha256 = ?`,
		renewed.CertificateItem.FingerprintSHA256,
	).Scan(&stored); err != nil {
		t.Fatalf("renewed certificate is not in the database: %v", err)
	}

	// And whatever it stores has to be a value the column actually allows.
	switch stored {
	case "acme", "est", "scep", "api", "manual":
	default:
		t.Fatalf("renewal_method %q is not in the schema's allowed set", stored)
	}
}

// Found 2026-08-20 using the product against a real backend: the crypto
// posture report showed "0 vulnerable" and a red 0% PQC score for an
// estate whose certificate was flagged pqc_vulnerable = true.
//
// computePQCReadiness ran at issuance and the answer lived only in memory;
// pqc_vulnerable had a column, pqc_readiness never did. So every DB-backed
// read returned "", the aggregator bucketed the certificate as
// not_applicable, and the product's headline metric reported a false
// all-clear. Same "looked fine until you read it back" family as S-50.
func TestPQCReadinessSurvivesReadBack(t *testing.T) {
	ctx := context.Background()
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	caID := getFirstCAID(t, engine)

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "pqc-readback.example.com", "pqc-readback.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-pqc",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	atIssuance := issued.CertificateItem.PQCReadiness
	if atIssuance == "" {
		t.Fatal("issuance must classify PQC readiness")
	}

	// GetCertificate serves the in-memory map, so it would pass even with
	// nothing persisted. Build a SECOND provider over the same database —
	// that is a restart, and it is the only path that proves the value was
	// actually stored and hydrated.
	restarted, _ := newIntegrationCAProvider(t, db)
	got, ok, err := restarted.GetCertificate(ctx, issued.CertificateItem.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("certificate missing after restart: %v ok=%v", err, ok)
	}
	if got.CertificateItem.PQCReadiness != atIssuance {
		t.Fatalf("PQC readiness lost across a restart: issued %q, read %q",
			atIssuance, got.CertificateItem.PQCReadiness)
	}

	// The two PQC fields must agree — their disagreement is what produced
	// the false all-clear.
	if got.CertificateItem.PQCVulnerable && got.CertificateItem.PQCReadiness == "" {
		t.Fatal("a certificate flagged vulnerable must not read back unclassified")
	}
}
