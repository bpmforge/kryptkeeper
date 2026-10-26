// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/cloudinventory"
)

// W38-05 (D-323): cloud-found certificates become inventory rows.

func certPEMText(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

type cloudImportEnv struct {
	t        *testing.T
	db       *sql.DB
	provider CertificateProvider
	listed   []cloudinventory.CloudCertificate
	scopes   []cloudinventory.Scope
	scopeErr map[string]string
}

func newCloudImportEnv(t *testing.T) *cloudImportEnv {
	t.Helper()
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	e := &cloudImportEnv{t: t, db: db, provider: provider, scopeErr: map[string]string{}}

	origConn, origScope, origLoad, origAfter := newCloudConnector, newCloudScopeConnector, loadCloudScopes, afterDiscoveryScanPersist
	newCloudConnector = func(context.Context, string) (cloudConnector, error) { return e, nil }
	newCloudScopeConnector = func(_ context.Context, s cloudinventory.Scope) (cloudConnector, error) {
		if msg := e.scopeErr[s.Key()]; msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return scopedLister{e: e, key: s.Key()}, nil
	}
	loadCloudScopes = func(context.Context) ([]cloudinventory.Scope, error) { return e.scopes, nil }
	afterDiscoveryScanPersist = func(string) {}
	t.Cleanup(func() {
		newCloudConnector, newCloudScopeConnector, loadCloudScopes, afterDiscoveryScanPersist = origConn, origScope, origLoad, origAfter
	})
	return e
}

func (e *cloudImportEnv) ListCertificates(context.Context) ([]cloudinventory.CloudCertificate, error) {
	return e.listed, nil
}

// scopedLister serves the certificates of e.listed whose Scope matches; the
// fan-out stamps Scope itself, so the fixture tags the scope in advance.
type scopedLister struct {
	e   *cloudImportEnv
	key string
}

func (s scopedLister) ListCertificates(context.Context) ([]cloudinventory.CloudCertificate, error) {
	var out []cloudinventory.CloudCertificate
	for _, c := range s.e.listed {
		if c.Scope == s.key {
			out = append(out, c)
		}
	}
	return out, nil
}

// scan runs one cloud_acm scan job owned by tenant and returns its summary.
func (e *cloudImportEnv) scan(tenant string) cloudScanSummary {
	e.t.Helper()
	id := fmt.Sprintf("scan-%d", time.Now().UnixNano())
	if _, err := e.db.Exec(`INSERT INTO scan_jobs (id, type, connector, scope, status, tenant) VALUES (?, 'cloud_acm', 'api', '{}', 'running', ?)`, id, tenant); err != nil {
		e.t.Fatalf("insert scan job: %v", err)
	}
	runCloudScanAndFinalize(context.Background(), e.db, false, id, scanTypeCloudACM)
	var raw sql.NullString
	var status string
	if err := e.db.QueryRow(`SELECT status, results_summary FROM scan_jobs WHERE id = ?`, id).Scan(&status, &raw); err != nil {
		e.t.Fatal(err)
	}
	var sum cloudScanSummary
	if err := json.Unmarshal([]byte(raw.String), &sum); err != nil {
		e.t.Fatalf("summary (%s): %v / %q", status, err, raw.String)
	}
	if sum.Import == nil {
		e.t.Fatalf("scan has no import summary (status %s): %s", status, raw.String)
	}
	return sum
}

func (e *cloudImportEnv) inventory() map[string]CertificateItem {
	e.t.Helper()
	res, err := listAllCertificates(context.Background(), e.provider, CertificateListQuery{})
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]CertificateItem{}
	for _, c := range res.Items {
		if c.Source == "discovery_cloud" {
			out[c.FingerprintSHA256] = c
		}
	}
	return out
}

func (e *cloudImportEnv) activeLinks(tenant string) int {
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM certificate_cloud_resources WHERE tenant = ? AND currently_active = 1`, tenant).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

const acmARN = "arn:aws:acm:us-east-1:111122223333:certificate/"

func acmCert(id, cn, pemText string, withKey bool) cloudinventory.CloudCertificate {
	c := cloudinventory.CloudCertificate{
		Provider: cloudinventory.ProviderAWSACM, Region: "us-east-1", ResourceID: acmARN + id, CommonName: cn,
		DNSNames: []string{cn}, Status: "ISSUED", InUse: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour),
		CertificatePEM: pemText,
	}
	if withKey {
		c.KeyAlgorithm = "RSA_2048"
	}
	return c
}

func TestCloudImportRealAndSyntheticRowsAreInventoryRowsAndRerunAddsNone(t *testing.T) {
	e := newCloudImportEnv(t)
	real := newSelfSignedForDiscovery(t, "real.example.com")
	pending := acmCert("pending", "p.example.com", "", true)
	pending.Status, pending.NotAfter = "PENDING_VALIDATION", time.Time{}
	azureNoKey := cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderAzureKeyVault, ResourceID: "https://v.vault.azure.net/certificates/x/1", CommonName: "x", NotAfter: time.Now().Add(time.Hour)}
	e.listed = []cloudinventory.CloudCertificate{
		acmCert("real", "real.example.com", certPEMText(real), true),
		acmCert("meta", "meta.example.com", "", true),
		pending, azureNoKey,
	}

	first := e.scan("")
	if got := first.Import; got.Imported != 2 || got.Known != 0 || got.Skipped != 2 || got.MetadataOnly != 1 || len(got.Failed) != 0 {
		t.Fatalf("first import: %+v", got)
	}
	inv := e.inventory()
	if len(inv) != 2 {
		t.Fatalf("want 2 inventory rows, got %d", len(inv))
	}
	realRow, ok := inv[fingerprintOf(real)]
	if !ok {
		t.Fatal("the real certificate must be keyed by its DER fingerprint (same key discovery uses)")
	}
	if realRow.Origin != "discovered" || realRow.ManagementState != "unmanaged" || realRow.CommonName != "real.example.com" {
		t.Fatalf("real row estate/facts wrong: %+v", realRow)
	}
	var synth CertificateItem
	for fp, c := range inv {
		if fp != fingerprintOf(real) {
			synth = c
		}
	}
	if synth.CommonName != "meta.example.com" || synth.PublicKeyAlgorithm != "RSA" || synth.KeySizeBits != 2048 || synth.PQCReadiness != "vulnerable" {
		t.Fatalf("synthetic row facts wrong: %+v", synth)
	}
	var kind, account, region string
	if err := e.db.QueryRow(`SELECT fingerprint_kind, account, region FROM certificate_cloud_resources WHERE resource_id = ?`, acmARN+"meta").Scan(&kind, &account, &region); err != nil {
		t.Fatal(err)
	}
	if kind != "synthetic" || account != "111122223333" || region != "us-east-1" {
		t.Fatalf("link must record kind/account/region: %s %s %s", kind, account, region)
	}

	second := e.scan("")
	if got := second.Import; got.Imported != 0 || got.Known != 2 || got.Removed != 0 {
		t.Fatalf("rerun must add 0 rows: %+v", got)
	}
	if len(e.inventory()) != 2 || e.activeLinks("") != 2 {
		t.Fatalf("rerun duplicated rows or links: %d / %d", len(e.inventory()), e.activeLinks(""))
	}
	if strings.Contains(fmt.Sprint(second), "BEGIN CERTIFICATE") {
		t.Fatal("certificate PEM leaked into the scan summary")
	}
}

func TestCloudImportRetiresLinksOfResourcesRemovedAtSource(t *testing.T) {
	e := newCloudImportEnv(t)
	a, b := newSelfSignedForDiscovery(t, "a.example.com"), newSelfSignedForDiscovery(t, "b.example.com")
	e.listed = []cloudinventory.CloudCertificate{acmCert("a", "a", certPEMText(a), true), acmCert("b", "b", certPEMText(b), true)}
	e.scan("")
	e.listed = e.listed[:1]
	sum := e.scan("")
	if sum.Import.Removed != 1 || e.activeLinks("") != 1 {
		t.Fatalf("removed-at-source: %+v active=%d", sum.Import, e.activeLinks(""))
	}
	var removedAt sql.NullString
	if err := e.db.QueryRow(`SELECT removed_at FROM certificate_cloud_resources WHERE resource_id = ?`, acmARN+"b").Scan(&removedAt); err != nil || !removedAt.Valid {
		t.Fatalf("removed_at not stamped: %v", err)
	}
	// The row stays in the inventory (like a discovered certificate whose
	// endpoint went quiet); only the link says it is no longer in the cloud.
	if _, ok := e.inventory()[fingerprintOf(b)]; !ok {
		t.Fatal("certificate row must survive the retirement of its link")
	}
	// It comes back when the resource reappears.
	e.listed = append(e.listed, acmCert("b", "b", certPEMText(b), true))
	if sum = e.scan(""); sum.Import.Removed != 0 || e.activeLinks("") != 2 {
		t.Fatalf("reappearing resource must reactivate: %+v active=%d", sum.Import, e.activeLinks(""))
	}
}

func TestCloudImportFailedScopeIsNotSweptAndSameCertAcrossScopesIsOneRow(t *testing.T) {
	e := newCloudImportEnv(t)
	shared := newSelfSignedForDiscovery(t, "shared.example.com")
	e.scopes = []cloudinventory.Scope{
		{Provider: cloudinventory.ProviderAWSACM, Region: "us-east-1"},
		{Provider: cloudinventory.ProviderAWSACM, Region: "eu-west-1"},
	}
	k1, k2 := e.scopes[0].Key(), e.scopes[1].Key()
	c1, c2 := acmCert("one", "shared", certPEMText(shared), true), acmCert("two", "shared", certPEMText(shared), true)
	c1.Scope, c2.Scope = k1, k2
	c2.Region = "eu-west-1"
	e.listed = []cloudinventory.CloudCertificate{c1, c2}

	if sum := e.scan(""); sum.Import.Imported != 1 || sum.Import.Known != 1 {
		t.Fatalf("same certificate in two regions must be one row: %+v", sum.Import)
	}
	if len(e.inventory()) != 1 || e.activeLinks("") != 2 {
		t.Fatalf("want 1 row / 2 links, got %d / %d", len(e.inventory()), e.activeLinks(""))
	}

	e.scopeErr[k2] = "AccessDenied"
	e.listed = []cloudinventory.CloudCertificate{c1}
	sum := e.scan("")
	if sum.Import.Removed != 0 || e.activeLinks("") != 2 {
		t.Fatalf("a failed scope must not retire its links: %+v active=%d", sum.Import, e.activeLinks(""))
	}
}

func TestCloudImportNeverOverwritesAManagedRowAndLinksIt(t *testing.T) {
	e := newCloudImportEnv(t)
	c := newSelfSignedForDiscovery(t, "hub-issued.example.com")
	if _, err := e.db.Exec(`INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names, issuer_dn,
		 valid_from, valid_until, public_key_algorithm, signature_algorithm, risk_score, risk_flags,
		 raw_cert_b64, updated_at, source, origin, management_state)
		VALUES (?, '1', 'CN=hub-issued.example.com', 'hub-issued.example.com', '[]', 'CN=Hub', '2026-01-01T00:00:00Z', '2030-01-01T00:00:00Z',
		        'ECDSA', 'ECDSA-SHA256', 0, '[]', NULL, '2026-01-01T00:00:00Z', 'api', 'internal', 'managed')`, fingerprintOf(c)); err != nil {
		t.Fatal(err)
	}
	e.listed = []cloudinventory.CloudCertificate{acmCert("hub", "hub-issued.example.com", certPEMText(c), true)}
	sum := e.scan("")
	if sum.Import.Known != 1 || sum.Import.Imported != 0 {
		t.Fatalf("import: %+v", sum.Import)
	}
	var origin, mgmt, source string
	if err := e.db.QueryRow(`SELECT origin, management_state, source FROM certificates WHERE fingerprint_sha256 = ?`, fingerprintOf(c)).Scan(&origin, &mgmt, &source); err != nil {
		t.Fatal(err)
	}
	if origin != "internal" || mgmt != "managed" || source != "api" {
		t.Fatalf("a managed row must keep its estate: %s/%s/%s", origin, mgmt, source)
	}
	if e.activeLinks("") != 1 {
		t.Fatal("the cloud resource must still be recorded against the managed certificate")
	}
}

func TestCloudImportLinksAreTenantScoped(t *testing.T) {
	e := newCloudImportEnv(t)
	c := newSelfSignedForDiscovery(t, "t.example.com")
	e.listed = []cloudinventory.CloudCertificate{acmCert("t", "t", certPEMText(c), true)}
	e.scan("team-a")
	e.scan("")
	if e.activeLinks("team-a") != 1 || e.activeLinks("") != 1 {
		t.Fatalf("each tenant keeps its own link: a=%d default=%d", e.activeLinks("team-a"), e.activeLinks(""))
	}
	// The default tenant's scan stops seeing the resource: only its link retires.
	e.listed = nil
	e.scan("")
	if e.activeLinks("team-a") != 1 || e.activeLinks("") != 0 {
		t.Fatalf("a sweep must stay inside its tenant: a=%d default=%d", e.activeLinks("team-a"), e.activeLinks(""))
	}
}

func TestCloudImportSyntheticRowIsSupersededWhenTheBodyArrives(t *testing.T) {
	e := newCloudImportEnv(t)
	c := newSelfSignedForDiscovery(t, "later.example.com")
	e.listed = []cloudinventory.CloudCertificate{acmCert("later", "later.example.com", "", true)}
	e.scan("")
	synthetic := ""
	for fp := range e.inventory() {
		synthetic = fp
	}
	e.listed = []cloudinventory.CloudCertificate{acmCert("later", "later.example.com", certPEMText(c), true)}
	e.scan("")
	var succ sql.NullString
	var status string
	if err := e.db.QueryRow(`SELECT successor_fingerprint, renewal_status FROM certificates WHERE fingerprint_sha256 = ?`, synthetic).Scan(&succ, &status); err != nil {
		t.Fatal(err)
	}
	if succ.String != fingerprintOf(c) || status != "renewed" {
		t.Fatalf("placeholder must point at the real row: succ=%q status=%q", succ.String, status)
	}
	if e.activeLinks("") != 1 {
		t.Fatal("one resource, one active link")
	}
}

func TestCloudMetadataKeyRefusesGuessedKeys(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		c    cloudinventory.CloudCertificate
		ok   bool
		alg  string
		bits int
	}{
		{"acm rsa", cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderAWSACM, KeyAlgorithm: "RSA_4096", NotAfter: exp}, true, "RSA", 4096},
		{"acm ec", cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderAWSACM, KeyAlgorithm: "EC_secp384r1", NotAfter: exp}, true, "ECDSA", 384},
		{"acm unknown label", cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderAWSACM, KeyAlgorithm: "ML_DSA_65", NotAfter: exp}, false, "", 0},
		{"acm no expiry", cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderAWSACM, KeyAlgorithm: "RSA_2048"}, false, "", 0},
		{"gcp default is a guess", cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderGCPCertManager, KeyAlgorithm: "RSA-2048", NotAfter: exp}, false, "", 0},
		{"azure has no label", cloudinventory.CloudCertificate{Provider: cloudinventory.ProviderAzureKeyVault, NotAfter: exp}, false, "", 0},
	}
	for _, tc := range cases {
		alg, bits, ok := cloudMetadataKey(tc.c)
		if ok != tc.ok || alg != tc.alg || bits != tc.bits {
			t.Errorf("%s: got (%q,%d,%v)", tc.name, alg, bits, ok)
		}
	}
}

func TestCloudResourceAccount(t *testing.T) {
	cases := map[string]cloudinventory.CloudCertificate{
		"111122223333":      {Provider: cloudinventory.ProviderAWSACM, ResourceID: acmARN + "x"},
		"my-proj":           {Provider: cloudinventory.ProviderGCPCertManager, ResourceID: "projects/my-proj/locations/global/certificates/c"},
		"v.vault.azure.net": {Provider: cloudinventory.ProviderAzureKeyVault, ResourceID: "https://v.vault.azure.net/certificates/n/1"},
		"":                  {Provider: cloudinventory.ProviderAWSACM, ResourceID: "garbage"},
	}
	for want, c := range cases {
		if got := cloudResourceAccount(c); got != want {
			t.Errorf("%s: got %q want %q", c.ResourceID, got, want)
		}
	}
}
