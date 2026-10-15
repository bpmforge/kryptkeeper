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
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/discovery/scanner"
	"kryptkeeper/internal/keystore"
)

type trustNode struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// trustIssue signs a fresh cert with parent (nil = self-signed). Keys are
// generated in-test and discarded with it.
func trustIssue(t *testing.T, parent *trustNode, cn string, isCA bool) *trustNode {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &trustNode{cert: c, key: key}
}

// servedEndpoint mimics captureTLS: every cert marked Served, leaf first.
func servedEndpoint(host string, nodes ...*trustNode) scanner.DiscoveredEndpoint {
	ep := scanner.DiscoveredEndpoint{Host: host, Port: 443, Protocol: "tls"}
	for i, n := range nodes {
		dc := scanner.CertToDiscovered(n.cert, host, i == 0)
		dc.Served = true
		ep.Certs = append(ep.Certs, dc)
	}
	return ep
}

type trustTestStore interface {
	dbDiscoveryStore
	dbDiscoveryStoreUpserter
	SetHubCASource(hubCASource)
}

func TestDiscoveryTrustPersistence(t *testing.T) {
	db := setupIntegrationDB(t)
	store := migratedDiscoveryStore(t, db)
	runDiscoveryTrustCase(t, db, false, store, func(f func() (*x509.CertPool, error)) { store.trust.systemRoots = f })
}

// Postgres twin: same case on the real migrated Postgres schema (native
// BOOLEAN is_ca/chain_*), skipped unless KRYPTKEEPER_TEST_POSTGRES_DSN is set.
func TestDiscoveryTrustPersistence_Postgres(t *testing.T) {
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
	runDiscoveryTrustCase(t, db, true, store, func(f func() (*x509.CertPool, error)) { store.trust.systemRoots = f })
}

func runDiscoveryTrustCase(t *testing.T, db *sql.DB, postgres bool, store trustTestStore, setSystem func(func() (*x509.CertPool, error))) {
	t.Helper()
	stubEndpointAudit(t)
	ctx := context.Background()

	hubRoot := trustIssue(t, nil, "Hub Root", true)
	hubInt := trustIssue(t, hubRoot, "Hub Issuing", true)
	hubLeaf := trustIssue(t, hubInt, "app.hub.test", false)

	pubRoot := trustIssue(t, nil, "Test Public Root", true)
	pubInt := trustIssue(t, pubRoot, "Test Public Issuing", true)
	pubLeaf := trustIssue(t, pubInt, "www.public.test", false)

	otherRoot := trustIssue(t, nil, "Other Root", true)
	otherInt := trustIssue(t, otherRoot, "Other Issuing", true)
	otherLeaf := trustIssue(t, otherInt, "svc.other.test", false)

	selfSigned := trustIssue(t, nil, "self.test", true)

	sysPool := x509.NewCertPool()
	sysPool.AddCert(pubRoot.cert)
	setSystem(func() (*x509.CertPool, error) { return sysPool, nil })
	store.SetHubCASource(func(context.Context) ([]*x509.Certificate, error) {
		return []*x509.Certificate{hubRoot.cert, hubInt.cert}, nil
	})

	if _, err := store.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{
		servedEndpoint("app.hub.test", hubLeaf, hubInt),
		servedEndpoint("www.public.test", pubLeaf, pubInt),
		servedEndpoint("svc.other.test", otherLeaf, otherInt, otherRoot),
		servedEndpoint("self.test", selfSigned),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	type row struct {
		class         sql.NullString
		trusted, isCA bool
		flags         string
	}
	read := func(c *x509.Certificate) row {
		t.Helper()
		var r row
		var trusted, isCA any
		q := `SELECT trust_class, chain_trusted, is_ca, risk_flags FROM certificates WHERE fingerprint_sha256 = ?`
		if postgres {
			q = `SELECT trust_class, chain_trusted, is_ca, risk_flags::text FROM certificates WHERE fingerprint_sha256 = $1`
		}
		if err := db.QueryRow(q, fingerprintOf(c)).Scan(&r.class, &trusted, &isCA, &r.flags); err != nil {
			t.Fatalf("read %s: %v", c.Subject.CommonName, err)
		}
		r.trusted, r.isCA = truthy(trusted), truthy(isCA)
		return r
	}
	// readLink is the endpoint-scoped half: what serving the cert at host says.
	type link struct {
		complete sql.NullBool
		flags    string
	}
	readLink := func(c *x509.Certificate, host string) link {
		t.Helper()
		var l link
		q := `SELECT ce.chain_complete, ce.endpoint_flags FROM certificate_endpoints ce JOIN endpoints e ON e.id = ce.endpoint_id WHERE ce.certificate_fingerprint = ? AND e.ip_address = ?`
		if postgres {
			q = `SELECT ce.chain_complete, ce.endpoint_flags FROM certificate_endpoints ce JOIN endpoints e ON e.id = ce.endpoint_id WHERE ce.certificate_fingerprint = $1 AND e.ip_address = $2`
		}
		if err := db.QueryRow(q, fingerprintOf(c), host).Scan(&l.complete, &l.flags); err != nil {
			t.Fatalf("read link %s@%s: %v", c.Subject.CommonName, host, err)
		}
		return l
	}

	for _, tc := range []struct {
		name            string
		node            *trustNode
		host            string
		class           string
		complete, trust bool
		certFlag        string
		linkFlag        string
	}{
		{"hub leaf", hubLeaf, "app.hub.test", "managed", true, true, "", ""},
		{"public leaf", pubLeaf, "www.public.test", "public", true, true, "", ""},
		{"other private leaf", otherLeaf, "svc.other.test", "private_other", true, false, "", "UNTRUSTED_ROOT"},
		{"self-signed CA:TRUE leaf", selfSigned, "self.test", "self_signed", true, false, "SELF_SIGNED", ""},
	} {
		r, l := read(tc.node.cert), readLink(tc.node.cert, tc.host)
		if r.class.String != tc.class || r.trusted != tc.trust || r.isCA || !l.complete.Valid || l.complete.Bool != tc.complete {
			t.Errorf("%s: %+v %+v, want class=%s complete=%v trusted=%v is_ca=false", tc.name, r, l, tc.class, tc.complete, tc.trust)
		}
		if tc.certFlag != "" && !strings.Contains(r.flags, tc.certFlag) {
			t.Errorf("%s: cert flags %s missing %s", tc.name, r.flags, tc.certFlag)
		}
		if tc.linkFlag != "" && !strings.Contains(l.flags, tc.linkFlag) {
			t.Errorf("%s: link flags %s missing %s", tc.name, l.flags, tc.linkFlag)
		}
		// Endpoint-scoped flags never live on the shared certificate row.
		for _, f := range scanner.EndpointFlags {
			if strings.Contains(r.flags, f) {
				t.Errorf("%s: certificate row carries endpoint flag %s: %s", tc.name, f, r.flags)
			}
		}
	}
	for _, n := range []*trustNode{hubInt, pubInt, otherInt, otherRoot} {
		if r := read(n.cert); !r.isCA || r.class.Valid {
			t.Errorf("served chain CA %s: %+v, want is_ca=true and no leaf verdict", n.cert.Subject.CommonName, r)
		}
	}

	// Inventory: chain CAs are queryable in the table but never leaf inventory.
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, postgres))
	provider := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, postgres), db, postgres)
	provider.(*caCertificateProvider).discoveryRefreshEvery = 0

	all, err := provider.ListCertificates(ctx, CertificateListQuery{ManagementState: "unmanaged", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 4 {
		t.Fatalf("unmanaged inventory = %d certs, want the 4 leaves only (chain CAs excluded)", all.Total)
	}
	for _, c := range []struct {
		class string
		want  *trustNode
	}{{"managed", hubLeaf}, {"public", pubLeaf}, {"private_other", otherLeaf}, {"self_signed", selfSigned}} {
		res, err := provider.ListCertificates(ctx, CertificateListQuery{TrustClass: c.class, Origin: "discovered"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 1 || res.Items[0].FingerprintSHA256 != fingerprintOf(c.want.cert) || res.Items[0].TrustClass != c.class {
			t.Errorf("trust_class=%s filter returned %+v", c.class, res.Items)
		}
	}

	// Discovery summary: the breakdown counts leaves only.
	sum, err := store.GetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (TrustClassCounts{Managed: 1, Public: 1, PrivateOther: 1, SelfSigned: 1}); sum.TrustClasses != want {
		t.Errorf("trust breakdown = %+v, want %+v", sum.TrustClasses, want)
	}
	if sum.MappedCertificates != 4 {
		t.Errorf("mapped certificates = %d, want 4 leaves (chain CAs excluded)", sum.MappedCertificates)
	}

	// Endpoint filter and per-cert exposure.
	eps, err := store.ListEndpoints(ctx, DiscoveryEndpointQuery{TrustClass: "private_other"})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps.Endpoints) != 1 || eps.Endpoints[0].Hostname != "svc.other.test" {
		t.Fatalf("endpoint filter private_other = %+v", eps.Endpoints)
	}
	var sawLeaf, sawRoot bool
	for _, mc := range eps.Endpoints[0].MappedCerts {
		switch mc.Fingerprint {
		case fingerprintOf(otherLeaf.cert):
			sawLeaf = mc.TrustClass == "private_other" && !mc.ChainCA && mc.ChainComplete != nil && *mc.ChainComplete && !mc.ChainTrusted
		case fingerprintOf(otherRoot.cert):
			sawRoot = mc.ChainCA
		}
	}
	if !sawLeaf || !sawRoot {
		t.Errorf("mapped certs not exposing trust fields: %+v", eps.Endpoints[0].MappedCerts)
	}
	if none, err := store.ListEndpoints(ctx, DiscoveryEndpointQuery{TrustClass: "unknown"}); err != nil || len(none.Endpoints) != 0 {
		t.Errorf("unknown filter = %+v err=%v, want none", none.Endpoints, err)
	}

	// A sighting that cannot classify (no Served) must not erase the verdict,
	// and a cert seen as a served leaf stays in the leaf inventory even when
	// another endpoint also serves it as part of a chain ("leaf wins").
	scoreBefore := riskScoreOf(t, db, postgres, otherLeaf.cert)
	plain := scanner.DiscoveredEndpoint{Host: "winrm.host", Port: 5986, Protocol: "winrm-https",
		Certs: []scanner.DiscoveredCert{scanner.CertToDiscovered(otherLeaf.cert, "winrm.host", true)}}
	asLeafElsewhere := servedEndpoint("ca.as.leaf.test", otherInt)
	chainOnlyAgain := servedEndpoint("svc.other.test", otherLeaf, otherInt, otherRoot)
	if _, err := store.upsertScanResults(ctx, []scanner.DiscoveredEndpoint{plain, asLeafElsewhere, chainOnlyAgain}); err != nil {
		t.Fatal(err)
	}
	if r := read(otherLeaf.cert); r.class.String != "private_other" {
		t.Errorf("unclassified sighting erased the verdict: %+v", r)
	}
	if riskScoreOf(t, db, postgres, otherLeaf.cert) != scoreBefore {
		t.Errorf("unclassified sighting changed the certificate score")
	}
	// The winrm endpoint saw no chain, so it holds no chain verdict; the
	// served endpoint keeps its own.
	if l := readLink(otherLeaf.cert, "winrm.host"); l.complete.Valid || strings.Contains(l.flags, "UNTRUSTED_ROOT") {
		t.Errorf("an unclassified sighting must not invent a chain verdict: %+v", l)
	}
	if l := readLink(otherLeaf.cert, "svc.other.test"); !l.complete.Valid || !l.complete.Bool || !strings.Contains(l.flags, "UNTRUSTED_ROOT") {
		t.Errorf("served endpoint lost its own verdict: %+v", l)
	}
	if r := read(otherInt.cert); r.isCA {
		t.Errorf("a cert served as a leaf must stay in leaf inventory, got %+v", r)
	}
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x == 1
	}
	return false
}

func TestDiscoveryTrustUnreadableAnchorsLeaveChainUnclassified(t *testing.T) {
	root := trustIssue(t, nil, "R", true)
	leaf := trustIssue(t, root, "l.test", false)

	for name, tr := range map[string]*discoveryTrust{
		"system roots unreadable": {systemRoots: func() (*x509.CertPool, error) { return nil, errors.New("no roots") }},
		"hub CAs unreadable": func() *discoveryTrust {
			d := &discoveryTrust{systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }}
			d.SetHubCASource(func(context.Context) ([]*x509.Certificate, error) { return nil, errors.New("ca provider down") })
			return d
		}(),
	} {
		ep := servedEndpoint("l.test", leaf, root)
		results := []scanner.DiscoveredEndpoint{ep}
		tr.classify(context.Background(), results)
		if got := results[0].Certs[0].TrustClass; got != "" {
			t.Errorf("%s: leaf classified as %q against an incomplete anchor set", name, got)
		}
		if !results[0].Certs[1].ChainCA {
			t.Errorf("%s: chain CA marking must not depend on the verdict", name)
		}
	}
}

func TestTrustClassPredicateRejectsOutOfVocabulary(t *testing.T) {
	if got := trustClassPredicate("x' OR '1'='1", "c", "a", "b"); got != "1 = 0" {
		t.Fatalf("injection-shaped class produced %q", got)
	}
}

func TestEffectiveTrustClass(t *testing.T) {
	for _, tc := range []struct {
		item CertificateItem
		want string
	}{
		{CertificateItem{TrustClass: "public", ManagementState: "unmanaged"}, "public"},
		{CertificateItem{ManagementState: "managed", Source: "api"}, "managed"},
		{CertificateItem{ManagementState: "unmanaged", Source: "discovery_network"}, "unknown"},
		{CertificateItem{ManagementState: "unmanaged", Source: "import"}, ""},
	} {
		if got := effectiveTrustClass(tc.item); got != tc.want {
			t.Errorf("%+v = %q, want %q", tc.item, got, tc.want)
		}
	}
}

func trustTestMux(t *testing.T, disc DiscoveryProvider) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	mux := http.NewServeMux()
	RegisterHandlers(mux, NewAuthenticatorFromEnv(),
		stubCertSummaryProvider{snapshot: CertSummarySnapshot{Source: "file-store"}},
		stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{},
		NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(),
		disc, stubNotificationProvider{}, stubDashboardActionProvider{}, nil)
	return mux
}

func getAuthed(mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestTrustClassesReachTheWire(t *testing.T) {
	counts := TrustClassCounts{Managed: 1, Public: 2, PrivateOther: 3, SelfSigned: 4, Unknown: 5}
	mux := trustTestMux(t, stubDiscoveryProvider{summary: DiscoverySummary{TrustClasses: counts}})
	for _, path := range []string{"/api/v1/dashboard/summary", "/api/v1/discovery/summary"} {
		rec := getAuthed(mux, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		var body struct {
			Data struct {
				TrustClasses TrustClassCounts `json:"trust_classes"`
				Discovery    struct {
					TrustClasses TrustClassCounts `json:"trust_classes"`
				} `json:"discovery"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Data.TrustClasses != counts && body.Data.Discovery.TrustClasses != counts {
			t.Errorf("%s: trust_classes missing from %s", path, rec.Body.String())
		}
	}
}

func TestTrustClassFilterRejectsUnknownValue(t *testing.T) {
	mux := trustTestMux(t, stubDiscoveryProvider{})
	for _, path := range []string{"/api/v1/discovery/endpoints?trust_class=bogus", "/api/v1/certificates?trust_class=bogus"} {
		if rec := getAuthed(mux, path); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", path, rec.Code)
		}
	}
	if rec := getAuthed(mux, "/api/v1/discovery/endpoints?trust_class=public"); rec.Code != http.StatusOK {
		t.Errorf("valid class = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func riskScoreOf(t *testing.T, db *sql.DB, postgres bool, c *x509.Certificate) int {
	t.Helper()
	q := `SELECT risk_score FROM certificates WHERE fingerprint_sha256 = ?`
	if postgres {
		q = `SELECT risk_score FROM certificates WHERE fingerprint_sha256 = $1`
	}
	var n int
	if err := db.QueryRow(q, fingerprintOf(c)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
