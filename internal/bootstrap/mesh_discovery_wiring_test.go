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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/discovery"
	"kryptkeeper/internal/discovery/scanner"
)

// W12-04: mesh discovery persists through the real discovery store —
// same tables ListEndpoints reads — with no bogus audit issues on
// socket-less (port-0) rows.

func meshWiringSelfSignedPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMeshSchedulerPersistsThroughDiscoveryStore(t *testing.T) {
	certPEM := meshWiringSelfSignedPEM(t, "gw.example.com")
	k8s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"metadata": map[string]string{"name": "shop-tls", "namespace": "edge"},
				"type":     "kubernetes.io/tls",
				"data":     map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(certPEM)},
			}}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(k8s.Close)

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "disc.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := &sqliteDiscoveryStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}

	mesh := discovery.NewMeshDiscovery(discovery.MeshConfig{K8sBaseURL: k8s.URL, BearerToken: ""}, k8s.Client())
	s := &MeshDiscoveryScheduler{
		mesh:         mesh,
		store:        store,
		pollInterval: time.Minute,
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), time.Now())

	// The endpoint is visible through the SAME store network scans use.
	res, err := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Endpoints) != 1 {
		t.Fatalf("expected the mesh secret persisted as an endpoint, got %+v", res.Endpoints)
	}
	// Port-0 (socket-less) rows must carry NO bogus audit issues.
	findings, err := store.ListEndpointFindings(context.Background())
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	for _, f := range findings {
		if len(f.Issues) != 0 {
			t.Fatalf("socket-less mesh row must have no audit issues: %+v", f)
		}
	}
}

func TestMeshSchedulerDormantWhenUnconfigured(t *testing.T) {
	t.Setenv("KRYPTKEEPER_MESH_K8S_URL", "")
	t.Setenv("KRYPTKEEPER_SAAS_ENDPOINTS", "")
	if s := NewMeshDiscoverySchedulerFromEnv(); s != nil {
		t.Fatal("unconfigured mesh discovery must be dormant")
	}
}

// W24-23: multi-cluster mesh sweeps.

func meshTLSServer(t *testing.T, certPEM []byte, secretsStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets" {
			if secretsStatus != 0 && secretsStatus != http.StatusOK {
				w.WriteHeader(secretsStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"metadata": map[string]string{"name": "shop-tls", "namespace": "edge"},
				"type":     "kubernetes.io/tls",
				"data":     map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(certPEM)},
			}}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newMeshTestStore(t *testing.T) *sqliteDiscoveryStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "disc.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := &sqliteDiscoveryStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return store
}

func twoClusterScheduler(t *testing.T, statusB int) (*MeshDiscoveryScheduler, *sqliteDiscoveryStore) {
	t.Helper()
	pemA, pemB := meshWiringSelfSignedPEM(t, "a.example.com"), meshWiringSelfSignedPEM(t, "b.example.com")
	a, b := meshTLSServer(t, pemA, 0), meshTLSServer(t, pemB, statusB)
	store := newMeshTestStore(t)
	s := &MeshDiscoveryScheduler{
		store:        store,
		pollInterval: time.Minute,
		stop:         make(chan struct{}),
		clusters: func(context.Context) []meshClusterSweep {
			return []meshClusterSweep{
				{name: "a", mesh: discovery.NewMeshDiscovery(discovery.MeshConfig{K8sBaseURL: a.URL}, a.Client())},
				{name: "b", mesh: discovery.NewMeshDiscovery(discovery.MeshConfig{K8sBaseURL: b.URL}, b.Client())},
			}
		},
	}
	return s, store
}

func listMeshHosts(t *testing.T, store *sqliteDiscoveryStore) []string {
	t.Helper()
	res, err := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var hosts []string
	for _, e := range res.Endpoints {
		hosts = append(hosts, e.Hostname)
	}
	return hosts
}

func hasHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if h == want {
			return true
		}
	}
	return false
}

func TestMeshSweepTwoClustersPrefixesHost(t *testing.T) {
	s, store := twoClusterScheduler(t, 0)
	s.tick(context.Background(), time.Now())
	hosts := listMeshHosts(t, store)
	if !hasHost(hosts, "a/edge/shop-tls") || !hasHost(hosts, "b/edge/shop-tls") {
		t.Fatalf("hosts %v", hosts)
	}
}

func TestMeshSweepRBACDeniedClusterIsolated(t *testing.T) {
	s, store := twoClusterScheduler(t, http.StatusForbidden)
	s.tick(context.Background(), time.Now())
	hosts := listMeshHosts(t, store)
	if !hasHost(hosts, "a/edge/shop-tls") {
		t.Fatalf("healthy cluster lost: %v", hosts)
	}
	var errRow bool
	for _, h := range hosts {
		if strings.HasPrefix(h, "b/") {
			errRow = true
		}
	}
	if !errRow {
		t.Fatalf("denied cluster must leave an error row: %v", hosts)
	}
}

func TestMeshSecondSweepAddsNoDuplicates(t *testing.T) {
	s, store := twoClusterScheduler(t, 0)
	s.tick(context.Background(), time.Now())
	first, _ := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 50})
	s.tick(context.Background(), time.Now().Add(time.Hour))
	second, _ := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 50})
	if len(first.Endpoints) != 2 || len(second.Endpoints) != len(first.Endpoints) {
		t.Fatalf("first %d second %d", len(first.Endpoints), len(second.Endpoints))
	}
}

func shortLivedEndpoint(protocol string, validFrom time.Time, life time.Duration, isCA bool) scanner.DiscoveredEndpoint {
	return scanner.DiscoveredEndpoint{Host: "ns/x", Protocol: protocol, Certs: []scanner.DiscoveredCert{{
		ValidFrom: validFrom, ValidUntil: validFrom.Add(life), IsCA: isCA,
	}}}
}

func TestSuppressStaleShortLived(t *testing.T) {
	now := time.Now()
	old := now.Add(-8 * 24 * time.Hour)
	in := []scanner.DiscoveredEndpoint{
		shortLivedEndpoint("istio-mesh", old, 24*time.Hour, false),                 // dropped
		shortLivedEndpoint("istio-mesh", old, 24*time.Hour, true),                  // CA kept
		shortLivedEndpoint("k8s-tls-secret", old, 90*24*time.Hour, false),          // long-lived kept
		shortLivedEndpoint("istio-mesh", now.Add(-time.Hour), 24*time.Hour, false), // recent kept
		shortLivedEndpoint("https", old, 24*time.Hour, false),                      // other protocol untouched
		{Host: "err", Protocol: "k8s-tls-secret", Error: "403"},                    // error row kept
	}
	kept, dropped := suppressStaleShortLived(in, now, 7*24*time.Hour)
	if dropped != 1 || len(kept) != 5 {
		t.Fatalf("dropped %d kept %d", dropped, len(kept))
	}
}

func TestSuppressStaleShortLivedRetentionConfigurable(t *testing.T) {
	now := time.Now()
	in := []scanner.DiscoveredEndpoint{shortLivedEndpoint("istio-mesh", now.Add(-8*24*time.Hour), 24*time.Hour, false)}
	if _, d := suppressStaleShortLived(in, now, 7*24*time.Hour); d != 1 {
		t.Fatalf("7d retention should drop, dropped=%d", d)
	}
	if _, d := suppressStaleShortLived(in, now, 10*24*time.Hour); d != 0 {
		t.Fatalf("10d retention should keep, dropped=%d", d)
	}
	if parseLeafRetentionDays("10") != 10*24*time.Hour || parseLeafRetentionDays("") != 7*24*time.Hour || parseLeafRetentionDays("-3") != 7*24*time.Hour {
		t.Fatal("retention parsing")
	}
}

func TestParseSaaSEndpoints(t *testing.T) {
	if got := parseSaaSEndpoints(`["a.example.com:443"," b.example.com:8443 ",""]`); len(got) != 2 || got[1] != "b.example.com:8443" {
		t.Fatalf("got %v", got)
	}
	if parseSaaSEndpoints("a:1,b:2") != nil || parseSaaSEndpoints("") != nil {
		t.Fatal("non-JSON must fall back to env")
	}
}
