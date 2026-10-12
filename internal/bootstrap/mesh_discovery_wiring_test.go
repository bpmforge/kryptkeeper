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
	"testing"
	"time"

	"kryptkeeper/internal/discovery"
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
