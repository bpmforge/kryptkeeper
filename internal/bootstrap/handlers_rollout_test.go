// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// W17-07: coordinated rollout. The property that matters most is that
// ONE renewal reaches EVERY node — renewing per node would give each
// cluster member a different identity, which is the bug this feature
// exists to prevent.

// fakeCluster stands in for N F5 BIG-IP appliances — the canonical
// multi-node case where several LB nodes serve the SAME certificate.
// Each node records the certificate bytes it was handed.
type fakeCluster struct {
	mu       sync.Mutex
	received map[string][]byte // node name -> the PEM the appliance would serve
	// expectFingerprint is what the injected verifier reports back; the
	// pusher compares it against the fingerprint it pushed.
	expectFingerprint string
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{received: map[string][]byte{}}
}

func (c *fakeCluster) handler(node string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := readAllBody(r)
		// iControl file upload carries the raw PEM; that is the material
		// the appliance will serve, so record it per node.
		if strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/") &&
			strings.HasSuffix(r.URL.Path, ".crt") {
			c.mu.Lock()
			c.received[node] = append([]byte(nil), raw...)
			// A correctly-installed appliance would serve exactly what it
			// was handed, so report that leaf's fingerprint back.
			if fp, err := leafFingerprint(raw); err == nil {
				c.expectFingerprint = fp
			}
			c.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}
}

func readAllBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}

func rolloutTestMux(t *testing.T, cluster *fakeCluster, nodeNames []string) (*http.ServeMux, CertificateProvider, string, []string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	certDB := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, certDB)
	caID := getFirstCAID(t, engine)

	storeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "rollout.db"))
	if err != nil {
		t.Fatalf("open store db: %v", err)
	}
	t.Cleanup(func() { storeDB.Close() })
	targetStore := &sqliteManagedTargetStore{db: storeDB}
	if err := targetStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("target schema: %v", err)
	}
	credStore := &sqliteOutboundCredentialStore{db: storeDB, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := credStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("cred schema: %v", err)
	}

	ctx := context.Background()
	var targetIDs []string
	for _, node := range nodeNames {
		srv := httptest.NewServer(cluster.handler(node))
		t.Cleanup(srv.Close)
		credJSON, _ := json.Marshal(map[string]string{
			"base_url": srv.URL, "username": "admin", "password": "pw",
			"client_ssl_profile": "cluster-clientssl",
		})
		if _, err := credStore.Create(ctx, "cred-"+node, node, CredentialTypeAPIToken, "", credJSON); err != nil {
			t.Fatalf("create credential: %v", err)
		}
		tgt, err := targetStore.Create(ctx, ManagedTarget{
			ID: "tgt-" + node, Name: node, Host: "127.0.0.1",
			DiscoveryMode: "none", InstallMode: "f5", RenewalMethod: "manual",
			CredentialRef: "cred-" + node,
		})
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
		targetIDs = append(targetIDs, tgt.ID)
	}

	// Inject a verifier so the canary gate can PASS without real TLS
	// listeners; it echoes back whatever fingerprint was pushed, which is
	// what a correctly-installed appliance would serve.
	prev := newRolloutExecutor
	newRolloutExecutor = func(certs CertificateProvider, creds OutboundCredentialStore) *RenewalExecutor {
		e := NewRenewalExecutor(certs, creds)
		e.verifier = func(_ context.Context, hostPort string) (string, error) {
			c := cluster
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.expectFingerprint, nil
		}
		return e
	}
	t.Cleanup(func() { newRolloutExecutor = prev })

	mux := http.NewServeMux()
	registerRolloutHandler(mux, auth, provider, targetStore, credStore, stubAuditProvider{}, nil)
	return mux, provider, caID, targetIDs
}

func postRollout(t *testing.T, mux *http.ServeMux, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/rollout", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// THE headline property: one renewal, identical material on every node.
func TestRolloutPushesOneIdenticalCertToEveryNode(t *testing.T) {
	cluster := newFakeCluster()
	nodes := []string{"node-a", "node-b", "node-c"}
	mux, provider, caID, targetIDs := rolloutTestMux(t, cluster, nodes)

	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "cluster.example.com", "cluster.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-cluster",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	specs := []map[string]any{}
	for i, id := range targetIDs {
		specs = append(specs, map[string]any{"target_id": id, "is_canary": i == 0})
	}
	rec := postRollout(t, mux, map[string]any{
		"fingerprint": issued.CertificateItem.FingerprintSHA256,
		"group":       "edge-cluster",
		"nodes":       specs,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if len(cluster.received) != len(nodes) {
		t.Fatalf("every node must receive the certificate, got %d of %d: %v",
			len(cluster.received), len(nodes), keysOf(cluster.received))
	}
	// All nodes must hold BYTE-IDENTICAL material. This is the invariant
	// that a per-node renewal would silently violate.
	var reference []byte
	for node, got := range cluster.received {
		if reference == nil {
			reference = got
			continue
		}
		if !bytes.Equal(reference, got) {
			t.Fatalf("node %s received DIFFERENT certificate material — the cluster would serve a split identity", node)
		}
	}
	// And it must be a real leaf, not an empty push.
	if block, _ := pem.Decode(reference); block == nil {
		t.Fatalf("nodes received non-PEM material (%d bytes)", len(reference))
	}
	// The response must never carry key material.
	if bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("rollout response leaked key material")
	}
	_ = hex.EncodeToString(sha256.New().Sum(nil))
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Tenant visibility is authorized for EVERY node BEFORE anything is
// installed: an unknown target must abort the whole rollout untouched.
func TestRolloutAuthorizesAllNodesBeforeTouchingAny(t *testing.T) {
	cluster := newFakeCluster()
	mux, provider, caID, targetIDs := rolloutTestMux(t, cluster, []string{"node-a"})

	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "c2.example.com", "c2.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-cluster",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	rec := postRollout(t, mux, map[string]any{
		"fingerprint": issued.CertificateItem.FingerprintSHA256,
		"group":       "mixed",
		"nodes": []map[string]any{
			{"target_id": targetIDs[0], "is_canary": true},
			{"target_id": "tgt-does-not-exist"},
		},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unresolvable node must abort the rollout, got %d", rec.Code)
	}
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if len(cluster.received) != 0 {
		t.Fatalf("NO node may be touched when authorization fails: %v", keysOf(cluster.received))
	}
}

func TestRolloutValidatesBodyAndAuth(t *testing.T) {
	mux, _, _, _ := rolloutTestMux(t, newFakeCluster(), []string{"node-a"})

	rec := postRollout(t, mux, map[string]any{"group": "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing fingerprint/nodes must be refused, got %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/rollout", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
