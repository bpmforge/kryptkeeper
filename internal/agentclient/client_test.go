// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentclient"
)

// stubHub provides an in-process hub that mimics the real endpoints.
type stubHub struct {
	agentID       string
	token         string
	tasks         []agentclient.RenewalTask
	lastInventory []agentclient.DiscoveredCert
	lastEndpoints []agentclient.Endpoint
	lastResult    *agentclient.RenewalResult
	heartbeats    int
}

func newStubHub() (*stubHub, *httptest.Server) {
	hub := &stubHub{
		agentID: "test-agent-id",
		token:   "test-agent-token",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": hub.agentID,
			"token":    hub.token,
		})
	})

	mux.HandleFunc("POST /api/v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		hub.heartbeats++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/agent/inventory", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Certs     []agentclient.DiscoveredCert `json:"certs"`
			Endpoints []agentclient.Endpoint       `json:"endpoints"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		hub.lastInventory = req.Certs
		hub.lastEndpoints = req.Endpoints
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(req.Certs)})
	})

	mux.HandleFunc("GET /api/v1/agent/tasks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": hub.tasks})
	})

	mux.HandleFunc("POST /api/v1/agent/renewal-result", func(w http.ResponseWriter, r *http.Request) {
		var res agentclient.RenewalResult
		_ = json.NewDecoder(r.Body).Decode(&res)
		hub.lastResult = &res
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
	})

	return hub, httptest.NewServer(mux)
}

func TestClient_Register(t *testing.T) {
	_, srv := newStubHub()
	defer srv.Close()

	c := agentclient.New(srv.URL, "", "", nil)
	resp, err := c.Register(context.Background(), "my-agent", agentclient.AgentTypeLinux)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.AgentID != "test-agent-id" {
		t.Errorf("expected agent_id 'test-agent-id', got %q", resp.AgentID)
	}
	if resp.Token != "test-agent-token" {
		t.Errorf("expected token 'test-agent-token', got %q", resp.Token)
	}
	// Client should store credentials for subsequent calls.
	if c.AgentID != "test-agent-id" {
		t.Error("Register did not update client AgentID")
	}
}

func TestClient_Heartbeat(t *testing.T) {
	hub, srv := newStubHub()
	defer srv.Close()

	c := agentclient.New(srv.URL, hub.agentID, hub.token, nil)
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if hub.heartbeats != 1 {
		t.Errorf("expected 1 heartbeat recorded, got %d", hub.heartbeats)
	}
}

func TestClient_PostInventory(t *testing.T) {
	hub, srv := newStubHub()
	defer srv.Close()

	certs := []agentclient.DiscoveredCert{
		{
			Fingerprint: "aa:bb:cc",
			Subject:     "CN=example.com",
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(90 * 24 * time.Hour),
			Source:      "/etc/ssl/example.crt",
		},
	}

	endpoints := []agentclient.Endpoint{
		{
			ServerType: agentclient.ServerNginx,
			CertPath:   "/etc/nginx/ssl/example.crt",
			KeyPath:    "/etc/nginx/ssl/example.key",
			ServerName: "example.com",
			ListenPort: 443,
		},
	}

	c := agentclient.New(srv.URL, hub.agentID, hub.token, nil)
	accepted, err := c.PostInventory(context.Background(), certs, endpoints)
	if err != nil {
		t.Fatalf("PostInventory: %v", err)
	}
	if accepted != 1 {
		t.Errorf("expected 1 accepted, got %d", accepted)
	}
	if len(hub.lastInventory) != 1 {
		t.Errorf("hub recorded %d certs, want 1", len(hub.lastInventory))
	}
	if len(hub.lastEndpoints) != 1 {
		t.Fatalf("hub recorded %d endpoints, want 1", len(hub.lastEndpoints))
	}
	if hub.lastEndpoints[0].KeyPath != "/etc/nginx/ssl/example.key" {
		t.Errorf("endpoint key path round-trip failed: %+v", hub.lastEndpoints[0])
	}
}

func TestClient_GetTasks_Empty(t *testing.T) {
	hub, srv := newStubHub()
	defer srv.Close()

	c := agentclient.New(srv.URL, hub.agentID, hub.token, nil)
	tasks, err := c.GetTasks(context.Background())
	if err != nil {
		t.Fatalf("GetTasks: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasks))
	}
}

func TestClient_GetTasks_WithTask(t *testing.T) {
	hub, srv := newStubHub()
	defer srv.Close()

	hub.tasks = []agentclient.RenewalTask{
		{TaskID: "t1", Fingerprint: "aa:bb", Subject: "CN=example.com", Action: "renew"},
	}

	c := agentclient.New(srv.URL, hub.agentID, hub.token, nil)
	tasks, err := c.GetTasks(context.Background())
	if err != nil {
		t.Fatalf("GetTasks: %v", err)
	}
	if len(tasks) != 1 || tasks[0].TaskID != "t1" {
		t.Errorf("expected task t1, got %+v", tasks)
	}
}

func TestClient_Register_HubError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := agentclient.New(srv.URL, "", "", nil)
	_, err := c.Register(context.Background(), "agent", agentclient.AgentTypeLinux)
	if err == nil {
		t.Fatal("expected error from hub 503, got nil")
	}
}

func TestClient_PostRenewalResult(t *testing.T) {
	hub, srv := newStubHub()
	defer srv.Close()

	c := agentclient.New(srv.URL, hub.agentID, hub.token, nil)
	err := c.PostRenewalResult(context.Background(), agentclient.RenewalResult{
		TaskID:            "task-1",
		Fingerprint:       "abcd",
		Outcome:           "installed_verified",
		ServedFingerprint: "abcd",
	})
	if err != nil {
		t.Fatalf("PostRenewalResult: %v", err)
	}
	if hub.lastResult == nil {
		t.Fatal("hub did not record a result")
	}
	if hub.lastResult.Outcome != "installed_verified" || hub.lastResult.TaskID != "task-1" {
		t.Errorf("result round-trip wrong: %+v", hub.lastResult)
	}
}

// --- W19-32: agent trust of a hub-issued TLS certificate ---

// pemForServer PEM-encodes the leaf certificate httptest.NewTLSServer
// generated for srv, the same shape a real Hub operator would export via
// EST cacerts (tests/live/tls/run.sh) and hand to the agent as
// KRYPTKEEPER_HUB_CA_CERT/_FILE.
func pemForServer(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

// otherCAPEM generates a fresh, unrelated self-signed certificate: stands in
// for "some other CA" that never signed the Hub's certificate, for the
// untrusted-cert test below.
func otherCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTLSStubHub() (*stubHub, *httptest.Server) {
	hub, plainSrv := newStubHub()
	// newStubHub already registered handlers on plainSrv's own mux via
	// httptest.NewServer; rebuild the same mux under NewTLSServer instead
	// of reusing plainSrv, since httptest does not support upgrading a
	// running server's listener to TLS after the fact.
	plainSrv.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": hub.agentID, "token": hub.token})
	})
	mux.HandleFunc("POST /api/v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		hub.heartbeats++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	srv := httptest.NewTLSServer(mux)
	return hub, srv
}

func TestHubCACertPoolFromEnv_Unset(t *testing.T) {
	pool, err := agentclient.HubCACertPoolFromEnv()
	if err != nil {
		t.Fatalf("HubCACertPoolFromEnv: %v", err)
	}
	if pool != nil {
		t.Error("expected nil pool when neither env var is set (system roots)")
	}
}

func TestHubCACertPoolFromEnv_EmptyBundleIsStartupError(t *testing.T) {
	t.Setenv("KRYPTKEEPER_HUB_CA_CERT", "not a pem certificate")
	if _, err := agentclient.HubCACertPoolFromEnv(); err == nil {
		t.Fatal("expected an error for an unparseable bundle, got nil (must fail startup, not fall back silently)")
	}
}

func TestHubCACertPoolFromEnv_MissingFile(t *testing.T) {
	t.Setenv("KRYPTKEEPER_HUB_CA_CERT_FILE", "/nonexistent/kk-hub-ca.pem")
	if _, err := agentclient.HubCACertPoolFromEnv(); err == nil {
		t.Fatal("expected an error reading a missing CA file, got nil")
	}
}

func TestClient_TrustedHubCAPool_Succeeds(t *testing.T) {
	hub, srv := newTLSStubHub()
	defer srv.Close()

	t.Setenv("KRYPTKEEPER_HUB_CA_CERT", string(pemForServer(srv)))
	pool, err := agentclient.HubCACertPoolFromEnv()
	if err != nil {
		t.Fatalf("HubCACertPoolFromEnv: %v", err)
	}
	if pool == nil {
		t.Fatal("expected a non-nil pool")
	}

	c := agentclient.New(srv.URL, hub.agentID, hub.token, pool)
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat against a Hub cert in the trust pool should succeed: %v", err)
	}
}

func TestClient_TrustedHubCAPool_FromFile(t *testing.T) {
	hub, srv := newTLSStubHub()
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "hub-ca.pem")
	if err := os.WriteFile(caPath, pemForServer(srv), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	t.Setenv("KRYPTKEEPER_HUB_CA_CERT_FILE", caPath)
	pool, err := agentclient.HubCACertPoolFromEnv()
	if err != nil {
		t.Fatalf("HubCACertPoolFromEnv: %v", err)
	}

	c := agentclient.New(srv.URL, hub.agentID, hub.token, pool)
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat against a Hub cert loaded from file should succeed: %v", err)
	}
}

func TestClient_UntrustedHubCert_Fails(t *testing.T) {
	_, hubSrv := newTLSStubHub()
	defer hubSrv.Close()

	// httptest.NewTLSServer defaults every server in the process to the
	// SAME baked-in localhost cert, so a second httptest.NewTLSServer's
	// cert would trivially "trust" hubSrv too and defeat this test.
	// otherCAPEM is an independently generated self-signed cert standing in
	// for "some other, unrelated CA" that never signed hubSrv's cert.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(otherCAPEM(t)) {
		t.Fatal("failed to build the unrelated trust pool")
	}

	c := agentclient.New(hubSrv.URL, "agent", "token", pool)
	err := c.Heartbeat(context.Background())
	if err == nil {
		t.Fatal("expected Heartbeat to fail against a Hub cert not in the trust pool")
	}
	if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected a clear TLS/certificate verification error, got: %v", err)
	}
}

func TestAcmeRenewer_UsesSameTrustPool(t *testing.T) {
	var hit bool
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/directory", func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemForServer(srv)) {
		t.Fatal("failed to build trust pool")
	}

	renewer := agentclient.NewAcmeRenewer(srv.URL, pool)
	req, err := http.NewRequest(http.MethodGet, renewer.HubURL+"/acme/directory", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := renewer.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("AcmeRenewer.HTTPClient should trust the same pool the Client does: %v", err)
	}
	defer resp.Body.Close()
	if !hit {
		t.Error("expected the directory handler to be reached")
	}

	// Without the pool (system roots only), the same self-signed server must
	// be rejected -- proving the pool, not luck, is what made the call above
	// succeed.
	untrusted := agentclient.NewAcmeRenewer(srv.URL, nil)
	req2, _ := http.NewRequest(http.MethodGet, untrusted.HubURL+"/acme/directory", nil)
	if _, err := untrusted.HTTPClient.Do(req2); err == nil {
		t.Fatal("expected the ACME renewer to reject a hub cert absent from its trust pool")
	}
}

// The hub closes agent enrollment by default (W5-07): a self-registering
// agent must present the enrollment secret, or the Windows service's first
// start can never register against a production-shaped hub.
func TestClient_Register_SendsEnrollmentSecret(t *testing.T) {
	for _, tc := range []struct{ name, secret string }{{"set", "s3cret"}, {"unset", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&got)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"agent_id":"a","token":"t"}`))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			c := agentclient.New(srv.URL, "", "", nil)
			c.EnrollmentSecret = tc.secret
			if _, err := c.Register(context.Background(), "agent", agentclient.AgentTypeWindows); err != nil {
				t.Fatalf("Register: %v", err)
			}
			v, present := got["enrollment_secret"]
			if tc.secret == "" {
				if present {
					t.Fatalf("empty secret must be omitted, body had %v", v)
				}
				return
			}
			if v != tc.secret {
				t.Fatalf("enrollment_secret = %v, want %q", v, tc.secret)
			}
		})
	}
}
