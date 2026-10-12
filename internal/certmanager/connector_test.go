// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanager

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := Config{
		APIServerURL: "https://k8s.example.com",
		Token:        "test-token",
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestListCertificates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(90 * 24 * time.Hour)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		list := k8sCertList{
			Items: []k8sCert{
				{
					Metadata: k8sMeta{
						Name:              "web-tls",
						Namespace:         "default",
						CreationTimestamp: now,
					},
					Spec: k8sCertSpec{
						SecretName: "web-tls-secret",
						CommonName: "web.example.com",
						DNSNames:   []string{"web.example.com", "www.web.example.com"},
						Duration:   "2160h",
						IssuerRef: struct {
							Name  string `json:"name"`
							Kind  string `json:"kind"`
							Group string `json:"group"`
						}{Name: "letsencrypt-prod", Kind: "ClusterIssuer"},
					},
					Status: k8sCertStatus{
						Conditions: []struct {
							Type    string `json:"type"`
							Status  string `json:"status"`
							Message string `json:"message"`
						}{{Type: "Ready", Status: "True", Message: "Certificate is up to date"}},
						NotAfter: &notAfter,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	}))
	defer srv.Close()

	c, err := New(Config{
		APIServerURL: srv.URL,
		Token:        "test-token",
		CACert:       serverCAPEM(srv),
	})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}

	certs, err := c.ListCertificates(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	cert := certs[0]
	if cert.CommonName != "web.example.com" {
		t.Errorf("unexpected common name %q", cert.CommonName)
	}
	if !cert.Ready {
		t.Error("expected cert to be ready")
	}
	if cert.NotAfter.IsZero() {
		t.Error("expected non-zero NotAfter")
	}
	if cert.SecretName != "web-tls-secret" {
		t.Errorf("unexpected secret name %q", cert.SecretName)
	}
}

func TestListCertificatesUnauthorized(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, _ := New(Config{APIServerURL: srv.URL, CACert: serverCAPEM(srv)})
	_, err := c.ListCertificates(t.Context())
	if err == nil {
		t.Error("expected error for 403 response")
	}
}

func TestListCertificatesCRDNotInstalled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, _ := New(Config{APIServerURL: srv.URL, CACert: serverCAPEM(srv)})
	_, err := c.ListCertificates(t.Context())
	if err == nil {
		t.Error("expected error for 404 (CRD not installed)")
	}
}

func TestParseCertificateListDerivesCommonNameFromDNS(t *testing.T) {
	list := k8sCertList{
		Items: []k8sCert{
			{
				Metadata: k8sMeta{Name: "api-tls", Namespace: "prod"},
				Spec: k8sCertSpec{
					SecretName: "api-tls-secret",
					CommonName: "", // not set
					DNSNames:   []string{"api.example.com"},
					IssuerRef: struct {
						Name  string `json:"name"`
						Kind  string `json:"kind"`
						Group string `json:"group"`
					}{Name: "internal-ca", Kind: "Issuer"},
				},
			},
		},
	}
	body, _ := json.Marshal(list)
	certs, err := parseCertificateList(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName != "api.example.com" {
		t.Errorf("expected common name derived from DNS, got %q", certs[0].CommonName)
	}
}

func TestListURLNamespaced(t *testing.T) {
	c := &Connector{serverURL: "https://k8s.example.com", namespace: "default"}
	url := c.listURL()
	expected := "https://k8s.example.com/apis/cert-manager.io/v1/namespaces/default/certificates"
	if url != expected {
		t.Errorf("got %q, want %q", url, expected)
	}
}

func TestListURLAllNamespaces(t *testing.T) {
	c := &Connector{serverURL: "https://k8s.example.com", namespace: ""}
	url := c.listURL()
	expected := "https://k8s.example.com/apis/cert-manager.io/v1/certificates"
	if url != expected {
		t.Errorf("got %q, want %q", url, expected)
	}
}

func TestNewInvalidCACert(t *testing.T) {
	_, err := New(Config{
		APIServerURL: "https://k8s.example.com",
		CACert:       []byte("not a valid PEM certificate"),
	})
	if err == nil {
		t.Error("expected error for invalid CA cert")
	}
}

func TestPing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"major":"1","minor":"28"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, _ := New(Config{APIServerURL: srv.URL, CACert: serverCAPEM(srv)})
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("expected Ping to succeed: %v", err)
	}
}

func TestPingReturnsErrorOn4xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c, _ := New(Config{APIServerURL: srv.URL, CACert: serverCAPEM(srv)})
	if err := c.Ping(context.Background()); err == nil {
		t.Error("expected error for 401 response")
	}
}

func TestConfigFromEnvBasic(t *testing.T) {
	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test:6443")
	t.Setenv("KRYPTKEEPER_K8S_TOKEN", "my-token")
	t.Setenv("KRYPTKEEPER_K8S_NAMESPACE", "default")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.APIServerURL != "https://k8s.test:6443" {
		t.Errorf("unexpected API URL: %s", cfg.APIServerURL)
	}
	if cfg.Token != "my-token" {
		t.Errorf("unexpected token: %s", cfg.Token)
	}
	if cfg.Namespace != "default" {
		t.Errorf("unexpected namespace: %s", cfg.Namespace)
	}
}

// SEMGREP-003: the plain skip-verify option is gone.
func TestConfigFromEnvRefusesSkipVerify(t *testing.T) {
	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test")
	t.Setenv("KRYPTKEEPER_K8S_SKIP_VERIFY", "true")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "CA_CERT_FILE") {
		t.Fatalf("expected an actionable refusal, got %v", err)
	}
}

func TestConnectorVerifiesServerCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	// No CA supplied: the self-signed httptest cert must be rejected. Before
	// SEMGREP-003 SkipVerify=true made this succeed with the token attached.
	c, err := New(Config{APIServerURL: srv.URL, Token: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("an unverifiable server certificate must fail the connection")
	}

	// With the cluster CA, verification succeeds.
	c, _ = New(Config{APIServerURL: srv.URL, Token: "secret", CACert: serverCAPEM(srv)})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("a server certificate signed by the supplied CA must verify: %v", err)
	}
}

func TestCACertFileAlias(t *testing.T) {
	f := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(f, []byte("pem-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRYPTKEEPER_K8S_CA_FILE", f)
	b, err := CACertPEMFromEnv()
	if err != nil || string(b) != "pem-bytes" {
		t.Fatalf("got %q, %v", b, err)
	}
}

func serverCAPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestConfigFromEnvTokenFile(t *testing.T) {
	f, err := os.CreateTemp("", "token-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("file-token\n")
	f.Close()
	defer os.Remove(f.Name())

	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test")
	t.Setenv("KRYPTKEEPER_K8S_TOKEN_FILE", f.Name())

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.Token != "file-token" {
		t.Errorf("expected file-token, got %q", cfg.Token)
	}
}

func TestConfigFromEnvTokenFileError(t *testing.T) {
	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test")
	t.Setenv("KRYPTKEEPER_K8S_TOKEN_FILE", "/nonexistent/path/token.txt")

	_, err := ConfigFromEnv()
	if err == nil {
		t.Error("expected error for missing token file")
	}
}

func TestConfigFromEnvCACert(t *testing.T) {
	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test")
	t.Setenv("KRYPTKEEPER_K8S_CA_CERT", "fake-pem-data")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if string(cfg.CACert) != "fake-pem-data" {
		t.Errorf("unexpected CA cert: %s", cfg.CACert)
	}
}

func TestConfigFromEnvCACertFile(t *testing.T) {
	f, err := os.CreateTemp("", "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("fake-ca-pem")
	f.Close()
	defer os.Remove(f.Name())

	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test")
	t.Setenv("KRYPTKEEPER_K8S_CA_CERT_FILE", f.Name())

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if string(cfg.CACert) != "fake-ca-pem" {
		t.Errorf("unexpected CA cert: %s", cfg.CACert)
	}
}

func TestConfigFromEnvCACertFileError(t *testing.T) {
	t.Setenv("KRYPTKEEPER_K8S_API_URL", "https://k8s.test")
	t.Setenv("KRYPTKEEPER_K8S_CA_CERT_FILE", "/nonexistent/path/ca.pem")

	_, err := ConfigFromEnv()
	if err == nil {
		t.Error("expected error for missing CA cert file")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 100) != "short" {
		t.Error("short string should not be truncated")
	}
	if truncate("hello world", 5) != "hello..." {
		t.Errorf("expected truncation, got %q", truncate("hello world", 5))
	}
	if truncate("exact", 5) != "exact" {
		t.Error("exact length should not be truncated")
	}
}
