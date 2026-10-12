// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

// W7-06: Istio/Linkerd mesh certs from K8s secrets + configured SaaS
// endpoints, unified into scanner.ScanResult.

func selfSignedPEM(t *testing.T, cn string, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// meshFixture serves the three K8s secret sources.
func meshFixture(t *testing.T, gatewayPEM, istioPEM, linkerdPEM []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mesh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"metadata": map[string]string{"name": "shop-tls", "namespace": "edge"},
				"type":     "kubernetes.io/tls",
				"data":     map[string]string{"tls.crt": b64(gatewayPEM), "tls.key": b64([]byte("REDACTED"))},
			}}})
		case r.URL.Path == "/api/v1/namespaces/istio-system/secrets/istio-ca-secret":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]string{"name": "istio-ca-secret", "namespace": "istio-system"},
				"data":     map[string]string{"ca-cert.pem": b64(istioPEM)},
			})
		case r.URL.Path == "/api/v1/namespaces/istio-system/secrets/cacerts":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/api/v1/namespaces/linkerd/secrets/linkerd-identity-issuer":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]string{"name": "linkerd-identity-issuer", "namespace": "linkerd"},
				"data":     map[string]string{"crt.pem": b64(linkerdPEM)},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func endpointsByProtocol(res *scanner.ScanResult) map[string][]scanner.DiscoveredEndpoint {
	out := map[string][]scanner.DiscoveredEndpoint{}
	for _, ep := range res.Endpoints {
		out[ep.Protocol] = append(out[ep.Protocol], ep)
	}
	return out
}

func TestMeshDiscoveryFindsIstioLinkerdAndGatewaySecrets(t *testing.T) {
	gateway := selfSignedPEM(t, "gw.example.com", false)
	istio := selfSignedPEM(t, "istio-ca.example.org", true)
	linkerd := selfSignedPEM(t, "identity.linkerd.cluster.local", true)
	srv := meshFixture(t, gateway, istio, linkerd)

	m := NewMeshDiscovery(MeshConfig{K8sBaseURL: srv.URL, BearerToken: "mesh-token"}, srv.Client())
	res := m.Discover(context.Background(), "job-1")
	if res.ErrorCount != 0 {
		t.Fatalf("unexpected errors: %+v", res.Endpoints)
	}
	byProto := endpointsByProtocol(res)

	gw := byProto["k8s-tls-secret"]
	if len(gw) != 1 || gw[0].Host != "edge/shop-tls" || len(gw[0].Certs) != 1 {
		t.Fatalf("gateway secret: %+v", gw)
	}
	if gw[0].Certs[0].CommonName != "gw.example.com" || gw[0].Certs[0].Fingerprint == "" {
		t.Fatalf("gateway cert not parsed: %+v", gw[0].Certs[0])
	}

	ist := byProto["istio-mesh"]
	if len(ist) != 1 || !ist[0].Certs[0].IsCA || ist[0].Certs[0].CommonName != "istio-ca.example.org" {
		t.Fatalf("istio mesh root: %+v", ist)
	}

	lkd := byProto["linkerd-mesh"]
	if len(lkd) != 1 || lkd[0].Certs[0].CommonName != "identity.linkerd.cluster.local" {
		t.Fatalf("linkerd issuer: %+v", lkd)
	}

	if res.CertsFound != 3 || res.TotalScanned != 3 {
		t.Fatalf("totals: found=%d scanned=%d", res.CertsFound, res.TotalScanned)
	}
}

func TestMeshDiscoveryScansConfiguredSaaSEndpoints(t *testing.T) {
	// A live TLS server plays the SaaS API; discovery must capture its
	// cert through the scanner's handshake path.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsSrv.Close)
	target := strings.TrimPrefix(tlsSrv.URL, "https://")

	m := NewMeshDiscovery(MeshConfig{SaaSEndpoints: []string{target}, Timeout: 5 * time.Second}, nil)
	res := m.Discover(context.Background(), "job-2")
	byProto := endpointsByProtocol(res)
	saas := byProto["saas-api"]
	if len(saas) != 1 {
		t.Fatalf("expected one saas endpoint: %+v", res.Endpoints)
	}
	if len(saas[0].Certs) == 0 || saas[0].Certs[0].Fingerprint == "" {
		t.Fatalf("saas cert not captured: %+v", saas[0])
	}
}

func TestMeshDiscoveryToleratesClusterWithoutMeshes(t *testing.T) {
	// Only the TLS-secret list exists; Istio/Linkerd secrets 404.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	m := NewMeshDiscovery(MeshConfig{K8sBaseURL: srv.URL, BearerToken: "x"}, srv.Client())
	res := m.Discover(context.Background(), "job-3")
	if res.ErrorCount != 0 || len(res.Endpoints) != 0 {
		t.Fatalf("meshless cluster must be quiet: %+v", res.Endpoints)
	}
}

func TestMeshDiscoveryRecordsAPIErrorsVisibly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	m := NewMeshDiscovery(MeshConfig{K8sBaseURL: srv.URL, BearerToken: "x"}, srv.Client())
	res := m.Discover(context.Background(), "job-4")
	if res.ErrorCount == 0 {
		t.Fatal("API failure must be recorded, not swallowed")
	}
	found := false
	for _, ep := range res.Endpoints {
		if ep.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("error must appear on an endpoint's Error field")
	}
}

func TestNewMeshDiscoveryFromEnvDormantWhenUnconfigured(t *testing.T) {
	t.Setenv("KRYPTKEEPER_MESH_K8S_URL", "")
	t.Setenv("KRYPTKEEPER_SAAS_ENDPOINTS", "")
	if NewMeshDiscoveryFromEnv() != nil {
		t.Fatal("unconfigured discovery must be dormant")
	}
	t.Setenv("KRYPTKEEPER_SAAS_ENDPOINTS", "api.example.com:443, billing.example.com:443")
	m := NewMeshDiscoveryFromEnv()
	if m == nil || len(m.cfg.SaaSEndpoints) != 2 {
		t.Fatalf("csv endpoints not parsed: %+v", m)
	}
}

// W19-20: found live on W19-09's kind fixture -- a MeshDiscovery pointed
// at a real cluster's HTTPS API server with a private (kind-generated)
// CA had no way to trust it, so every k8sGet failed TLS verification and
// the sweep produced nothing but "x509: certificate signed by unknown
// authority" errors. These pin the fix: a configured CACert must let the
// handshake succeed, and an absent/wrong one must still fail closed (no
// InsecureSkipVerify escape hatch).

func istioLinkerdTLSFixture(t *testing.T, istioPEM, linkerdPEM []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		case "/api/v1/namespaces/istio-system/secrets/istio-ca-secret":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]string{"name": "istio-ca-secret", "namespace": "istio-system"},
				"data":     map[string]string{"ca-cert.pem": b64(istioPEM)},
			})
		case "/api/v1/namespaces/linkerd/secrets/linkerd-identity-issuer":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]string{"name": "linkerd-identity-issuer", "namespace": "linkerd"},
				"data":     map[string]string{"crt.pem": b64(linkerdPEM)},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serverCAPEM(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestNewMeshDiscoveryTrustsConfiguredCACert(t *testing.T) {
	istio := selfSignedPEM(t, "istio-ca.example.org", true)
	linkerd := selfSignedPEM(t, "identity.linkerd.cluster.local", true)
	srv := istioLinkerdTLSFixture(t, istio, linkerd)

	// The default client() constructed for a CACert-bearing config (not
	// srv.Client(), which already trusts the test server out of band) --
	// this is what NewMeshDiscoveryFromEnv wires in production.
	m := NewMeshDiscovery(MeshConfig{K8sBaseURL: srv.URL, CACert: serverCAPEM(t, srv)}, nil)
	res := m.Discover(context.Background(), "job-ca-ok")
	if res.ErrorCount != 0 {
		t.Fatalf("configured CA must make the handshake succeed, got errors: %+v", res.Endpoints)
	}
	byProto := endpointsByProtocol(res)
	if len(byProto["istio-mesh"]) != 1 || len(byProto["linkerd-mesh"]) != 1 {
		t.Fatalf("expected both mesh sources found: %+v", res.Endpoints)
	}
}

func TestNewMeshDiscoveryFailsClosedWithoutCACert(t *testing.T) {
	istio := selfSignedPEM(t, "istio-ca.example.org", true)
	linkerd := selfSignedPEM(t, "identity.linkerd.cluster.local", true)
	srv := istioLinkerdTLSFixture(t, istio, linkerd)

	// No CACert configured and no injected client: the system root pool
	// does not trust the test server's self-signed cert, so every k8sGet
	// must fail TLS verification -- never silently skip verification.
	m := NewMeshDiscovery(MeshConfig{K8sBaseURL: srv.URL}, nil)
	res := m.Discover(context.Background(), "job-ca-missing")
	if res.ErrorCount == 0 {
		t.Fatal("an untrusted API server must surface as an error, not a quiet empty result")
	}
	for _, ep := range res.Endpoints {
		if ep.Error != "" && !strings.Contains(ep.Error, "certificate") && !strings.Contains(ep.Error, "x509") && !strings.Contains(ep.Error, "tls") {
			t.Fatalf("expected a TLS trust error, got: %s", ep.Error)
		}
	}
}

func TestMeshCACertPEMFromEnvReadsFileAndInline(t *testing.T) {
	t.Setenv("KRYPTKEEPER_MESH_K8S_CA_CERT", "")
	t.Setenv("KRYPTKEEPER_MESH_K8S_CA_CERT_FILE", "")
	if b, err := meshCACertPEMFromEnv(); err != nil || b != nil {
		t.Fatalf("unset env must return (nil, nil), got (%v, %v)", b, err)
	}

	t.Setenv("KRYPTKEEPER_MESH_K8S_CA_CERT", "inline-pem-bytes")
	b, err := meshCACertPEMFromEnv()
	if err != nil || string(b) != "inline-pem-bytes" {
		t.Fatalf("inline CA cert not read: %v %v", b, err)
	}

	t.Setenv("KRYPTKEEPER_MESH_K8S_CA_CERT", "")
	dir := t.TempDir()
	path := dir + "/ca.pem"
	if err := os.WriteFile(path, []byte("file-pem-bytes"), 0o600); err != nil {
		t.Fatalf("write fixture CA file: %v", err)
	}
	t.Setenv("KRYPTKEEPER_MESH_K8S_CA_CERT_FILE", path)
	b, err = meshCACertPEMFromEnv()
	if err != nil || string(b) != "file-pem-bytes" {
		t.Fatalf("CA cert file not read: %v %v", b, err)
	}
}
