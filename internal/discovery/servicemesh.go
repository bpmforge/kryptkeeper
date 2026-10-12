// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package discovery holds discovery sources beyond the network scanner
// (which lives in the scanner subpackage). Every source emits the
// scanner's public types so results flow through the one inventory.
package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

// W7-06 (D-060): mesh + SaaS discovery breadth. Istio/Linkerd keep
// cert material in Kubernetes secrets rather than on listening
// sockets, and SaaS/API endpoints are known by configuration, not by
// CIDR sweep. Both surface here as scanner.ScanResult — same types,
// same inventory, no parallel store.

// MeshConfig locates the cluster and the configured SaaS endpoints.
type MeshConfig struct {
	// K8sBaseURL, e.g. https://k8s.example.com:6443 ("" = no cluster,
	// only SaaS endpoints are scanned).
	K8sBaseURL  string
	BearerToken string
	// SaaSEndpoints are host:port targets scanned live over TLS.
	SaaSEndpoints []string
	// Timeout per SaaS handshake (default 10s).
	Timeout time.Duration
	// CACert is a PEM-encoded CA bundle used to verify the cluster's API
	// server. W19-20: found live on W19-09's kind fixture -- unlike
	// certmanager.Config (see internal/certmanager/connector.go), this
	// type had no CA-trust field at all, so any cluster with a private
	// CA (every kind cluster; every real one) failed every k8sGet with
	// "x509: certificate signed by unknown authority" and mesh discovery
	// was silently unusable outside a cluster with a publicly-trusted
	// API server. Empty = use the system root pool (works only for a
	// dev-mode http:// base URL or a publicly-trusted apiserver cert).
	CACert []byte
}

// MeshDiscovery discovers mesh and SaaS certificates.
type MeshDiscovery struct {
	cfg    MeshConfig
	client *http.Client
}

func NewMeshDiscovery(cfg MeshConfig, client *http.Client) *MeshDiscovery {
	if client == nil {
		client = defaultMeshHTTPClient(cfg.CACert)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &MeshDiscovery{cfg: cfg, client: client}
}

// defaultMeshHTTPClient mirrors internal/certmanager/connector.go's New:
// an explicit RootCAs pool when a CA bundle is configured, the system
// pool otherwise. No InsecureSkipVerify escape hatch -- a mesh cluster's
// identity is exactly what this discovery source exists to establish
// trust in, so unlike certmanager.Config there is no
// KRYPTKEEPER_..._SKIP_VERIFY here.
func defaultMeshHTTPClient(caCertPEM []byte) *http.Client {
	if len(caCertPEM) == 0 {
		return http.DefaultClient
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		// Falls through to the system pool; k8sGet's HTTP error surfaces
		// the resulting TLS failure rather than hiding it.
		return http.DefaultClient
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
}

// meshCACertPEMFromEnv reads KRYPTKEEPER_MESH_K8S_CA_CERT[_FILE] -- its
// own env-var family, matching K8sBaseURL/BearerToken's
// KRYPTKEEPER_MESH_K8S_* vocabulary rather than certmanager's
// KRYPTKEEPER_K8S_* one, since a mesh cluster's API server need not be
// the same cluster/CA a cert-manager connector is configured against.
func meshCACertPEMFromEnv() ([]byte, error) {
	if caCert := os.Getenv("KRYPTKEEPER_MESH_K8S_CA_CERT"); caCert != "" {
		return []byte(caCert), nil
	}
	if caFile := strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_K8S_CA_CERT_FILE")); caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert file %q: %w", caFile, err)
		}
		return b, nil
	}
	return nil, nil
}

// NewMeshDiscoveryFromEnv returns nil when nothing is configured —
// the feature stays dormant.
func NewMeshDiscoveryFromEnv() *MeshDiscovery {
	caCert, err := meshCACertPEMFromEnv()
	if err != nil {
		return nil
	}
	cfg := MeshConfig{
		K8sBaseURL:  strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_K8S_URL")),
		BearerToken: strings.TrimSpace(os.Getenv("KRYPTKEEPER_MESH_K8S_TOKEN")),
		CACert:      caCert,
	}
	for _, e := range strings.Split(os.Getenv("KRYPTKEEPER_SAAS_ENDPOINTS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			cfg.SaaSEndpoints = append(cfg.SaaSEndpoints, e)
		}
	}
	if cfg.K8sBaseURL == "" && len(cfg.SaaSEndpoints) == 0 {
		return nil
	}
	return NewMeshDiscovery(cfg, nil)
}

// k8sSecret is the slice of the Secret manifest we consume.
type k8sSecret struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

func (m *MeshDiscovery) k8sGet(ctx context.Context, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.K8sBaseURL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+m.cfg.BearerToken)
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // error surfaces via status/decode
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("k8s GET %s: HTTP %d", path, resp.StatusCode)
	}
	return resp.StatusCode, json.Unmarshal(raw, out)
}

// parsePEMCerts converts a PEM chain into DiscoveredCerts. Unparsable
// blocks are skipped — one rotted secret must not hide the others.
func parsePEMCerts(pemBytes []byte) []scanner.DiscoveredCert {
	var out []scanner.DiscoveredCert
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		out = append(out, scanner.DiscoveredCert{
			Fingerprint:        hex.EncodeToString(sum[:]),
			SerialNumber:       cert.SerialNumber.Text(16),
			CommonName:         cert.Subject.CommonName,
			SubjectDN:          cert.Subject.String(),
			IssuerDN:           cert.Issuer.String(),
			DNSNames:           cert.DNSNames,
			ValidFrom:          cert.NotBefore,
			ValidUntil:         cert.NotAfter,
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			IsCA:               cert.IsCA,
			Raw:                cert.Raw,
		})
	}
	return out
}

func decodeSecretCerts(sec k8sSecret, keys ...string) []scanner.DiscoveredCert {
	var out []scanner.DiscoveredCert
	for _, key := range keys {
		b64, ok := sec.Data[key]
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		out = append(out, parsePEMCerts(raw)...)
	}
	return out
}

func meshEndpoint(host, protocol string, certs []scanner.DiscoveredCert, errText string, now time.Time) scanner.DiscoveredEndpoint {
	return scanner.DiscoveredEndpoint{
		Host: host, Protocol: protocol, Certs: certs, Error: errText, ScannedAt: now,
	}
}

// Discover sweeps the mesh secret sources and the configured SaaS
// endpoints. Absent mesh secrets are normal (skipped); API errors are
// recorded on an endpoint's Error field — visible, never fatal to the
// rest of the sweep.
func (m *MeshDiscovery) Discover(ctx context.Context, jobID string) *scanner.ScanResult {
	now := time.Now().UTC()
	result := &scanner.ScanResult{JobID: jobID, Status: "completed", StartedAt: now}

	if m.cfg.K8sBaseURL != "" {
		// 1. Every kubernetes.io/tls secret (gateway/ingress serving
		// certs, incl. Istio credentialName secrets).
		var list struct {
			Items []k8sSecret `json:"items"`
		}
		if _, err := m.k8sGet(ctx, "/api/v1/secrets?fieldSelector=type%3Dkubernetes.io%2Ftls", &list); err != nil {
			result.Endpoints = append(result.Endpoints, meshEndpoint(m.cfg.K8sBaseURL, "k8s-tls-secret", nil, err.Error(), now))
			result.ErrorCount++
		} else {
			for _, sec := range list.Items {
				certs := decodeSecretCerts(sec, "tls.crt")
				if len(certs) == 0 {
					continue
				}
				result.Endpoints = append(result.Endpoints, meshEndpoint(
					sec.Metadata.Namespace+"/"+sec.Metadata.Name, "k8s-tls-secret", certs, "", now))
				result.CertsFound += len(certs)
			}
		}

		// 2. Istio mesh root CA. Both the auto-generated secret
		// (istio-ca-secret) and an operator-provided cacerts are tried;
		// a cluster without Istio simply has neither.
		for _, probe := range []struct {
			path string
			keys []string
		}{
			{"/api/v1/namespaces/istio-system/secrets/istio-ca-secret", []string{"ca-cert.pem"}},
			{"/api/v1/namespaces/istio-system/secrets/cacerts", []string{"ca-cert.pem", "root-cert.pem"}},
		} {
			var sec k8sSecret
			status, err := m.k8sGet(ctx, probe.path, &sec)
			if err != nil {
				if status != http.StatusNotFound && status != 0 {
					result.Endpoints = append(result.Endpoints, meshEndpoint(probe.path, "istio-mesh", nil, err.Error(), now))
					result.ErrorCount++
				}
				continue
			}
			if certs := decodeSecretCerts(sec, probe.keys...); len(certs) > 0 {
				result.Endpoints = append(result.Endpoints, meshEndpoint(
					"istio-system/"+sec.Metadata.Name, "istio-mesh", certs, "", now))
				result.CertsFound += len(certs)
			}
		}

		// 3. Linkerd identity issuer.
		var sec k8sSecret
		status, err := m.k8sGet(ctx, "/api/v1/namespaces/linkerd/secrets/linkerd-identity-issuer", &sec)
		if err == nil {
			if certs := decodeSecretCerts(sec, "crt.pem", "ca.crt"); len(certs) > 0 {
				result.Endpoints = append(result.Endpoints, meshEndpoint(
					"linkerd/linkerd-identity-issuer", "linkerd-mesh", certs, "", now))
				result.CertsFound += len(certs)
			}
		} else if status != http.StatusNotFound && status != 0 {
			result.Endpoints = append(result.Endpoints, meshEndpoint("linkerd/linkerd-identity-issuer", "linkerd-mesh", nil, err.Error(), now))
			result.ErrorCount++
		}
	}

	// 4. Configured SaaS/API endpoints — live TLS handshake through the
	// same scanner path network discovery uses.
	for _, target := range m.cfg.SaaSEndpoints {
		ep, err := scanner.ScanHost(ctx, target, m.cfg.Timeout)
		if err != nil {
			result.Endpoints = append(result.Endpoints, meshEndpoint(target, "saas-api", nil, err.Error(), now))
			result.ErrorCount++
			continue
		}
		ep.Protocol = "saas-api"
		result.Endpoints = append(result.Endpoints, *ep)
		result.CertsFound += len(ep.Certs)
	}

	result.TotalScanned = len(result.Endpoints)
	result.CompletedAt = time.Now().UTC()
	return result
}
