// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package certmanager provides a discovery connector for cert-manager Certificate resources.
// It queries the Kubernetes API server directly using the cert-manager.io CRD API.
//
// Configuration (env vars):
//
//	KRYPTKEEPER_K8S_API_URL   - Kubernetes API server URL (default: auto-detect in-cluster)
//	KRYPTKEEPER_K8S_TOKEN     - Bearer token for API authentication
//	KRYPTKEEPER_K8S_TOKEN_FILE - Path to file containing the bearer token
//	KRYPTKEEPER_K8S_CA_CERT   - PEM-encoded CA certificate for TLS verification
//	KRYPTKEEPER_K8S_CA_CERT_FILE - Path to CA certificate file (KRYPTKEEPER_K8S_CA_FILE is accepted as an alias)
//	KRYPTKEEPER_K8S_NAMESPACE - Namespace to query (default: all namespaces)
//
// TLS verification cannot be disabled: the connector sends a bearer token, so
// a cluster with a private CA must supply that CA instead. Setting the removed
// KRYPTKEEPER_K8S_SKIP_VERIFY=true is a startup error, not a silent no-op.
package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	inClusterAPIServer = "https://kubernetes.default.svc"

	certManagerGroup   = "cert-manager.io"
	certManagerVersion = "v1"
	certResource       = "certificates"
)

// Certificate represents a cert-manager Certificate resource.
type Certificate struct {
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	SecretName  string    `json:"secret_name"`
	CommonName  string    `json:"common_name"`
	DNSNames    []string  `json:"dns_names"`
	IssuerRef   string    `json:"issuer_ref"`
	IssuerKind  string    `json:"issuer_kind"`
	Duration    string    `json:"duration"`
	RenewBefore string    `json:"renew_before"`
	Ready       bool      `json:"ready"`
	Message     string    `json:"message"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Config holds connection parameters for the Kubernetes API server.
type Config struct {
	APIServerURL string
	Token        string
	CACert       []byte
	Namespace    string // empty = all namespaces
}

// ConfigFromEnv builds a Config from environment variables, falling back to
// in-cluster service account files when running inside a Pod.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		APIServerURL: os.Getenv("KRYPTKEEPER_K8S_API_URL"),
		Token:        os.Getenv("KRYPTKEEPER_K8S_TOKEN"),
		Namespace:    os.Getenv("KRYPTKEEPER_K8S_NAMESPACE"),
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_K8S_SKIP_VERIFY")), "true") {
		return cfg, fmt.Errorf("KRYPTKEEPER_K8S_SKIP_VERIFY is no longer supported (the bearer token would be sent unverified); set KRYPTKEEPER_K8S_CA_CERT_FILE to the cluster CA bundle instead")
	}

	// Token from file takes precedence over env var.
	if tokenFile := os.Getenv("KRYPTKEEPER_K8S_TOKEN_FILE"); tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return cfg, fmt.Errorf("read token file %q: %w", tokenFile, err)
		}
		cfg.Token = strings.TrimSpace(string(b))
	}

	// CA cert from env or file.
	caPEM, err := CACertPEMFromEnv()
	if err != nil {
		return cfg, err
	}
	cfg.CACert = caPEM

	// In-cluster auto-detection: if no API URL specified, try service account files.
	if cfg.APIServerURL == "" {
		if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
			port := os.Getenv("KUBERNETES_SERVICE_PORT")
			if port == "" {
				port = "443"
			}
			cfg.APIServerURL = fmt.Sprintf("https://%s:%s", host, port)
		} else {
			cfg.APIServerURL = inClusterAPIServer
		}
	}

	if cfg.Token == "" {
		if b, err := os.ReadFile(inClusterTokenFile); err == nil {
			cfg.Token = strings.TrimSpace(string(b))
		}
	}

	if len(cfg.CACert) == 0 {
		if b, err := os.ReadFile(inClusterCAFile); err == nil {
			cfg.CACert = b
		}
	}

	return cfg, nil
}

// CACertPEMFromEnv reads the cluster CA bundle from KRYPTKEEPER_K8S_CA_CERT
// / _FILE. Exported (not just used inline by ConfigFromEnv) so W19-17's
// k8s push-target CA trust reuses the exact same vocabulary instead of a
// second, drift-prone copy of this env parsing. Returns (nil, nil) when
// neither is set.
func CACertPEMFromEnv() ([]byte, error) {
	if caCert := os.Getenv("KRYPTKEEPER_K8S_CA_CERT"); caCert != "" {
		return []byte(caCert), nil
	}
	caFile := os.Getenv("KRYPTKEEPER_K8S_CA_CERT_FILE")
	if caFile == "" {
		caFile = os.Getenv("KRYPTKEEPER_K8S_CA_FILE")
	}
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert file %q: %w", caFile, err)
		}
		return b, nil
	}
	return nil, nil
}

// Connector discovers cert-manager Certificate resources from a Kubernetes cluster.
type Connector struct {
	client    *http.Client
	serverURL string
	token     string
	namespace string
}

// New creates a Connector from the given config.
func New(cfg Config) (*Connector, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if len(cfg.CACert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.RootCAs = pool
	}

	return &Connector{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		serverURL: strings.TrimRight(cfg.APIServerURL, "/"),
		token:     cfg.Token,
		namespace: cfg.Namespace,
	}, nil
}

// NewFromEnv creates a Connector using ConfigFromEnv.
func NewFromEnv() (*Connector, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg)
}

// Ping checks connectivity to the Kubernetes API server.
func (c *Connector) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/version", nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("k8s api unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("k8s api returned %d", resp.StatusCode)
	}
	return nil
}

// ListCertificates returns all cert-manager Certificate resources in the configured namespace(s).
func (c *Connector) ListCertificates(ctx context.Context) ([]Certificate, error) {
	url := c.listURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("cert-manager CRD not installed on this cluster (404)")
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("k8s api auth error (%d) — check KRYPTKEEPER_K8S_TOKEN and RBAC permissions", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return parseCertificateList(body)
}

// k8sCertList is the minimal shape of a Kubernetes List response for cert-manager Certificates.
type k8sCertList struct {
	Items []k8sCert `json:"items"`
}

type k8sCert struct {
	Metadata k8sMeta       `json:"metadata"`
	Spec     k8sCertSpec   `json:"spec"`
	Status   k8sCertStatus `json:"status"`
}

type k8sMeta struct {
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	CreationTimestamp time.Time `json:"creationTimestamp"`
}

type k8sCertSpec struct {
	SecretName  string   `json:"secretName"`
	CommonName  string   `json:"commonName"`
	DNSNames    []string `json:"dnsNames"`
	Duration    string   `json:"duration"`
	RenewBefore string   `json:"renewBefore"`
	IssuerRef   struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Group string `json:"group"`
	} `json:"issuerRef"`
}

type k8sCertStatus struct {
	Conditions []struct {
		Type    string `json:"type"`
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"conditions"`
	NotBefore *time.Time `json:"notBefore,omitempty"`
	NotAfter  *time.Time `json:"notAfter,omitempty"`
}

func parseCertificateList(body []byte) ([]Certificate, error) {
	var list k8sCertList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse certificate list: %w", err)
	}

	certs := make([]Certificate, 0, len(list.Items))
	for _, item := range list.Items {
		cert := Certificate{
			Namespace:   item.Metadata.Namespace,
			Name:        item.Metadata.Name,
			SecretName:  item.Spec.SecretName,
			CommonName:  item.Spec.CommonName,
			DNSNames:    item.Spec.DNSNames,
			IssuerRef:   item.Spec.IssuerRef.Name,
			IssuerKind:  item.Spec.IssuerRef.Kind,
			Duration:    item.Spec.Duration,
			RenewBefore: item.Spec.RenewBefore,
			CreatedAt:   item.Metadata.CreationTimestamp,
		}

		// Derive common name from first DNS name if not explicitly set.
		if cert.CommonName == "" && len(cert.DNSNames) > 0 {
			cert.CommonName = cert.DNSNames[0]
		}

		// Extract readiness and timestamps from conditions.
		for _, cond := range item.Status.Conditions {
			if cond.Type == "Ready" {
				cert.Ready = cond.Status == "True"
				cert.Message = cond.Message
			}
		}
		if item.Status.NotBefore != nil {
			cert.NotBefore = *item.Status.NotBefore
		}
		if item.Status.NotAfter != nil {
			cert.NotAfter = *item.Status.NotAfter
		}

		certs = append(certs, cert)
	}
	return certs, nil
}

func (c *Connector) listURL() string {
	if c.namespace != "" {
		return fmt.Sprintf("%s/apis/%s/%s/namespaces/%s/%s",
			c.serverURL, certManagerGroup, certManagerVersion, c.namespace, certResource)
	}
	return fmt.Sprintf("%s/apis/%s/%s/%s",
		c.serverURL, certManagerGroup, certManagerVersion, certResource)
}

func (c *Connector) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
