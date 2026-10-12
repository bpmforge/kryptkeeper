// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"bytes"
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
	// serviceAccountTokenPath is the default in-cluster token path.
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	// serviceAccountCAPath is the default in-cluster CA cert path.
	serviceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// K8sClient performs raw HTTP requests against the Kubernetes API server.
type K8sClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewInClusterClient builds a K8sClient from the in-cluster service account credentials.
func NewInClusterClient() (*K8sClient, error) {
	token, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	caData, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("parse cluster CA certificate")
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	apiServer := os.Getenv("KUBERNETES_SERVICE_HOST")
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiServer == "" {
		apiServer = "kubernetes.default.svc"
	}
	if apiPort == "" {
		apiPort = "443"
	}

	return &K8sClient{
		BaseURL:    "https://" + apiServer + ":" + apiPort,
		Token:      strings.TrimSpace(string(token)),
		HTTPClient: httpClient,
	}, nil
}

// NewK8sClient returns a K8sClient with the given base URL, token, and HTTP client.
// Useful for testing (pass httptest.Server URL + custom client).
func NewK8sClient(baseURL, token string, httpClient *http.Client) *K8sClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &K8sClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		HTTPClient: httpClient,
	}
}

// ListCertificateRequests returns all CertificateRequests in the given namespace.
// Pass an empty namespace string to list across all namespaces.
func (c *K8sClient) ListCertificateRequests(ctx context.Context, namespace string) (*CertificateRequestList, error) {
	url := c.crURL(namespace, "")
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var list CertificateRequestList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode CertificateRequestList: %w", err)
	}
	return &list, nil
}

// PatchCRStatus updates a CertificateRequest's status with the issued certificate
// and/or a condition. Pass nil certPEM to set only the condition.
func (c *K8sClient) PatchCRStatus(ctx context.Context, cr *CertificateRequest, certPEM []byte, cond *Condition) error {
	status := CRStatus{
		Certificate: certPEM,
		Conditions:  cr.Status.Conditions,
	}

	if cond != nil {
		// Replace or append the condition of the same type.
		replaced := false
		for i, existing := range status.Conditions {
			if existing.Type == cond.Type {
				status.Conditions[i] = *cond
				replaced = true
				break
			}
		}
		if !replaced {
			status.Conditions = append(status.Conditions, *cond)
		}
	} else if certPEM != nil {
		// Set Ready=True condition on successful issuance.
		readyCond := Condition{
			Type:               "Ready",
			Status:             "True",
			LastTransitionTime: time.Now().UTC(),
			Reason:             "Issued",
			Message:            "Certificate issued by Kryptkeeper",
		}
		replaced := false
		for i, existing := range status.Conditions {
			if existing.Type == "Ready" {
				status.Conditions[i] = readyCond
				replaced = true
				break
			}
		}
		if !replaced {
			status.Conditions = append(status.Conditions, readyCond)
		}
	}

	patch := StatusPatch{Status: status}
	body, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal status patch: %w", err)
	}

	url := c.crURL(cr.Metadata.Namespace, cr.Metadata.Name) + "/status"
	return c.patch(ctx, url, body)
}

// crURL builds the URL for a CertificateRequest resource.
func (c *K8sClient) crURL(namespace, name string) string {
	var b strings.Builder
	b.WriteString(c.BaseURL)
	b.WriteString("/apis/cert-manager.io/v1/")
	if namespace != "" {
		b.WriteString("namespaces/")
		b.WriteString(namespace)
		b.WriteString("/")
	}
	b.WriteString("certificaterequests")
	if name != "" {
		b.WriteString("/")
		b.WriteString(name)
	}
	return b.String()
}

func (c *K8sClient) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read GET %s body: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *K8sClient) patch(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/merge-patch+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("PATCH %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PATCH %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (c *K8sClient) setHeaders(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Accept", "application/json")
}
