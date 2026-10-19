// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"bufio"
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

// GetCertificateRequest returns one CertificateRequest.
func (c *K8sClient) GetCertificateRequest(ctx context.Context, namespace, name string) (*CertificateRequest, error) {
	body, err := c.get(ctx, c.crURL(namespace, name))
	if err != nil {
		return nil, err
	}
	var cr CertificateRequest
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("decode CertificateRequest: %w", err)
	}
	return &cr, nil
}

// WatchCertificateRequests streams watch events for CertificateRequests from
// resourceVersion, calling onEvent for each. It returns nil on a clean EOF,
// ErrWatchExpired when the version is too old, and the callback's error if it
// fails. The stream is not subject to the client's request timeout.
func (c *K8sClient) WatchCertificateRequests(ctx context.Context, namespace, resourceVersion string, onEvent func(WatchEvent) error) error {
	url := c.crURL(namespace, "") + "?watch=true&allowWatchBookmarks=true&timeoutSeconds=300"
	if resourceVersion != "" {
		url += "&resourceVersion=" + resourceVersion
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)

	hc := *c.HTTPClient
	hc.Timeout = 0 // a client-wide timeout would kill the long-lived stream
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("WATCH %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusGone {
		return ErrWatchExpired
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("WATCH %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	r := bufio.NewReader(resp.Body)
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var ev WatchEvent
			if jerr := json.Unmarshal(line, &ev); jerr != nil {
				return fmt.Errorf("decode watch event: %w", jerr)
			}
			if ev.Type == "ERROR" {
				var st struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				}
				if jerr := json.Unmarshal(ev.Object, &st); jerr != nil {
					return fmt.Errorf("decode watch error event: %w", jerr)
				}
				if st.Code == http.StatusGone {
					return ErrWatchExpired
				}
				return fmt.Errorf("watch error event: code %d: %s", st.Code, st.Message)
			}
			if cerr := onEvent(ev); cerr != nil {
				return cerr
			}
		}
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read watch stream: %w", err)
		}
	}
}

// PatchCRConditions upserts conditions (by Type) on a CertificateRequest
// status, preserving the existing ones.
func (c *K8sClient) PatchCRConditions(ctx context.Context, cr *CertificateRequest, conds ...Condition) error {
	merged := append([]Condition(nil), cr.Status.Conditions...)
	for _, cond := range conds {
		replaced := false
		for i := range merged {
			if merged[i].Type == cond.Type {
				merged[i] = cond
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, cond)
		}
	}
	body, err := json.Marshal(StatusPatch{Status: CRStatus{Conditions: merged}})
	if err != nil {
		return fmt.Errorf("marshal status patch: %w", err)
	}
	return c.patch(ctx, c.crURL(cr.Metadata.Namespace, cr.Metadata.Name)+"/status", body)
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
