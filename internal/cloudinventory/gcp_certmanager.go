// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// GCPCertManagerConnector lists certificates from GCP Certificate Manager.
//
// Configuration (env vars):
//
//	GCP_PROJECT_ID          - GCP project ID
//	GCP_REGION              - GCP region (default: global)
//	GOOGLE_ACCESS_TOKEN     - OAuth2 access token (for simple cases / CI)
//	GOOGLE_APPLICATION_CREDENTIALS - Path to service account JSON (standard ADC)
type GCPCertManagerConnector struct {
	client    *http.Client
	projectID string
	region    string
	token     string
	apiBase   string // override for testing; defaults to https://certificatemanager.googleapis.com
}

// NewGCPCertManagerConnector creates a GCP Certificate Manager connector.
func NewGCPCertManagerConnector(ctx context.Context) (*GCPCertManagerConnector, error) {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return nil, fmt.Errorf("GCP_PROJECT_ID is required")
	}

	return NewGCPCertManagerConnectorForScope(ctx, Scope{Provider: ProviderGCPCertManager, ProjectID: projectID, Region: os.Getenv("GCP_REGION")})
}

// NewGCPCertManagerConnectorForScope targets one project and location
// (default "global"); the token still comes from the environment.
func NewGCPCertManagerConnectorForScope(ctx context.Context, sc Scope) (*GCPCertManagerConnector, error) {
	projectID, region := sc.ProjectID, sc.Region
	if projectID == "" {
		return nil, fmt.Errorf("project_id is required")
	}
	if region == "" {
		region = "global"
	}

	token, err := gcpGetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp certmanager: get token: %w", err)
	}

	return &GCPCertManagerConnector{
		client:    &http.Client{Timeout: 30 * time.Second},
		projectID: projectID,
		region:    region,
		token:     token,
	}, nil
}

// ListCertificates returns all GCP Certificate Manager certificates in the project/region.
func (c *GCPCertManagerConnector) ListCertificates(ctx context.Context) ([]CloudCertificate, error) {
	var certs []CloudCertificate
	pageToken := ""

	for {
		items, next, err := c.listPage(ctx, pageToken)
		if err != nil {
			return nil, err
		}
		certs = append(certs, items...)
		if next == "" {
			break
		}
		pageToken = next
	}
	return certs, nil
}

type gcpCertListResponse struct {
	Certificates  []gcpCert `json:"certificates"`
	NextPageToken string    `json:"nextPageToken"`
}

type gcpCert struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	SanDnsnames     []string `json:"sanDnsnames"`
	CreateTime      string   `json:"createTime"`
	ExpireTime      string   `json:"expireTime"`
	SubjectAltNames struct {
		DNSNames []string `json:"dnsNames"`
	} `json:"subjectAltNames"`
	Managed struct {
		Domains                  []string `json:"domains"`
		State                    string   `json:"state"`
		AuthorizationAttemptInfo []struct {
			Domain string `json:"domain"`
			State  string `json:"state"`
		} `json:"authorizationAttemptInfo"`
	} `json:"managed"`
	SelfManaged struct {
		PemCertificate string `json:"pemCertificate"`
	} `json:"selfManaged"`
	Labels map[string]string `json:"labels"`
	Scope  string            `json:"scope"`
}

func (c *GCPCertManagerConnector) listPage(ctx context.Context, pageToken string) ([]CloudCertificate, string, error) {
	base := c.apiBase
	if base == "" {
		base = "https://certificatemanager.googleapis.com"
	}
	parent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, c.region)
	listURL := fmt.Sprintf("%s/v1/%s/certificates", base, parent)
	if pageToken != "" {
		listURL += "?pageToken=" + pageToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("gcp certmanager list: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("gcp certmanager list: status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var page gcpCertListResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", fmt.Errorf("gcp certmanager parse: %w", err)
	}

	certs := make([]CloudCertificate, 0, len(page.Certificates))
	for _, item := range page.Certificates {
		cert := CloudCertificate{
			Provider:   "gcp-certmanager",
			Region:     c.region,
			ResourceID: item.Name,
			CommonName: gcpCertCommonName(item),
			DNSNames:   gcpCertDNSNames(item),
			Status:     strings.ToLower(item.Managed.State),
		}
		if item.ExpireTime != "" {
			if t, err := time.Parse(time.RFC3339, item.ExpireTime); err == nil {
				cert.NotAfter = t
			}
		}
		if item.CreateTime != "" {
			if t, err := time.Parse(time.RFC3339, item.CreateTime); err == nil {
				cert.NotBefore = t
			}
		}
		// Google-managed certs use RSA 2048 by default; self-managed varies.
		if item.SelfManaged.PemCertificate != "" {
			cert.KeyAlgorithm = "self-managed"
		} else {
			cert.KeyAlgorithm = "RSA-2048"
		}
		certs = append(certs, cert)
	}

	return certs, page.NextPageToken, nil
}

// gcpGetToken retrieves an OAuth2 token for GCP API access.
// Tries GOOGLE_ACCESS_TOKEN env var first, then the metadata server (works in GCE/GKE/Cloud Run).
func gcpGetToken(ctx context.Context) (string, error) {
	if tok := os.Getenv("GOOGLE_ACCESS_TOKEN"); tok != "" {
		return tok, nil
	}

	// Try GCE metadata server.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", fmt.Errorf("build metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GCP metadata server unreachable — set GOOGLE_ACCESS_TOKEN or run on GCE/GKE: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse metadata token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("empty access token from metadata server")
	}
	return tok.AccessToken, nil
}

func gcpCertCommonName(cert gcpCert) string {
	if len(cert.Managed.Domains) > 0 {
		return cert.Managed.Domains[0]
	}
	if len(cert.SanDnsnames) > 0 {
		return cert.SanDnsnames[0]
	}
	// Fall back to resource name (projects/.../certificates/name).
	parts := strings.Split(cert.Name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return cert.Name
}

func gcpCertDNSNames(cert gcpCert) []string {
	seen := make(map[string]bool)
	var names []string
	for _, d := range cert.Managed.Domains {
		if !seen[d] {
			names = append(names, d)
			seen[d] = true
		}
	}
	for _, d := range cert.SanDnsnames {
		if !seen[d] {
			names = append(names, d)
			seen[d] = true
		}
	}
	return names
}
