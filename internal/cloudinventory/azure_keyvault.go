// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AzureKVConnector lists certificates from Azure Key Vault.
//
// Configuration (env vars):
//
//	AZURE_KEYVAULT_URL       - Key Vault URL, e.g. https://myvault.vault.azure.net
//	AZURE_CLIENT_ID          - Service principal client ID
//	AZURE_CLIENT_SECRET      - Service principal client secret
//	AZURE_TENANT_ID          - Azure AD tenant ID
//	AZURE_KEYVAULT_API_VERSION - API version (default: 7.4)
type AzureKVConnector struct {
	client     *http.Client
	vaultURL   string
	token      string
	apiVersion string
}

// NewAzureKVConnector creates an Azure Key Vault connector using client credentials flow.
func NewAzureKVConnector(ctx context.Context) (*AzureKVConnector, error) {
	if os.Getenv("AZURE_KEYVAULT_URL") == "" {
		return nil, fmt.Errorf("AZURE_KEYVAULT_URL is required")
	}
	return NewAzureKVConnectorForScope(ctx, Scope{Provider: ProviderAzureKeyVault, VaultURL: os.Getenv("AZURE_KEYVAULT_URL")})
}

// NewAzureKVConnectorForScope targets one vault; the service-principal
// credentials still come from the environment.
func NewAzureKVConnectorForScope(ctx context.Context, sc Scope) (*AzureKVConnector, error) {
	vaultURL := strings.TrimRight(sc.VaultURL, "/")
	if vaultURL == "" {
		return nil, fmt.Errorf("vault_url is required")
	}
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	tenantID := os.Getenv("AZURE_TENANT_ID")

	apiVersion := os.Getenv("AZURE_KEYVAULT_API_VERSION")
	if apiVersion == "" {
		apiVersion = "7.4"
	}

	token, err := azureGetToken(ctx, tenantID, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("azure keyvault: get token: %w", err)
	}

	return &AzureKVConnector{
		client:     &http.Client{Timeout: 30 * time.Second},
		vaultURL:   vaultURL,
		token:      token,
		apiVersion: apiVersion,
	}, nil
}

// ListCertificates returns all certificates in the configured Key Vault.
func (c *AzureKVConnector) ListCertificates(ctx context.Context) ([]CloudCertificate, error) {
	var certs []CloudCertificate
	listURL := fmt.Sprintf("%s/certificates?api-version=%s&maxresults=25", c.vaultURL, c.apiVersion)

	for listURL != "" {
		items, next, err := c.listPage(ctx, listURL)
		if err != nil {
			return nil, err
		}
		certs = append(certs, items...)
		listURL = next
	}
	return certs, nil
}

type azureCertListResponse struct {
	Value    []azureCertItem `json:"value"`
	NextLink string          `json:"nextLink"`
}

type azureCertItem struct {
	ID         string `json:"id"`
	Attributes struct {
		Enabled   bool  `json:"enabled"`
		Created   int64 `json:"created"`
		Updated   int64 `json:"updated"`
		Expires   int64 `json:"exp"`
		NotBefore int64 `json:"nbf"`
	} `json:"attributes"`
	X5T string `json:"x5t"`
}

func (c *AzureKVConnector) listPage(ctx context.Context, listURL string) ([]CloudCertificate, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("azure keyvault list: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("azure keyvault list: status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var page azureCertListResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", fmt.Errorf("azure keyvault parse: %w", err)
	}

	certs := make([]CloudCertificate, 0, len(page.Value))
	for _, item := range page.Value {
		// Extract cert name from ID: https://vault.azure.net/certificates/name/version
		name := azureCertName(item.ID)
		status := "disabled"
		if item.Attributes.Enabled {
			status = "enabled"
		}
		cert := CloudCertificate{
			Provider:   "azure-keyvault",
			Region:     azureVaultRegion(c.vaultURL),
			ResourceID: item.ID,
			CommonName: name,
			Status:     status,
		}
		if item.Attributes.NotBefore != 0 {
			cert.NotBefore = time.Unix(item.Attributes.NotBefore, 0).UTC()
		}
		if item.Attributes.Expires != 0 {
			cert.NotAfter = time.Unix(item.Attributes.Expires, 0).UTC()
		}
		cert.CertificatePEM = c.fetchPEM(ctx, item.ID)
		certs = append(certs, cert)
	}

	return certs, page.NextLink, nil
}

// fetchPEM reads one certificate version's public DER ("cer") and returns it
// as PEM, or "" when it cannot be had (a missing certificates/get permission
// leaves the row metadata-only rather than failing the scan). id is the
// versioned certificate id the list returned.
// https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate
func (c *AzureKVConnector) fetchPEM(ctx context.Context, id string) string {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || !strings.HasPrefix(id, c.vaultURL+"/") {
		return "" // never send the bearer token to a host the scope did not name
	}
	q := u.Query()
	q.Set("api-version", c.apiVersion)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var bundle struct {
		Cer string `json:"cer"`
	}
	if json.Unmarshal(body, &bundle) != nil || bundle.Cer == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(bundle.Cer)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// azureGetToken fetches an access token via the client credentials grant.
func azureGetToken(ctx context.Context, tenantID, clientID, clientSecret string) (string, error) {
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required")
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://vault.azure.net/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}
	return tok.AccessToken, nil
}

func azureCertName(id string) string {
	parts := strings.Split(id, "/")
	// ID format: https://vault/certificates/name/version
	for i, p := range parts {
		if p == "certificates" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return id
}

func azureVaultRegion(vaultURL string) string {
	// Vault URLs are like: https://myvault.vault.azure.net — no region in URL.
	// Return the vault hostname as the "region" for display purposes.
	u, err := url.Parse(vaultURL)
	if err != nil {
		return vaultURL
	}
	return u.Hostname()
}
