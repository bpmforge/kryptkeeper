// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// W13-05: four more read-only InventorySources on the W11-05
// interface. Fixtures pin OUR request shapes and every base URL is
// configurable, so a vendor-path correction is a constant change (the
// W5-03 NITRO precedent). Per-item failures never sink a batch — the
// sync engine's contract.

const commercialHTTPTimeout = 30 * time.Second

func commercialGet(ctx context.Context, client *http.Client, url string, decorate func(*http.Request)) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if decorate != nil {
		decorate(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 300)])))
	}
	return body, nil
}

// --- Sectigo Certificate Manager -------------------------------------------

type sectigoSource struct {
	baseURL, customerURI, login, password string
	client                                *http.Client
}

func newSectigoSource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL     string `json:"base_url"`
		CustomerURI string `json:"customer_uri"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config caught by the checks below
	if cfg.BaseURL == "" || cfg.CustomerURI == "" {
		return nil, errors.New("sectigo source requires config_json.base_url and customer_uri")
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("sectigo source requires credential_ref holding {login, password} JSON")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("sectigo credential %q: %w", credentialRef, err)
	}
	var c struct{ Login, Password string }
	if err := json.Unmarshal(raw, &c); err != nil || c.Login == "" {
		return nil, errors.New("sectigo credential must be {login, password} JSON")
	}
	return &sectigoSource{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"), customerURI: cfg.CustomerURI,
		login: c.Login, password: c.Password,
		client: inventoryHTTPClient(commercialHTTPTimeout),
	}, nil
}

func (s *sectigoSource) headers(req *http.Request) {
	req.Header.Set("login", s.login)
	req.Header.Set("password", s.password)
	req.Header.Set("customerUri", s.customerURI)
}

func (s *sectigoSource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	var out []SyncedCertificate
	const page = 200
	for position := 0; ; position += page {
		body, err := commercialGet(ctx, s.client,
			fmt.Sprintf("%s/api/ssl/v1?size=%d&position=%d", s.baseURL, page, position), s.headers)
		if err != nil {
			return nil, err
		}
		var listing []struct {
			SSLID      int    `json:"sslId"`
			CommonName string `json:"commonName"`
			Status     string `json:"status"`
		}
		if err := json.Unmarshal(body, &listing); err != nil {
			return nil, fmt.Errorf("sectigo listing unparseable: %w", err)
		}
		for _, item := range listing {
			var status string
			switch item.Status {
			case "Issued":
				status = "active"
			case "Revoked":
				status = "revoked"
			default:
				continue // pending/rejected orders carry no cert
			}
			pemBody, err := commercialGet(ctx, s.client,
				fmt.Sprintf("%s/api/ssl/v1/collect/%d/x509CO", s.baseURL, item.SSLID), s.headers)
			if err != nil {
				continue // per-item failure never sinks the batch
			}
			out = append(out, SyncedCertificate{PEM: string(pemBody), UpstreamStatus: status})
		}
		if len(listing) < page {
			return out, nil
		}
	}
}

// --- AWS Private CA ---------------------------------------------------------

// awsPCASource inventories the AUTHORITY certificates. Honest scope:
// ACM-PCA has no list-issued-certificates API (that path is S3 audit
// reports — named follow-up, not faked), so the estate gains the CA
// layer here. Signed with the ALREADY-REQUIRED aws-sdk-go-v2 core
// SigV4 signer — no new dependency.
type awsPCASource struct {
	endpoint, region  string
	accessKey, secret string
	client            *http.Client
}

func newAWSPCASource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		Region   string `json:"region"`
		Endpoint string `json:"endpoint"` // test override
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config caught below
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = fmt.Sprintf("https://acm-pca.%s.amazonaws.com", cfg.Region)
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("aws_pca source requires credential_ref holding {access_key_id, secret_access_key} JSON")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("aws_pca credential %q: %w", credentialRef, err)
	}
	var c struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.AccessKeyID == "" {
		return nil, errors.New("aws_pca credential must be {access_key_id, secret_access_key} JSON")
	}
	return &awsPCASource{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"), region: cfg.Region,
		accessKey: c.AccessKeyID, secret: c.SecretAccessKey,
		client: inventoryHTTPClient(commercialHTTPTimeout),
	}, nil
}

func (s *awsPCASource) rpc(ctx context.Context, target string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/", strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "ACMPrivateCA."+target)
	sum := sha256.Sum256(raw)
	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, aws.Credentials{AccessKeyID: s.accessKey, SecretAccessKey: s.secret},
		req, hex.EncodeToString(sum[:]), "acm-pca", s.region, time.Now()); err != nil {
		return fmt.Errorf("aws_pca sign: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("aws_pca %s returned %d: %s", target, resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 300)])))
	}
	return json.Unmarshal(body, out)
}

func (s *awsPCASource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	var listing struct {
		CertificateAuthorities []struct {
			Arn    string `json:"Arn"`
			Status string `json:"Status"`
		} `json:"CertificateAuthorities"`
	}
	if err := s.rpc(ctx, "ListCertificateAuthorities", map[string]any{"MaxResults": 100}, &listing); err != nil {
		return nil, err
	}
	var out []SyncedCertificate
	for _, caEntry := range listing.CertificateAuthorities {
		status := "active"
		if caEntry.Status != "ACTIVE" {
			status = "revoked"
		}
		var cert struct {
			Certificate string `json:"Certificate"`
		}
		if err := s.rpc(ctx, "GetCertificateAuthorityCertificate",
			map[string]any{"CertificateAuthorityArn": caEntry.Arn}, &cert); err != nil || cert.Certificate == "" {
			continue // per-item failure never sinks the batch
		}
		out = append(out, SyncedCertificate{PEM: cert.Certificate, UpstreamStatus: status})
	}
	return out, nil
}

// --- Google Cloud CAS -------------------------------------------------------

type gcpCASSource struct {
	baseURL, project, location, pool, token string
	client                                  *http.Client
}

func newGCPCASSource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL  string `json:"base_url"` // test override
		Project  string `json:"project"`
		Location string `json:"location"`
		CAPool   string `json:"ca_pool"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config caught below
	if cfg.Project == "" || cfg.Location == "" || cfg.CAPool == "" {
		return nil, errors.New("gcp_cas source requires config_json.project, location, and ca_pool")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://privateca.googleapis.com"
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("gcp_cas source requires credential_ref holding an OAuth access token")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("gcp_cas credential %q: %w", credentialRef, err)
	}
	return &gcpCASSource{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"), project: cfg.Project,
		location: cfg.Location, pool: cfg.CAPool,
		token:  credentialSecretString(raw, "token"),
		client: inventoryHTTPClient(commercialHTTPTimeout),
	}, nil
}

func (s *gcpCASSource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	var out []SyncedCertificate
	pageToken := ""
	for {
		url := fmt.Sprintf("%s/v1/projects/%s/locations/%s/caPools/%s/certificates?pageSize=1000",
			s.baseURL, s.project, s.location, s.pool)
		if pageToken != "" {
			url += "&pageToken=" + pageToken
		}
		body, err := commercialGet(ctx, s.client, url, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+s.token)
		})
		if err != nil {
			return nil, err
		}
		var listing struct {
			Certificates []struct {
				PEMCertificate    string          `json:"pemCertificate"`
				RevocationDetails json.RawMessage `json:"revocationDetails"`
			} `json:"certificates"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &listing); err != nil {
			return nil, fmt.Errorf("gcp_cas listing unparseable: %w", err)
		}
		for _, item := range listing.Certificates {
			if item.PEMCertificate == "" {
				continue
			}
			status := "active"
			if len(item.RevocationDetails) > 0 && string(item.RevocationDetails) != "null" {
				status = "revoked"
			}
			out = append(out, SyncedCertificate{PEM: item.PEMCertificate, UpstreamStatus: status})
		}
		if listing.NextPageToken == "" {
			return out, nil
		}
		pageToken = listing.NextPageToken
	}
}
