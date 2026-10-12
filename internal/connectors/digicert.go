// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// W13-02: the CertCentral write path. The read-side sync (W11-05)
// already speaks this API family (X-DC-DEVKEY, /services/v2); this
// issues and renews upstream through it as an IssuerConnector.
// Renewal IS issuance here — the executor generates a fresh key/CSR
// per renewal, so there is no separate renew verb.

// DigiCertConfig locates and authenticates CertCentral.
type DigiCertConfig struct {
	// BaseURL defaults to https://www.digicert.com.
	BaseURL        string
	APIKey         string
	OrganizationID int
	// ProductNameID is the order product path segment (default ssl_basic).
	ProductNameID string
	ValidityYears int
	// Poll pacing for orders that need approval; tests shrink these.
	PollAttempts int
	PollInterval time.Duration
}

// DigiCertConnector is an IssuerConnector backed by CertCentral.
type DigiCertConnector struct {
	id     string
	cfg    DigiCertConfig
	client *http.Client

	mu        sync.Mutex
	lastError string
}

func NewDigiCertConnector(id string, cfg DigiCertConfig, client *http.Client) *DigiCertConnector {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.digicert.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.ProductNameID == "" {
		cfg.ProductNameID = "ssl_basic"
	}
	if cfg.ValidityYears <= 0 {
		cfg.ValidityYears = 1
	}
	if cfg.PollAttempts <= 0 {
		cfg.PollAttempts = 10
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	return &DigiCertConnector{id: id, cfg: cfg, client: client}
}

func (c *DigiCertConnector) ID() string     { return c.id }
func (c *DigiCertConnector) Type() string   { return "digicert" }
func (c *DigiCertConnector) Origin() string { return "synced" }

func (c *DigiCertConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// Health probes the account endpoint AND carries the last issue-path
// error — a throttled connector must show degraded, never silently
// fail renewals.
func (c *DigiCertConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	_, _, err := c.do(ctx, http.MethodGet, "/services/v2/user/me", nil)
	switch {
	case err != nil && last != "":
		return Health{Status: "degraded", Detail: err.Error() + "; last issue error: " + last}
	case err != nil:
		return Health{Status: "degraded", Detail: err.Error()}
	case last != "":
		return Health{Status: "degraded", Detail: "last issue error: " + last}
	}
	return Health{Status: "healthy"}
}

func (c *DigiCertConnector) do(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-DC-DEVKEY", c.cfg.APIKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // error surfaces via status below
	if resp.StatusCode == http.StatusTooManyRequests {
		return resp.StatusCode, raw, fmt.Errorf("digicert %s: rate limited (HTTP 429)", path)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, raw, fmt.Errorf("digicert %s: HTTP %d: %s", path, resp.StatusCode, truncate(raw))
	}
	return resp.StatusCode, raw, nil
}

func truncate(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

type digicertOrderResponse struct {
	ID          int `json:"id"`
	Certificate struct {
		ID int `json:"id"`
	} `json:"certificate"`
	Status string `json:"status"`
}

// Issue orders a certificate, waits for a certificate id (auto-approve
// orgs return it immediately; approval-gated orders are polled within
// a bounded budget), downloads the chain, and returns leaf PEM+FP.
func (c *DigiCertConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *DigiCertConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("digicert %s: CSRPEM is not a PEM certificate request", c.id)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("digicert %s: CSR unparseable: %w", c.id, err)
	}

	order := map[string]any{
		"certificate": map[string]any{
			"common_name":    csr.Subject.CommonName,
			"csr":            req.CSRPEM,
			"signature_hash": "sha256",
		},
		"organization":   map[string]any{"id": c.cfg.OrganizationID},
		"validity_years": c.cfg.ValidityYears,
	}
	_, raw, err := c.do(ctx, http.MethodPost, "/services/v2/order/certificate/"+c.cfg.ProductNameID, order)
	if err != nil {
		return IssueResult{}, err
	}
	var placed digicertOrderResponse
	if err := json.Unmarshal(raw, &placed); err != nil {
		return IssueResult{}, fmt.Errorf("digicert %s: order response unparseable: %w", c.id, err)
	}

	certID := placed.Certificate.ID
	for attempt := 0; certID == 0 && attempt < c.cfg.PollAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return IssueResult{}, ctx.Err()
		case <-time.After(c.cfg.PollInterval):
		}
		_, raw, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/services/v2/order/certificate/%d", placed.ID), nil)
		if err != nil {
			return IssueResult{}, err
		}
		var polled digicertOrderResponse
		if err := json.Unmarshal(raw, &polled); err != nil {
			return IssueResult{}, fmt.Errorf("digicert %s: poll response unparseable: %w", c.id, err)
		}
		certID = polled.Certificate.ID
	}
	if certID == 0 {
		// Never silent: name the order so an operator can chase the
		// pending approval in CertCentral.
		return IssueResult{}, fmt.Errorf("digicert %s: order %d still pending after %d polls — approve it in CertCentral or raise the poll budget", c.id, placed.ID, c.cfg.PollAttempts)
	}

	_, chainRaw, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/services/v2/certificate/%d/download/format/pem_all", certID), nil)
	if err != nil {
		return IssueResult{}, err
	}
	leaf, rest := pem.Decode(chainRaw)
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return IssueResult{}, fmt.Errorf("digicert %s: downloaded bundle is not PEM certificates", c.id)
	}
	_ = rest
	cert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("digicert %s: downloaded leaf unparseable: %w", c.id, err)
	}
	sum := sha256.Sum256(cert.Raw)
	return IssueResult{
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		CertificatePEM:    string(chainRaw),
	}, nil
}
