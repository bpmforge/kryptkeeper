// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client communicates with the Kryptkeeper Hub agent API.
// All outbound — no inbound port required on the agent host.
type Client struct {
	HubURL     string
	AgentID    string
	Token      string
	HTTPClient *http.Client
	// EnrollmentSecret is sent once, on Register. The hub refuses
	// self-registration without it unless enrollment is left open.
	EnrollmentSecret string
	// EnrollmentToken is a single-use admin-minted token (W33-25). When set
	// it is sent instead of EnrollmentSecret. Never log it.
	EnrollmentToken string
	// Version is the agent build, sent as X-Agent-Version so the hub can show
	// it. Omitted when empty.
	Version string
}

// New returns a Client configured for the given Hub. rootCAs, when non-nil,
// is used to verify the Hub's TLS certificate instead of the system roots —
// build it with HubCACertPoolFromEnv so every caller shares one parse of
// KRYPTKEEPER_HUB_CA_CERT/_FILE. Passing nil preserves system-roots
// verification (unchanged behaviour for hubs with a publicly-trusted cert).
// agentID and token may be empty on first run; call Register() to obtain them.
func New(hubURL, agentID, token string, rootCAs *x509.CertPool) *Client {
	return &Client{
		HubURL:  strings.TrimRight(hubURL, "/"),
		AgentID: agentID,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: hubTransport(rootCAs),
			// Go copies custom headers (X-Agent-Token) onto redirects, even
			// cross-host or https->http. The agent API never redirects, so
			// refuse rather than leak the token.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// ValidateHubURL refuses a hub URL that is not https unless its host is
// loopback (localhost, 127.0.0.0/8, ::1), so the agent token and enrolment
// secret are never sent in clear text over a real network.
func ValidateHubURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("KRYPTKEEPER_HUB_URL is not a valid absolute URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		h := strings.ToLower(u.Hostname())
		if h == "localhost" || strings.HasSuffix(h, ".localhost") {
			return nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("KRYPTKEEPER_HUB_URL must use https:// (plain http is allowed only for loopback hosts)")
	}
	return fmt.Errorf("KRYPTKEEPER_HUB_URL scheme %q is not supported; use https://", u.Scheme)
}

// hubTransport returns an http.Transport pinned to TLS 1.2+ and, when
// rootCAs is non-nil, to that pool instead of the system roots. Returning
// nil (rootCAs == nil) leaves http.Client to use http.DefaultTransport,
// matching pre-W19-32 behaviour exactly for the common case.
func hubTransport(rootCAs *x509.CertPool) http.RoundTripper {
	if rootCAs == nil {
		return nil
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
	}
}

// HubCACertPoolFromEnv builds the trust pool the agent uses for every
// connection to the Hub (registration, heartbeat, inventory, tasks, renewal
// results, and the ACME renewer) from KRYPTKEEPER_HUB_CA_CERT (inline PEM) or
// KRYPTKEEPER_HUB_CA_CERT_FILE (path) -- mirroring the vocabulary
// internal/agentdiscovery's WinRMRootCAsFromEnv and internal/certmanager's
// CACertPEMFromEnv already use for the same problem against other trust
// boundaries. Returns (nil, nil) when neither is set, meaning "verify
// against the system roots" (unchanged pre-W19-32 behaviour for hubs with a
// publicly-trusted certificate).
//
// There is deliberately no KRYPTKEEPER_HUB_TLS_SKIP_VERIFY or similar: an
// agent that can be told to skip verification can be pointed at a fake hub
// and made to leak its enrollment token and discovered cert inventory to it.
func HubCACertPoolFromEnv() (*x509.CertPool, error) {
	pemBytes := []byte(os.Getenv("KRYPTKEEPER_HUB_CA_CERT"))
	if f := os.Getenv("KRYPTKEEPER_HUB_CA_CERT_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read hub CA cert file %q: %w", f, err)
		}
		pemBytes = b
	}
	if len(pemBytes) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		// Silently falling back to system roots here would turn a mistyped
		// bundle into a confusing verification failure later, on the first
		// hub call -- fail fast at startup instead (same rule
		// WinRMRootCAsFromEnv already applies).
		return nil, fmt.Errorf("hub CA bundle contains no usable PEM certificate")
	}
	return pool, nil
}

// Register self-registers the agent with the Hub and stores the returned
// credentials on the client for subsequent calls.
func (c *Client) Register(ctx context.Context, name string, agentType AgentType) (*RegisterResponse, error) {
	rr := RegisterRequest{Name: name, Type: agentType, EnrollmentSecret: c.EnrollmentSecret}
	if c.EnrollmentToken != "" {
		rr.EnrollmentToken, rr.EnrollmentSecret = c.EnrollmentToken, ""
	}
	body, err := json.Marshal(rr)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HubURL+"/api/v1/agent/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("register: decode response: %w", err)
	}
	c.AgentID = out.AgentID
	c.Token = out.Token
	return &out, nil
}

// Heartbeat notifies the Hub that this agent is alive.
func (c *Client) Heartbeat(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HubURL+"/api/v1/agent/heartbeat", nil)
	if err != nil {
		return err
	}
	c.setAgentHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// PostInventory reports the agent's discovered certificate inventory and
// installable endpoints to the Hub. Returns the number of certs the Hub accepted.
func (c *Client) PostInventory(ctx context.Context, certs []DiscoveredCert, endpoints []Endpoint) (int, error) {
	return c.PostInventoryHost(ctx, certs, endpoints, nil)
}

// PostInventoryHost is PostInventory plus the W34-09 host pass: unreadable
// paths, file ownership and listeners, flattened into the same push so the hub
// can compute posture. A nil host sends the pre-W34 shape.
func (c *Client) PostInventoryHost(ctx context.Context, certs []DiscoveredCert, endpoints []Endpoint, host *HostInventory) (int, error) {
	payload := map[string]any{"certs": certs, "endpoints": endpoints}
	if host != nil {
		payload["host_scanned"] = host.Scanned
		payload["privilege_mode"] = host.PrivilegeMode
		payload["scan_user"] = host.User
		payload["unreadable_paths"] = host.UnreadablePaths
		payload["unreadable_total"] = host.UnreadableTotal
		payload["files"] = host.Files
		payload["listeners"] = host.Listeners
		payload["config_refs"] = host.ConfigRefs
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HubURL+"/api/v1/agent/inventory", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAgentHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post inventory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("post inventory: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out struct {
		Accepted int `json:"accepted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("post inventory: decode response: %w", err)
	}
	return out.Accepted, nil
}

// GetTasks fetches pending renewal tasks assigned to this agent by the Hub.
func (c *Client) GetTasks(ctx context.Context) ([]RenewalTask, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.HubURL+"/api/v1/agent/tasks", nil)
	if err != nil {
		return nil, err
	}
	c.setAgentHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get tasks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get tasks: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out struct {
		Tasks []RenewalTask `json:"tasks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("get tasks: decode response: %w", err)
	}
	return out.Tasks, nil
}

// PostRenewalResult reports the outcome of acting on a renewal task to the Hub.
func (c *Client) PostRenewalResult(ctx context.Context, result RenewalResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HubURL+"/api/v1/agent/renewal-result", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAgentHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("post renewal result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("post renewal result: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *Client) setAgentHeaders(req *http.Request) {
	req.Header.Set("X-Agent-ID", c.AgentID)
	req.Header.Set("X-Agent-Token", c.Token)
	if c.Version != "" {
		req.Header.Set("X-Agent-Version", c.Version)
	}
}

// GetTrustTasks fetches the trust-store bundles queued for this agent (W40-03).
func (c *Client) GetTrustTasks(ctx context.Context) ([]TrustTask, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.HubURL+"/api/v1/agent/trust-tasks", nil)
	if err != nil {
		return nil, err
	}
	c.setAgentHeaders(req)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get trust tasks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("get trust tasks: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Tasks []TrustTask `json:"tasks"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("get trust tasks: decode response: %w", err)
	}
	return out.Tasks, nil
}

// PostTrustResult reports what the agent did with one trust bundle.
func (c *Client) PostTrustResult(ctx context.Context, result TrustResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HubURL+"/api/v1/agent/trust-result", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAgentHeaders(req)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("post trust result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("post trust result: hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
