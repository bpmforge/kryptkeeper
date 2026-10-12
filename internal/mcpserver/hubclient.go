// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package mcpserver exposes Kryptkeeper as a Model Context Protocol (MCP) server.
// It is a thin adapter: each MCP tool maps to a Hub REST call carrying the
// caller's token, so the Hub's existing auth, RBAC, audit, and approval gating
// apply unchanged. Write tools (writetools.go) only ever PROPOSE an action via
// /pending-actions — this package holds no mutation logic; a human approves in
// the dashboard.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HubClient performs authenticated GET requests against the Kryptkeeper Hub API.
type HubClient struct {
	BaseURL string // e.g. https://kryptkeeper.example.com
	Token   string // bearer token for the Hub API
	HTTP    *http.Client
}

// NewHubClient returns a HubClient with a sane default timeout.
func NewHubClient(baseURL, token string) *HubClient {
	return &HubClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// get fetches /api/v1<path> with optional query params and returns the raw body.
func (c *HubClient) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	u := c.BaseURL + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hub request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("hub denied the request (HTTP %d) — check the MCP token's role/scope", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hub returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// SelfRole is this token's own resolved identity, as the Hub sees it.
type SelfRole struct {
	Role              string `json:"role"`
	CanApproveActions bool   `json:"can_approve_actions"`
}

// CheckSelfRole queries /api/v1/protected/whoami to learn this token's own
// resolved role and whether it is approver-capable (D-029/R-C1's second
// adopted option, G-58: the Hub already structurally rejects RoleMCPAgent
// from ever approving an action, but nothing stops an operator from instead
// provisioning this token with a genuinely approver-capable role like
// pki-admin by mistake — at that point the propose-only design collapses to
// "discipline"). CanApproveActions is computed Hub-side via the same
// canApproveActions function every approval endpoint enforces, not
// re-derived here from Role alone, so this package never needs to know
// Kryptkeeper's role taxonomy.
func (c *HubClient) CheckSelfRole(ctx context.Context) (SelfRole, error) {
	body, err := c.get(ctx, "/protected/whoami", nil)
	if err != nil {
		return SelfRole{}, err
	}
	var out SelfRole
	if err := json.Unmarshal(body, &out); err != nil {
		return SelfRole{}, fmt.Errorf("decode whoami response: %w", err)
	}
	return out, nil
}

// post sends a JSON body to /api/v1<path> and returns the response body. Used
// only to enqueue proposals on /pending-actions — the MCP server never calls a
// mutation endpoint directly.
func (c *HubClient) post(ctx context.Context, path string, jsonBody []byte) ([]byte, error) {
	u := c.BaseURL + "/api/v1" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hub request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("hub denied the request (HTTP %d) — check the MCP token's role/scope", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hub returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
