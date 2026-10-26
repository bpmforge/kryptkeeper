// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VaultAPI is the part of a Vault (or OpenBao) client every Kryptkeeper use
// shares: JSON calls with the namespace header, and a client token from a
// static token or an AppRole login that is never cached. The PKI issuer
// connector and the KV v2 credential source (W38-07) both sit on it, so
// there is one place that decides how Vault is called.
// https://developer.hashicorp.com/vault/api-docs/auth/approle
type VaultAPI struct {
	// Label prefixes error messages ("vault_pki", "vault_kv2").
	Label string
	// ConnectorID names the caller in a RateLimitError; empty for non-connectors.
	ConnectorID string
	BaseURL     string
	Namespace   string
	// Token authenticates directly (X-Vault-Token) and wins over AppRole.
	Token        string
	RoleID       string
	SecretID     string
	AppRoleMount string // default "approle"
	// Client must be the hub's egress-guarded client; VaultAPI never builds a
	// transport of its own.
	Client *http.Client
}

// maxVaultBody caps what one Vault response may read into memory.
const maxVaultBody = 8 << 20

// Do performs one JSON call. token == "" sends no X-Vault-Token (login).
// Failures return the raw body alongside the error so a caller can read
// Vault's own `errors` array; the error text carries at most a truncated
// body, which for Vault is its message, never a secret.
func (a *VaultAPI) Do(ctx context.Context, method, path, token string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.BaseURL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if a.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", a.Namespace)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxVaultBody)) // status below carries failure
	if resp.StatusCode == http.StatusTooManyRequests {
		return raw, &RateLimitError{ConnectorID: a.ConnectorID, Reason: "upstream_429",
			RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Err:        fmt.Errorf("%s %s: rate limited (HTTP 429)", a.Label, path)}
	}
	if resp.StatusCode >= 400 {
		return raw, &VaultStatusError{Label: a.Label, Path: path, Status: resp.StatusCode, Body: truncate(raw)}
	}
	return raw, nil
}

// VaultStatusError is a Vault answer of 400 or above.
type VaultStatusError struct {
	Label  string
	Path   string
	Status int
	Body   string
}

func (e *VaultStatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Label, e.Path, e.Status, e.Body)
}

// ClientToken returns the token for one call. AppRole logins are never
// cached: POST /v1/auth/<mount>/login {role_id, secret_id} ->
// auth.client_token.
func (a *VaultAPI) ClientToken(ctx context.Context) (string, error) {
	if a.Token != "" {
		return a.Token, nil
	}
	mount := strings.Trim(a.AppRoleMount, "/")
	if mount == "" {
		mount = "approle"
	}
	raw, err := a.Do(ctx, http.MethodPost, "/v1/auth/"+mount+"/login", "",
		map[string]string{"role_id": a.RoleID, "secret_id": a.SecretID})
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			return "", err
		}
		// Status only: base_url is operator-configured, and a server that reflects
		// the POST body would otherwise put role_id and secret_id into logs and
		// API responses through the error text.
		var se *VaultStatusError
		if errors.As(err, &se) {
			return "", fmt.Errorf("%s %s: approle login failed: HTTP %d", a.Label, a.ConnectorID, se.Status)
		}
		return "", fmt.Errorf("%s %s: approle login failed: %w", a.Label, a.ConnectorID, err)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Auth.ClientToken == "" {
		return "", fmt.Errorf("%s %s: approle login returned no client_token", a.Label, a.ConnectorID)
	}
	return out.Auth.ClientToken, nil
}

// KV2Secret is one version of a KV v2 secret.
type KV2Secret struct {
	// Data is data.data: the secret's key/value pairs, values as Vault stored
	// them (JSON strings, numbers or booleans).
	Data    map[string]any
	Version int
}

// ErrKV2NotFound is a missing secret or version, or a soft-deleted or
// destroyed one: Vault answers 404 for all of them.
var ErrKV2NotFound = errors.New("secret not found (missing path, deleted or destroyed version)")

// ErrKV2Denied is a 403: the token has no read capability on the path.
var ErrKV2Denied = errors.New("permission denied by the secret manager")

// ReadKV2 reads one version of a KV v2 secret: GET /v1/<mount>/data/<path>
// with ?version=N for a pinned version (0 or less reads the latest); the
// response carries data.data and data.metadata.version.
// https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version
// Each path segment is escaped separately so "/" keeps its meaning.
func (a *VaultAPI) ReadKV2(ctx context.Context, mount, secretPath string, version int) (KV2Secret, error) {
	token, err := a.ClientToken(ctx)
	if err != nil {
		return KV2Secret{}, err
	}
	p := "/v1/" + escapeVaultPath(mount) + "/data/" + escapeVaultPath(secretPath)
	if version > 0 {
		p += "?version=" + url.QueryEscape(fmt.Sprint(version))
	}
	raw, err := a.Do(ctx, http.MethodGet, p, token, nil)
	defer wipe(raw)
	if err != nil {
		var se *VaultStatusError
		if errors.As(err, &se) {
			switch se.Status {
			case http.StatusNotFound:
				return KV2Secret{}, ErrKV2NotFound
			case http.StatusForbidden:
				return KV2Secret{}, ErrKV2Denied
			}
			// A failed read never echoes the body; the status is all the
			// caller needs.
			return KV2Secret{}, fmt.Errorf("%s: HTTP %d", a.Label, se.Status)
		}
		return KV2Secret{}, err
	}
	var out struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return KV2Secret{}, fmt.Errorf("%s: response is not a KV v2 read (is the mount KV version 2?)", a.Label)
	}
	if out.Data.Data == nil {
		return KV2Secret{}, fmt.Errorf("%s: response has no data.data (is the mount KV version 2?)", a.Label)
	}
	return KV2Secret{Data: out.Data.Data, Version: out.Data.Metadata.Version}, nil
}

func escapeVaultPath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
