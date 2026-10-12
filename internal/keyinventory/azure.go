// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keyinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AzureKeyVaultSource inventories keys in an Azure Key Vault over REST
// with a bearer token (the cloudinventory GCP pattern). BaseURL is
// configurable so fixture servers pin our request shapes.
type AzureKeyVaultSource struct {
	baseURL string // e.g. https://myvault.vault.azure.net
	token   string
	client  *http.Client
}

func NewAzureKeyVaultSource(baseURL, token string, client *http.Client) *AzureKeyVaultSource {
	if client == nil {
		client = http.DefaultClient
	}
	return &AzureKeyVaultSource{baseURL: strings.TrimRight(baseURL, "/"), token: token, client: client}
}

func (s *AzureKeyVaultSource) Provider() string { return "azure-kv" }

func (s *AzureKeyVaultSource) ListKeys(ctx context.Context) ([]Key, error) {
	var keys []Key
	// Azure KV "Get Keys" is paginated (default page 25) via nextLink —
	// a single page silently drops the rest of a large vault, which
	// would undercount the PQC-vulnerable key inventory this feeds.
	url := s.baseURL + "/keys?api-version=7.4"
	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+s.token)
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("azure kv keys: HTTP %d", resp.StatusCode)
		}
		var listing struct {
			Value []struct {
				Kid        string `json:"kid"`
				Attributes struct {
					Enabled bool  `json:"enabled"`
					Created int64 `json:"created"`
				} `json:"attributes"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &listing); err != nil {
			return nil, fmt.Errorf("azure kv keys: %w", err)
		}
		for _, item := range listing.Value {
			// Key details (kty/crv) require a per-key GET; the list gives
			// the kid and enabled state.
			alg := s.keyAlgorithm(ctx, item.Kid)
			state := "disabled"
			if item.Attributes.Enabled {
				state = "enabled"
			}
			keys = append(keys, Key{
				Provider: "azure-kv", Location: s.baseURL, KeyID: item.Kid,
				Algorithm: alg, State: state, PQCReadiness: scoreKeyPQC(alg),
			})
		}
		url = listing.NextLink // nextLink is a full URL (api-version included), "" ends the walk
	}
	return keys, nil
}

// keyAlgorithm fetches a key's kty/crv. Failure yields "" (unknown).
func (s *AzureKeyVaultSource) keyAlgorithm(ctx context.Context, kid string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kid+"?api-version=7.4", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var detail struct {
		Key struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			N   string `json:"n"`
		} `json:"key"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		return ""
	}
	if detail.Key.Crv != "" {
		return detail.Key.Kty + "-" + detail.Key.Crv // e.g. EC-P-256
	}
	return detail.Key.Kty // e.g. RSA
}
