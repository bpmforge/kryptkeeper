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
	neturl "net/url"
	"strings"
)

// GCPKMSSource inventories Google Cloud KMS crypto keys over REST with
// a bearer token. BaseURL configurable for fixtures.
type GCPKMSSource struct {
	baseURL string // e.g. https://cloudkms.googleapis.com
	keyRing string // projects/{p}/locations/{l}/keyRings/{r}
	token   string
	client  *http.Client
}

func NewGCPKMSSource(baseURL, keyRing, token string, client *http.Client) *GCPKMSSource {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://cloudkms.googleapis.com"
	}
	return &GCPKMSSource{baseURL: strings.TrimRight(baseURL, "/"), keyRing: keyRing, token: token, client: client}
}

func (s *GCPKMSSource) Provider() string { return "gcp-kms" }

func (s *GCPKMSSource) ListKeys(ctx context.Context) ([]Key, error) {
	var keys []Key
	pageToken := ""
	for {
		url := fmt.Sprintf("%s/v1/%s/cryptoKeys", s.baseURL, s.keyRing)
		if pageToken != "" {
			url += "?pageToken=" + neturl.QueryEscape(pageToken)
		}
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
			return nil, fmt.Errorf("gcp kms keys: HTTP %d", resp.StatusCode)
		}
		var listing struct {
			CryptoKeys []struct {
				Name            string `json:"name"`
				Purpose         string `json:"purpose"`
				RotationPeriod  string `json:"rotationPeriod"`
				VersionTemplate struct {
					Algorithm string `json:"algorithm"`
				} `json:"versionTemplate"`
			} `json:"cryptoKeys"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &listing); err != nil {
			return nil, fmt.Errorf("gcp kms keys: %w", err)
		}
		for _, ck := range listing.CryptoKeys {
			keys = append(keys, Key{
				Provider: "gcp-kms", Location: s.keyRing, KeyID: ck.Name,
				Algorithm:       ck.VersionTemplate.Algorithm,
				Usage:           ck.Purpose,
				RotationEnabled: ck.RotationPeriod != "",
				PQCReadiness:    scoreKeyPQC(ck.VersionTemplate.Algorithm),
			})
		}
		if listing.NextPageToken == "" {
			return keys, nil
		}
		pageToken = listing.NextPageToken
	}
}
