// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"kryptkeeper/internal/connectors"
)

// Entrust Certificate Services (ECS) Enterprise API inventory, verified
// against the published 2.1.0 Swagger spec (see internal/connectors/entrust.go):
// base https://api.entrust.net/enterprise/v2, HTTP Basic (API username + API
// key) over mutual TLS, GET /certificates?offset=&limit= for the listing and
// GET /certificates/{trackingId} whose endEntityCert is the leaf PEM.

const entrustDefaultBaseURL = "https://api.entrust.net/enterprise/v2"

type entrustSource struct {
	baseURL, username, apiKey string
	client                    *http.Client
}

// newEntrustSource builds the source. config_json: {base_url, ca_cert_pem}.
// credential_ref payload: {username, api_key, client_cert_pem, client_key_pem}.
func newEntrustSource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL   string `json:"base_url"`
		CACertPEM string `json:"ca_cert_pem"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config falls back to defaults
	if cfg.BaseURL == "" {
		cfg.BaseURL = entrustDefaultBaseURL
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("entrust source requires credential_ref holding {username, api_key, client_cert_pem, client_key_pem} JSON")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("entrust credential %q: %w", credentialRef, err)
	}
	defer zeroize(raw)
	var c struct {
		Username      string `json:"username"`
		APIKey        string `json:"api_key"`
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Username == "" || c.APIKey == "" || c.ClientCertPEM == "" || c.ClientKeyPEM == "" {
		return nil, errors.New("entrust credential must be {username, api_key, client_cert_pem, client_key_pem} JSON")
	}
	certs, roots, err := connectors.TLSMaterial(c.ClientCertPEM, c.ClientKeyPEM, cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("entrust credential/config: %w", err)
	}
	return &entrustSource{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"), username: c.Username, apiKey: c.APIKey,
		client: upstreamConnectorMTLSClient(commercialHTTPTimeout, true, certs, roots),
	}, nil
}

func (s *entrustSource) headers(req *http.Request) {
	req.SetBasicAuth(s.username, s.apiKey)
}

func (s *entrustSource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	var out []SyncedCertificate
	const page = 200
	for offset := 0; ; offset += page {
		body, err := commercialGet(ctx, s.client,
			fmt.Sprintf("%s/certificates?offset=%d&limit=%d", s.baseURL, offset, page), s.headers)
		if err != nil {
			return nil, err
		}
		var listing struct {
			Certificates []struct {
				TrackingID int    `json:"trackingId"`
				Status     string `json:"status"`
			} `json:"certificates"`
		}
		if err := json.Unmarshal(body, &listing); err != nil {
			return nil, fmt.Errorf("entrust listing unparseable: %w", err)
		}
		for _, item := range listing.Certificates {
			var status string
			switch strings.ToUpper(item.Status) {
			case "ACTIVE":
				status = "active"
			case "REVOKED":
				status = "revoked"
			default:
				continue
			}
			body, err := commercialGet(ctx, s.client,
				fmt.Sprintf("%s/certificates/%d", s.baseURL, item.TrackingID), s.headers)
			if err != nil {
				continue
			}
			var detail struct {
				EndEntityCert string `json:"endEntityCert"`
			}
			if err := json.Unmarshal(body, &detail); err != nil || detail.EndEntityCert == "" {
				continue
			}
			out = append(out, SyncedCertificate{PEM: detail.EndEntityCert, UpstreamStatus: status})
		}
		if len(listing.Certificates) < page {
			return out, nil
		}
	}
}
