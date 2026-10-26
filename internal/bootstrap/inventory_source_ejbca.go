// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"kryptkeeper/internal/connectors"
)

// W36-05: read-only EJBCA inventory source. Reference:
// https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface
// (POST v1/certificate/search: max_number_of_results plus criteria of
// property/value/operation; STATUS=CERT_ACTIVE selects live certificates;
// the v1 response carries certificates[] and more_results).
// Not registered in inventory_source.go yet; a later ticket wires all types.

// defaultEJBCASearchLimit stays at EJBCA's default maximum query count (500)
// because the v1 search has no paging: a larger ask can be rejected.
const defaultEJBCASearchLimit = 500

type ejbcaSource struct {
	baseURL string
	limit   int
	client  *http.Client
}

// newEJBCASource reads config_json {base_url, ca_cert_pem?, max_results?}
// and a credential payload {client_cert_pem, client_key_pem}.
func newEJBCASource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL    string `json:"base_url"`
		CACertPEM  string `json:"ca_cert_pem"`
		MaxResults int    `json:"max_results"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config caught by the checks below
	if cfg.BaseURL == "" {
		return nil, errors.New("ejbca source requires config_json.base_url")
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("ejbca source requires credential_ref holding {client_cert_pem, client_key_pem} JSON")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("ejbca credential %q: %w", credentialRef, err)
	}
	var c struct {
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.ClientCertPEM == "" || c.ClientKeyPEM == "" {
		return nil, errors.New("ejbca credential must be {client_cert_pem, client_key_pem} JSON")
	}
	certs, roots, err := connectors.TLSMaterial(c.ClientCertPEM, c.ClientKeyPEM, cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("ejbca credential/config: %w", err)
	}
	limit := cfg.MaxResults
	if limit <= 0 {
		limit = defaultEJBCASearchLimit
	}
	return &ejbcaSource{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		limit:   limit,
		client:  upstreamConnectorMTLSClient(commercialHTTPTimeout, true, certs, roots),
	}, nil
}

func (s *ejbcaSource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	payload, err := json.Marshal(map[string]any{
		"max_number_of_results": s.limit,
		"criteria": []map[string]string{
			{"property": "STATUS", "value": "CERT_ACTIVE", "operation": "EQUAL"},
		},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/certificate/search", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ejbca search returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 300)])))
	}
	var listing struct {
		Certificates []struct {
			Certificate string `json:"certificate"`
			Base64Cert  string `json:"base64Cert"` // v2 search spelling, tolerated
		} `json:"certificates"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		return nil, fmt.Errorf("ejbca search unparseable: %w", err)
	}
	var out []SyncedCertificate
	for _, item := range listing.Certificates {
		enc := item.Certificate
		if enc == "" {
			enc = item.Base64Cert
		}
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
		if err != nil {
			continue // per-item failure never sinks the batch
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			continue
		}
		out = append(out, SyncedCertificate{
			PEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			UpstreamStatus: "active",
		})
	}
	return out, nil
}
