// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"kryptkeeper/internal/connectors"
)

// W36-09: read-only inventory of a GlobalSign Atlas HVCA account. It reuses
// the connector's ListCertificates (stats listing plus per-serial fetch) so
// request shapes live in one place. Not yet registered in inventory_source.go.

type globalSignSource struct {
	conn *connectors.GlobalSignConnector
}

// newGlobalSignSource builds the source. config_json: {base_url,
// lookback_days, ca_cert_pem}. credential_ref payload: {api_key, api_secret,
// client_cert_pem, client_key_pem} (the client pair is optional).
func newGlobalSignSource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL      string `json:"base_url"`
		LookbackDays int    `json:"lookback_days"`
		CACertPEM    string `json:"ca_cert_pem"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config falls back to defaults
	if credentialRef == "" || creds == nil {
		return nil, errors.New("globalsign source requires credential_ref holding {api_key, api_secret, client_cert_pem, client_key_pem} JSON")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("globalsign credential %q: %w", credentialRef, err)
	}
	var c struct {
		APIKey        string `json:"api_key"`
		APISecret     string `json:"api_secret"`
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.APIKey == "" || c.APISecret == "" {
		return nil, errors.New("globalsign credential must be {api_key, api_secret, client_cert_pem, client_key_pem} JSON")
	}
	certs, roots, err := connectors.TLSMaterial(c.ClientCertPEM, c.ClientKeyPEM, cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("globalsign credential/config: %w", err)
	}
	return &globalSignSource{conn: connectors.NewGlobalSignConnector("globalsign-inventory", connectors.GlobalSignConfig{
		BaseURL: cfg.BaseURL, APIKey: c.APIKey, APISecret: c.APISecret,
		ClientCertPEM: c.ClientCertPEM, ClientKeyPEM: c.ClientKeyPEM,
		CACertPEM: cfg.CACertPEM, LookbackDays: cfg.LookbackDays,
	}, upstreamConnectorMTLSClient(commercialHTTPTimeout, true, certs, roots))}, nil
}

func (s *globalSignSource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
	recs, err := s.conn.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SyncedCertificate, 0, len(recs))
	for _, r := range recs {
		status := "active"
		if r.Revoked {
			status = "revoked"
		}
		out = append(out, SyncedCertificate{PEM: r.PEM, UpstreamStatus: status})
	}
	return out, nil
}
