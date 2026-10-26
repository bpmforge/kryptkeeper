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

// W36-04: read-only inventory of a Vault PKI mount. It reuses the
// vault_pki connector's list/read calls (LIST /v1/{mount}/certs, then
// GET /v1/{mount}/cert/{serial}), so request shapes live in one place. Not
// yet registered in inventory_source.go (a later ticket wires every type).

type vaultPKISource struct {
	conn *connectors.VaultPKIConnector
}

// newVaultPKISource builds the source. config_json: {base_url, namespace,
// mount, approle_mount, ca_cert_pem}. credential_ref payload: either
// {"token":"..."} or {"role_id":"...","secret_id":"..."}.
func newVaultPKISource(ctx context.Context, configJSON, credentialRef string, creds OutboundCredentialStore) (InventorySource, error) {
	var cfg struct {
		BaseURL      string `json:"base_url"`
		Namespace    string `json:"namespace"`
		Mount        string `json:"mount"`
		AppRoleMount string `json:"approle_mount"`
		CACertPEM    string `json:"ca_cert_pem"`
	}
	_ = json.Unmarshal([]byte(configJSON), &cfg) // malformed config caught by the checks below
	if cfg.BaseURL == "" {
		return nil, errors.New("vault_pki source requires config_json.base_url")
	}
	if credentialRef == "" || creds == nil {
		return nil, errors.New("vault_pki source requires credential_ref holding {token} or {role_id, secret_id} JSON")
	}
	raw, err := creds.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("vault_pki credential %q: %w", credentialRef, err)
	}
	var c struct {
		Token    string `json:"token"`
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || (c.Token == "" && (c.RoleID == "" || c.SecretID == "")) {
		return nil, errors.New("vault_pki credential must be {token} or {role_id, secret_id} JSON")
	}
	_, roots, err := connectors.TLSMaterial("", "", cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("vault_pki config: %w", err)
	}
	conn, err := connectors.NewVaultPKIConnector("vault-pki-inventory", connectors.VaultPKIConfig{
		BaseURL: cfg.BaseURL, Namespace: cfg.Namespace, Mount: cfg.Mount, AppRoleMount: cfg.AppRoleMount,
		Token: c.Token, RoleID: c.RoleID, SecretID: c.SecretID,
	}, upstreamConnectorMTLSClient(commercialHTTPTimeout, true, nil, roots))
	if err != nil {
		return nil, err
	}
	return &vaultPKISource{conn: conn}, nil
}

func (s *vaultPKISource) Fetch(ctx context.Context) ([]SyncedCertificate, error) {
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
