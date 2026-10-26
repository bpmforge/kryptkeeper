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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"kryptkeeper/internal/egress"
)

// W36-04: HashiCorp Vault PKI secrets engine as an upstream issuer.
// API reference: https://developer.hashicorp.com/vault/api-docs/secret/pki
// (sign, revoke, list/read certificate), /system/health and
// /auth/approle (login). Request shapes here follow those pages exactly;
// the real-container proof is W36-16.

// VaultPKIConfig locates and authenticates a Vault PKI mount. Exactly one of
// Token or RoleID+SecretID is used (Token wins when both are set).
type VaultPKIConfig struct {
	// BaseURL is the Vault address, e.g. https://vault.example:8200.
	BaseURL string
	// Namespace is sent as X-Vault-Namespace on authenticated calls
	// (Vault Enterprise / HCP). Optional.
	Namespace string
	// Mount is the PKI engine mount path, default "pki".
	Mount string
	// Role is the PKI role signing requests are made against.
	Role string
	// TTL is the requested lifetime, e.g. "720h". Optional: Vault falls
	// back to the role ttl, and refuses anything above the role max_ttl.
	TTL string

	// Token authenticates directly (X-Vault-Token).
	Token string
	// AppRole login: RoleID+SecretID are exchanged for a client_token that
	// is used for a single call and never cached.
	RoleID       string
	SecretID     string
	AppRoleMount string // default "approle"

	// CACertPEM pins a private Vault CA. The hub builds the egress client
	// from it via TLSMaterial; the connector never touches the transport.
	CACertPEM string
}

// VaultPKIConnector is an IssuerConnector (and RevokingConnector) backed by
// Vault's PKI engine.
type VaultPKIConnector struct {
	id     string
	cfg    VaultPKIConfig
	client *http.Client

	mu        sync.Mutex
	lastError string
}

func NewVaultPKIConnector(id string, cfg VaultPKIConfig, client *http.Client) (*VaultPKIConnector, error) {
	if client == nil {
		client = egress.NewClient(egress.Policy{RequireHTTPS: true, MaxRedirects: 0})
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		return nil, errors.New("vault_pki: base_url is required")
	}
	cfg.Mount = strings.Trim(cfg.Mount, "/")
	if cfg.Mount == "" {
		cfg.Mount = "pki"
	}
	cfg.AppRoleMount = strings.Trim(cfg.AppRoleMount, "/")
	if cfg.AppRoleMount == "" {
		cfg.AppRoleMount = "approle"
	}
	if cfg.Token == "" && (cfg.RoleID == "" || cfg.SecretID == "") {
		return nil, errors.New("vault_pki: a token or an AppRole role_id and secret_id is required")
	}
	// The hub builds the client from ca_cert_pem (TLSMaterial); here it is
	// only validated.
	if _, _, err := TLSMaterial("", "", cfg.CACertPEM); err != nil {
		return nil, fmt.Errorf("vault_pki: %w", err)
	}
	return &VaultPKIConnector{id: id, cfg: cfg, client: client}, nil
}

func (c *VaultPKIConnector) ID() string     { return c.id }
func (c *VaultPKIConnector) Type() string   { return "vault_pki" }
func (c *VaultPKIConnector) Origin() string { return "synced" }

func (c *VaultPKIConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// Health probes GET /v1/sys/health, which is unauthenticated and read-only
// (https://developer.hashicorp.com/vault/api-docs/system/health). Status
// codes: 200 active, 429 unsealed standby (a standby forwards writes to the
// active node, so it is still usable and reported healthy with a note),
// 472 DR secondary, 473 performance standby, 474 standby cut off from the
// active node, 501 uninitialized, 503 sealed, 530 removed from cluster. All
// of those except 200/429 are degraded. The call carries no namespace
// header: the docs require the root namespace.
func (c *VaultPKIConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	status, detail := c.probe(ctx)
	switch {
	case status != "healthy" && last != "":
		return Health{Status: "degraded", Detail: detail + "; last issue error: " + last}
	case status != "healthy":
		return Health{Status: "degraded", Detail: detail}
	case last != "":
		return Health{Status: "degraded", Detail: "last issue error: " + last}
	}
	return Health{Status: "healthy", Detail: detail}
}

func (c *VaultPKIConnector) probe(ctx context.Context) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/v1/sys/health", nil)
	if err != nil {
		return "degraded", err.Error()
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "degraded", "vault health: " + err.Error()
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil {
		return "degraded", "vault health: " + err.Error()
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return "healthy", ""
	case http.StatusTooManyRequests:
		return "healthy", "vault node is an unsealed standby"
	case 472:
		return "degraded", "vault node is a disaster-recovery secondary"
	case 473:
		return "degraded", "vault node is a performance standby"
	case 474:
		return "degraded", "vault standby cannot reach the active node"
	case http.StatusNotImplemented:
		return "degraded", "vault is not initialized"
	case http.StatusServiceUnavailable:
		return "degraded", "vault is sealed"
	case 530:
		return "degraded", "vault node was removed from the cluster"
	}
	return "degraded", fmt.Sprintf("vault health: unexpected HTTP %d", resp.StatusCode)
}

// do and clientToken delegate to VaultAPI, which the KV credential source
// shares. AppRole logins are never cached:
// https://developer.hashicorp.com/vault/api-docs/auth/approle
func (c *VaultPKIConnector) do(ctx context.Context, method, path, token string, payload any) ([]byte, error) {
	return c.api().Do(ctx, method, path, token, payload)
}

func (c *VaultPKIConnector) clientToken(ctx context.Context) (string, error) {
	return c.api().ClientToken(ctx)
}

func (c *VaultPKIConnector) api() *VaultAPI {
	return &VaultAPI{Label: "vault_pki", ConnectorID: c.id, BaseURL: c.cfg.BaseURL, Namespace: c.cfg.Namespace,
		Token: c.cfg.Token, RoleID: c.cfg.RoleID, SecretID: c.cfg.SecretID, AppRoleMount: c.cfg.AppRoleMount, Client: c.client}
}

// VaultSerialFromHex converts a bare hex serial ("39dd2e") into Vault's
// colon-separated form ("39:dd:2e"), left-padding to whole bytes. Revoke
// accepts hyphen- or colon-separated hex per the docs; the list endpoint
// returns lower-case colon-separated, so we use that.
func VaultSerialFromHex(serialHex string) (string, error) {
	s := strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(serialHex))
	if s == "" {
		return "", errors.New("empty serial")
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", errors.New("serial is not hexadecimal")
	}
	parts := make([]string, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

// Issue signs the CSR via POST /v1/{mount}/sign/{role}. common_name is
// required by the endpoint; alt_names (DNS + email), ip_sans and uri_sans are
// derived from the CSR so the role's policy sees them and Vault does not
// silently drop SANs.
func (c *VaultPKIConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *VaultPKIConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	if c.cfg.Role == "" {
		return IssueResult{}, fmt.Errorf("vault_pki %s: role is required to issue", c.id)
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("vault_pki %s: CSRPEM is not a PEM certificate request", c.id)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("vault_pki %s: CSR unparseable: %w", c.id, err)
	}

	cn := csr.Subject.CommonName
	if cn == "" && len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0] // Vault requires common_name; a SAN-only CSR borrows its first name
	}
	payload := map[string]any{"csr": req.CSRPEM, "common_name": cn, "format": "pem"}
	if alt := append(append([]string{}, csr.DNSNames...), csr.EmailAddresses...); len(alt) > 0 {
		payload["alt_names"] = strings.Join(alt, ",")
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		payload["ip_sans"] = strings.Join(ips, ",")
	}
	if len(csr.URIs) > 0 {
		uris := make([]string, len(csr.URIs))
		for i, u := range csr.URIs {
			uris[i] = u.String()
		}
		payload["uri_sans"] = strings.Join(uris, ",")
	}
	if c.cfg.TTL != "" {
		payload["ttl"] = c.cfg.TTL
	}

	token, err := c.clientToken(ctx)
	if err != nil {
		return IssueResult{}, err
	}
	raw, err := c.do(ctx, http.MethodPost,
		"/v1/"+c.cfg.Mount+"/sign/"+url.PathEscape(c.cfg.Role), token, payload)
	if err != nil {
		return IssueResult{}, err
	}
	var out struct {
		Data struct {
			Certificate string   `json:"certificate"`
			IssuingCA   string   `json:"issuing_ca"`
			CAChain     []string `json:"ca_chain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return IssueResult{}, fmt.Errorf("vault_pki %s: sign response unparseable: %w", c.id, err)
	}
	leafBlock, _ := pem.Decode([]byte(out.Data.Certificate))
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		return IssueResult{}, fmt.Errorf("vault_pki %s: sign response certificate is not PEM", c.id)
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("vault_pki %s: issued leaf unparseable: %w", c.id, err)
	}

	// Leaf first, then the chain; ca_chain supersedes issuing_ca, which is
	// only its first element. Skip anything that duplicates the leaf.
	chain := out.Data.CAChain
	if len(chain) == 0 && out.Data.IssuingCA != "" {
		chain = []string{out.Data.IssuingCA}
	}
	var bundle strings.Builder
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	for _, p := range chain {
		b, _ := pem.Decode([]byte(p))
		if b == nil || b.Type != "CERTIFICATE" {
			return IssueResult{}, fmt.Errorf("vault_pki %s: ca_chain entry is not PEM", c.id)
		}
		if bytes.Equal(b.Bytes, leaf.Raw) {
			continue
		}
		bundle.Write(pem.EncodeToMemory(b))
	}
	sum := sha256.Sum256(leaf.Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(sum[:]), CertificatePEM: bundle.String()}, nil
}

// Revoke calls POST /v1/{mount}/revoke {serial_number}. Vault's revoke
// endpoint takes no revocation reason (the CRL entry carries none), so
// req.Reason is accepted and deliberately ignored; do not read that as the
// reason having been recorded upstream.
func (c *VaultPKIConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	serial, err := VaultSerialFromHex(req.SerialHex)
	if err != nil {
		return fmt.Errorf("vault_pki %s: revoke: %w", c.id, err)
	}
	token, err := c.clientToken(ctx)
	if err != nil {
		c.recordError(err)
		return err
	}
	_, err = c.do(ctx, http.MethodPost, "/v1/"+c.cfg.Mount+"/revoke", token,
		map[string]string{"serial_number": serial})
	c.recordError(err)
	return err
}

// VaultCertRecord is one stored certificate read back from the mount.
type VaultCertRecord struct {
	Serial  string
	PEM     string
	Revoked bool
}

// ListCertificates enumerates the mount read-only: LIST /v1/{mount}/certs
// (authenticated, data.keys = colon-separated serials; only certs stored by
// this mount) then GET /v1/{mount}/cert/{serial} (data.certificate,
// data.revocation_time, 0 when not revoked).
func (c *VaultPKIConnector) ListCertificates(ctx context.Context) ([]VaultCertRecord, error) {
	token, err := c.clientToken(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, "LIST", "/v1/"+c.cfg.Mount+"/certs", token, nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("vault_pki %s: certs listing unparseable: %w", c.id, err)
	}
	out := make([]VaultCertRecord, 0, len(list.Data.Keys))
	for _, serial := range list.Data.Keys {
		raw, err := c.do(ctx, http.MethodGet, "/v1/"+c.cfg.Mount+"/cert/"+url.PathEscape(serial), token, nil)
		if err != nil {
			return nil, err
		}
		var rd struct {
			Data struct {
				Certificate    string  `json:"certificate"`
				RevocationTime float64 `json:"revocation_time"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &rd); err != nil {
			return nil, fmt.Errorf("vault_pki %s: cert %s unparseable: %w", c.id, serial, err)
		}
		out = append(out, VaultCertRecord{Serial: serial, PEM: rd.Data.Certificate, Revoked: rd.Data.RevocationTime > 0})
	}
	return out, nil
}
