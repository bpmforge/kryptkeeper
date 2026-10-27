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
	"net/url"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/connectors"
)

// W27-35: hub wiring for the DigiCert, SCEP, EST and WSTEP upstream
// connector types. The clients in internal/connectors take their secret in
// their config struct, so each call here resolves credential_ref, builds a
// fresh client on the egress-policy HTTP client, delegates, and lets the
// secret go out of scope — it is never held on the adapter between calls.

var upstreamConnectorTypes = map[string]bool{
	"digicert": true, "scep": true, "est": true, "wstep": true,
	"vault_pki": true, "ejbca": true, "aws_pca": true, "gcp_cas": true,
	"sectigo": true, "globalsign": true, "entrust": true,
}

// forbiddenUpstreamConfigKeys may not appear at any depth of config_json:
// that column is unencrypted and echoed by the list API.
var forbiddenUpstreamConfigKeys = map[string]bool{
	"api_key": true, "password": true, "secret": true, "token": true,
	"secret_id": true, "secret_access_key": true, "session_token": true,
	"service_account_json": true, "client_key_pem": true, "api_secret": true,
}

var errUpstreamCredentialRequired = errors.New("connector credential_ref is required for this connector type")

// upstreamConnectorConfig is the non-secret config_json. cert_type is a
// number for sectigo and a string for entrust, so it stays raw until the type
// is known.
type upstreamConnectorConfig struct {
	// digicert
	BaseURL        string `json:"base_url"`
	OrganizationID int    `json:"organization_id"`
	ProductNameID  string `json:"product_name_id"`
	ValidityYears  int    `json:"validity_years"`
	// scep, wstep, aws_pca (endpoint override)
	EndpointURL string `json:"endpoint_url"`
	// est, wstep
	Username     string `json:"username"`
	TemplateName string `json:"template_name"`
	// every type that can pin a private server root
	CACertPEM string `json:"ca_cert_pem"`
	// vault_pki
	Namespace    string `json:"namespace"`
	Mount        string `json:"mount"`
	Role         string `json:"role"`
	TTL          string `json:"ttl"`
	AppRoleMount string `json:"approle_mount"`
	// ejbca
	CertificateProfileName   string `json:"certificate_profile_name"`
	EndEntityProfileName     string `json:"end_entity_profile_name"`
	CertificateAuthorityName string `json:"certificate_authority_name"`
	UsernamePrefix           string `json:"username_prefix"`
	// aws_pca
	CertificateAuthorityARN string `json:"certificate_authority_arn"`
	Region                  string `json:"region"`
	SigningAlgorithm        string `json:"signing_algorithm"`
	TemplateARN             string `json:"template_arn"`
	// aws_pca, gcp_cas: "" (static credential) or "ambient"
	Auth string `json:"auth"`
	// gcp_cas
	Project                string `json:"project"`
	Location               string `json:"location"`
	CAPool                 string `json:"ca_pool"`
	CertificateAuthorityID string `json:"certificate_authority_id"`
	CertificateTemplate    string `json:"certificate_template"`
	LifetimeDays           int    `json:"lifetime_days"`
	// sectigo
	CustomerURI string `json:"customer_uri"`
	OrgID       int    `json:"org_id"`
	TermDays    int    `json:"term_days"`
	// sectigo (number) / entrust (string)
	CertType json.RawMessage `json:"cert_type"`
	// aws_pca, globalsign, entrust
	ValidityDays int `json:"validity_days"`
	// globalsign
	LookbackDays int `json:"lookback_days"`
	// entrust
	ClientID       int    `json:"client_id"`
	CertLifetime   string `json:"cert_lifetime"`
	RequesterName  string `json:"requester_name"`
	RequesterEmail string `json:"requester_email"`
	RequesterPhone string `json:"requester_phone"`
}

// upstreamCredentialPayload is the plaintext of credential_ref. Per type:
// digicert {api_key}; est/wstep {password}; vault_pki {token} or {role_id,
// secret_id}; ejbca {client_cert_pem, client_key_pem}; aws_pca static
// {access_key_id, secret_access_key[, session_token]}; gcp_cas
// {service_account_json}; sectigo {login, password} or the client pair;
// globalsign {api_key, api_secret[, client pair]}; entrust {username,
// api_key, client pair}.
type upstreamCredentialPayload struct {
	APIKey             string `json:"api_key"`
	Password           string `json:"password"`
	Token              string `json:"token"`
	RoleID             string `json:"role_id"`
	SecretID           string `json:"secret_id"`
	ClientCertPEM      string `json:"client_cert_pem"`
	ClientKeyPEM       string `json:"client_key_pem"`
	AccessKeyID        string `json:"access_key_id"`
	SecretAccessKey    string `json:"secret_access_key"`
	SessionToken       string `json:"session_token"`
	ServiceAccountJSON string `json:"service_account_json"`
	Login              string `json:"login"`
	APISecret          string `json:"api_secret"`
	Username           string `json:"username"`
}

const gcpCASDefaultBaseURL = "https://privateca.googleapis.com"

func upstreamAmbient(connType string, cfg upstreamConnectorConfig) bool {
	return (connType == "aws_pca" || connType == "gcp_cas") && cfg.Auth == "ambient"
}

func upstreamNeedsCredential(connType string, cfg upstreamConnectorConfig) bool {
	return connType != "scep" && !upstreamAmbient(connType, cfg)
}

// upstreamCanRevoke is the types whose upstream has a revoke verb.
func upstreamCanRevoke(connType string) bool {
	switch connType {
	case "scep", "est", "wstep":
		return false
	}
	return upstreamConnectorTypes[connType]
}

// upstreamSecretMissing names the first missing secret field for the type, or "".
func upstreamSecretMissing(connType string, cfg upstreamConnectorConfig, p upstreamCredentialPayload) string {
	pair := p.ClientCertPEM != "" && p.ClientKeyPEM != ""
	switch connType {
	case "digicert":
		if p.APIKey == "" {
			return "api_key"
		}
	case "est", "wstep":
		if p.Password == "" {
			return "password"
		}
	case "vault_pki":
		if p.Token == "" && (p.RoleID == "" || p.SecretID == "") {
			return "token or role_id+secret_id"
		}
	case "ejbca":
		if !pair {
			return "client_cert_pem+client_key_pem"
		}
	case "aws_pca":
		if !upstreamAmbient(connType, cfg) && (p.AccessKeyID == "" || p.SecretAccessKey == "") {
			return "access_key_id+secret_access_key"
		}
	case "gcp_cas":
		if !upstreamAmbient(connType, cfg) && p.ServiceAccountJSON == "" {
			return "service_account_json"
		}
	case "sectigo":
		if !pair && (p.Login == "" || p.Password == "") {
			return "login+password or client_cert_pem+client_key_pem"
		}
	case "globalsign":
		if p.APIKey == "" || p.APISecret == "" {
			return "api_key+api_secret"
		}
	case "entrust":
		if p.Username == "" || p.APIKey == "" || !pair {
			return "username+api_key+client_cert_pem+client_key_pem"
		}
	}
	return ""
}

// certTypeInt/certTypeString read the raw cert_type for sectigo/entrust.
func (c upstreamConnectorConfig) certTypeInt() (int, bool) {
	var n int
	if len(c.CertType) == 0 || json.Unmarshal(c.CertType, &n) != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func (c upstreamConnectorConfig) certTypeString() (string, bool) {
	var s string
	if len(c.CertType) == 0 {
		return "", true
	}
	if json.Unmarshal(c.CertType, &s) != nil {
		return "", false
	}
	return s, true
}

func containsForbiddenKey(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if forbiddenUpstreamConfigKeys[strings.ToLower(k)] || containsForbiddenKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if containsForbiddenKey(child) {
				return true
			}
		}
	}
	return false
}

func upstreamConfigInvalid(field string) error {
	return fmt.Errorf("connector config invalid: %s", field)
}

func validUpstreamURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// validateUpstreamConnector checks a digicert/scep/est/wstep create. Errors
// never echo config values (a misplaced secret must not come back in a 400).
func validateUpstreamConnector(rec ConnectorRecord) error {
	if strings.TrimSpace(rec.ConfigJSON) == "" {
		rec.ConfigJSON = "{}"
	}
	var generic any
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &generic); err != nil {
		return upstreamConfigInvalid("config_json")
	}
	if containsForbiddenKey(generic) {
		return errors.New("credentials belong in credential_ref, not config_json")
	}
	var cfg upstreamConnectorConfig
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
		return upstreamConfigInvalid("config_json")
	}
	switch rec.Type {
	case "digicert":
		if cfg.OrganizationID <= 0 {
			return upstreamConfigInvalid("organization_id")
		}
	case "scep":
		if !validUpstreamURL(cfg.EndpointURL) {
			return upstreamConfigInvalid("endpoint_url")
		}
	case "est":
		if !validUpstreamURL(cfg.BaseURL) {
			return upstreamConfigInvalid("base_url")
		}
		if strings.TrimSpace(cfg.Username) == "" {
			return upstreamConfigInvalid("username")
		}
	case "wstep":
		if !validUpstreamURL(cfg.EndpointURL) {
			return upstreamConfigInvalid("endpoint_url")
		}
		if strings.TrimSpace(cfg.Username) == "" {
			return upstreamConfigInvalid("username")
		}
		if strings.TrimSpace(cfg.TemplateName) == "" {
			return upstreamConfigInvalid("template_name")
		}
	}
	if err := validateUpstreamTypeConfig(rec.Type, cfg); err != nil {
		return err
	}
	if cfg.BaseURL != "" && !validUpstreamURL(cfg.BaseURL) {
		return upstreamConfigInvalid("base_url")
	}
	if cfg.CACertPEM != "" {
		if _, _, err := connectors.TLSMaterial("", "", cfg.CACertPEM); err != nil {
			return upstreamConfigInvalid("ca_cert_pem")
		}
	}
	if upstreamNeedsCredential(rec.Type, cfg) && strings.TrimSpace(rec.CredentialRef) == "" {
		return errUpstreamCredentialRequired
	}
	return nil
}

// validateUpstreamTypeConfig checks the required config fields of the
// vendor CA types; the legacy four are checked inline in validateUpstreamConnector.
func validateUpstreamTypeConfig(connType string, cfg upstreamConnectorConfig) error {
	required := func(fields ...[2]string) error {
		for _, f := range fields {
			if strings.TrimSpace(f[1]) == "" {
				return upstreamConfigInvalid(f[0])
			}
		}
		return nil
	}
	switch connType {
	case "vault_pki":
		if !validUpstreamURL(cfg.BaseURL) {
			return upstreamConfigInvalid("base_url")
		}
		return required([2]string{"role", cfg.Role})
	case "ejbca":
		if !validUpstreamURL(cfg.BaseURL) {
			return upstreamConfigInvalid("base_url")
		}
		return required(
			[2]string{"certificate_profile_name", cfg.CertificateProfileName},
			[2]string{"end_entity_profile_name", cfg.EndEntityProfileName},
			[2]string{"certificate_authority_name", cfg.CertificateAuthorityName})
	case "aws_pca":
		if cfg.Auth != "" && cfg.Auth != "ambient" && cfg.Auth != "static" {
			return upstreamConfigInvalid("auth")
		}
		if cfg.EndpointURL != "" && !validUpstreamURL(cfg.EndpointURL) {
			return upstreamConfigInvalid("endpoint_url")
		}
		// C-01: ambient auth signs with the hub's own IAM identity; a caller
		// chosen endpoint would receive requests signed by it.
		if cfg.Auth == "ambient" && cfg.EndpointURL != "" {
			return errors.New("aws_pca ambient auth cannot set endpoint_url")
		}
		return required([2]string{"certificate_authority_arn", cfg.CertificateAuthorityARN}, [2]string{"region", cfg.Region})
	case "gcp_cas":
		if cfg.Auth != "" && cfg.Auth != "ambient" && cfg.Auth != "service_account" {
			return upstreamConfigInvalid("auth")
		}
		// C-01: ambient auth sends the hub's metadata-server token as Bearer
		// to base_url, so it may only point at the real Private CA API.
		if cfg.Auth == "ambient" && cfg.BaseURL != "" && strings.TrimSuffix(cfg.BaseURL, "/") != gcpCASDefaultBaseURL {
			return errors.New("gcp_cas ambient auth requires base_url to be empty or " + gcpCASDefaultBaseURL)
		}
		return required([2]string{"project", cfg.Project}, [2]string{"location", cfg.Location}, [2]string{"ca_pool", cfg.CAPool})
	case "sectigo":
		if err := required([2]string{"customer_uri", cfg.CustomerURI}); err != nil {
			return err
		}
		if cfg.OrgID <= 0 {
			return upstreamConfigInvalid("org_id")
		}
		if _, ok := cfg.certTypeInt(); !ok {
			return upstreamConfigInvalid("cert_type")
		}
		if cfg.TermDays <= 0 {
			return upstreamConfigInvalid("term_days")
		}
	case "entrust":
		if _, ok := cfg.certTypeString(); !ok {
			return upstreamConfigInvalid("cert_type")
		}
		return required(
			[2]string{"requester_name", cfg.RequesterName},
			[2]string{"requester_email", cfg.RequesterEmail},
			[2]string{"requester_phone", cfg.RequesterPhone})
	}
	return nil
}

type upstreamConnector struct {
	id      string
	connTyp string
	cfg     upstreamConnectorConfig
	credRef string
	creds   OutboundCredentialStore

	// The inner clients keep their last DigiCert error in memory; a fresh
	// client per call would forget it, so the adapter carries it for Health.
	mu        sync.Mutex
	lastError string
}

var _ connectors.IssuerConnector = (*upstreamConnector)(nil)

// NewUpstreamIssuerConnector builds the lazy adapter for a stored
// digicert/scep/est/wstep row. Malformed config zeroes out and the connector
// then fails clearly on use (same as the acme type).
func NewUpstreamIssuerConnector(rec ConnectorRecord, creds OutboundCredentialStore) connectors.IssuerConnector {
	var cfg upstreamConnectorConfig
	_ = json.Unmarshal([]byte(rec.ConfigJSON), &cfg) // malformed config zeroes out; validated at create
	return &upstreamConnector{id: rec.ID, connTyp: rec.Type, cfg: cfg, credRef: rec.CredentialRef, creds: creds}
}

func (c *upstreamConnector) ID() string     { return c.id }
func (c *upstreamConnector) Type() string   { return c.connTyp }
func (c *upstreamConnector) Origin() string { return "synced" }

func (c *upstreamConnector) credential(ctx context.Context) (upstreamCredentialPayload, error) {
	var payload upstreamCredentialPayload
	if !upstreamNeedsCredential(c.connTyp, c.cfg) {
		return payload, nil
	}
	if c.credRef == "" || c.creds == nil {
		return payload, errUpstreamCredentialRequired
	}
	plaintext, err := c.creds.Resolve(ctx, c.credRef)
	if err != nil {
		return payload, fmt.Errorf("%s connector credential %q: %w", c.connTyp, c.credRef, err)
	}
	defer zeroize(plaintext)
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return payload, fmt.Errorf("%s connector credential payload is not the documented JSON shape", c.connTyp)
	}
	if field := upstreamSecretMissing(c.connTyp, c.cfg, payload); field != "" {
		return payload, fmt.Errorf("%s connector credential payload is missing %s", c.connTyp, field)
	}
	return payload, nil
}

// httpClient is the egress-guarded client for the type: the mTLS variant
// carries the client pair and private root, built from the PEMs the payload
// and config hold.
func (c *upstreamConnector) httpClient(p upstreamCredentialPayload) (*http.Client, error) {
	switch c.connTyp {
	case "vault_pki", "ejbca", "sectigo", "globalsign", "entrust":
		certs, roots, err := connectors.TLSMaterial(p.ClientCertPEM, p.ClientKeyPEM, c.cfg.CACertPEM)
		if err != nil {
			return nil, fmt.Errorf("%s connector: %w", c.connTyp, err)
		}
		return upstreamConnectorMTLSClient(30*time.Second, true, certs, roots), nil
	}
	return upstreamConnectorHTTPClient(30*time.Second, c.connTyp != "scep"), nil
}

// inner resolves the credential and builds a one-call client. The egress
// client is built here, not at registry construction, so policy env and the
// test seam are read per call.
func (c *upstreamConnector) inner(ctx context.Context) (connectors.IssuerConnector, error) {
	payload, err := c.credential(ctx)
	if err != nil {
		return nil, err
	}
	client, err := c.httpClient(payload)
	if err != nil {
		return nil, err
	}
	cfg := c.cfg
	switch c.connTyp {
	case "digicert":
		return connectors.NewDigiCertConnector(c.id, connectors.DigiCertConfig{
			BaseURL: cfg.BaseURL, APIKey: payload.APIKey, OrganizationID: cfg.OrganizationID,
			ProductNameID: cfg.ProductNameID, ValidityYears: cfg.ValidityYears,
		}, client), nil
	case "scep":
		return connectors.NewSCEPClient(c.id, connectors.SCEPClientConfig{EndpointURL: cfg.EndpointURL}, client), nil
	case "est":
		return connectors.NewESTClient(c.id, connectors.ESTClientConfig{
			BaseURL: cfg.BaseURL, Username: cfg.Username, Password: payload.Password,
		}, client), nil
	case "wstep":
		return connectors.NewWSTEPClient(c.id, connectors.WSTEPClientConfig{
			EndpointURL: cfg.EndpointURL, Username: cfg.Username, Password: payload.Password,
			TemplateName: cfg.TemplateName,
		}, client), nil
	case "vault_pki":
		return connectors.NewVaultPKIConnector(c.id, connectors.VaultPKIConfig{
			BaseURL: cfg.BaseURL, Namespace: cfg.Namespace, Mount: cfg.Mount, Role: cfg.Role, TTL: cfg.TTL,
			Token: payload.Token, RoleID: payload.RoleID, SecretID: payload.SecretID,
			AppRoleMount: cfg.AppRoleMount, CACertPEM: cfg.CACertPEM,
		}, client)
	case "ejbca":
		return connectors.NewEJBCAConnector(c.id, connectors.EJBCAConfig{
			BaseURL: cfg.BaseURL, CertificateProfileName: cfg.CertificateProfileName,
			EndEntityProfileName: cfg.EndEntityProfileName, CertificateAuthorityName: cfg.CertificateAuthorityName,
			UsernamePrefix: cfg.UsernamePrefix, ClientCertPEM: payload.ClientCertPEM,
			ClientKeyPEM: payload.ClientKeyPEM, CACertPEM: cfg.CACertPEM,
		}, client), nil
	case "aws_pca":
		return connectors.NewAWSPCAConnector(c.id, connectors.AWSPCAConfig{
			CertificateAuthorityARN: cfg.CertificateAuthorityARN, Region: cfg.Region,
			SigningAlgorithm: cfg.SigningAlgorithm, ValidityDays: int64(cfg.ValidityDays),
			TemplateARN: cfg.TemplateARN, EndpointURL: cfg.EndpointURL, Auth: cfg.Auth,
			AccessKeyID: payload.AccessKeyID, SecretAccessKey: payload.SecretAccessKey, SessionToken: payload.SessionToken,
		}, client), nil
	case "gcp_cas":
		gcfg := connectors.GCPCASConfig{
			Project: cfg.Project, Location: cfg.Location, CAPool: cfg.CAPool,
			CertificateAuthorityID: cfg.CertificateAuthorityID, CertificateTemplate: cfg.CertificateTemplate,
			LifetimeDays: cfg.LifetimeDays, BaseURL: cfg.BaseURL, Auth: cfg.Auth,
			ServiceAccountJSON: payload.ServiceAccountJSON,
		}
		if cfg.Auth == "ambient" {
			gcfg.MetadataClient = gcpMetadataHTTPClient()
		}
		return connectors.NewGCPCASConnector(c.id, gcfg, client), nil
	case "sectigo":
		certType, _ := cfg.certTypeInt()
		return connectors.NewSectigoConnector(c.id, connectors.SectigoConfig{
			BaseURL: cfg.BaseURL, CustomerURI: cfg.CustomerURI, OrgID: cfg.OrgID, CertType: certType,
			TermDays: cfg.TermDays, Login: payload.Login, Password: payload.Password,
			ClientCertPEM: payload.ClientCertPEM, ClientKeyPEM: payload.ClientKeyPEM, CACertPEM: cfg.CACertPEM,
		}, client), nil
	case "globalsign":
		return connectors.NewGlobalSignConnector(c.id, connectors.GlobalSignConfig{
			BaseURL: cfg.BaseURL, APIKey: payload.APIKey, APISecret: payload.APISecret,
			ClientCertPEM: payload.ClientCertPEM, ClientKeyPEM: payload.ClientKeyPEM, CACertPEM: cfg.CACertPEM,
			ValidityDays: cfg.ValidityDays, LookbackDays: cfg.LookbackDays,
		}, client), nil
	case "entrust":
		certType, _ := cfg.certTypeString()
		return connectors.NewEntrustConnector(c.id, connectors.EntrustConfig{
			BaseURL: cfg.BaseURL, Username: payload.Username, APIKey: payload.APIKey,
			ClientCertPEM: payload.ClientCertPEM, ClientKeyPEM: payload.ClientKeyPEM, CACertPEM: cfg.CACertPEM,
			ClientID: cfg.ClientID, CertType: certType, ValidityDays: cfg.ValidityDays, CertLifetime: cfg.CertLifetime,
			RequesterName: cfg.RequesterName, RequesterEmail: cfg.RequesterEmail, RequesterPhone: cfg.RequesterPhone,
		}, client), nil
	}
	return nil, fmt.Errorf("unsupported upstream connector type %q", c.connTyp)
}

func (c *upstreamConnector) Health(ctx context.Context) connectors.Health {
	in, err := c.inner(ctx)
	if err != nil {
		return connectors.Health{Status: "degraded", Detail: err.Error()}
	}
	h := in.Health(ctx)
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	if h.Status == "healthy" && last != "" {
		return connectors.Health{Status: "degraded", Detail: "last issue error: " + last}
	}
	return h
}

func (c *upstreamConnector) Issue(ctx context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	in, err := c.inner(ctx)
	if err != nil {
		c.recordError(err)
		return connectors.IssueResult{}, err
	}
	res, err := in.Issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *upstreamConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

var _ connectors.RevokingConnector = (*upstreamConnector)(nil)

// CanRevoke is per type: the adapter always has a Revoke method, but SCEP,
// EST and WSTEP have no upstream revoke verb.
func (c *upstreamConnector) CanRevoke() bool { return upstreamCanRevoke(c.connTyp) }

// Revoke builds the inner connector and delegates when it can revoke.
func (c *upstreamConnector) Revoke(ctx context.Context, req connectors.RevokeRequest) error {
	if !c.CanRevoke() {
		return connectors.ErrRevokeUnsupported
	}
	in, err := c.inner(ctx)
	if err != nil {
		return err
	}
	rc, ok := in.(connectors.RevokingConnector)
	if !ok {
		return connectors.ErrRevokeUnsupported
	}
	err = rc.Revoke(ctx, req)
	c.recordError(err)
	return err
}
