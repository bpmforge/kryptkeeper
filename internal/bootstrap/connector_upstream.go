// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

var upstreamConnectorTypes = map[string]bool{"digicert": true, "scep": true, "est": true, "wstep": true}

// forbiddenUpstreamConfigKeys may not appear at any depth of config_json:
// that column is unencrypted and echoed by the list API.
var forbiddenUpstreamConfigKeys = map[string]bool{"api_key": true, "password": true, "secret": true, "token": true}

var errUpstreamCredentialRequired = errors.New("connector credential_ref is required for this connector type")

type upstreamConnectorConfig struct {
	// digicert
	BaseURL        string `json:"base_url"`
	OrganizationID int    `json:"organization_id"`
	ProductNameID  string `json:"product_name_id"`
	ValidityYears  int    `json:"validity_years"`
	// scep, wstep
	EndpointURL string `json:"endpoint_url"`
	// est, wstep
	Username     string `json:"username"`
	TemplateName string `json:"template_name"`
}

// upstreamCredentialPayload is the plaintext of credential_ref: digicert
// {"api_key"}, est/wstep {"password"}.
type upstreamCredentialPayload struct {
	APIKey   string `json:"api_key"`
	Password string `json:"password"`
}

func upstreamNeedsCredential(connType string) bool { return connType != "scep" }

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
		if cfg.BaseURL != "" && !validUpstreamURL(cfg.BaseURL) {
			return upstreamConfigInvalid("base_url")
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
	if upstreamNeedsCredential(rec.Type) && strings.TrimSpace(rec.CredentialRef) == "" {
		return errUpstreamCredentialRequired
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
	if !upstreamNeedsCredential(c.connTyp) {
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
	secret := payload.Password
	if c.connTyp == "digicert" {
		secret = payload.APIKey
	}
	if secret == "" {
		return payload, fmt.Errorf("%s connector credential payload is missing its secret field", c.connTyp)
	}
	return payload, nil
}

// inner resolves the credential and builds a one-call client. The egress
// client is built here, not at registry construction, so policy env and the
// test seam are read per call.
func (c *upstreamConnector) inner(ctx context.Context) (connectors.IssuerConnector, error) {
	payload, err := c.credential(ctx)
	if err != nil {
		return nil, err
	}
	client := upstreamConnectorHTTPClient(30*time.Second, c.connTyp != "scep")
	switch c.connTyp {
	case "digicert":
		return connectors.NewDigiCertConnector(c.id, connectors.DigiCertConfig{
			BaseURL: c.cfg.BaseURL, APIKey: payload.APIKey, OrganizationID: c.cfg.OrganizationID,
			ProductNameID: c.cfg.ProductNameID, ValidityYears: c.cfg.ValidityYears,
		}, client), nil
	case "scep":
		return connectors.NewSCEPClient(c.id, connectors.SCEPClientConfig{EndpointURL: c.cfg.EndpointURL}, client), nil
	case "est":
		return connectors.NewESTClient(c.id, connectors.ESTClientConfig{
			BaseURL: c.cfg.BaseURL, Username: c.cfg.Username, Password: payload.Password,
		}, client), nil
	case "wstep":
		return connectors.NewWSTEPClient(c.id, connectors.WSTEPClientConfig{
			EndpointURL: c.cfg.EndpointURL, Username: c.cfg.Username, Password: payload.Password,
			TemplateName: c.cfg.TemplateName,
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
