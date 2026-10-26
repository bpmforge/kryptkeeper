// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	"time"

	"kryptkeeper/internal/egress"
)

// W36-05: EJBCA (Keyfactor) REST issuer. Reference:
// https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface
// and the generated model docs at
// https://github.com/Keyfactor/ejbca-java-client-sdk/tree/main/docs
// The REST API authenticates with the same client certificate as the
// Admin GUI, so the mTLS pair rides in the config (resolved by the caller
// from the outbound credential store; it signs nothing a relying party trusts).

// EJBCAConfig locates and authenticates an EJBCA REST endpoint.
type EJBCAConfig struct {
	// BaseURL is the REST root, default https://localhost:8443/ejbca/ejbca-rest-api.
	BaseURL                  string
	CertificateProfileName   string
	EndEntityProfileName     string
	CertificateAuthorityName string
	// UsernamePrefix prefixes the per-request end-entity username
	// (prefix + first 16 hex of sha256(CSR DER)); default "kk-".
	UsernamePrefix string
	// ClientCertPEM/ClientKeyPEM are the mTLS pair; CACertPEM optionally pins
	// the EJBCA server's private TLS root.
	ClientCertPEM string
	ClientKeyPEM  string
	CACertPEM     string
}

// EJBCAConnector is an IssuerConnector (and RevokingConnector) backed by EJBCA.
type EJBCAConnector struct {
	id      string
	cfg     EJBCAConfig
	client  *http.Client
	initErr error

	mu        sync.Mutex
	lastError string
}

// NewEJBCAConnector uses the supplied (egress-guarded, mTLS-carrying) client
// as is. A bad PEM is held
// and surfaced by every call rather than failing construction, so a
// misconfigured connector still lists (degraded) instead of vanishing.
func NewEJBCAConnector(id string, cfg EJBCAConfig, client *http.Client) *EJBCAConnector {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://localhost:8443/ejbca/ejbca-rest-api"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = "kk-"
	}
	if client == nil {
		client = egress.NewClient(egress.Policy{RequireHTTPS: true, MaxRedirects: 0})
	}
	c := &EJBCAConnector{id: id, cfg: cfg, client: client}
	// The client is built by the hub from these PEMs (TLSMaterial); here they
	// are only validated so a bad pair lists as degraded.
	if _, _, err := TLSMaterial(cfg.ClientCertPEM, cfg.ClientKeyPEM, cfg.CACertPEM); err != nil {
		c.initErr = fmt.Errorf("ejbca: %w", err)
	}
	return c
}

func (c *EJBCAConnector) ID() string     { return c.id }
func (c *EJBCAConnector) Type() string   { return "ejbca" }
func (c *EJBCAConnector) Origin() string { return "synced" }

func (c *EJBCAConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// Health probes GET v1/certificate/status and carries the last issue error.
func (c *EJBCAConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	_, _, err := c.do(ctx, http.MethodGet, "/v1/certificate/status", "", nil)
	switch {
	case err != nil && last != "":
		return Health{Status: "degraded", Detail: err.Error() + "; last issue error: " + last}
	case err != nil:
		return Health{Status: "degraded", Detail: err.Error()}
	case last != "":
		return Health{Status: "degraded", Detail: "last issue error: " + last}
	}
	return Health{Status: "healthy"}
}

// do sends one request. path must already be escaped (the issuer DN has to
// stay a single path segment).
func (c *EJBCAConnector) do(ctx context.Context, method, path, rawQuery string, payload any) (int, []byte, error) {
	if c.initErr != nil {
		return 0, nil, fmt.Errorf("ejbca %s: %w", c.id, c.initErr)
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(raw)
	}
	u, err := url.Parse(c.cfg.BaseURL + path)
	if err != nil {
		return 0, nil, fmt.Errorf("ejbca %s: bad url: %w", c.id, err)
	}
	u.RawQuery = rawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // error surfaces via status below
	if resp.StatusCode == http.StatusTooManyRequests {
		return resp.StatusCode, raw, &RateLimitError{ConnectorID: c.id, Reason: "upstream_429",
			RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Err:        fmt.Errorf("ejbca %s: rate limited (HTTP 429)", method)}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, raw, fmt.Errorf("ejbca %s: HTTP %d: %s", method, resp.StatusCode, truncate(raw))
	}
	return resp.StatusCode, raw, nil
}

// Issue enrolls the CSR through v1/certificate/pkcs10enroll.
func (c *EJBCAConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *EJBCAConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("ejbca %s: CSRPEM is not a PEM certificate request", c.id)
	}
	if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
		return IssueResult{}, fmt.Errorf("ejbca %s: CSR unparseable: %w", c.id, err)
	}
	sum := sha256.Sum256(block.Bytes)
	pw := make([]byte, 24)
	if _, err := rand.Read(pw); err != nil {
		return IssueResult{}, fmt.Errorf("ejbca %s: enrollment code: %w", c.id, err)
	}

	// Docs: pkcs10enroll takes the PEM CSR in certificate_request; DER is the
	// default response_format and is requested explicitly. The enrollment
	// code is single-use and never stored.
	payload := map[string]any{
		"certificate_request":        req.CSRPEM,
		"certificate_profile_name":   c.cfg.CertificateProfileName,
		"end_entity_profile_name":    c.cfg.EndEntityProfileName,
		"certificate_authority_name": c.cfg.CertificateAuthorityName,
		"username":                   c.cfg.UsernamePrefix + hex.EncodeToString(sum[:])[:16],
		"password":                   hex.EncodeToString(pw),
		"include_chain":              true,
		"response_format":            "DER",
	}
	_, raw, err := c.do(ctx, http.MethodPost, "/v1/certificate/pkcs10enroll", "", payload)
	if err != nil {
		return IssueResult{}, err
	}
	var out struct {
		Certificate      string   `json:"certificate"`
		CertificateChain []string `json:"certificate_chain"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return IssueResult{}, fmt.Errorf("ejbca %s: enroll response unparseable: %w", c.id, err)
	}
	leaf, err := ejbcaDecodeCert(out.Certificate)
	if err != nil {
		return IssueResult{}, fmt.Errorf("ejbca %s: issued certificate: %w", c.id, err)
	}
	var bundle strings.Builder
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	for i, entry := range out.CertificateChain {
		ca, err := ejbcaDecodeCert(entry)
		if err != nil {
			return IssueResult{}, fmt.Errorf("ejbca %s: chain entry %d: %w", c.id, i, err)
		}
		if bytes.Equal(ca.Raw, leaf.Raw) {
			continue // include_chain may echo the leaf first
		}
		bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	}
	fp := sha256.Sum256(leaf.Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(fp[:]), CertificatePEM: bundle.String()}, nil
}

// ejbcaDecodeCert accepts base64 DER (the documented JSON encoding) and, as
// a tolerance for server-side format variation, a PEM block.
func ejbcaDecodeCert(s string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty certificate")
	}
	var der []byte
	if b, _ := pem.Decode([]byte(s)); b != nil {
		der = b.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, errors.New("not base64 DER or PEM")
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("unparseable: %w", err)
	}
	return cert, nil
}

// ejbcaReasons maps RFC 5280 CRLReason codes to the EJBCA REST reason names
// (V1CertificateApi revoke docs); unknown codes map to UNSPECIFIED.
var ejbcaReasons = map[int]string{
	0: "UNSPECIFIED", 1: "KEY_COMPROMISE", 2: "CA_COMPROMISE", 3: "AFFILIATION_CHANGED",
	4: "SUPERSEDED", 5: "CESSATION_OF_OPERATION", 6: "CERTIFICATE_HOLD",
	8: "REMOVE_FROM_CRL", 9: "PRIVILEGES_WITHDRAWN", 10: "AA_COMPROMISE",
}

// Revoke calls PUT v1/certificate/{issuer_dn}/{serial}/revoke?reason=NAME.
// EJBCA revokes by issuer DN + hex serial, so the DN is taken from the leaf.
func (c *EJBCAConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	block, _ := pem.Decode([]byte(req.CertificatePEM))
	if block == nil {
		return fmt.Errorf("ejbca %s: revoke needs CertificatePEM to learn the issuer DN", c.id)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("ejbca %s: revoke certificate unparseable: %w", c.id, err)
	}
	serial := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.SerialHex)), "0x")
	if serial == "" {
		serial = cert.SerialNumber.Text(16)
	}
	reason, ok := ejbcaReasons[req.Reason]
	if !ok {
		reason = "UNSPECIFIED"
	}
	dn := cert.Issuer.String()
	if dn == "" {
		return fmt.Errorf("ejbca %s: certificate has an empty issuer DN", c.id)
	}
	// PathEscape keeps the DN a single path segment (commas, slashes).
	_, raw, err := c.do(ctx, http.MethodPut,
		"/v1/certificate/"+url.PathEscape(dn)+"/"+url.PathEscape(serial)+"/revoke",
		"reason="+url.QueryEscape(reason), nil)
	if err != nil {
		return err
	}
	var out struct {
		Revoked *bool `json:"revoked"`
	}
	if json.Unmarshal(raw, &out) == nil && out.Revoked != nil && !*out.Revoked {
		return fmt.Errorf("ejbca %s: server reported revoked=false: %s", c.id, truncate(raw))
	}
	return nil
}
