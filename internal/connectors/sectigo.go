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
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
)

// W36-08: Sectigo Certificate Manager (SCM) issuer. Reference (Admin API):
// https://scm.devx.sectigo.com/llms.txt indexes every page used below.
// Header-based auth on https://cert-manager.com/ is documented at
// https://scm.devx.sectigo.com/docs/authentication.md (login, password,
// customerUri; certificate login sends login + customerUri over mTLS and uses
// /private/... paths). The current reference documents /api/ssl/v2/...; the
// read-only inventory source still calls v1, whose reference is no longer
// published, so this connector targets v2 on the same host and headers.

// SectigoConfig locates and authenticates an SCM account.
type SectigoConfig struct {
	// BaseURL defaults to https://cert-manager.com (header-auth host).
	BaseURL     string
	CustomerURI string
	// OrgID is the SCM organization the certificate is requested for.
	OrgID int
	// CertType is the SCM certificate profile id (GET /api/ssl/v2/types).
	CertType int
	// TermDays is the validity period; it must be one the profile allows.
	TermDays int
	// Login/Password are the password-auth pair. With ClientCertPEM set the
	// password is not sent (certificate login).
	Login    string
	Password string
	// ClientCertPEM/ClientKeyPEM enable certificate login; CACertPEM optionally
	// pins a private TLS root.
	ClientCertPEM string
	ClientKeyPEM  string
	CACertPEM     string
	// Poll pacing for the collect step; tests shrink these.
	PollAttempts int
	PollInterval time.Duration
}

// SectigoConnector is an IssuerConnector (and RevokingConnector) backed by SCM.
type SectigoConnector struct {
	id      string
	cfg     SectigoConfig
	client  *http.Client
	initErr error

	mu        sync.Mutex
	lastError string
}

// NewSectigoConnector builds the connector. A bad client PEM is held and
// surfaced by every call so a misconfigured connector lists as degraded.
func NewSectigoConnector(id string, cfg SectigoConfig, client *http.Client) *SectigoConnector {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://cert-manager.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.PollAttempts <= 0 {
		cfg.PollAttempts = 10
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	c := &SectigoConnector{id: id, cfg: cfg, client: client}
	if c.client == nil {
		c.client = egress.NewClient(egress.Policy{RequireHTTPS: true, MaxRedirects: 0})
	}
	// The hub builds the client from these PEMs (TLSMaterial); here they are
	// only validated so a bad pair lists as degraded.
	if _, _, err := TLSMaterial(cfg.ClientCertPEM, cfg.ClientKeyPEM, cfg.CACertPEM); err != nil {
		c.initErr = fmt.Errorf("sectigo: %w", err)
	}
	return c
}

func (c *SectigoConnector) ID() string     { return c.id }
func (c *SectigoConnector) Type() string   { return "sectigo" }
func (c *SectigoConnector) Origin() string { return "synced" }

func (c *SectigoConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// Health probes GET /api/ssl/v2/types (profile listing, read-only) and
// carries the last issue error.
func (c *SectigoConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	_, _, err := c.do(ctx, http.MethodGet, "/types", nil, nil)
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

// certLogin reports whether certificate login (no password) is in use.
func (c *SectigoConnector) certLogin() bool { return c.cfg.ClientCertPEM != "" }

// scrub keeps the password out of anything that becomes an error string.
func (c *SectigoConnector) scrub(s string) string {
	if c.cfg.Password != "" {
		s = strings.ReplaceAll(s, c.cfg.Password, "[redacted]")
	}
	return s
}

// do sends one request below /api/ssl/v2 (or /private/api/ssl/v2 for
// certificate login). path starts with "/".
func (c *SectigoConnector) do(ctx context.Context, method, path string, query url.Values, payload any) (int, []byte, error) {
	if c.initErr != nil {
		return 0, nil, fmt.Errorf("sectigo %s: %w", c.id, c.initErr)
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(raw)
	}
	prefix := "/api/ssl/v2"
	if c.certLogin() {
		prefix = "/private" + prefix
	}
	u := c.cfg.BaseURL + prefix + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, nil, fmt.Errorf("sectigo %s: bad request: %s", c.id, c.scrub(err.Error()))
	}
	req.Header.Set("login", c.cfg.Login)
	if !c.certLogin() {
		req.Header.Set("password", c.cfg.Password)
	}
	req.Header.Set("customerUri", c.cfg.CustomerURI)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sectigo %s: %s", c.id, c.scrub(err.Error()))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // error surfaces via status below
	if resp.StatusCode == http.StatusTooManyRequests {
		return resp.StatusCode, raw, &RateLimitError{ConnectorID: c.id, Reason: "upstream_429",
			RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Err:        fmt.Errorf("sectigo %s: rate limited (HTTP 429)", path)}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, raw, fmt.Errorf("sectigo %s: HTTP %d: %s", path, resp.StatusCode, c.scrub(truncate(raw)))
	}
	return resp.StatusCode, raw, nil
}

// Issue enrolls the CSR (POST /enroll) then polls GET /collect/{sslId}.
func (c *SectigoConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *SectigoConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	if c.cfg.OrgID <= 0 || c.cfg.CertType <= 0 || c.cfg.TermDays <= 0 {
		return IssueResult{}, fmt.Errorf("sectigo %s: org_id, cert_type and term_days are required", c.id)
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("sectigo %s: CSRPEM is not a PEM certificate request", c.id)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("sectigo %s: CSR unparseable: %w", c.id, err)
	}
	sum := sha256.Sum256(block.Bytes)
	sans := make([]string, 0, len(csr.DNSNames)+len(csr.IPAddresses))
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Docs: https://scm.devx.sectigo.com/reference/enroll-ssl-certificate.md
	// csr, orgId required; certType = profile id; term in days; subjAltNames is
	// one comma-separated string. Response {sslId, renewId}.
	payload := map[string]any{
		"orgId":    c.cfg.OrgID,
		"csr":      req.CSRPEM,
		"certType": c.cfg.CertType,
		"term":     c.cfg.TermDays,
		"comments": "Kryptkeeper CSR sha256:" + hex.EncodeToString(sum[:])[:16],
	}
	if len(sans) > 0 {
		payload["subjAltNames"] = strings.Join(sans, ",")
	}
	_, raw, err := c.do(ctx, http.MethodPost, "/enroll", nil, payload)
	if err != nil {
		return IssueResult{}, err
	}
	var enrolled struct {
		SSLID int `json:"sslId"`
	}
	if err := json.Unmarshal(raw, &enrolled); err != nil || enrolled.SSLID <= 0 {
		return IssueResult{}, fmt.Errorf("sectigo %s: enroll response has no sslId: %s", c.id, truncate(raw))
	}
	return c.collect(ctx, enrolled.SSLID, csr)
}

// collect polls GET /collect/{sslId}?format=x509 (certificate with chain, PEM).
// The reference documents no pending status: it lists 400/404 (404 carries
// {code, description}) for "not available". Both are therefore treated as
// not-yet-issued until the poll budget runs out; 401/403/5xx fail at once.
// Docs: https://scm.devx.sectigo.com/reference/collect-ssl-certificate.md
func (c *SectigoConnector) collect(ctx context.Context, sslID int, csr *x509.CertificateRequest) (IssueResult, error) {
	var lastPending string
	for attempt := 0; attempt < c.cfg.PollAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return IssueResult{}, ctx.Err()
			case <-time.After(c.cfg.PollInterval):
			}
		}
		status, raw, err := c.do(ctx, http.MethodGet, "/collect/"+strconv.Itoa(sslID),
			url.Values{"format": {"x509"}}, nil)
		if err != nil {
			var rl *RateLimitError
			if errors.As(err, &rl) || (status != http.StatusBadRequest && status != http.StatusNotFound) {
				return IssueResult{}, err
			}
			lastPending = truncate(raw)
			continue
		}
		return c.bundle(raw, csr)
	}
	return IssueResult{}, fmt.Errorf("sectigo %s: certificate %d not issued after %d polls (last response: %s) — it may need approval or domain validation in SCM, or raise the poll budget",
		c.id, sslID, c.cfg.PollAttempts, c.scrub(lastPending))
}

// bundle parses the PEM chain and puts the leaf first. The docs do not state
// the order of the "w/ chain" format, so the leaf is the certificate whose
// public key matches the CSR; if none does, the first block is kept as-is
// (the hub's external-CA decorator then rejects the mismatch).
func (c *SectigoConnector) bundle(body []byte, csr *x509.CertificateRequest) (IssueResult, error) {
	var certs []*x509.Certificate
	rest := body
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return IssueResult{}, fmt.Errorf("sectigo %s: issued certificate unparseable: %w", c.id, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return IssueResult{}, fmt.Errorf("sectigo %s: collect response holds no PEM certificate", c.id)
	}
	leafIdx := 0
	for i, cert := range certs {
		if sectigoSamePublicKey(cert, csr) {
			leafIdx = i
			break
		}
	}
	ordered := append([]*x509.Certificate{certs[leafIdx]}, certs[:leafIdx]...)
	ordered = append(ordered, certs[leafIdx+1:]...)
	var out strings.Builder
	for _, cert := range ordered {
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	fp := sha256.Sum256(ordered[0].Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(fp[:]), CertificatePEM: out.String()}, nil
}

func sectigoSamePublicKey(cert *x509.Certificate, csr *x509.CertificateRequest) bool {
	a, errA := x509.MarshalPKIXPublicKey(cert.PublicKey)
	b, errB := x509.MarshalPKIXPublicKey(csr.PublicKey)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// sectigoReasonCodes: SCM accepts only these RFC 5280 codes (Mozilla policy
// 6.1.1): 0, 1, 3, 4, 5. Anything else is sent as unspecified (0).
// Docs: https://scm.devx.sectigo.com/reference/revokessl-certificate-by-id.md
var sectigoReasonCodes = map[int]bool{0: true, 1: true, 3: true, 4: true, 5: true}

// normSerial lower-cases and strips separators/leading zeros so SCM's
// serial formatting (undocumented) never decides a revoke target.
func normSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	return strings.TrimLeft(s, "0")
}

// Revoke finds the sslId with GET /api/ssl/v2?serialNumber=... and then calls
// POST /revoke/{sslId}. Exactly one listing entry must match the serial, else
// the revoke is refused rather than guessed.
// Docs: https://scm.devx.sectigo.com/reference/get-ssl-certificates-list.md
func (c *SectigoConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	serial := normSerial(req.SerialHex)
	if serial == "" && req.CertificatePEM != "" {
		if b, _ := pem.Decode([]byte(req.CertificatePEM)); b != nil {
			if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
				serial = normSerial(cert.SerialNumber.Text(16))
			}
		}
	}
	if serial == "" {
		return fmt.Errorf("sectigo %s: revoke needs SerialHex or CertificatePEM", c.id)
	}
	_, raw, err := c.do(ctx, http.MethodGet, "", url.Values{"serialNumber": {strings.ToUpper(serial)}}, nil)
	if err != nil {
		return err
	}
	var listing []struct {
		SSLID        int    `json:"sslId"`
		SerialNumber string `json:"serialNumber"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		return fmt.Errorf("sectigo %s: serial lookup unparseable: %w", c.id, err)
	}
	var matches []int
	for _, item := range listing {
		if normSerial(item.SerialNumber) == serial {
			matches = append(matches, item.SSLID)
		}
	}
	switch len(matches) {
	case 0:
		return fmt.Errorf("sectigo %s: no SCM certificate with serial %s", c.id, serial)
	case 1:
	default:
		return fmt.Errorf("sectigo %s: %d SCM certificates share serial %s; refusing to guess", c.id, len(matches), serial)
	}
	code := req.Reason
	if !sectigoReasonCodes[code] {
		code = 0
	}
	// Docs: .../revokessl-certificate-by-id.md — reasonCode is a string enum,
	// reason is mandatory (1-512 chars); success is 204.
	payload := map[string]any{
		"reasonCode": strconv.Itoa(code),
		"reason":     "Revoked by Kryptkeeper (RFC 5280 reason " + strconv.Itoa(req.Reason) + ")",
	}
	_, _, err = c.do(ctx, http.MethodPost, "/revoke/"+strconv.Itoa(matches[0]), nil, payload)
	return err
}
