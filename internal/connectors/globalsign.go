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
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
)

// W36-09: GlobalSign Atlas (HVCA) issuer. Reference, verified 2026-10-24:
// https://www.globalsign.com/en/resources/apis/api-documentation/globalsign_hvca_api_documentation_version_v2.html
//
// Facts taken from that reference:
//   - POST /login {api_key, api_secret} -> 200 {access_token}, Bearer, valid 10 minutes.
//   - POST /certificates takes validity{not_before,not_after (unix)}, subject_dn,
//     san{dns_names,emails,ip_addresses,uris} and public_key. There is no csr
//     field: public_key accepts a PEM SPKI or a PEM PKCS10 CSR, but for a CSR the
//     service uses ONLY the key and discards the subject and attributes. So we send
//     the CSR in public_key (it proves possession) and copy the subject and SANs out
//     of the CSR into subject_dn and san ourselves.
//   - 201 with a Location header ({base}/certificates/{id}); no body.
//   - GET /certificates/{id}: 200 {certificate (PEM), status ISSUED|REVOKED}; 202 means
//     issuance still in progress.
//   - GET /trustchain: JSON array of PEM, issuing CA to root.
//   - PATCH /certificates/{id} {revocation_reason} -> 204 is the recommended revoke;
//     DELETE is documented as deprecated and takes no reason, so Revoke uses PATCH.
//     Reasons: unspecified, keyCompromise, affiliationChanged, cessationOfOperation,
//     superseded.
//   - GET /validationpolicy is the cheap authenticated read used for Health.
//   - Listing: no GET /certificates exists; GET /stats/issued and /stats/revoked
//     (from, to unix, max 30-day window, page, per_page) return [{serial_number,...}].
//   - Errors are application/problem+json; 429 has no documented Retry-After.
//
// NOT verified (the reference is silent): that mTLS is mandatory (the page only
// mentions an optional X-SSL-Client-Serial header on /login, although deployments are
// commonly fronted with client-cert auth, so the pair is applied whenever configured),
// and the textual form of {id} in the path. Stats list serials as decimal strings, so
// Revoke tries the decimal form of the serial first and the hex form on a 404.

// GlobalSignConfig locates and authenticates an Atlas HVCA account.
type GlobalSignConfig struct {
	// BaseURL defaults to https://emea.api.hvca.globalsign.com:8443/v2.
	BaseURL   string
	APIKey    string
	APISecret string
	// ClientCertPEM/ClientKeyPEM are the optional mTLS pair (both or neither);
	// CACertPEM optionally pins a private server root.
	ClientCertPEM string
	ClientKeyPEM  string
	CACertPEM     string
	// ValidityDays is the requested lifetime (default 90); the account policy may clamp it.
	ValidityDays int
	// LookbackDays bounds ListCertificates (default 30, max 365).
	LookbackDays int
	PollAttempts int
	PollInterval time.Duration
}

// GlobalSignCertRecord is one certificate seen by ListCertificates.
type GlobalSignCertRecord struct {
	PEM     string
	Revoked bool
}

// GlobalSignConnector is an IssuerConnector and RevokingConnector for Atlas HVCA.
type GlobalSignConnector struct {
	id      string
	cfg     GlobalSignConfig
	client  *http.Client
	initErr error

	mu        sync.Mutex
	lastError string
}

// NewGlobalSignConnector applies defaults and uses the supplied egress-guarded
// client as is. A bad PEM is held and surfaced by every call so the connector
// still lists as degraded.
func NewGlobalSignConnector(id string, cfg GlobalSignConfig, client *http.Client) *GlobalSignConnector {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://emea.api.hvca.globalsign.com:8443/v2"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 90
	}
	if cfg.LookbackDays <= 0 {
		cfg.LookbackDays = 30
	}
	if cfg.LookbackDays > 365 {
		cfg.LookbackDays = 365
	}
	if cfg.PollAttempts <= 0 {
		cfg.PollAttempts = 10
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	if client == nil {
		client = egress.NewClient(egress.Policy{RequireHTTPS: true, MaxRedirects: 0})
	}
	c := &GlobalSignConnector{id: id, cfg: cfg, client: client}
	// The hub builds the client from these PEMs (TLSMaterial); here they are
	// only validated so a bad pair lists as degraded.
	if _, _, err := TLSMaterial(cfg.ClientCertPEM, cfg.ClientKeyPEM, cfg.CACertPEM); err != nil {
		c.initErr = fmt.Errorf("globalsign: %w", err)
	}
	return c
}

func (c *GlobalSignConnector) ID() string     { return c.id }
func (c *GlobalSignConnector) Type() string   { return "globalsign" }
func (c *GlobalSignConnector) Origin() string { return "synced" }

func (c *GlobalSignConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// do sends one request. token is empty only for /login.
func (c *GlobalSignConnector) do(ctx context.Context, method, path, token string, payload any) (int, http.Header, []byte, error) {
	if c.initErr != nil {
		return 0, nil, nil, fmt.Errorf("globalsign %s: %w", c.id, c.initErr)
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("globalsign %s: bad url", c.id)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // error surfaces via status below
	if resp.StatusCode == http.StatusTooManyRequests {
		return resp.StatusCode, resp.Header, raw, &RateLimitError{ConnectorID: c.id, Reason: "upstream_429",
			RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Err:        fmt.Errorf("globalsign %s %s: rate limited (HTTP 429)", method, path)}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, resp.Header, raw, fmt.Errorf("globalsign %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(raw))
	}
	return resp.StatusCode, resp.Header, raw, nil
}

// login obtains a fresh token. It is called once per operation and never
// cached: the token lives 10 minutes and holding it buys nothing here.
func (c *GlobalSignConnector) login(ctx context.Context) (string, error) {
	if c.cfg.APIKey == "" || c.cfg.APISecret == "" {
		return "", fmt.Errorf("globalsign %s: api_key and api_secret are required", c.id)
	}
	_, _, raw, err := c.do(ctx, http.MethodPost, "/login", "",
		map[string]string{"api_key": c.cfg.APIKey, "api_secret": c.cfg.APISecret})
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(raw, &out) != nil || out.AccessToken == "" {
		return "", fmt.Errorf("globalsign %s: login response carried no access_token", c.id)
	}
	return out.AccessToken, nil
}

// Health logs in and reads GET /validationpolicy, carrying the last issue error.
func (c *GlobalSignConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	tok, err := c.login(ctx)
	if err == nil {
		_, _, _, err = c.do(ctx, http.MethodGet, "/validationpolicy", tok, nil)
	}
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

// Issue submits the CSR and waits (bounded) for the certificate.
func (c *GlobalSignConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func globalSignIssueBody(csr *x509.CertificateRequest, csrPEM string, validityDays int, now time.Time) map[string]any {
	s := csr.Subject
	subject := map[string]any{}
	set := func(k, v string) {
		if v != "" {
			subject[k] = v
		}
	}
	set("common_name", s.CommonName)
	if len(s.Organization) > 0 {
		set("organization", s.Organization[0])
	}
	if len(s.OrganizationalUnit) > 0 {
		subject["organizational_unit"] = s.OrganizationalUnit
	}
	if len(s.Country) > 0 {
		set("country", s.Country[0])
	}
	if len(s.Province) > 0 {
		set("state", s.Province[0])
	}
	if len(s.Locality) > 0 {
		set("locality", s.Locality[0])
	}
	san := map[string]any{}
	if len(csr.DNSNames) > 0 {
		san["dns_names"] = csr.DNSNames
	}
	if len(csr.EmailAddresses) > 0 {
		san["emails"] = csr.EmailAddresses
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		san["ip_addresses"] = ips
	}
	if len(csr.URIs) > 0 {
		uris := make([]string, len(csr.URIs))
		for i, u := range csr.URIs {
			uris[i] = u.String()
		}
		san["uris"] = uris
	}
	body := map[string]any{
		"validity": map[string]any{
			"not_before": now.Unix(),
			"not_after":  now.Add(time.Duration(validityDays) * 24 * time.Hour).Unix(),
		},
		"subject_dn": subject,
		// A PKCS10 CSR is accepted here; only its public key is used by Atlas.
		"public_key": csrPEM,
	}
	if len(san) > 0 {
		body["san"] = san
	}
	return body
}

func (c *GlobalSignConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("globalsign %s: CSRPEM is not a PEM certificate request", c.id)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("globalsign %s: CSR unparseable: %w", c.id, err)
	}
	tok, err := c.login(ctx)
	if err != nil {
		return IssueResult{}, err
	}
	_, hdr, _, err := c.do(ctx, http.MethodPost, "/certificates", tok,
		globalSignIssueBody(csr, req.CSRPEM, c.cfg.ValidityDays, time.Now()))
	if err != nil {
		return IssueResult{}, err
	}
	loc := hdr.Get("Location")
	if loc == "" {
		return IssueResult{}, fmt.Errorf("globalsign %s: 201 response carried no Location header", c.id)
	}
	// Only the last path segment is used and the request goes to our configured
	// base, so a hostile Location cannot redirect the bearer token elsewhere.
	id := loc[strings.LastIndex(loc, "/")+1:]
	if id == "" {
		return IssueResult{}, fmt.Errorf("globalsign %s: Location header has no certificate id", c.id)
	}
	certPEM, err := c.pollIssued(ctx, tok, id)
	if err != nil {
		return IssueResult{}, err
	}
	leaf, err := parseSinglePEMCert(certPEM)
	if err != nil {
		return IssueResult{}, fmt.Errorf("globalsign %s: issued certificate: %w", c.id, err)
	}
	_, _, raw, err := c.do(ctx, http.MethodGet, "/trustchain", tok, nil)
	if err != nil {
		return IssueResult{}, err
	}
	var chain []string
	if err := json.Unmarshal(raw, &chain); err != nil {
		return IssueResult{}, fmt.Errorf("globalsign %s: trustchain unparseable: %w", c.id, err)
	}
	var bundle strings.Builder
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	for i, entry := range chain {
		ca, err := parseSinglePEMCert(entry)
		if err != nil {
			return IssueResult{}, fmt.Errorf("globalsign %s: trustchain entry %d: %w", c.id, i, err)
		}
		if bytes.Equal(ca.Raw, leaf.Raw) {
			continue
		}
		bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	}
	fp := sha256.Sum256(leaf.Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(fp[:]), CertificatePEM: bundle.String()}, nil
}

func parseSinglePEMCert(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unparseable: %w", err)
	}
	return cert, nil
}

// pollIssued waits for GET /certificates/{id} to return 200 ISSUED
// (202 means still in progress).
func (c *GlobalSignConnector) pollIssued(ctx context.Context, tok, id string) (string, error) {
	for attempt := 0; attempt < c.cfg.PollAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(c.cfg.PollInterval):
			}
		}
		code, _, raw, err := c.do(ctx, http.MethodGet, "/certificates/"+url.PathEscape(id), tok, nil)
		if err != nil {
			return "", err
		}
		if code == http.StatusAccepted {
			continue
		}
		var out struct {
			Certificate string `json:"certificate"`
			Status      string `json:"status"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return "", fmt.Errorf("globalsign %s: certificate response unparseable: %w", c.id, err)
		}
		switch out.Status {
		case "ISSUED":
			return out.Certificate, nil
		case "REVOKED":
			return "", fmt.Errorf("globalsign %s: certificate %s was revoked before retrieval", c.id, id)
		}
	}
	return "", fmt.Errorf("globalsign %s: certificate %s still pending after %d polls; raise the poll budget", c.id, id, c.cfg.PollAttempts)
}

// globalSignReasons maps RFC 5280 CRLReason codes to the Atlas vocabulary.
// Codes Atlas has no name for (CA compromise, hold, ...) map to unspecified.
var globalSignReasons = map[int]string{
	0: "unspecified", 1: "keyCompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation",
}

// Revoke calls PATCH /certificates/{serial} {revocation_reason} (the
// documented replacement for the deprecated DELETE, which carries no reason).
func (c *GlobalSignConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	serial := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.SerialHex)), "0x")
	n, ok := new(big.Int).SetString(serial, 16)
	if !ok {
		return fmt.Errorf("globalsign %s: SerialHex %q is not hex", c.id, req.SerialHex)
	}
	reason, ok := globalSignReasons[req.Reason]
	if !ok {
		reason = "unspecified"
	}
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}
	payload := map[string]string{"revocation_reason": reason}
	// The path id format is undocumented; stats list decimal serials, so decimal first.
	code, _, _, err := c.do(ctx, http.MethodPatch, "/certificates/"+n.String(), tok, payload)
	if err != nil && code == http.StatusNotFound {
		_, _, _, err = c.do(ctx, http.MethodPatch, "/certificates/"+serial, tok, payload)
	}
	return err
}

// ListCertificates enumerates issued and revoked serials via /stats/issued and
// /stats/revoked (30-day windows covering LookbackDays) and fetches each PEM.
func (c *GlobalSignConnector) ListCertificates(ctx context.Context) ([]GlobalSignCertRecord, error) {
	tok, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	const window = 30 * 24 * time.Hour
	end := time.Now()
	start := end.Add(-time.Duration(c.cfg.LookbackDays) * 24 * time.Hour)
	seen := map[string]bool{}
	var out []GlobalSignCertRecord
	for _, kind := range []string{"issued", "revoked"} {
		for from := start; from.Before(end); from = from.Add(window) {
			to := from.Add(window)
			if to.After(end) {
				to = end
			}
			for page := 1; ; page++ {
				q := fmt.Sprintf("/stats/%s?from=%d&to=%d&page=%d&per_page=100", kind, from.Unix(), to.Unix(), page)
				_, _, raw, err := c.do(ctx, http.MethodGet, q, tok, nil)
				if err != nil {
					return nil, err
				}
				var items []struct {
					SerialNumber string `json:"serial_number"`
				}
				if err := json.Unmarshal(raw, &items); err != nil {
					return nil, fmt.Errorf("globalsign %s: stats unparseable: %w", c.id, err)
				}
				for _, it := range items {
					if it.SerialNumber == "" || seen[it.SerialNumber] {
						continue
					}
					seen[it.SerialNumber] = true
					_, _, body, err := c.do(ctx, http.MethodGet, "/certificates/"+url.PathEscape(it.SerialNumber), tok, nil)
					if err != nil {
						return nil, err
					}
					var cert struct {
						Certificate string `json:"certificate"`
						Status      string `json:"status"`
					}
					if json.Unmarshal(body, &cert) != nil || cert.Certificate == "" {
						continue // pending or unparseable entries carry no cert
					}
					out = append(out, GlobalSignCertRecord{PEM: cert.Certificate, Revoked: cert.Status == "REVOKED"})
				}
				if len(items) < 100 || page > 1000 {
					break
				}
			}
		}
	}
	return out, nil
}
