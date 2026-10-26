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

// W36-10: Entrust Certificate Services (ECS) Enterprise API issuer. Reference,
// verified 2026-10-24 against the published Swagger 2.0 spec "Entrust Certificate
// Services Enterprise API" 2.1.0:
// https://cloud.entrust.net/EntrustCloud/documentation/cms-api-2.1.0.yaml
//
// Facts taken from that spec:
//   - host api.entrust.net, basePath /enterprise/v2.
//   - Auth is BOTH an API user's client certificate (HTTPS client auth) AND
//     HTTP Basic (API username + API key).
//   - POST /certificates: csr, certType (required), subjectAltName[], signingAlg
//     (SHA-2), eku, clientId (default 1), certExpiryDate (YYYY-MM-DD, pooling
//     accounts) or certLifetime (P1Y|P2Y|P3Y, non-pooling accounts), tracking{
//     requesterName, requesterEmail, requesterPhone}, queueForApproval.
//     201 {trackingId, endEntityCert, chainCerts, serialNumber, ...} when issued;
//     202 {trackingId} when queued for approval. 429 carries Retry-After.
//   - GET /certificates/{trackingId}: {status, endEntityCert, chainCerts, declineReason}.
//     status is ACTIVE, PENDING, PENDING_QUORUM, APPROVED, READY, DECLINED, ...
//   - GET /certificates?serialNumber=<HEX>: {summary, certificates:[{trackingId,...}]};
//     serial is upper-case hex (example: 239010FB4DD0FD050000000053DA5896).
//   - POST /certificates/{trackingId}/revocations {crlReason, revocationComment}
//     -> 200. crlReason is one of keyCompromise, affiliationChanged, superseded,
//     cessationOfOperation; there is no "unspecified", so it is omitted instead.
//   - chainCerts is documented as including the end-entity cert and excluding the
//     root; the leaf is therefore de-duplicated when assembling the bundle.
//   - GET /clients is the cheap read-only call used for Health.
//
// NOT verified: whether an issued certificate is returned synchronously for every
// certType (the spec allows 201 with the certificate or 202 pending, both handled),
// and that serialNumber filtering is exact for every account (we refuse 0 or >1).

// EntrustConfig locates and authenticates an ECS Enterprise API account.
type EntrustConfig struct {
	// BaseURL defaults to https://api.entrust.net/enterprise/v2.
	BaseURL  string
	Username string
	APIKey   string
	// ClientCertPEM/ClientKeyPEM are the API user's mTLS pair (required by ECS);
	// CACertPEM optionally pins a private server root.
	ClientCertPEM string
	ClientKeyPEM  string
	CACertPEM     string
	// ClientID is the ECS client the certificate is issued for (default 1).
	ClientID int
	// CertType defaults to STANDARD_SSL.
	CertType string
	// ValidityDays sets certExpiryDate (default 90) for pooling accounts.
	ValidityDays int
	// CertLifetime (P1Y, P2Y or P3Y), when set, is sent as certLifetime instead of
	// certExpiryDate, because non-pooling accounts only accept the former.
	CertLifetime   string
	RequesterName  string
	RequesterEmail string
	RequesterPhone string
	PollAttempts   int
	PollInterval   time.Duration
}

// EntrustConnector is an IssuerConnector (and RevokingConnector) backed by ECS.
type EntrustConnector struct {
	id      string
	cfg     EntrustConfig
	client  *http.Client
	initErr error

	mu        sync.Mutex
	lastError string
}

// NewEntrustConnector uses the supplied egress-guarded client as is. A bad PEM is held and
// surfaced by every call so a misconfigured connector lists as degraded.
func NewEntrustConnector(id string, cfg EntrustConfig, client *http.Client) *EntrustConnector {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.entrust.net/enterprise/v2"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.ClientID <= 0 {
		cfg.ClientID = 1
	}
	if cfg.CertType == "" {
		cfg.CertType = "STANDARD_SSL"
	}
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 90
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
	c := &EntrustConnector{id: id, cfg: cfg, client: client}
	// The hub builds the client from these PEMs (TLSMaterial); here they are
	// only validated so a bad pair lists as degraded.
	if _, _, err := TLSMaterial(cfg.ClientCertPEM, cfg.ClientKeyPEM, cfg.CACertPEM); err != nil {
		c.initErr = fmt.Errorf("entrust: %w", err)
	}
	return c
}

func (c *EntrustConnector) ID() string     { return c.id }
func (c *EntrustConnector) Type() string   { return "entrust" }
func (c *EntrustConnector) Origin() string { return "synced" }

func (c *EntrustConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

// Health probes GET /clients and carries the last issue error.
func (c *EntrustConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	_, _, err := c.do(ctx, http.MethodGet, "/clients", "", nil)
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

func (c *EntrustConnector) do(ctx context.Context, method, path, rawQuery string, payload any) (int, []byte, error) {
	if c.initErr != nil {
		return 0, nil, fmt.Errorf("entrust %s: %w", c.id, c.initErr)
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
		return 0, nil, fmt.Errorf("entrust %s: bad url: %w", c.id, err)
	}
	u.RawQuery = rawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.APIKey)
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
			Err:        fmt.Errorf("entrust %s %s: rate limited (HTTP 429)", method, path)}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, raw, fmt.Errorf("entrust %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(raw))
	}
	return resp.StatusCode, raw, nil
}

type entrustCertBody struct {
	TrackingID    int      `json:"trackingId"`
	Status        string   `json:"status"`
	EndEntityCert string   `json:"endEntityCert"`
	ChainCerts    []string `json:"chainCerts"`
	DeclineReason string   `json:"declineReason"`
}

// Issue submits the CSR and, when the order is queued, polls until it is issued.
func (c *EntrustConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *EntrustConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("entrust %s: CSRPEM is not a PEM certificate request", c.id)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("entrust %s: CSR unparseable: %w", c.id, err)
	}
	payload := map[string]any{
		"csr":        req.CSRPEM,
		"certType":   c.cfg.CertType,
		"signingAlg": "SHA-2",
		"eku":        "SERVER_AUTH",
		"clientId":   c.cfg.ClientID,
	}
	if c.cfg.CertLifetime != "" {
		payload["certLifetime"] = c.cfg.CertLifetime
	} else {
		payload["certExpiryDate"] = time.Now().UTC().AddDate(0, 0, c.cfg.ValidityDays).Format("2006-01-02")
	}
	// Passing subjectAltName makes ECS ignore SANs inside the CSR, so the CSR's own
	// names are forwarded to keep both views identical.
	if len(csr.DNSNames) > 0 {
		payload["subjectAltName"] = csr.DNSNames
	}
	tracking := map[string]string{}
	for k, v := range map[string]string{
		"requesterName": c.cfg.RequesterName, "requesterEmail": c.cfg.RequesterEmail, "requesterPhone": c.cfg.RequesterPhone,
	} {
		if v != "" {
			tracking[k] = v
		}
	}
	if len(tracking) > 0 {
		payload["tracking"] = tracking
	}

	_, raw, err := c.do(ctx, http.MethodPost, "/certificates", "", payload)
	if err != nil {
		return IssueResult{}, err
	}
	var out entrustCertBody
	if err := json.Unmarshal(raw, &out); err != nil {
		return IssueResult{}, fmt.Errorf("entrust %s: issue response unparseable: %w", c.id, err)
	}
	if out.TrackingID == 0 {
		return IssueResult{}, fmt.Errorf("entrust %s: issue response has no trackingId", c.id)
	}
	if out.EndEntityCert == "" {
		if out, err = c.pollIssued(ctx, out.TrackingID); err != nil {
			return IssueResult{}, err
		}
	}
	return c.bundle(out)
}

// pollIssued waits for GET /certificates/{trackingId} to carry the certificate.
func (c *EntrustConnector) pollIssued(ctx context.Context, id int) (entrustCertBody, error) {
	for attempt := 0; attempt < c.cfg.PollAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return entrustCertBody{}, ctx.Err()
			case <-time.After(c.cfg.PollInterval):
			}
		}
		_, raw, err := c.do(ctx, http.MethodGet, "/certificates/"+strconv.Itoa(id), "", nil)
		if err != nil {
			return entrustCertBody{}, err
		}
		var out entrustCertBody
		if err := json.Unmarshal(raw, &out); err != nil {
			return entrustCertBody{}, fmt.Errorf("entrust %s: certificate response unparseable: %w", c.id, err)
		}
		switch strings.ToUpper(out.Status) {
		case "DECLINED":
			return entrustCertBody{}, fmt.Errorf("entrust %s: order %d declined: %s", c.id, id, truncate([]byte(out.DeclineReason)))
		case "REVOKED", "EXPIRED", "DEACTIVATED", "SUSPENDED":
			return entrustCertBody{}, fmt.Errorf("entrust %s: order %d is %s", c.id, id, out.Status)
		}
		if out.EndEntityCert != "" {
			out.TrackingID = id
			return out, nil
		}
	}
	return entrustCertBody{}, fmt.Errorf("entrust %s: order %d not issued after %d polls", c.id, id, c.cfg.PollAttempts)
}

func (c *EntrustConnector) bundle(out entrustCertBody) (IssueResult, error) {
	leaf, err := entrustParsePEM(out.EndEntityCert)
	if err != nil {
		return IssueResult{}, fmt.Errorf("entrust %s: issued certificate: %w", c.id, err)
	}
	var b strings.Builder
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	for i, entry := range out.ChainCerts {
		ca, err := entrustParsePEM(entry)
		if err != nil {
			return IssueResult{}, fmt.Errorf("entrust %s: chain entry %d: %w", c.id, i, err)
		}
		if bytes.Equal(ca.Raw, leaf.Raw) {
			continue // chainCerts is documented to include the end-entity cert
		}
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	}
	fp := sha256.Sum256(leaf.Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(fp[:]), CertificatePEM: b.String()}, nil
}

func entrustParsePEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unparseable: %w", err)
	}
	return cert, nil
}

// entrustReasons maps RFC 5280 CRLReason codes to the ECS crlReason enum. The
// spec offers no "unspecified", so any other code omits the field.
var entrustReasons = map[int]string{
	1: "keyCompromise", 3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation",
}

// Revoke finds the trackingId by serial (ECS revokes by trackingId, not serial)
// and refuses unless exactly one certificate matches.
func (c *EntrustConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	serial := strings.ToUpper(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.SerialHex)), "0x"))
	if serial == "" {
		if block, _ := pem.Decode([]byte(req.CertificatePEM)); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				serial = strings.ToUpper(cert.SerialNumber.Text(16))
			}
		}
	}
	if serial == "" {
		return fmt.Errorf("entrust %s: revoke needs a serial number", c.id)
	}
	if len(serial)%2 == 1 {
		serial = "0" + serial // ECS prints whole bytes
	}
	q := url.Values{"serialNumber": {serial}}
	_, raw, err := c.do(ctx, http.MethodGet, "/certificates", q.Encode(), nil)
	if err != nil {
		return err
	}
	var list struct {
		Certificates []struct {
			TrackingID int `json:"trackingId"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("entrust %s: certificate listing unparseable: %w", c.id, err)
	}
	if n := len(list.Certificates); n != 1 {
		return fmt.Errorf("entrust %s: serial %s matched %d certificates, refusing to revoke", c.id, serial, n)
	}
	body := map[string]any{"revocationComment": "revoked by Kryptkeeper"}
	if reason, ok := entrustReasons[req.Reason]; ok {
		body["crlReason"] = reason
	}
	_, _, err = c.do(ctx, http.MethodPost,
		"/certificates/"+strconv.Itoa(list.Certificates[0].TrackingID)+"/revocations", "", body)
	return err
}
