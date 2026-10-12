// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.mozilla.org/pkcs7"
)

// W13-03: RFC 7030 (EST) client — drive any legacy CA speaking EST as
// an upstream issuer. Proven against our own internal/est server.
//
// Response handling tries the bare base64-DER certs-only form first (some
// certs-only ESTs in the wild emit that), then falls back to a real PKCS#7
// certs-only SignedData (RFC 7030 §4.2.3 mandates this, and W19-14 fixed
// our own internal/est server to emit it correctly, so this connector must
// consume it too — go.mozilla.org/pkcs7 is a real dependency of
// internal/est as of that ticket, not gated behind approval anymore).

// ESTClientConfig locates and authenticates the EST endpoint.
type ESTClientConfig struct {
	// BaseURL, e.g. https://est.example.com (the /.well-known/est
	// prefix is appended here).
	BaseURL  string
	Username string
	Password string
}

// ESTClient is an IssuerConnector backed by a remote EST CA.
type ESTClient struct {
	id     string
	cfg    ESTClientConfig
	client *http.Client
}

func NewESTClient(id string, cfg ESTClientConfig, client *http.Client) *ESTClient {
	if client == nil {
		client = http.DefaultClient
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &ESTClient{id: id, cfg: cfg, client: client}
}

func (c *ESTClient) ID() string     { return c.id }
func (c *ESTClient) Type() string   { return "est" }
func (c *ESTClient) Origin() string { return "synced" }

// Health probes /cacerts — the mandatory EST distribution endpoint.
func (c *ESTClient) Health(ctx context.Context) Health {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/.well-known/est/cacerts", nil)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return Health{Status: "degraded", Detail: fmt.Sprintf("cacerts HTTP %d", resp.StatusCode)}
	}
	return Health{Status: "healthy"}
}

// Issue enrolls via simpleenroll and returns the issued cert PEM.
func (c *ESTClient) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("est client %s: CSRPEM is not a PEM certificate request", c.id)
	}
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.BaseURL+"/.well-known/est/simpleenroll", strings.NewReader(body))
	if err != nil {
		return IssueResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/pkcs10")
	httpReq.Header.Set("Content-Transfer-Encoding", "base64")
	if c.cfg.Username != "" {
		httpReq.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return IssueResult{}, fmt.Errorf("est client %s: %w", c.id, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // error surfaces via status/parse below
	if resp.StatusCode >= 400 {
		return IssueResult{}, fmt.Errorf("est client %s: simpleenroll HTTP %d: %s", c.id, resp.StatusCode, truncate(raw))
	}
	return parseCertsOnlyResponse(c.id, "est", raw)
}

// parseCertsOnlyResponse decodes a base64-DER certs-only body into the
// leaf certificate. Shared by the EST and SCEP clients.
func parseCertsOnlyResponse(id, proto string, raw []byte) (IssueResult, error) {
	// Strip ALL whitespace, not just the ends: real EST/SCEP servers
	// commonly emit the base64 body wrapped at 64 columns with CRLF
	// (the norm for Content-Transfer-Encoding: base64), and
	// base64.StdEncoding rejects interior newlines — which would
	// misdiagnose a valid certs-only response as an unsupported
	// PKCS#7 envelope.
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, string(raw))
	der, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		// Maybe raw DER already.
		der = raw
	}
	cert, certErr := x509.ParseCertificate(der)
	if certErr != nil {
		// Not a bare certificate -- try it as a real PKCS#7 certs-only
		// SignedData (RFC 7030 §4.2.3 / RFC 8894 §4.2 both allow the CA to
		// return one, and RFC 7030 requires it for EST).
		p7, perr := pkcs7.Parse(der)
		if perr != nil || len(p7.Certificates) == 0 {
			return IssueResult{}, fmt.Errorf("%s client %s: response is neither a bare certificate nor a parseable PKCS#7 certs-only structure: %w", proto, id, certErr)
		}
		cert = p7.Certificates[0]
	}
	sum := sha256.Sum256(cert.Raw)
	return IssueResult{
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}, nil
}
