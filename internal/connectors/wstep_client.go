// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// W13-01: the inverse of our XCEP/WSTEP server — submit CSRs TO a
// running Windows AD CS over its Certificate Enrollment Web Service.
// MS-WSTEP is WS-Trust 1.3 RST/RSTR carrying a base64 PKCS#10 in a
// BinarySecurityToken; the envelope here mirrors what our own server
// (internal/wstep) speaks, which also makes that server the protocol
// test double.
//
// Auth is HTTP Basic over TLS (CES UsernamePasswordCredential mode, a
// supported ADCS configuration). Kerberos/Negotiate — the AD-joined
// default — is deliberately out of v1: it needs a SPNEGO dependency,
// which is approval-gated. Disclosed, not hidden.

// WSTEPClientConfig locates and authenticates the CES endpoint.
type WSTEPClientConfig struct {
	// EndpointURL is the CES service URI, e.g.
	// https://ca.corp.example/ADPolicyProvider_CEP_UsernamePassword/service.svc/CES
	EndpointURL string
	Username    string
	Password    string
	// TemplateName is the AD CS certificate template requested via
	// the RST TokenType.
	TemplateName string
}

// WSTEPClient is an IssuerConnector backed by a remote AD CS.
type WSTEPClient struct {
	id     string
	cfg    WSTEPClientConfig
	client *http.Client
}

func NewWSTEPClient(id string, cfg WSTEPClientConfig, client *http.Client) *WSTEPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &WSTEPClient{id: id, cfg: cfg, client: client}
}

func (c *WSTEPClient) ID() string     { return c.id }
func (c *WSTEPClient) Type() string   { return "adcs-wstep" }
func (c *WSTEPClient) Origin() string { return "synced" }

// Health probes the endpoint: any HTTP response means the service is
// there (CES answers non-POSTs with errors, which is still alive);
// transport failure is degraded with the dial detail.
func (c *WSTEPClient) Health(ctx context.Context) Health {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.EndpointURL, nil)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Health{Status: "degraded", Detail: err.Error()}
	}
	_ = resp.Body.Close()
	return Health{Status: "healthy"}
}

const wstepRSTTemplate = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://www.w3.org/2005/08/addressing"
  xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>%s</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken
        ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
        EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`

// rstrEnvelope parses the response leniently by element NAME: real CES
// emits namespace-prefixed XML that strict struct-matching would
// fumble, and encoding/xml matches local names here.
type rstrEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Collection struct {
			Response struct {
				Token struct {
					BinarySecurityToken string `xml:"BinarySecurityToken"`
				} `xml:"RequestedSecurityToken"`
			} `xml:"RequestSecurityTokenResponse"`
		} `xml:"RequestSecurityTokenResponseCollection"`
		Fault struct {
			Reason struct {
				Text string `xml:"Text"`
			} `xml:"Reason"`
		} `xml:"Fault"`
	} `xml:"Body"`
}

// Issue submits the CSR and returns the issued certificate PEM.
func (c *WSTEPClient) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("wstep client %s: CSRPEM is not a PEM certificate request", c.id)
	}
	envelope := fmt.Sprintf(wstepRSTTemplate,
		xmlEscape(c.cfg.EndpointURL),
		xmlEscape(c.cfg.TemplateName),
		base64.StdEncoding.EncodeToString(block.Bytes))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.EndpointURL, strings.NewReader(envelope))
	if err != nil {
		return IssueResult{}, err
	}
	httpReq.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	httpReq.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return IssueResult{}, fmt.Errorf("wstep client %s: %w", c.id, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // error surfaces via status/parse below
	if resp.StatusCode == http.StatusUnauthorized {
		return IssueResult{}, fmt.Errorf("wstep client %s: HTTP 401 (check CES username auth configuration)", c.id)
	}

	var parsed rstrEnvelope
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return IssueResult{}, fmt.Errorf("wstep client %s: unparsable response (HTTP %d): %w", c.id, resp.StatusCode, err)
	}
	if reason := strings.TrimSpace(parsed.Body.Fault.Reason.Text); reason != "" {
		return IssueResult{}, fmt.Errorf("wstep client %s: SOAP fault: %s", c.id, reason)
	}
	certB64 := strings.TrimSpace(parsed.Body.Collection.Response.Token.BinarySecurityToken)
	if certB64 == "" {
		return IssueResult{}, fmt.Errorf("wstep client %s: response carried no certificate token (HTTP %d)", c.id, resp.StatusCode)
	}
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return IssueResult{}, fmt.Errorf("wstep client %s: certificate token is not base64: %w", c.id, err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return IssueResult{}, fmt.Errorf("wstep client %s: issued bytes are not a certificate: %w", c.id, err)
	}
	sum := sha256.Sum256(cert.Raw)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return IssueResult{
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		CertificatePEM:    string(certPEM),
	}, nil
}

// xmlEscape escapes text content for the envelope template.
func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // bytes.Buffer writes cannot fail
	return b.String()
}
