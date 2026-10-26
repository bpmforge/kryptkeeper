// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
)

// W36-07: Google Cloud Certificate Authority Service, REST only. No Google
// SDK: the OAuth2 service-account flow is a short RFC 7523 JWT bearer grant
// and CAS is three JSON calls, so a dependency would buy nothing.
//
// Neither internal/keystore nor internal/cloudinventory mints service-account
// tokens (both read GOOGLE_ACCESS_TOKEN), so the minting lives here.

const (
	gcpCASScope         = "https://www.googleapis.com/auth/cloud-platform"
	gcpMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

// GCPCASConfig locates and authenticates a CAS CA pool.
type GCPCASConfig struct {
	Project  string
	Location string
	CAPool   string
	// CertificateAuthorityID pins issuance to one CA in the pool
	// (issuingCertificateAuthorityId); empty lets CAS choose.
	CertificateAuthorityID string
	// CertificateTemplate is the full resource name
	// projects/*/locations/*/certificateTemplates/*; optional.
	CertificateTemplate string
	LifetimeDays        int
	// BaseURL defaults to https://privateca.googleapis.com.
	BaseURL string
	// Auth is "" / "service_account" (uses ServiceAccountJSON) or "ambient"
	// (GCE metadata server).
	Auth string
	// ServiceAccountJSON is the key file content. Never logged or echoed.
	ServiceAccountJSON string
	// TokenURL overrides the key's token_uri; MetadataURL overrides the GCE
	// metadata token endpoint. Both exist so tests can point at httptest.
	TokenURL    string
	MetadataURL string
	// MetadataClient carries the ambient-auth token request. It must be able
	// to reach only the fixed GCE metadata endpoint; the egress-guarded client
	// refuses link-local space by design. Required when Auth is "ambient".
	MetadataClient *http.Client
}

// GCPCASConnector is an IssuerConnector + RevokingConnector for CAS.
type GCPCASConnector struct {
	id     string
	cfg    GCPCASConfig
	client *http.Client

	mu        sync.Mutex
	lastError string
	token     string
	tokenExp  time.Time
	// now is overridable for token-expiry tests.
	now func() time.Time
}

func NewGCPCASConnector(id string, cfg GCPCASConfig, client *http.Client) *GCPCASConnector {
	if client == nil {
		client = egress.NewClient(egress.Policy{RequireHTTPS: true, MaxRedirects: 0})
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://privateca.googleapis.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.LifetimeDays <= 0 {
		cfg.LifetimeDays = 90
	}
	if cfg.MetadataURL == "" {
		cfg.MetadataURL = gcpMetadataTokenURL
	}
	return &GCPCASConnector{id: id, cfg: cfg, client: client, now: time.Now}
}

func (c *GCPCASConnector) ID() string     { return c.id }
func (c *GCPCASConnector) Type() string   { return "gcp_cas" }
func (c *GCPCASConnector) Origin() string { return "synced" }

func (c *GCPCASConnector) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

func (c *GCPCASConnector) poolPath() string {
	return "/v1/projects/" + url.PathEscape(c.cfg.Project) + "/locations/" + url.PathEscape(c.cfg.Location) +
		"/caPools/" + url.PathEscape(c.cfg.CAPool)
}

// Health reads the CA pool (caPools.get, read-only) and carries the last
// issue-path error so a throttled or denied connector shows degraded.
// https://docs.cloud.google.com/certificate-authority-service/docs/reference/rest/v1/projects.locations.caPools/get
func (c *GCPCASConnector) Health(ctx context.Context) Health {
	c.mu.Lock()
	last := c.lastError
	c.mu.Unlock()
	_, err := c.do(ctx, http.MethodGet, c.poolPath(), nil, nil)
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

type gcpSAKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// accessToken returns a cached OAuth2 token, minting a new one when within
// a minute of expiry.
func (c *GCPCASConnector) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Add(time.Minute).Before(c.tokenExp) {
		return c.token, nil
	}
	var (
		tr  gcpTokenResponse
		err error
	)
	if c.cfg.Auth == "ambient" {
		tr, err = c.metadataToken(ctx)
	} else {
		tr, err = c.serviceAccountToken(ctx)
	}
	if err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("gcp_cas %s: token endpoint returned no access_token", c.id)
	}
	c.token = tr.AccessToken
	c.tokenExp = c.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

// metadataToken: https://cloud.google.com/compute/docs/access/authenticate-workloads#applications
func (c *GCPCASConnector) metadataToken(ctx context.Context) (gcpTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.MetadataURL, nil)
	if err != nil {
		return gcpTokenResponse{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	if c.cfg.MetadataClient == nil {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: ambient auth needs a metadata client", c.id)
	}
	return c.fetchTokenWith(c.cfg.MetadataClient, req)
}

// serviceAccountToken is the RFC 7523 JWT bearer grant against token_uri.
// https://developers.google.com/identity/protocols/oauth2/service-account#httprest
func (c *GCPCASConnector) serviceAccountToken(ctx context.Context) (gcpTokenResponse, error) {
	var key gcpSAKey
	if err := json.Unmarshal([]byte(c.cfg.ServiceAccountJSON), &key); err != nil {
		// err text from encoding/json can echo input fragments; do not wrap it.
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: service account JSON is not valid JSON", c.id)
	}
	if key.ClientEmail == "" || key.PrivateKey == "" {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: service account JSON lacks client_email or private_key", c.id)
	}
	tokenURI := c.cfg.TokenURL
	if tokenURI == "" {
		tokenURI = key.TokenURI
	}
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: service account private_key is not PEM", c.id)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: service account private_key is not PKCS#8", c.id)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: service account private_key is not RSA", c.id)
	}

	now := c.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": key.ClientEmail, "scope": gcpCASScope, "aud": tokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	b64 := base64.RawURLEncoding
	signingInput := b64.EncodeToString(hdr) + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: signing JWT assertion failed", c.id)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signingInput + "." + b64.EncodeToString(sig)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return gcpTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.fetchTokenWith(c.client, req)
}

func (c *GCPCASConnector) fetchTokenWith(client *http.Client, req *http.Request) (gcpTokenResponse, error) {
	resp, err := client.Do(req)
	if err != nil {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: token request failed: %w", c.id, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // status below carries failures
	if resp.StatusCode != http.StatusOK {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: token endpoint HTTP %d: %s", c.id, resp.StatusCode, truncate(raw))
	}
	var tr gcpTokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return gcpTokenResponse{}, fmt.Errorf("gcp_cas %s: token response unparseable", c.id)
	}
	return tr, nil
}

// do calls CAS; path already carries /v1/..., query is optional.
func (c *GCPCASConnector) do(ctx context.Context, method, path string, query url.Values, payload any) ([]byte, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	u := c.cfg.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // status below carries failures
	// Google surfaces quota as HTTP 429 and as a JSON status
	// RESOURCE_EXHAUSTED (sometimes on another HTTP code); treat both alike.
	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 400 && gcpResourceExhausted(raw)) {
		return raw, &RateLimitError{ConnectorID: c.id, Reason: "upstream_429",
			RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Err:        fmt.Errorf("gcp_cas %s: rate limited (HTTP %d)", path, resp.StatusCode)}
	}
	if resp.StatusCode >= 400 {
		return raw, fmt.Errorf("gcp_cas %s: HTTP %d: %s", path, resp.StatusCode, truncate(raw))
	}
	return raw, nil
}

func gcpResourceExhausted(raw []byte) bool {
	var e struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	return json.Unmarshal(raw, &e) == nil && e.Error.Status == "RESOURCE_EXHAUSTED"
}

type gcpCASCertificate struct {
	Name                string   `json:"name"`
	PEMCertificate      string   `json:"pemCertificate"`
	PEMCertificateChain []string `json:"pemCertificateChain"`
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Issue creates a certificate from the CSR. CAS issues synchronously.
// https://docs.cloud.google.com/certificate-authority-service/docs/reference/rest/v1/projects.locations.caPools.certificates/create
func (c *GCPCASConnector) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	res, err := c.issue(ctx, req)
	c.recordError(err)
	return res, err
}

func (c *GCPCASConnector) issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return IssueResult{}, fmt.Errorf("gcp_cas %s: CSRPEM is not a PEM certificate request", c.id)
	}
	if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
		return IssueResult{}, fmt.Errorf("gcp_cas %s: CSR unparseable: %w", c.id, err)
	}
	// certificateId is unique per location and [a-zA-Z0-9_-]{1,63}.
	sum := sha256.Sum256(block.Bytes)
	certID := fmt.Sprintf("kk-%s-%d", hex.EncodeToString(sum[:])[:24], time.Now().Unix())

	q := url.Values{"certificateId": {certID}, "requestId": {newUUID()}}
	if c.cfg.CertificateAuthorityID != "" {
		q.Set("issuingCertificateAuthorityId", c.cfg.CertificateAuthorityID)
	}
	body := map[string]any{
		"pemCsr":   req.CSRPEM,
		"lifetime": fmt.Sprintf("%ds", c.cfg.LifetimeDays*86400),
	}
	if c.cfg.CertificateTemplate != "" {
		body["certificateTemplate"] = c.cfg.CertificateTemplate
	}
	raw, err := c.do(ctx, http.MethodPost, c.poolPath()+"/certificates", q, body)
	if err != nil {
		return IssueResult{}, err
	}
	var cert gcpCASCertificate
	if err := json.Unmarshal(raw, &cert); err != nil {
		return IssueResult{}, fmt.Errorf("gcp_cas %s: create response unparseable: %w", c.id, err)
	}
	leaf, _ := pem.Decode([]byte(cert.PEMCertificate))
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return IssueResult{}, fmt.Errorf("gcp_cas %s: response pemCertificate is not a PEM certificate", c.id)
	}
	parsed, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		return IssueResult{}, fmt.Errorf("gcp_cas %s: issued leaf unparseable: %w", c.id, err)
	}
	var out strings.Builder
	out.WriteString(strings.TrimSpace(cert.PEMCertificate) + "\n")
	for _, p := range cert.PEMCertificateChain {
		out.WriteString(strings.TrimSpace(p) + "\n")
	}
	fp := sha256.Sum256(parsed.Raw)
	return IssueResult{FingerprintSHA256: hex.EncodeToString(fp[:]), CertificatePEM: out.String()}, nil
}

// gcpRevocationReason maps RFC 5280 CRLReason codes to CAS RevocationReason.
// removeFromCRL (8) has no CAS equivalent and maps to unspecified.
// https://docs.cloud.google.com/certificate-authority-service/docs/reference/rest/v1/RevocationReason
func gcpRevocationReason(code int) string {
	switch code {
	case 1:
		return "KEY_COMPROMISE"
	case 2:
		return "CERTIFICATE_AUTHORITY_COMPROMISE"
	case 3:
		return "AFFILIATION_CHANGED"
	case 4:
		return "SUPERSEDED"
	case 5:
		return "CESSATION_OF_OPERATION"
	case 6:
		return "CERTIFICATE_HOLD"
	case 9:
		return "PRIVILEGE_WITHDRAWN"
	case 10:
		return "ATTRIBUTE_AUTHORITY_COMPROMISE"
	}
	return "REVOCATION_REASON_UNSPECIFIED"
}

// Revoke finds the CAS certificate by serial (CAS names are ours, but the
// caller only knows the serial) and revokes it. Refuses 0 or >1 matches.
// List filter field and operators (= and != only, no wildcard):
// https://docs.cloud.google.com/certificate-authority-service/docs/sorting-filtering-certificates
// Revoke: https://docs.cloud.google.com/certificate-authority-service/docs/reference/rest/v1/projects.locations.caPools.certificates/revoke
func (c *GCPCASConnector) Revoke(ctx context.Context, req RevokeRequest) error {
	serial := strings.ToLower(strings.TrimLeft(strings.TrimSpace(req.SerialHex), "0"))
	if serial == "" && req.CertificatePEM != "" {
		if b, _ := pem.Decode([]byte(req.CertificatePEM)); b != nil {
			if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
				serial = cert.SerialNumber.Text(16)
			}
		}
	}
	if serial == "" {
		return fmt.Errorf("gcp_cas %s: revoke needs a serial number", c.id)
	}
	// The serial is spliced into a filter expression: hex only.
	if strings.Trim(serial, "0123456789abcdef") != "" {
		return fmt.Errorf("gcp_cas %s: revoke serial is not hex", c.id)
	}
	err := c.revoke(ctx, serial, req.Reason)
	c.recordError(err)
	return err
}

func (c *GCPCASConnector) revoke(ctx context.Context, serial string, reason int) error {
	q := url.Values{"filter": {"certificate_description.subject_description.hex_serial_number=" + serial}}
	raw, err := c.do(ctx, http.MethodGet, c.poolPath()+"/certificates", q, nil)
	if err != nil {
		return err
	}
	var list struct {
		Certificates []gcpCASCertificate `json:"certificates"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("gcp_cas %s: list response unparseable: %w", c.id, err)
	}
	if len(list.Certificates) != 1 {
		return fmt.Errorf("gcp_cas %s: revoke by serial matched %d certificates, need exactly 1", c.id, len(list.Certificates))
	}
	name := list.Certificates[0].Name
	// The name is spliced into a URL path; it must be inside our pool.
	prefix := strings.TrimPrefix(c.poolPath(), "/v1/") + "/certificates/"
	if !strings.HasPrefix(name, prefix) || strings.ContainsAny(strings.TrimPrefix(name, prefix), "/?#") {
		return fmt.Errorf("gcp_cas %s: listed certificate name is outside the configured pool", c.id)
	}
	_, err = c.do(ctx, http.MethodPost, "/v1/"+name+":revoke", nil, map[string]string{
		"reason":    gcpRevocationReason(reason),
		"requestId": newUUID(),
	})
	return err
}

var (
	_ IssuerConnector   = (*GCPCASConnector)(nil)
	_ RevokingConnector = (*GCPCASConnector)(nil)
)
