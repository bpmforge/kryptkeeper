// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package intune implements the Intune SCEP challenge validation REST
// contract that third-party SCEP servers use (W20-23, D-327).
//
// Sources, all read for this implementation:
//   - Overview and Entra app registration:
//     https://learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep
//   - Developer contract:
//     https://learn.microsoft.com/en-us/intune/fundamentals/certificates/ref-scep-api
//   - Microsoft's open-source client, commit eae184eea8f7dab417d3ac29cc3ac39b7db8cace of
//     https://github.com/microsoft/Intune-Resource-Access, under src/CsrValidation/:
//     java/lib/src/main/java/com/microsoft/intune/scepvalidation/{IntuneClient,IntuneScepServiceClient,IntuneScepServiceException}.java
//     and csharp/ScepValidation/{IntuneServiceLocationProvider,IntuneScepValidator}.cs.
//
// The contract in short: get a client-credentials token for the Intune API
// and for Microsoft Graph; ask Graph where the "ScepRequestValidationFEService"
// lives; POST ScepActions/validateRequest with the CSR (the encrypted
// challenge is inside it, in challengePassword: Intune reads it, the server
// never does); issue only on success; then POST successNotification or
// failureNotification. Intune answers {"code","errorDescription"} and never
// names the approved subject: it compares the CSR to what the profile expects.
package intune

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the contract's certificateThumbprint is a SHA-1 thumbprint, an identifier and not a security use
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAuthority and DefaultGraphURL are the public-cloud endpoints.
	DefaultAuthority = "https://login.microsoftonline.com"
	DefaultGraphURL  = "https://graph.microsoft.com"

	// intuneAppID is the Intune service principal's appId (IntuneClient.java intuneAppId).
	intuneAppID = "0000000a-0000-0000-c000-000000000000"
	// intuneScope reproduces the library's scope bytes exactly, double slash
	// included (IntuneClient.java: intuneResourceUrl + "/.default"; the C#
	// library does the same). Do not "fix" it without a tenant to prove it.
	intuneScope = "https://api.manage.microsoft.com//.default"
	graphScope  = "https://graph.microsoft.com/.default"

	validationService = "sceprequestvalidationfeservice" // ScepRequestValidationFEService, lower-cased as the library does
	serviceVersion    = "2018-02-20"

	pathValidate = "ScepActions/validateRequest"
	pathSuccess  = "ScepActions/successNotification"
	pathFailure  = "ScepActions/failureNotification"

	maxResponseBytes = 1 << 20
	tokenSkew        = 2 * time.Minute

	// HResultFail is E_FAIL (0x80004005) as the signed 32-bit value the Java
	// example sends for an hResult (Example.java passes 0x8000ffff, a negative
	// int widened to long). See MS-ERREF:
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
	HResultFail int32 = -2147467259
)

var tenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// ErrUnavailable is wrapped when Intune, Entra or Graph could not give an
// answer (network, token, discovery, HTTP status, malformed body). The caller
// must treat it as a refusal: nothing is issued on an unknown.
var ErrUnavailable = errors.New("intune unavailable")

// UnavailableError says which stage failed. Detail never carries a secret,
// token or CSR.
type UnavailableError struct {
	Stage  string // token, discovery, validate, success_notification, failure_notification
	Detail string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("intune unavailable at %s: %s", e.Stage, e.Detail)
}

// Unwrap lets errors.Is match ErrUnavailable.
func (e *UnavailableError) Unwrap() error { return ErrUnavailable }

// ServiceError is Intune's own refusal: a code other than Success.
type ServiceError struct {
	Code        string // e.g. SubjectNameMismatch, ChallengeExpired
	Description string // Intune's text, cleaned and truncated
	ActivityID  string // the client-request-id, for Intune support
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("intune refused (activity %s): %s: %s", e.ActivityID, e.Code, e.Description)
}

// Connection is one Entra app registration to talk to Intune with.
type Connection struct {
	TenantID         string
	ClientID         string
	CredentialRef    string // outbound credential store id; never the secret
	IssuingAuthority string // certIssuingAuthority in the success notification
}

// Options configures a Manager. Authority and GraphURL are injectable (the
// library has AUTH_AUTHORITY and MS_GRAPH_RESOURCE_URL) so a fake can stand in.
type Options struct {
	Authority string
	GraphURL  string
	// HTTP must be the hub's egress-guarded client.
	HTTP *http.Client
	// Resolve returns the plaintext of a credential store entry.
	Resolve   func(ctx context.Context, ref string) ([]byte, error)
	UserAgent string // callerInfo and UserAgent: product and version
	Now       func() time.Time
}

// Manager holds one token and service-location cache per Entra app, so many
// SCEP requests share them (the library's advice).
type Manager struct {
	opt     Options
	mu      sync.Mutex
	clients map[string]*client
}

// NewManager returns a Manager; HTTP and Resolve are required.
func NewManager(opt Options) (*Manager, error) {
	if opt.HTTP == nil || opt.Resolve == nil {
		return nil, errors.New("intune: HTTP client and credential resolver are required")
	}
	if opt.Authority == "" {
		opt.Authority = DefaultAuthority
	}
	if opt.GraphURL == "" {
		opt.GraphURL = DefaultGraphURL
	}
	if opt.UserAgent == "" {
		opt.UserAgent = "Kryptkeeper"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	opt.Authority = strings.TrimRight(opt.Authority, "/")
	opt.GraphURL = strings.TrimRight(opt.GraphURL, "/")
	return &Manager{opt: opt, clients: map[string]*client{}}, nil
}

type cachedToken struct {
	value   string
	expires time.Time
}

type client struct {
	m    *Manager
	conn Connection

	mu       sync.Mutex
	tokens   map[string]cachedToken
	endpoint string
}

func (m *Manager) clientFor(c Connection) (*client, error) {
	if !tenantRE.MatchString(c.TenantID) {
		return nil, fmt.Errorf("%w: tenant id is not a tenant GUID or domain", ErrCredential)
	}
	if c.ClientID == "" || c.CredentialRef == "" {
		return nil, fmt.Errorf("%w: client id and credential are required", ErrCredential)
	}
	key := c.TenantID + "|" + c.ClientID + "|" + c.CredentialRef
	m.mu.Lock()
	defer m.mu.Unlock()
	cl, ok := m.clients[key]
	if !ok {
		cl = &client{m: m, conn: c, tokens: map[string]cachedToken{}}
		m.clients[key] = cl
	}
	cl.conn = c
	return cl, nil
}

// Validate asks Intune whether the CSR carries a live challenge for it. A nil
// return is the only permission to issue. transactionID is the SCEP
// transaction id.
func (m *Manager) Validate(ctx context.Context, c Connection, transactionID string, csrDER []byte) error {
	cl, err := m.clientFor(c)
	if err != nil {
		return err
	}
	body := map[string]any{"request": map[string]string{
		"transactionId": transactionID, "certificateRequest": base64.StdEncoding.EncodeToString(csrDER), "callerInfo": m.opt.UserAgent,
	}}
	return cl.post(ctx, "validate", pathValidate, body)
}

// NotifySuccess tells Intune a certificate was issued for the request. The
// caller must not return the certificate to the device if this fails.
func (m *Manager) NotifySuccess(ctx context.Context, c Connection, transactionID string, csrDER []byte, cert *x509.Certificate) error {
	cl, err := m.clientFor(c)
	if err != nil {
		return err
	}
	thumb := sha1.Sum(cert.Raw) //nolint:gosec // see import
	authority := c.IssuingAuthority
	if authority == "" {
		authority = cert.Issuer.String()
	}
	body := map[string]any{"notification": map[string]string{
		"transactionId":                transactionID,
		"certificateRequest":           base64.StdEncoding.EncodeToString(csrDER),
		"certificateThumbprint":        strings.ToUpper(hex.EncodeToString(thumb[:])),
		"certificateSerialNumber":      strings.ToUpper(cert.SerialNumber.Text(16)),
		"certificateExpirationDateUtc": cert.NotAfter.UTC().Format("2006-01-02T15:04:05.000Z"),
		"issuingCertificateAuthority":  authority,
		"callerInfo":                   m.opt.UserAgent,
	}}
	return cl.post(ctx, "success_notification", pathSuccess, body)
}

// NotifyFailure tells Intune the hub could not issue after a successful
// validation. It is not for Validate's own failures (ref-scep-api).
func (m *Manager) NotifyFailure(ctx context.Context, c Connection, transactionID string, csrDER []byte, hresult int32, description string) error {
	cl, err := m.clientFor(c)
	if err != nil {
		return err
	}
	if description == "" {
		description = "certificate issuance failed"
	}
	body := map[string]any{"notification": map[string]any{
		"transactionId": transactionID, "certificateRequest": base64.StdEncoding.EncodeToString(csrDER),
		"hResult": hresult, "errorDescription": clean(description, 200), "callerInfo": m.opt.UserAgent,
	}}
	return cl.post(ctx, "failure_notification", pathFailure, body)
}

// newUUID is a random version-4 UUID for client-request-id. It is local so
// the package needs no module that go.mod lists only as indirect.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("intune: no randomness: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func unavailable(stage, format string, args ...any) error {
	return &UnavailableError{Stage: stage, Detail: fmt.Sprintf(format, args...)}
}

// clean keeps Intune-supplied text printable and short enough for an audit row.
func clean(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// token returns a cached or fresh client-credentials token for scope.
func (c *client) token(ctx context.Context, stage, scope string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.m.opt.Now()
	if t, ok := c.tokens[scope]; ok && now.Before(t.expires) {
		return t.value, nil
	}
	payload, err := c.m.opt.Resolve(ctx, c.conn.CredentialRef)
	if err != nil {
		return "", unavailable(stage, "credential %q could not be read", c.conn.CredentialRef)
	}
	cred, err := ParseCredential(payload)
	if err != nil {
		return "", unavailable(stage, "%v", err)
	}
	tokenURL := c.m.opt.Authority + "/" + url.PathEscape(c.conn.TenantID) + "/oauth2/v2.0/token"
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.conn.ClientID}, "scope": {scope}}
	if err := cred.addTo(form, c.conn.ClientID, tokenURL, now); err != nil {
		return "", unavailable(stage, "client assertion could not be built")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", unavailable(stage, "token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, status, err := c.do(req)
	if err != nil {
		return "", unavailable(stage, "token endpoint unreachable: %v", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
	}
	if json.Unmarshal(body, &tr) != nil {
		tr.AccessToken = "" // not a token answer: refused below
	}
	if status != http.StatusOK || tr.AccessToken == "" {
		// Only the OAuth error code (invalid_client, ...) is repeated; the
		// body can echo request fields.
		return "", unavailable(stage, "token endpoint answered %d %s", status, clean(tr.Error, 40))
	}
	ttl := time.Duration(tr.ExpiresIn)*time.Second - tokenSkew
	if ttl < 0 {
		ttl = 0
	}
	c.tokens[scope] = cachedToken{value: tr.AccessToken, expires: now.Add(ttl)}
	return tr.AccessToken, nil
}

func (c *client) dropToken(scope string) {
	c.mu.Lock()
	delete(c.tokens, scope)
	c.mu.Unlock()
}

func (c *client) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.m.opt.HTTP.Do(req)
	if err != nil {
		// url.Error repeats the URL: it holds no secret (the form is in the body).
		return nil, 0, errors.New(clean(err.Error(), 200))
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, errors.New("response read failed")
	}
	return b, resp.StatusCode, nil
}

// serviceURL finds ScepRequestValidationFEService through Graph, as the
// library does: GET {graph}/v1.0/servicePrincipals/appId={intune}/endpoints,
// providerName (case-insensitive) to uri. The location is cached and cleared
// when a call to it fails to connect.
func (c *client) serviceURL(ctx context.Context) (string, error) {
	c.mu.Lock()
	cached := c.endpoint
	c.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	tok, err := c.token(ctx, "discovery", graphScope)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.m.opt.GraphURL+"/v1.0/servicePrincipals/appId="+intuneAppID+"/endpoints", nil)
	if err != nil {
		return "", unavailable("discovery", "request could not be built")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("client-request-id", newUUID())
	body, status, err := c.do(req)
	if err != nil {
		return "", unavailable("discovery", "graph unreachable: %v", err)
	}
	if status == http.StatusUnauthorized {
		c.dropToken(graphScope)
	}
	if status != http.StatusOK {
		return "", unavailable("discovery", "graph answered %d", status)
	}
	var out struct {
		Value []struct {
			ProviderName string `json:"providerName"`
			URI          string `json:"uri"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", unavailable("discovery", "graph answer is not the endpoints list")
	}
	for _, e := range out.Value {
		if strings.ToLower(e.ProviderName) != validationService {
			continue
		}
		u, err := url.Parse(e.URI)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return "", unavailable("discovery", "the validation service location is not an https URL")
		}
		found := strings.TrimRight(e.URI, "/")
		c.mu.Lock()
		c.endpoint = found
		c.mu.Unlock()
		return found, nil
	}
	return "", unavailable("discovery", "graph does not list ScepRequestValidationFEService for this tenant")
}

// post sends one ScepActions call. Intune's reply is 2xx with
// {"code","errorDescription"}; code Success is the only pass. A non-2xx, a
// non-JSON body or any transport error is "unavailable", never a pass.
func (c *client) post(ctx context.Context, stage, path string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return unavailable(stage, "request could not be encoded")
	}
	activity := newUUID()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		base, err := c.serviceURL(ctx)
		if err != nil {
			return err
		}
		tok, err := c.token(ctx, stage, intuneScope)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+path, bytes.NewReader(raw))
		if err != nil {
			return unavailable(stage, "request could not be built")
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("client-request-id", activity)
		req.Header.Set("api-version", serviceVersion)
		req.Header.Set("UserAgent", c.m.opt.UserAgent)
		body, status, derr := c.do(req)
		if derr != nil {
			// The service may have moved: forget its location and look it up
			// once more, as the library does on a failed connection.
			c.mu.Lock()
			c.endpoint = ""
			c.mu.Unlock()
			lastErr = unavailable(stage, "intune service unreachable: %v", derr)
			continue
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			c.dropToken(intuneScope)
			lastErr = unavailable(stage, "intune service answered 401")
			continue
		}
		if status < 200 || status >= 300 {
			return unavailable(stage, "intune service answered %d", status)
		}
		var res struct {
			Code             string `json:"code"`
			ErrorDescription string `json:"errorDescription"`
		}
		if err := json.Unmarshal(body, &res); err != nil || res.Code == "" {
			return unavailable(stage, "intune answer has no code")
		}
		if res.Code != "Success" {
			return &ServiceError{Code: clean(res.Code, 64), Description: clean(res.ErrorDescription, 200), ActivityID: activity}
		}
		return nil
	}
	return lastErr
}
