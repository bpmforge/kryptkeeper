// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command gcp-secretmanager is a delivery plugin that stores the certificate
// and key (PEM, certificate first) as a new version of a Google Cloud Secret
// Manager secret. The manifest declares verification "readback": the hub
// calls Verify, which returns the certificate blocks of the exact version
// Push wrote (versions/<N>:access), and fingerprints them itself.
//
// Rollback: the "latest" alias is documented as the most recently created
// version, not the most recent enabled one, so disabling a bad newest
// version would leave "latest" pointing at a disabled version. Rollback
// therefore adds the prior version's payload as a newest version and then
// disables the failed one, best effort. With no prior version the new one
// is only disabled. Old versions are never rewritten.
//
// API shapes (v1): secrets.create, secrets.addVersion (body
// payload.data, base64), secrets.versions.access, .get (name, state),
// .disable. Auth is the service-account JWT bearer flow
// (https://developers.google.com/identity/protocols/oauth2/service-account):
// RS256 JWT, 1 h lifetime, POST to oauth2.googleapis.com/token. The JSON
// key's token_uri is ignored so the host grant is never widened.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(gcp{}) }

func main() {}

type gcp struct{}

// now is injectable so the JWT is deterministic in tests.
var now = time.Now

const (
	apiBase  = "https://secretmanager.googleapis.com/v1/"
	tokenURL = "https://oauth2.googleapis.com/token"
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	projectPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	versionPattern = regexp.MustCompile(`^[0-9]{1,18}$`)
)

// handle is the RollbackHandle: the version that was latest before Push
// ("" = none usable) and the version Push wrote.
type handle struct {
	Prior string `json:"prior"`
	New   string `json:"new"`
}

func locate(inv abi.Invocation) (secret string, err error) {
	if !projectPattern.MatchString(inv.Credential["project_id"]) {
		return "", errors.New("credential project_id is required")
	}
	id := inv.Target["secret_id"]
	if !idPattern.MatchString(id) {
		return "", errors.New("target setting secret_id is required (letters, digits, - and _ only)")
	}
	return "projects/" + inv.Credential["project_id"] + "/secrets/" + id, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signJWT builds the RS256 assertion for the service account.
func signJWT(keyJSON string) (string, error) {
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if json.Unmarshal([]byte(keyJSON), &sa) != nil || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", errors.New("service_account_json must hold client_email and private_key")
	}
	blk, _ := pem.Decode([]byte(sa.PrivateKey))
	if blk == nil {
		return "", errors.New("service account private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return "", errors.New("service account private_key is not PKCS8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("service account private_key is not RSA")
	}
	iat := now().Unix()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": sa.ClientEmail, "scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud": tokenURL, "iat": iat, "exp": iat + 3600,
	})
	signing := b64url(hdr) + "." + b64url(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("signing the token assertion failed")
	}
	return signing + "." + b64url(sig), nil
}

// accessToken exchanges the assertion. Failures carry the status only.
func accessToken(h *delivery.Host, inv abi.Invocation) (string, error) {
	jwt, err := signJWT(inv.Credential["service_account_json"])
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}
	resp, err := h.HTTP(abi.HTTPRequest{Method: "POST", URL: tokenURL,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: []byte(form.Encode())})
	if err != nil {
		return "", errors.New("token request: " + err.Error())
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("token request: HTTP %d", resp.Status)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(resp.Body, &tr) != nil || tr.AccessToken == "" {
		return "", errors.New("token request: no access_token in response")
	}
	return tr.AccessToken, nil
}

type client struct {
	h     *delivery.Host
	token string
}

func newClient(h *delivery.Host, inv abi.Invocation) (*client, error) {
	tok, err := accessToken(h, inv)
	if err != nil {
		return nil, err
	}
	return &client{h: h, token: tok}, nil
}

// do returns the body and status; only a status in want is success. Errors
// carry method, path and status, never a body (an access body is the secret).
func (c *client) do(method, path string, body any, want ...int) ([]byte, int, error) {
	headers := map[string]string{"Authorization": "Bearer " + c.token}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, 0, err
		}
		headers["Content-Type"] = "application/json"
	}
	resp, err := c.h.HTTP(abi.HTTPRequest{Method: method, URL: apiBase + path, Headers: headers, Body: raw})
	short := strings.SplitN(path, "?", 2)[0]
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, short, err)
	}
	for _, w := range want {
		if resp.Status == w {
			return resp.Body, resp.Status, nil
		}
	}
	return nil, resp.Status, fmt.Errorf("%s %s: HTTP %d", method, short, resp.Status)
}

func (gcp) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	if _, err := locate(req.Invocation); err != nil {
		return err
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return err
	}
	_, _, err = c.do("GET", "projects/"+req.Invocation.Credential["project_id"]+"/secrets?pageSize=1", nil, 200)
	return err
}

// versionNumber is the last path segment of a SecretVersion name.
func versionNumber(name string) (string, error) {
	i := strings.LastIndex(name, "/versions/")
	if i < 0 || !versionPattern.MatchString(name[i+len("/versions/"):]) {
		return "", errors.New("response carried no usable secret version name")
	}
	return name[i+len("/versions/"):], nil
}

// access returns the decoded payload of version n.
func (c *client) access(secret, n string) (string, error) {
	body, _, err := c.do("GET", secret+"/versions/"+n+":access", nil, 200)
	if err != nil {
		return "", err
	}
	var r struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if json.Unmarshal(body, &r) != nil {
		return "", errors.New("access response unreadable")
	}
	raw, err := base64.StdEncoding.DecodeString(r.Payload.Data)
	if err != nil {
		return "", errors.New("secret payload is not base64")
	}
	return string(raw), nil
}

// addVersion stores value as a new version and returns its number.
func (c *client) addVersion(secret, value string) (string, error) {
	body, _, err := c.do("POST", secret+":addVersion",
		map[string]any{"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(value))}}, 200)
	if err != nil {
		return "", err
	}
	var v struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &v) != nil {
		return "", errors.New("addVersion response unreadable")
	}
	return versionNumber(v.Name)
}

func (c *client) disable(secret, n string) error {
	_, _, err := c.do("POST", secret+"/versions/"+n+":disable", map[string]any{}, 200)
	return err
}

// ensureSecret creates the secret when it does not exist.
func (c *client) ensureSecret(secret string) error {
	_, status, err := c.do("GET", secret, nil, 200, 404)
	if err != nil {
		return err
	}
	if status == 404 {
		parent, id := secret[:strings.LastIndex(secret, "/secrets/")], secret[strings.LastIndex(secret, "/")+1:]
		_, _, err = c.do("POST", parent+"/secrets?secretId="+url.QueryEscape(id),
			map[string]any{"replication": map[string]any{"automatic": map[string]any{}}}, 200)
	}
	return err
}

// latestEnabled is the number of the latest version when it is enabled.
func (c *client) latestEnabled(secret string) (string, error) {
	body, status, err := c.do("GET", secret+"/versions/latest", nil, 200, 404)
	if err != nil || status == 404 {
		return "", err
	}
	var v struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if json.Unmarshal(body, &v) != nil {
		return "", errors.New("version metadata unreadable")
	}
	if v.State != "ENABLED" {
		return "", nil
	}
	return versionNumber(v.Name)
}

func certBlocks(bundlePEM string) string {
	var out []byte
	rest := []byte(bundlePEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return string(out)
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(b)...)
		}
	}
}

func fingerprint(bundlePEM string) string {
	b, _ := pem.Decode([]byte(certBlocks(bundlePEM)))
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

// restore undoes the version Push wrote.
func (c *client) restore(secret string, hd handle) (string, error) {
	if hd.Prior == "" {
		return "no previous version; new version disabled", c.disable(secret, hd.New)
	}
	old, err := c.access(secret, hd.Prior)
	if err != nil {
		return "", err
	}
	if _, err := c.addVersion(secret, old); err != nil {
		return "", err
	}
	// The restored copy is already latest; disabling the bad version only
	// stops it being read by number, so a failure here does not fail the restore.
	_ = c.disable(secret, hd.New)
	return "", nil
}

func (gcp) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: detail}, nil
	}
	secret, err := locate(req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	fp := fingerprint(req.CertPEM)
	if fp == "" {
		return fail(abi.OutcomeWriteFailed, "certificate is not PEM")
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	if err := c.ensureSecret(secret); err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	prior, err := c.latestEnabled(secret)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	newVersion, err := c.addVersion(secret, req.CertPEM+"\n"+req.KeyPEM)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	hd := handle{Prior: prior, New: newVersion}

	// The plugin's own check only decides whether to restore early; the hub
	// still verifies through Verify.
	got, err := c.access(secret, newVersion)
	if err == nil && fingerprint(got) != fp {
		err = errors.New("version read back does not match the pushed certificate")
	}
	if err != nil {
		detail := err.Error()
		if _, rerr := c.restore(secret, hd); rerr != nil {
			detail += "; RESTORE FAILED: " + rerr.Error()
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}
	raw, _ := json.Marshal(hd)
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(raw)}, nil
}

func parseHandle(s string) (handle, error) {
	var hd handle
	if err := json.Unmarshal([]byte(s), &hd); err != nil || !versionPattern.MatchString(hd.New) || (hd.Prior != "" && !versionPattern.MatchString(hd.Prior)) {
		return handle{}, errors.New("rollback handle is not a Secret Manager version handle")
	}
	return hd, nil
}

// Verify returns the certificate blocks stored in the exact version Push wrote.
func (gcp) Verify(h *delivery.Host, req abi.VerifyRequest) (abi.VerifyResult, error) {
	secret, err := locate(req.Invocation)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	hd, err := parseHandle(req.Handle)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	val, err := c.access(secret, hd.New)
	return abi.VerifyResult{CertPEM: certBlocks(val)}, err
}

func (gcp) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	secret, err := locate(req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	hd, err := parseHandle(req.Handle)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	detail, err := c.restore(secret, hd)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true, Detail: detail}, nil
}
