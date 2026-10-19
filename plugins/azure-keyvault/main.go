// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command azure-keyvault is a delivery plugin that stores the certificate and
// key as a new version of an Azure Key Vault secret (PEM, certificate first).
// The manifest declares verification "readback": the hub calls Verify, which
// returns the certificate blocks of the exact version Push wrote, and
// fingerprints them itself.
//
// Rollback: Key Vault has no way to make an older version current, and its
// documentation does not promise that an unversioned read skips a disabled
// newest version. So rollback writes the prior version's value as a newest
// version (the same approach as the Vault plugin) and then disables the
// failed version, best effort. With no prior version the new one is only
// disabled. Old versions are never rewritten.
//
// API shapes (api-version 7.4): Set Secret (PUT /secrets/{name}), Get Secret
// (GET /secrets/{name}/{version}, version optional), Update Secret
// (PATCH /secrets/{name}/{version}); SecretBundle has id, value and
// attributes.enabled. Token: client-credentials grant on the Microsoft
// identity platform v2 endpoint with scope https://vault.azure.net/.default.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(akv{}) }

func main() {}

type akv struct{}

const apiVersion = "7.4"

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)
	// A Key Vault version id is 32 hex characters; accept a generous token.
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// handle is the RollbackHandle: the version current before Push ("" = the
// secret had none) and the version Push wrote.
type handle struct {
	Prior string `json:"prior"`
	New   string `json:"new"`
}

func secretName(inv abi.Invocation) (string, error) {
	n := inv.Target["secret_name"]
	if !namePattern.MatchString(n) {
		return "", errors.New("target setting secret_name is required (letters, digits and - only)")
	}
	return n, nil
}

// accessToken runs the client-credentials grant. Failures carry the status
// only: the response and request hold the client secret.
func accessToken(h *delivery.Host, inv abi.Invocation) (string, error) {
	tenant := url.PathEscape(inv.Credential["tenant_id"])
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {inv.Credential["client_id"]},
		"client_secret": {inv.Credential["client_secret"]},
		"scope":         {"https://vault.azure.net/.default"},
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method: "POST", URL: "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: []byte(form.Encode()),
	})
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
	vault string
	token string
}

func newClient(h *delivery.Host, inv abi.Invocation) (*client, error) {
	tok, err := accessToken(h, inv)
	if err != nil {
		return nil, err
	}
	return &client{h: h, vault: strings.TrimRight(inv.Credential["vault_url"], "/"), token: tok}, nil
}

// do returns the body and status. Only a status in want is success; errors
// carry method, path and status, never a body (a GET body is the secret).
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
	resp, err := c.h.HTTP(abi.HTTPRequest{Method: method, URL: c.vault + path, Headers: headers, Body: raw})
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, strings.SplitN(path, "?", 2)[0], err)
	}
	for _, w := range want {
		if resp.Status == w {
			return resp.Body, resp.Status, nil
		}
	}
	return nil, resp.Status, fmt.Errorf("%s %s: HTTP %d", method, strings.SplitN(path, "?", 2)[0], resp.Status)
}

func (akv) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	if _, err := secretName(req.Invocation); err != nil {
		return err
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return err
	}
	_, _, err = c.do("GET", "/secrets?api-version="+apiVersion+"&maxresults=1", nil, 200)
	return err
}

type bundle struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func (b bundle) version() (string, error) {
	v := b.ID[strings.LastIndex(b.ID, "/")+1:]
	if !versionPattern.MatchString(v) {
		return "", errors.New("response carried no usable secret version id")
	}
	return v, nil
}

func (c *client) get(name, version string) (bundle, int, error) {
	path := "/secrets/" + name
	if version != "" {
		path += "/" + version
	}
	body, status, err := c.do("GET", path+"?api-version="+apiVersion, nil, 200)
	if err != nil {
		return bundle{}, status, err
	}
	var b bundle
	if json.Unmarshal(body, &b) != nil {
		return bundle{}, status, errors.New("secret bundle unreadable")
	}
	return b, status, nil
}

// set stores value as a new version and returns its version id.
func (c *client) set(name, value string) (string, error) {
	body, _, err := c.do("PUT", "/secrets/"+name+"?api-version="+apiVersion,
		map[string]string{"value": value, "contentType": "application/x-pem-file"}, 200)
	if err != nil {
		return "", err
	}
	var b bundle
	if json.Unmarshal(body, &b) != nil {
		return "", errors.New("secret bundle unreadable")
	}
	return b.version()
}

func (c *client) disable(name, version string) error {
	_, _, err := c.do("PATCH", "/secrets/"+name+"/"+version+"?api-version="+apiVersion,
		map[string]any{"attributes": map[string]bool{"enabled": false}}, 200)
	return err
}

// certBlocks keeps only the CERTIFICATE blocks of a stored PEM bundle, so
// the private key never leaves the plugin through Verify.
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
func (c *client) restore(name string, hd handle) (string, error) {
	if hd.Prior == "" {
		return "no previous version; new version disabled", c.disable(name, hd.New)
	}
	old, _, err := c.get(name, hd.Prior)
	if err != nil {
		return "", err
	}
	if _, err := c.set(name, old.Value); err != nil {
		return "", err
	}
	// The restored copy is already the newest version; disabling the bad one
	// only stops it being read by id, so a failure here does not fail the restore.
	_ = c.disable(name, hd.New)
	return "", nil
}

func (akv) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: detail}, nil
	}
	name, err := secretName(req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	value := req.CertPEM + "\n" + req.KeyPEM
	fp := fingerprint(req.CertPEM)
	if fp == "" {
		return fail(abi.OutcomeWriteFailed, "certificate is not PEM")
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}

	// A secret with no version, or whose newest version is disabled (403),
	// has nothing to roll back to.
	prior := ""
	switch cur, status, err := c.get(name, ""); {
	case err == nil:
		if prior, err = cur.version(); err != nil {
			return fail(abi.OutcomeWriteFailed, err.Error())
		}
	case status != 404 && status != 403:
		return fail(abi.OutcomeWriteFailed, err.Error())
	}

	newVersion, err := c.set(name, value)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	hd := handle{Prior: prior, New: newVersion}

	// The plugin's own check only decides whether to restore early; the hub
	// still verifies through Verify.
	got, _, err := c.get(name, newVersion)
	if err == nil && fingerprint(got.Value) != fp {
		err = errors.New("version read back does not match the pushed certificate")
	}
	if err != nil {
		detail := err.Error()
		if _, rerr := c.restore(name, hd); rerr != nil {
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
		return handle{}, errors.New("rollback handle is not a Key Vault version handle")
	}
	return hd, nil
}

// Verify returns the certificate blocks stored in the exact version Push wrote.
func (akv) Verify(h *delivery.Host, req abi.VerifyRequest) (abi.VerifyResult, error) {
	name, err := secretName(req.Invocation)
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
	b, _, err := c.get(name, hd.New)
	return abi.VerifyResult{CertPEM: certBlocks(b.Value)}, err
}

func (akv) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	name, err := secretName(req.Invocation)
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
	detail, err := c.restore(name, hd)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true, Detail: detail}, nil
}
