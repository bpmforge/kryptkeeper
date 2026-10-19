// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command aws-secretsmanager is a delivery plugin that stores the
// certificate and key as a new version of an AWS Secrets Manager secret and
// makes it AWSCURRENT. The manifest declares verification "readback": the
// hub calls Verify, which returns the certificate blocks of the exact
// VersionId Push wrote (GetSecretValue with that VersionId), and fingerprints
// them itself.
//
// SecretString is JSON {certificate, private_key, fingerprint_sha256}.
//
// Rollback: PutSecretValue with VersionStages AWSCURRENT moves AWSCURRENT to
// the new version and AWSPREVIOUS to the old one (AWS does that itself).
// Undoing it is UpdateSecretVersionStage moving AWSCURRENT back to the prior
// version; nothing is rewritten or deleted. With no prior version the new
// one stays current and the rollback reports it did nothing.
//
// The version id is derived from the leaf fingerprint (ClientRequestToken),
// so re-delivering the same certificate is idempotent.
//
// API shapes verified against the AWS Secrets Manager API reference:
// X-Amz-Target secretsmanager.<Action>, JSON 1.1, DescribeSecret
// VersionIdsToStages, PutSecretValue, GetSecretValue, UpdateSecretVersionStage.
//
// Minimum IAM: secretsmanager:DescribeSecret, PutSecretValue,
// GetSecretValue, UpdateSecretVersionStage (plus kms:Decrypt and
// kms:GenerateDataKey for a customer-managed key).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(sm{}) }

func main() {}

type sm struct{}

const stageCurrent = "AWSCURRENT"

// regions mirrors the hosts in manifest.json; a manifest cannot hold wildcards.
var regions = map[string]bool{
	"us-east-1": true, "us-east-2": true, "us-west-1": true, "us-west-2": true, "eu-west-1": true,
	"eu-west-2": true, "eu-central-1": true, "ap-southeast-1": true, "ap-southeast-2": true, "ap-northeast-1": true,
}

var (
	secretIDPattern = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)
	// A VersionId is 32 to 64 characters; the ones this plugin writes are UUIDs.
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9-]{32,64}$`)
	errTypePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

// now is injectable so tests sign with a fixed clock.
var now = time.Now

// handle is the RollbackHandle: the version that was AWSCURRENT before Push
// ("" = none) and the version Push wrote.
type handle struct {
	Prior string `json:"prior"`
	New   string `json:"new"`
}

type client struct {
	h      *delivery.Host
	c      creds
	region string
	secret string
}

func newClient(h *delivery.Host, inv abi.Invocation) (*client, error) {
	cr := inv.Credential
	c := &client{h: h, c: creds{cr["access_key_id"], cr["secret_access_key"], cr["session_token"]}, region: cr["region"], secret: inv.Target["secret_id"]}
	switch {
	case c.c.AccessKeyID == "" || c.c.SecretAccessKey == "":
		return nil, errors.New("credential access_key_id and secret_access_key are required")
	case !regions[c.region]:
		return nil, fmt.Errorf("credential region %q is not one this plugin's manifest grants; fork the manifest to add it", c.region)
	case !secretIDPattern.MatchString(c.secret):
		return nil, errors.New("target setting secret_id is required (name or ARN)")
	}
	return c, nil
}

// call is an AWS JSON 1.1 request. Errors carry the action, status and the
// service's error type, never a body: GetSecretValue replies hold the key.
func (c *client) call(action string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req := abi.HTTPRequest{
		Method: "POST", URL: "https://secretsmanager." + c.region + ".amazonaws.com/", Body: body,
		Headers: map[string]string{"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "secretsmanager." + action},
	}
	if err := signV4(&req, "secretsmanager", c.region, c.c, now()); err != nil {
		return err
	}
	resp, err := c.h.HTTP(req)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.Status != 200 {
		var e struct {
			Type string `json:"__type"`
		}
		_ = json.Unmarshal(resp.Body, &e)
		if i := strings.LastIndex(e.Type, "#"); i >= 0 {
			e.Type = e.Type[i+1:]
		}
		if !errTypePattern.MatchString(e.Type) {
			e.Type = ""
		}
		return fmt.Errorf("%s: HTTP %d %s", action, resp.Status, e.Type)
	}
	if out == nil {
		return nil
	}
	if json.Unmarshal(resp.Body, out) != nil {
		return fmt.Errorf("%s: response unreadable", action)
	}
	return nil
}

// currentVersion is the version holding AWSCURRENT ("" if none).
func (c *client) currentVersion() (string, error) {
	var out struct {
		VersionIdsToStages map[string][]string `json:"VersionIdsToStages"`
	}
	if err := c.call("DescribeSecret", map[string]string{"SecretId": c.secret}, &out); err != nil {
		return "", err
	}
	for id, stages := range out.VersionIdsToStages {
		for _, s := range stages {
			if s == stageCurrent {
				return id, nil
			}
		}
	}
	return "", nil
}

type secretValue struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key,omitempty"`
	Fingerprint string `json:"fingerprint_sha256"`
}

// token is a UUID-shaped ClientRequestToken derived from the fingerprint.
func token(fp string) string {
	s := sha256.Sum256([]byte(fp))
	h := hex.EncodeToString(s[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (c *client) put(v secretValue) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var out struct {
		VersionId string `json:"VersionId"`
	}
	err = c.call("PutSecretValue", map[string]any{
		"SecretId": c.secret, "SecretString": string(raw),
		"ClientRequestToken": token(v.Fingerprint), "VersionStages": []string{stageCurrent},
	}, &out)
	if err == nil && !versionPattern.MatchString(out.VersionId) {
		err = errors.New("PutSecretValue: no usable VersionId in response")
	}
	return out.VersionId, err
}

// get returns the certificate PEM stored in one version.
func (c *client) get(version string) (string, error) {
	var out struct {
		SecretString string `json:"SecretString"`
	}
	if err := c.call("GetSecretValue", map[string]string{"SecretId": c.secret, "VersionId": version}, &out); err != nil {
		return "", err
	}
	var v secretValue
	if json.Unmarshal([]byte(out.SecretString), &v) != nil || v.Certificate == "" {
		return "", errors.New("GetSecretValue: secret is not a certificate bundle")
	}
	return v.Certificate, nil
}

func (c *client) restore(hd handle) (string, error) {
	if hd.Prior == "" {
		return "no previous version", nil
	}
	return "", c.call("UpdateSecretVersionStage", map[string]string{
		"SecretId": c.secret, "VersionStage": stageCurrent, "MoveToVersionId": hd.Prior, "RemoveFromVersionId": hd.New,
	}, nil)
}

// certBlocks keeps only the CERTIFICATE blocks, so the private key never
// leaves the plugin through Verify.
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

func (sm) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return err
	}
	_, err = c.currentVersion()
	return err
}

func (sm) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: detail}, nil
	}
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	fp := fingerprint(req.CertPEM)
	if fp == "" {
		return fail(abi.OutcomeWriteFailed, "certificate is not PEM")
	}
	prior, err := c.currentVersion()
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	newVersion, err := c.put(secretValue{Certificate: req.CertPEM, PrivateKey: req.KeyPEM, Fingerprint: fp})
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	if newVersion == prior {
		// The same certificate was already current (idempotent token): there
		// is nothing earlier to return to.
		prior = ""
	}
	hd := handle{Prior: prior, New: newVersion}

	// The plugin's own check only decides whether to restore early; the hub
	// still verifies through Verify.
	got, err := c.get(newVersion)
	if err == nil && fingerprint(got) != fp {
		err = errors.New("version read back does not match the pushed certificate")
	}
	if err != nil {
		detail := err.Error()
		note, rerr := c.restore(hd)
		switch {
		case rerr != nil:
			detail += "; RESTORE FAILED: " + rerr.Error()
		case note != "":
			detail += "; " + note
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}
	raw, _ := json.Marshal(hd)
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(raw)}, nil
}

func parseHandle(s string) (handle, error) {
	var hd handle
	if err := json.Unmarshal([]byte(s), &hd); err != nil || !versionPattern.MatchString(hd.New) || (hd.Prior != "" && !versionPattern.MatchString(hd.Prior)) {
		return handle{}, errors.New("rollback handle is not a Secrets Manager version handle")
	}
	return hd, nil
}

// Verify returns the certificate blocks stored in the exact version Push wrote.
func (sm) Verify(h *delivery.Host, req abi.VerifyRequest) (abi.VerifyResult, error) {
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	hd, err := parseHandle(req.Handle)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	pemText, err := c.get(hd.New)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	return abi.VerifyResult{CertPEM: certBlocks(pemText)}, nil
}

func (sm) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	c, err := newClient(h, req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	hd, err := parseHandle(req.Handle)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	note, err := c.restore(hd)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	if note != "" {
		return abi.RollbackResult{Detail: note}, nil
	}
	return abi.RollbackResult{RolledBack: true}, nil
}
