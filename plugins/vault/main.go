// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command vault is a delivery plugin for HashiCorp Vault KV v2. Push writes
// the certificate and key as a new version of one secret (check-and-set on
// the current version, so a concurrent writer is never overwritten) and reads
// that version back. The manifest declares verification "readback": the hub
// calls Verify, which returns the PEM of the exact version Push wrote, and
// fingerprints it itself. Rollback makes the prior version's content the
// newest version again (KV v2 cannot promote an older version), or soft-
// deletes the new version when the secret did not exist before.
//
// API shapes: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
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

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(kv{}) }

func main() {}

type kv struct{}

var (
	mountPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
	// Deliberately narrower than Vault allows: no escaping needed in a URL.
	pathPattern = regexp.MustCompile(`^[A-Za-z0-9_.@=+-]+(/[A-Za-z0-9_.@=+-]+)*$`)
)

// handle is the RollbackHandle: the version current before Push (0 = the
// secret did not exist) and the version Push wrote.
type handle struct {
	Prior int `json:"prior"`
	New   int `json:"new"`
}

func locate(inv abi.Invocation) (mount, path string, err error) {
	mount = strings.Trim(inv.Target["mount"], "/")
	if mount == "" {
		mount = "secret"
	}
	path = inv.Target["path"]
	if !mountPattern.MatchString(mount) {
		return "", "", errors.New("target setting mount is not a valid KV mount path")
	}
	if !pathPattern.MatchString(path) || strings.Contains(path, "..") {
		return "", "", errors.New("target setting path is required and may not contain .., a leading /, ? or #")
	}
	return mount, path, nil
}

// call returns the body on a status in want. Errors carry method, path and
// status only: a GET body can hold the stored secret.
func call(h *delivery.Host, inv abi.Invocation, method, path string, body any, want ...int) ([]byte, int, error) {
	headers := map[string]string{"X-Vault-Token": inv.Credential["token"]}
	if ns := inv.Credential["namespace"]; ns != "" {
		headers["X-Vault-Namespace"] = ns
	}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, 0, err
		}
		headers["Content-Type"] = "application/json"
	}
	resp, err := h.HTTP(abi.HTTPRequest{Method: method, URL: strings.TrimRight(inv.Credential["base_url"], "/") + "/v1/" + path, Headers: headers, Body: raw})
	if err != nil {
		return nil, 0, fmt.Errorf("%s /v1/%s: %w", method, path, err)
	}
	for _, w := range want {
		if resp.Status == w {
			return resp.Body, resp.Status, nil
		}
	}
	return nil, resp.Status, fmt.Errorf("%s /v1/%s: HTTP %d", method, path, resp.Status)
}

func (kv) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	mount, _, err := locate(req.Invocation)
	if err != nil {
		return err
	}
	if _, _, err := call(h, req.Invocation, "GET", "auth/token/lookup-self", nil, 200); err != nil {
		return err
	}
	_, _, err = call(h, req.Invocation, "GET", mount+"/config", nil, 200)
	return err
}

func fingerprint(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

type versionData struct {
	Data struct {
		Data json.RawMessage `json:"data"`
	} `json:"data"`
}

func readVersion(h *delivery.Host, inv abi.Invocation, mount, path string, version int) (json.RawMessage, error) {
	body, _, err := call(h, inv, "GET", fmt.Sprintf("%s/data/%s?version=%d", mount, path, version), nil, 200)
	if err != nil {
		return nil, err
	}
	var vd versionData
	if err := json.Unmarshal(body, &vd); err != nil || len(vd.Data.Data) == 0 {
		return nil, errors.New("version data unreadable")
	}
	return vd.Data.Data, nil
}

func readCert(h *delivery.Host, inv abi.Invocation, mount, path string, version int) (string, error) {
	raw, err := readVersion(h, inv, mount, path, version)
	if err != nil {
		return "", err
	}
	var d struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", errors.New("version data unreadable")
	}
	return d.Certificate, nil
}

// writeVersion posts data as a new version, check-and-set on cas, and
// returns the new version number.
func writeVersion(h *delivery.Host, inv abi.Invocation, mount, path string, cas int, data any) (int, error) {
	body, _, err := call(h, inv, "POST", mount+"/data/"+path, map[string]any{"options": map[string]int{"cas": cas}, "data": data}, 200)
	if err != nil {
		return 0, err
	}
	var r struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data.Version < 1 {
		return 0, errors.New("write response carried no version")
	}
	return r.Data.Version, nil
}

// restore undoes version n whose predecessor was prior.
func restore(h *delivery.Host, inv abi.Invocation, mount, path string, hd handle) error {
	if hd.Prior > 0 {
		old, err := readVersion(h, inv, mount, path, hd.Prior)
		if err != nil {
			return err
		}
		_, err = writeVersion(h, inv, mount, path, hd.New, old)
		return err
	}
	_, _, err := call(h, inv, "POST", mount+"/delete/"+path, map[string][]int{"versions": {hd.New}}, 200, 204)
	return err
}

func (kv) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	fail := func(outcome, detail string) (abi.PushResult, error) {
		return abi.PushResult{Outcome: outcome, Detail: detail}, nil
	}
	mount, path, err := locate(req.Invocation)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	fp := fingerprint(req.CertPEM)
	if fp == "" {
		return fail(abi.OutcomeWriteFailed, "certificate is not PEM")
	}

	prior := 0
	body, status, err := call(h, req.Invocation, "GET", mount+"/metadata/"+path, nil, 200, 404)
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	if status == 200 {
		var md struct {
			Data struct {
				CurrentVersion int `json:"current_version"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &md); err != nil {
			return fail(abi.OutcomeWriteFailed, "metadata unreadable")
		}
		prior = md.Data.CurrentVersion
	}

	newVersion, err := writeVersion(h, req.Invocation, mount, path, prior, map[string]string{
		"certificate": req.CertPEM, "private_key": req.KeyPEM, "fingerprint_sha256": fp,
	})
	if err != nil {
		return fail(abi.OutcomeWriteFailed, err.Error())
	}
	hd := handle{Prior: prior, New: newVersion}

	// The plugin's own check only decides whether to restore early; the hub
	// still verifies through Verify and never takes this result on trust.
	got, err := readCert(h, req.Invocation, mount, path, newVersion)
	if err == nil && fingerprint(got) != fp {
		err = errors.New("version read back does not match the pushed certificate")
	}
	if err != nil {
		detail := err.Error()
		if rerr := restore(h, req.Invocation, mount, path, hd); rerr != nil {
			detail += "; RESTORE FAILED: " + rerr.Error()
		}
		return fail(abi.OutcomeBindingFailed, detail)
	}
	raw, _ := json.Marshal(hd)
	return abi.PushResult{Installed: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(raw)}, nil
}

func parseHandle(s string) (handle, error) {
	var hd handle
	if err := json.Unmarshal([]byte(s), &hd); err != nil || hd.New < 1 || hd.Prior < 0 {
		return handle{}, errors.New("rollback handle is not a Vault version handle")
	}
	return hd, nil
}

// Verify returns the certificate stored in the exact version Push wrote.
func (kv) Verify(h *delivery.Host, req abi.VerifyRequest) (abi.VerifyResult, error) {
	mount, path, err := locate(req.Invocation)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	hd, err := parseHandle(req.Handle)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	cert, err := readCert(h, req.Invocation, mount, path, hd.New)
	return abi.VerifyResult{CertPEM: cert}, err
}

func (kv) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	mount, path, err := locate(req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	hd, err := parseHandle(req.Handle)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	if err := restore(h, req.Invocation, mount, path, hd); err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true}, nil
}
