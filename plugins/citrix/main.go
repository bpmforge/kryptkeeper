// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command citrix is the first-party delivery plugin for Citrix ADC /
// NetScaler (W20-22, D-118), ported from internal/agentinstall/citrix.go
// onto the plugin ABI. Over NITRO it uploads the certificate and key under
// file names unique to this certificate, records which files the cert-key
// pair uses now, and re-points the pair at the new files. Unlike the
// built-in pusher, which updated files in place and could not roll back,
// rollback re-points the pair at the previous files, which are left on disk.
//
// Not yet verified against a real ADC; see docs/ops/DELIVERY_PLUGINS.md.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(adc{}) }

func main() {}

type adc struct{}

const sslDir = "/nsconfig/ssl/"

func call(h *delivery.Host, inv abi.Invocation, method, path string, payload any) ([]byte, int, error) {
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return nil, 0, err
		}
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method: method,
		URL:    strings.TrimRight(inv.Credential["base_url"], "/") + path,
		Headers: map[string]string{
			"X-NITRO-USER": inv.Credential["username"],
			"X-NITRO-PASS": inv.Credential["password"],
			"Content-Type": "application/json",
		},
		Body: body,
	})
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.Status, nil
}

func certKeyName(inv abi.Invocation) (string, error) {
	n := strings.TrimSpace(inv.Target["certkey_name"])
	if n == "" || strings.ContainsAny(n, "/?#") {
		return "", errors.New("target setting certkey_name is required and must be a cert-key pair name")
	}
	return n, nil
}

type certKeyFiles struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// current reads the files the cert-key pair uses; ok is false when the pair
// does not exist yet (a first install).
func current(h *delivery.Host, inv abi.Invocation, name string) (certKeyFiles, bool, error) {
	out, status, err := call(h, inv, "GET", "/nitro/v1/config/sslcertkey/"+name, nil)
	if err != nil {
		return certKeyFiles{}, false, err
	}
	if status == 404 {
		return certKeyFiles{}, false, nil
	}
	if status < 200 || status > 299 {
		return certKeyFiles{}, false, fmt.Errorf("read sslcertkey %s: HTTP %d", name, status)
	}
	var resp struct {
		SSLCertKey []certKeyFiles `json:"sslcertkey"`
	}
	if err := json.Unmarshal(out, &resp); err != nil || len(resp.SSLCertKey) == 0 {
		return certKeyFiles{}, false, fmt.Errorf("sslcertkey %s unreadable", name)
	}
	return resp.SSLCertKey[0], true, nil
}

func pointAt(h *delivery.Host, inv abi.Invocation, name string, files certKeyFiles, exists bool) error {
	body := map[string]any{"sslcertkey": map[string]string{"certkey": name, "cert": files.Cert, "key": files.Key}}
	path := "/nitro/v1/config/sslcertkey?action=update"
	if !exists {
		path = "/nitro/v1/config/sslcertkey"
	}
	out, status, err := call(h, inv, "POST", path, body)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("sslcertkey %s: HTTP %d %.200s", name, status, out)
	}
	return nil
}

func (adc) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	name, err := certKeyName(req.Invocation)
	if err != nil {
		return err
	}
	_, _, err = current(h, req.Invocation, name)
	return err
}

func (adc) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	name, err := certKeyName(req.Invocation)
	if err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	if req.KeyPEM == "" {
		return abi.PushResult{Outcome: abi.OutcomeWriteFailed, Detail: "no private key: this plugin needs receive_private_key"}, nil
	}
	sum := sha256.Sum256([]byte(req.CertPEM))
	base := req.Name + "-" + hex.EncodeToString(sum[:4])
	files := certKeyFiles{Cert: sslDir + base + ".crt", Key: sslDir + base + ".key"}
	for _, f := range []struct{ file, pem string }{{base + ".crt", req.CertPEM}, {base + ".key", req.KeyPEM}} {
		out, status, err := call(h, req.Invocation, "POST", "/nitro/v1/config/systemfile", map[string]any{
			"systemfile": map[string]string{
				"filename": f.file, "filelocation": strings.TrimSuffix(sslDir, "/"),
				"filecontent": base64.StdEncoding.EncodeToString([]byte(f.pem)), "fileencoding": "BASE64",
			},
		})
		if err != nil || status < 200 || status > 299 {
			return abi.PushResult{Outcome: abi.OutcomeWriteFailed, Detail: fmt.Sprintf("upload %s: HTTP %d %.200s %v", f.file, status, out, err)}, nil
		}
	}
	prior, exists, err := current(h, req.Invocation, name)
	if err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	if err := pointAt(h, req.Invocation, name, files, exists); err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	handle := ""
	if exists {
		b, _ := json.Marshal(prior)
		handle = string(b)
	}
	h.Logf("cert-key pair %s now uses %s", name, files.Cert)
	return abi.PushResult{Installed: true, Reloaded: true, Outcome: abi.OutcomeInstalled, RollbackHandle: handle}, nil
}

func (adc) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	name, err := certKeyName(req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	var prior certKeyFiles
	if err := json.Unmarshal([]byte(req.Handle), &prior); err != nil || prior.Cert == "" {
		return abi.RollbackResult{Detail: "the pair was new; there is nothing earlier to restore"}, nil
	}
	if err := pointAt(h, req.Invocation, name, prior, true); err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true}, nil
}
