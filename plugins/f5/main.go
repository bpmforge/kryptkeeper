// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command f5 is the first-party delivery plugin for F5 BIG-IP (W20-22, D-118),
// ported from internal/agentinstall/f5.go onto the plugin ABI. Over iControl
// REST it uploads the certificate and key, installs them as crypto objects
// under a name unique to this certificate, records the client-ssl profile's
// current cert and key, then re-points the profile. Rollback re-points the
// profile at what it served before; the old objects are never deleted.
//
// Not yet verified against a real BIG-IP (the built-in pusher was not
// either); see docs/ops/DELIVERY_PLUGINS.md.
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

func init() { delivery.Register(bigip{}) }

func main() {}

type bigip struct{}

func basic(inv abi.Invocation) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(inv.Credential["username"]+":"+inv.Credential["password"]))
}

func call(h *delivery.Host, inv abi.Invocation, method, path, contentType string, body []byte) ([]byte, error) {
	headers := map[string]string{"Authorization": basic(inv)}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	if contentType == "application/octet-stream" {
		// iControl's file-transfer convention: one chunk declares the full range.
		headers["Content-Range"] = fmt.Sprintf("0-%d/%d", len(body)-1, len(body))
	}
	resp, err := h.HTTP(abi.HTTPRequest{Method: method, URL: strings.TrimRight(inv.Credential["base_url"], "/") + path, Headers: headers, Body: body})
	if err != nil {
		return nil, err
	}
	if resp.Status < 200 || resp.Status > 299 {
		return nil, fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.Status, truncate(resp.Body))
	}
	return resp.Body, nil
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

func profilePath(inv abi.Invocation) (string, error) {
	p := strings.TrimSpace(inv.Target["client_ssl_profile"])
	if p == "" || strings.ContainsAny(p, "/?#") {
		return "", errors.New("target setting client_ssl_profile is required and must be a profile name")
	}
	return "/mgmt/tm/ltm/profile/client-ssl/" + p, nil
}

type profileRefs struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (bigip) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	path, err := profilePath(req.Invocation)
	if err != nil {
		return err
	}
	_, err = call(h, req.Invocation, "GET", path, "", nil)
	return err
}

func (bigip) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	path, err := profilePath(req.Invocation)
	if err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	if req.KeyPEM == "" {
		return abi.PushResult{Outcome: abi.OutcomeWriteFailed, Detail: "no private key: this plugin needs receive_private_key"}, nil
	}
	// A name per certificate, so a renewal never overwrites the objects the
	// profile serves now, and rollback can point back at them.
	sum := sha256.Sum256([]byte(req.CertPEM))
	name := req.Name + "-" + hex.EncodeToString(sum[:4])
	for _, f := range []struct{ file, pem string }{{name + ".crt", req.CertPEM}, {name + ".key", req.KeyPEM}} {
		if _, err := call(h, req.Invocation, "POST", "/mgmt/shared/file-transfer/uploads/"+f.file, "application/octet-stream", []byte(f.pem)); err != nil {
			return abi.PushResult{Outcome: abi.OutcomeWriteFailed, Detail: err.Error()}, nil
		}
	}
	for _, kind := range []string{"cert", "key"} {
		ext := map[string]string{"cert": ".crt", "key": ".key"}[kind]
		body, _ := json.Marshal(map[string]string{"name": name, "fromLocalFile": "/var/config/rest/downloads/" + name + ext})
		if _, err := call(h, req.Invocation, "POST", "/mgmt/tm/sys/crypto/"+kind, "application/json", body); err != nil {
			return abi.PushResult{Outcome: abi.OutcomeCertImportFailed, Detail: err.Error()}, nil
		}
	}
	priorRaw, err := call(h, req.Invocation, "GET", path, "", nil)
	if err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	var prior profileRefs
	if err := json.Unmarshal(priorRaw, &prior); err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: "current profile unreadable"}, nil
	}
	patch, _ := json.Marshal(profileRefs{Cert: name, Key: name})
	if _, err := call(h, req.Invocation, "PATCH", path, "application/json", patch); err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	handle, _ := json.Marshal(prior)
	h.Logf("profile %s now serves %s (was %s)", req.Target["client_ssl_profile"], name, prior.Cert)
	return abi.PushResult{Installed: true, Reloaded: true, Outcome: abi.OutcomeInstalled, RollbackHandle: string(handle)}, nil
}

func (bigip) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	path, err := profilePath(req.Invocation)
	if err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	var prior profileRefs
	if err := json.Unmarshal([]byte(req.Handle), &prior); err != nil || prior.Cert == "" || prior.Key == "" {
		return abi.RollbackResult{Detail: "no previous cert and key recorded"}, nil
	}
	body, _ := json.Marshal(prior)
	if _, err := call(h, req.Invocation, "PATCH", path, "application/json", body); err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true}, nil
}
