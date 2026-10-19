// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command example is a reference Kryptkeeper delivery plugin for a simple
// HTTPS device API, and the plugin the conformance kit grades itself with:
//
//	GET  /api/status            reachability and auth ("test connection")
//	POST /api/certs             {name, cert_pem, key_pem} upload
//	GET  /api/binding?listener= {cert} currently served
//	PUT  /api/binding           {listener, cert} serve another certificate
//	GET  /api/certs?name=       {cert_pem} stored object (only for the
//	                            "readback" verify op, see Verify below)
//
// Build: GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func init() { delivery.Register(device{}) }

func main() {}

type device struct{}

func call(h *delivery.Host, inv abi.Invocation, method, path string, body any) (abi.HTTPResponse, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return abi.HTTPResponse{}, err
		}
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  method,
		URL:     strings.TrimRight(inv.Credential["base_url"], "/") + path,
		Headers: map[string]string{"Authorization": "Bearer " + inv.Credential["token"], "Content-Type": "application/json"},
		Body:    raw,
	})
	if err != nil {
		return resp, err
	}
	if resp.Status < 200 || resp.Status > 299 {
		return resp, fmt.Errorf("%s %s: HTTP %d", method, path, resp.Status)
	}
	return resp, nil
}

func (device) Validate(h *delivery.Host, req abi.ValidateRequest) error {
	_, err := call(h, req.Invocation, "GET", "/api/status", nil)
	return err
}

func (device) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error) {
	listener := req.Target["listener"]
	if _, err := call(h, req.Invocation, "POST", "/api/certs", map[string]string{"name": req.Name, "cert_pem": req.CertPEM, "key_pem": req.KeyPEM}); err != nil {
		return abi.PushResult{Outcome: abi.OutcomeWriteFailed, Detail: err.Error()}, nil
	}
	cur, err := call(h, req.Invocation, "GET", "/api/binding?listener="+url.QueryEscape(listener), nil)
	if err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	var prior struct {
		Cert string `json:"cert"`
	}
	if err := json.Unmarshal(cur.Body, &prior); err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: "current binding unreadable"}, nil
	}
	if _, err := call(h, req.Invocation, "PUT", "/api/binding", map[string]string{"listener": listener, "cert": req.Name}); err != nil {
		return abi.PushResult{Outcome: abi.OutcomeBindingFailed, Detail: err.Error()}, nil
	}
	h.Logf("bound %s to %s (was %s)", req.Name, listener, prior.Cert)
	return abi.PushResult{Installed: true, Reloaded: true, Outcome: abi.OutcomeInstalled, RollbackHandle: prior.Cert}, nil
}

// Verify makes the example usable as a "verification":"readback" plugin: it
// returns the certificate the device stores under the name Push used. The hub
// parses and fingerprints it; the plugin never reports "verified".
func (device) Verify(h *delivery.Host, req abi.VerifyRequest) (abi.VerifyResult, error) {
	resp, err := call(h, req.Invocation, "GET", "/api/certs?name="+url.QueryEscape(req.Name), nil)
	if err != nil {
		return abi.VerifyResult{}, err
	}
	var got struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.Unmarshal(resp.Body, &got); err != nil {
		return abi.VerifyResult{}, fmt.Errorf("stored certificate unreadable")
	}
	return abi.VerifyResult{CertPEM: got.CertPEM}, nil
}

func (device) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error) {
	if req.Handle == "" {
		return abi.RollbackResult{Detail: "no previous certificate to restore"}, nil
	}
	if _, err := call(h, req.Invocation, "PUT", "/api/binding", map[string]string{"listener": req.Target["listener"], "cert": req.Handle}); err != nil {
		return abi.RollbackResult{Detail: err.Error()}, nil
	}
	return abi.RollbackResult{RolledBack: true}, nil
}
