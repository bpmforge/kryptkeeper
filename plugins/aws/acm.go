// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

// now is injectable so tests sign with a fixed clock.
var now = time.Now

type aws struct {
	h *delivery.Host
	c creds
}

var errTypePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// send signs and sends one request. Errors name the call and status, and the
// service's error type when it is a plain token; never a body, since request
// bodies carry the private key.
func (a *aws) send(what, service, region string, req abi.HTTPRequest) (abi.HTTPResponse, error) {
	if err := signV4(&req, service, region, a.c, now()); err != nil {
		return abi.HTTPResponse{}, err
	}
	resp, err := a.h.HTTP(req)
	if err != nil {
		return resp, fmt.Errorf("%s: %w", what, err)
	}
	return resp, nil
}

func hostFor(service, region string) string {
	return "https://" + service + "." + region + ".amazonaws.com/"
}

// jsonCall is an AWS JSON 1.1 call; out may be nil.
func (a *aws) jsonCall(service, region, target string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	name := target[strings.Index(target, ".")+1:]
	resp, err := a.send(name, service, region, abi.HTTPRequest{
		Method: "POST", URL: hostFor(service, region), Body: body,
		Headers: map[string]string{"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": target},
	})
	if err != nil {
		return err
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
		return fmt.Errorf("%s: HTTP %d %s", name, resp.Status, e.Type)
	}
	if out == nil {
		return nil
	}
	if json.Unmarshal(resp.Body, out) != nil {
		return fmt.Errorf("%s: response unreadable", name)
	}
	return nil
}

// importCert imports leaf+key (replacing arn when set) and returns the ARN.
// Blobs are the base64 of the PEM text (JSON encodes []byte as base64).
func (a *aws) importCert(region, arn, leaf, chain, key string) (string, error) {
	in := struct {
		Certificate      []byte `json:"Certificate"`
		PrivateKey       []byte `json:"PrivateKey"`
		CertificateChain []byte `json:"CertificateChain,omitempty"`
		CertificateArn   string `json:"CertificateArn,omitempty"`
	}{Certificate: []byte(leaf), PrivateKey: []byte(key), CertificateChain: []byte(chain), CertificateArn: arn}
	var out struct {
		CertificateArn string `json:"CertificateArn"`
	}
	if err := a.jsonCall("acm", region, "CertificateManager.ImportCertificate", in, &out); err != nil {
		return "", err
	}
	return out.CertificateArn, nil
}

// certFingerprint is the SHA-256 of the leaf ACM holds under arn.
func (a *aws) certFingerprint(region, arn string) (string, error) {
	var out struct {
		Certificate string `json:"Certificate"`
	}
	if err := a.jsonCall("acm", region, "CertificateManager.GetCertificate", map[string]string{"CertificateArn": arn}, &out); err != nil {
		return "", err
	}
	_, _, fp, err := splitCert(out.Certificate)
	if err != nil {
		return "", errors.New("GetCertificate: no certificate in response")
	}
	return fp, nil
}
