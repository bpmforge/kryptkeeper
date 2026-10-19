// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// W5-03: push a renewed certificate onto a Citrix ADC (NetScaler) via
// the NITRO v1 config API — upload as systemfiles, re-point the
// sslcertkey, verify-after-push. NITRO's paths follow its long-stable
// v1 conventions; BaseURL is configurable and the tests pin our request
// shapes, so a vendor-path correction is a constant change. Rollback is
// deliberately NOT implemented here: sslcertkey update replaces content
// in place and the pusher never held the previous files — a verify
// failure reports honestly with the prior files still on disk under
// their own names.

// CitrixConfig locates and authenticates the ADC.
type CitrixConfig struct {
	// BaseURL, e.g. https://adc.example.com (no trailing slash).
	BaseURL  string
	Username string
	Password string
	// CertKeyName is the sslcertkey object to re-point.
	CertKeyName string
}

// CitrixPusher drives the push; http.Client injectable as with F5.
type CitrixPusher struct {
	cfg    CitrixConfig
	client *http.Client
	verify Verifier
}

func NewCitrixPusher(cfg CitrixConfig, client *http.Client) *CitrixPusher {
	if client == nil {
		client = guardedPushClient(nil)
	}
	return &CitrixPusher{cfg: cfg, client: client, verify: defaultVerifier}
}

func (p *CitrixPusher) WithVerifier(v Verifier) *CitrixPusher { p.verify = v; return p }

func (p *CitrixPusher) do(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	// NITRO authenticates every request via its own headers.
	req.Header.Set("X-NITRO-USER", p.cfg.Username)
	req.Header.Set("X-NITRO-PASS", p.cfg.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // error surfaces via the status code
	return resp.StatusCode, out, nil
}

// Push uploads the cert and key as systemfiles, re-points (or creates)
// the sslcertkey, and verifies.
func (p *CitrixPusher) Push(ctx context.Context, req PushRequest) (InstallResult, error) {
	if req.Name == "" || len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return InstallResult{}, fmt.Errorf("citrix push: name, cert and key are required")
	}
	certFile := req.Name + ".crt"
	keyFile := req.Name + ".key"

	// 1. Upload both files under /nsconfig/ssl.
	for _, f := range []struct {
		name    string
		content []byte
	}{{certFile, req.CertPEM}, {keyFile, req.KeyPEM}} {
		status, out, err := p.do(ctx, http.MethodPost, "/nitro/v1/config/systemfile", map[string]any{
			"systemfile": map[string]string{
				"filename":     f.name,
				"filelocation": "/nsconfig/ssl",
				"filecontent":  base64.StdEncoding.EncodeToString(f.content),
				"fileencoding": "BASE64",
			},
		})
		if err != nil || status >= 300 {
			detail := fmt.Sprintf("upload %s: HTTP %d %s %v", f.name, status, truncateBody(out), err)
			return InstallResult{Outcome: OutcomeWriteFailed, Detail: detail}, fmt.Errorf("citrix push: %s", detail)
		}
	}

	// 2. Re-point the existing sslcertkey; fall back to add on first
	// install (update of a nonexistent certkey fails).
	certkey := map[string]any{"sslcertkey": map[string]string{
		"certkey": p.cfg.CertKeyName,
		"cert":    "/nsconfig/ssl/" + certFile,
		"key":     "/nsconfig/ssl/" + keyFile,
	}}
	status, out, err := p.do(ctx, http.MethodPost, "/nitro/v1/config/sslcertkey?action=update", certkey)
	if err == nil && status >= 300 {
		status, out, err = p.do(ctx, http.MethodPost, "/nitro/v1/config/sslcertkey", certkey)
	}
	if err != nil || status >= 300 {
		detail := fmt.Sprintf("sslcertkey: HTTP %d %s %v", status, truncateBody(out), err)
		return InstallResult{Outcome: OutcomeBindingFailed, Detail: detail}, fmt.Errorf("citrix push: %s", detail)
	}

	// 3. Verify-after-push. No rollback (see the file comment) — the
	// failure is reported, never masked.
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, verr := p.verify(ctx, req.VerifyHostPort)
		if verr != nil || normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			detail := "served fingerprint does not match renewed cert"
			if verr != nil {
				detail = verr.Error()
			}
			return InstallResult{Installed: true, Reloaded: true, ServedFingerprint: served, Outcome: OutcomeVerifyFailed, Detail: detail},
				fmt.Errorf("citrix push: verify failed (no automatic rollback on ADC — prior files remain at /nsconfig/ssl)")
		}
		return InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}
