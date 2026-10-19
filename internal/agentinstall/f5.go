// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// W5-03: push a renewed certificate onto an F5 BIG-IP via iControl REST
// and re-point a client-ssl profile at it, with verify-after-push and a
// profile-level rollback. Endpoint family grounded against F5's
// clouddocs API reference (tm/sys/crypto/cert + fromLocalFile); the
// upload endpoint is iControl's standard file-transfer path.

// F5Config locates and authenticates the BIG-IP.
type F5Config struct {
	// BaseURL, e.g. https://bigip.example.com (no trailing slash).
	BaseURL  string
	Username string
	Password string
	// ClientSSLProfile is the profile whose cert/key get re-pointed,
	// e.g. "clientssl-shop".
	ClientSSLProfile string
}

// F5Pusher drives the push. The http.Client is injectable for tests and
// for deployments that need custom TLS trust for the management plane.
type F5Pusher struct {
	cfg    F5Config
	client *http.Client
	verify Verifier
}

func NewF5Pusher(cfg F5Config, client *http.Client) *F5Pusher {
	if client == nil {
		client = guardedPushClient(nil)
	}
	return &F5Pusher{cfg: cfg, client: client, verify: defaultVerifier}
}

func (p *F5Pusher) WithVerifier(v Verifier) *F5Pusher { p.verify = v; return p }

// PushRequest is shared by the load-balancer pushers.
type PushRequest struct {
	// Name is the object name on the device (cert/key files and objects
	// derive from it).
	Name    string
	CertPEM []byte
	KeyPEM  []byte

	// Verify-after-push, same contract as InstallRequest.
	VerifyHostPort      string
	ExpectedFingerprint string
}

func (p *F5Pusher) do(ctx context.Context, method, path string, contentType string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.Username, p.cfg.Password)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method == http.MethodPost && contentType == "application/octet-stream" {
		// iControl's file-transfer convention: a single-chunk upload
		// declares the full range.
		req.Header.Set("Content-Range", fmt.Sprintf("0-%d/%d", len(body)-1, len(body)))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // error surfaces via status check below
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("f5 %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncateBody(out))
	}
	return out, nil
}

func truncateBody(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

// Push uploads, installs, re-points the client-ssl profile, verifies,
// and rolls the profile back on a verification mismatch.
func (p *F5Pusher) Push(ctx context.Context, req PushRequest) (InstallResult, error) {
	if req.Name == "" || len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return InstallResult{}, fmt.Errorf("f5 push: name, cert and key are required")
	}
	certFile := req.Name + ".crt"
	keyFile := req.Name + ".key"

	// 1. Upload both files to the device.
	if _, err := p.do(ctx, http.MethodPost, "/mgmt/shared/file-transfer/uploads/"+certFile, "application/octet-stream", req.CertPEM); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, err
	}
	if _, err := p.do(ctx, http.MethodPost, "/mgmt/shared/file-transfer/uploads/"+keyFile, "application/octet-stream", req.KeyPEM); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, err
	}

	// 2. Install as crypto objects from the uploaded files.
	certBody, _ := json.Marshal(map[string]string{ // fixed-shape map: cannot fail
		"name": req.Name, "fromLocalFile": "/var/config/rest/downloads/" + certFile,
	})
	if _, err := p.do(ctx, http.MethodPost, "/mgmt/tm/sys/crypto/cert", "application/json", certBody); err != nil {
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()}, err
	}
	keyBody, _ := json.Marshal(map[string]string{
		"name": req.Name, "fromLocalFile": "/var/config/rest/downloads/" + keyFile,
	})
	if _, err := p.do(ctx, http.MethodPost, "/mgmt/tm/sys/crypto/key", "application/json", keyBody); err != nil {
		return InstallResult{Outcome: OutcomeCertImportFailed, Detail: err.Error()}, err
	}

	// 3. Record the profile's CURRENT refs, then re-point it.
	profilePath := "/mgmt/tm/ltm/profile/client-ssl/" + p.cfg.ClientSSLProfile
	prior, err := p.do(ctx, http.MethodGet, profilePath, "", nil)
	if err != nil {
		return InstallResult{Outcome: OutcomeBindingFailed, Detail: err.Error()}, err
	}
	var priorProfile struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if err := json.Unmarshal(prior, &priorProfile); err != nil {
		return InstallResult{Outcome: OutcomeBindingFailed, Detail: "prior profile unreadable"}, fmt.Errorf("f5 push: prior profile: %w", err)
	}
	patch, _ := json.Marshal(map[string]string{"cert": req.Name, "key": req.Name})
	if _, err := p.do(ctx, http.MethodPatch, profilePath, "application/json", patch); err != nil {
		return InstallResult{Outcome: OutcomeBindingFailed, Detail: err.Error()}, err
	}

	// 4. Verify-after-push; roll the PROFILE back on mismatch so the
	// device keeps serving the old cert.
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, verr := p.verify(ctx, req.VerifyHostPort)
		if verr != nil || normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			restore, _ := json.Marshal(map[string]string{"cert": priorProfile.Cert, "key": priorProfile.Key})
			// RolledBack must reflect whether the restore ACTUALLY
			// succeeded: if it fails, the device is left on the new,
			// unverified cert and the operator must NOT be told it
			// reverted (a false RolledBack is a dangerous claim).
			_, rberr := p.do(ctx, http.MethodPatch, profilePath, "application/json", restore)
			detail := "served fingerprint does not match renewed cert"
			if verr != nil {
				detail = verr.Error()
			}
			if rberr != nil {
				return InstallResult{Installed: true, Reloaded: true, RolledBack: false, ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
						Detail: detail + "; ROLLBACK FAILED (device may still serve the unverified cert): " + rberr.Error()},
					fmt.Errorf("f5 push: verify failed AND rollback failed: %v", rberr)
			}
			return InstallResult{Installed: true, Reloaded: true, RolledBack: true, ServedFingerprint: served, Outcome: OutcomeVerifyFailed, Detail: detail},
				fmt.Errorf("f5 push: verify failed, profile rolled back to %s/%s", priorProfile.Cert, priorProfile.Key)
		}
		return InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}
