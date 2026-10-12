// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/agentinstall"
)

const (
	defaultTimeout = 2 * time.Minute
	// Same retry as the built-in installers: a device can still be handing
	// over to the new certificate when the first verify dials it.
	verifyAttempts = 6
	verifyDelay    = 250 * time.Millisecond
)

func osMode(m uint32) os.FileMode { return os.FileMode(m & 0o777) }

func (p *Plugin) state(env Env) *callState {
	redact := make([]string, 0, len(env.Secrets))
	for _, name := range env.Secrets {
		if v := env.Credential[name]; v != "" {
			redact = append(redact, v)
		}
	}
	return &callState{env: env, granted: p.granted, redact: redact}
}

func (p *Plugin) run(ctx context.Context, env Env, st *callState, op string, req any, out any) error {
	timeout := env.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	in, err := json.Marshal(req)
	if err != nil {
		return err
	}
	raw, err := p.invoke(ctx, st, op, in)
	if err != nil {
		return err
	}
	var resp abi.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("plugin returned malformed JSON: %w", err)
	}
	if resp.Error != "" {
		return errors.New(sanitize(resp.Error, st.redact))
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("plugin returned a malformed result: %w", err)
		}
	}
	return nil
}

func invocation(env Env) abi.Invocation {
	return abi.Invocation{Credential: env.Credential, Target: env.Target}
}

// Validate is the plugin's "test connection".
func (p *Plugin) Validate(ctx context.Context, env Env) error {
	return p.run(ctx, env, p.state(env), abi.OpValidate, abi.ValidateRequest{Invocation: invocation(env)}, nil)
}

// DeliverRequest is a renewed certificate for one target.
type DeliverRequest struct {
	Name    string
	CertPEM []byte
	KeyPEM  []byte
	// Verify-after-push, as for the built-in installers.
	VerifyHostPort      string
	ExpectedFingerprint string
}

// Deliver pushes through the plugin, verifies what the device serves, and
// rolls back on a mismatch. The plugin reports only whether it installed;
// Verified and RolledBack are the hub's findings, never the plugin's word.
func (p *Plugin) Deliver(ctx context.Context, env Env, req DeliverRequest, verify agentinstall.Verifier) agentinstall.InstallResult {
	st := p.state(env)
	push := abi.PushRequest{Invocation: invocation(env), Name: req.Name, CertPEM: string(req.CertPEM)}
	if p.granted.ReceivePrivateKey {
		push.KeyPEM = string(req.KeyPEM)
		st.redact = append(st.redact, strings.TrimSpace(string(req.KeyPEM)))
	}
	var pr abi.PushResult
	if err := p.run(ctx, env, st, abi.OpPush, push, &pr); err != nil {
		return agentinstall.InstallResult{Outcome: abi.OutcomeWriteFailed, Detail: sanitize(err.Error(), st.redact)}
	}
	res := agentinstall.InstallResult{Installed: pr.Installed, Reloaded: pr.Reloaded, Outcome: pr.Outcome, Detail: sanitize(pr.Detail, st.redact)}
	if !abi.PluginOutcomes[res.Outcome] {
		return agentinstall.InstallResult{Outcome: abi.OutcomeWriteFailed, Detail: fmt.Sprintf("plugin returned unknown outcome %q", sanitize(pr.Outcome, nil))}
	}
	if res.Outcome != abi.OutcomeInstalled || !res.Installed {
		res.Installed = res.Installed && res.Outcome == abi.OutcomeInstalled
		return res
	}
	if req.VerifyHostPort == "" || req.ExpectedFingerprint == "" || verify == nil {
		return res
	}

	want := strings.ToLower(strings.ReplaceAll(req.ExpectedFingerprint, ":", ""))
	var served string
	var verr error
	for i := range verifyAttempts {
		if i > 0 {
			time.Sleep(verifyDelay)
		}
		served, verr = verify(ctx, req.VerifyHostPort)
		if verr == nil && strings.ToLower(strings.ReplaceAll(served, ":", "")) == want {
			res.Verified, res.ServedFingerprint, res.Outcome = true, served, agentinstall.OutcomeInstalledVerified
			return res
		}
	}
	res.ServedFingerprint, res.Outcome = served, agentinstall.OutcomeVerifyFailed
	detail := "served certificate does not match the delivered one"
	if verr != nil {
		detail = sanitize(verr.Error(), st.redact)
	}
	var rb abi.RollbackResult
	rbErr := p.run(ctx, env, p.state(env), abi.OpRollback, abi.RollbackRequest{Invocation: invocation(env), Handle: pr.RollbackHandle}, &rb)
	if rbErr == nil && rb.RolledBack {
		res.RolledBack = true
		res.Detail = detail + "; rolled back"
		return res
	}
	why := rb.Detail
	if rbErr != nil {
		why = rbErr.Error()
	}
	res.Detail = detail + "; ROLLBACK FAILED (device may still serve the unverified cert): " + sanitize(why, st.redact)
	return res
}
