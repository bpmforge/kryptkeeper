// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	// Cadence of the manifest-declared propagation window (after the quick
	// attempts), kept coarse so a minutes-long CDN rollout is not hammered.
	verifyPollInterval = 15 * time.Second
)

// verifyClock is the time source for verification; tests replace it so a
// 20-minute window runs instantly. Zero value = real time.
type verifyClock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
	// poll overrides verifyPollInterval.
	poll time.Duration
}

func (c verifyClock) Now() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c verifyClock) Sleep(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c verifyClock) pollInterval() time.Duration {
	if c.poll > 0 {
		return c.poll
	}
	return verifyPollInterval
}

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
	// ReadbackVerify verifies through the plugin's verify op instead of a TLS
	// dial (secret stores serve nothing to dial). Only honoured for a manifest
	// declaring verification "readback"; the caller leaves VerifyHostPort
	// empty, since an explicit verify_host_port always forces the TLS dial.
	ReadbackVerify bool
}

func normalizeFP(fp string) string { return strings.ToLower(strings.ReplaceAll(fp, ":", "")) }

// leafFingerprint is the SHA-256 of the first CERTIFICATE block in pemData:
// the hub's own computation from bytes a store returned.
func leafFingerprint(pemData string) (string, error) {
	rest := []byte(pemData)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return "", errors.New("store returned no certificate PEM block")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return "", errors.New("store returned an unparseable certificate")
		}
		sum := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(sum[:]), nil
	}
}

// readbackServed asks the plugin for the certificate the store holds for the
// pushed object and fingerprints it here. Any error fails closed.
func (p *Plugin) readbackServed(ctx context.Context, env Env, st *callState, name, handle string) (string, error) {
	var vr abi.VerifyResult
	if err := p.run(ctx, env, st, abi.OpVerify, abi.VerifyRequest{Invocation: invocation(env), Name: name, Handle: handle}, &vr); err != nil {
		return "", err
	}
	return leafFingerprint(vr.CertPEM)
}

// Deliver pushes through the plugin, verifies what the device serves, and
// rolls back on a mismatch. The plugin reports only whether it installed;
// Verified and RolledBack are the hub's findings, never the plugin's word.
func (p *Plugin) Deliver(ctx context.Context, env Env, req DeliverRequest, verify agentinstall.Verifier) agentinstall.InstallResult {
	st := p.state(env)
	if req.ReadbackVerify {
		switch {
		case p.manifest.Verification != abi.VerificationReadback:
			return agentinstall.InstallResult{Outcome: abi.OutcomeWriteFailed, Detail: "read-back verification requested for a plugin that does not declare it"}
		case req.VerifyHostPort != "":
			return agentinstall.InstallResult{Outcome: abi.OutcomeWriteFailed, Detail: "read-back verification cannot be combined with a TLS verify target"}
		case req.ExpectedFingerprint == "":
			return agentinstall.InstallResult{Outcome: abi.OutcomeWriteFailed, Detail: "read-back verification needs the expected fingerprint"}
		}
	}
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
	if !req.ReadbackVerify && (req.VerifyHostPort == "" || req.ExpectedFingerprint == "" || verify == nil) {
		return res
	}

	want := normalizeFP(req.ExpectedFingerprint)
	fetch := func() (string, error) { return verify(ctx, req.VerifyHostPort) }
	verifiedDetail := ""
	if req.ReadbackVerify {
		fetch = func() (string, error) { return p.readbackServed(ctx, env, st, req.Name, pr.RollbackHandle) }
		verifiedDetail = "verified by store read-back"
	}
	var served string
	var verr error
	matched := func() bool {
		served, verr = fetch()
		return verr == nil && normalizeFP(served) == want
	}
	ok := false
	for i := range verifyAttempts {
		if i > 0 && p.clock.Sleep(ctx, verifyDelay) != nil {
			break
		}
		if matched() {
			ok = true
			break
		}
	}
	// Propagation window declared by the manifest: same comparison, more time.
	if window := time.Duration(p.manifest.VerifyPropagationSeconds) * time.Second; !ok && window > 0 {
		deadline := p.clock.Now().Add(window)
		for !ok && ctx.Err() == nil && p.clock.Now().Before(deadline) {
			step := min(p.clock.pollInterval(), deadline.Sub(p.clock.Now()))
			if p.clock.Sleep(ctx, step) != nil {
				break
			}
			ok = matched()
		}
	}
	if ok {
		res.Verified, res.ServedFingerprint, res.Outcome = true, served, agentinstall.OutcomeInstalledVerified
		if verifiedDetail != "" {
			res.Detail = verifiedDetail
		}
		return res
	}
	res.ServedFingerprint, res.Outcome = served, agentinstall.OutcomeVerifyFailed
	detail := "served certificate does not match the delivered one"
	if verr != nil {
		detail = sanitize(verr.Error(), st.redact)
	}
	var rb abi.RollbackResult
	rbErr := p.run(context.WithoutCancel(ctx), env, p.state(env), abi.OpRollback, abi.RollbackRequest{Invocation: invocation(env), Handle: pr.RollbackHandle}, &rb)
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
