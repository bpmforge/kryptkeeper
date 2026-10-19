// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/discovery/scanner"
	"kryptkeeper/internal/privexec"
)

// W24-08: NewAgentlessSSHScanner had no production caller. This is it: an
// "ssh" scan type whose target is a managed target id, run through the same
// scan_jobs row, upsert and risk scoring the winrm type uses
// (winrm_discovery.go is the pattern).

const (
	scanTypeSSH = "ssh"
	// maxSSHUnreadableFindings caps UNREADABLE_PATH findings per endpoint so
	// a locked-down host cannot flood the findings funnel.
	maxSSHUnreadableFindings = 20
	// maxSSHPostureFindings caps per-file posture findings per scan.
	maxSSHPostureFindings = 100
)

// jitSudo is a sudo password supplied for one scan or renewal (W34-17). It
// rides the context from the HTTP handler into the job, lives only in process
// memory, and is zeroized when the job ends. It is never persisted, logged or
// audited; the audit trail records only privilege_source=jit.
type jitSudo struct {
	mu sync.Mutex
	pw []byte
}

type jitSudoKey struct{}

// maxJITSudoPasswordLen bounds the request field.
const maxJITSudoPasswordLen = 256

func newJITSudo(password string) *jitSudo { return &jitSudo{pw: []byte(password)} }

func withJITSudo(ctx context.Context, j *jitSudo) context.Context {
	if j == nil {
		return ctx
	}
	return context.WithValue(ctx, jitSudoKey{}, j)
}

func jitSudoFrom(ctx context.Context) *jitSudo {
	j, _ := ctx.Value(jitSudoKey{}).(*jitSudo)
	return j
}

// carryJITSudo moves the secret from a request context onto a job context
// created from context.Background().
func carryJITSudo(from, to context.Context) context.Context {
	return withJITSudo(to, jitSudoFrom(from))
}

func (j *jitSudo) zero() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	zeroize(j.pw)
	j.pw = nil
}

func (j *jitSudo) text() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return string(j.pw)
}

// withJIT applies a supplied password to a credential that has no sudo of its
// own (mode none) or a stored password (the supplied one wins). Other modes
// ignore it: the operator configured a stronger arrangement.
func (p sshCredentialPayload) withJIT(j *jitSudo) sshCredentialPayload {
	if j == nil || j.text() == "" {
		return p
	}
	if mode := p.SudoMode; mode == "" || mode == string(privexec.ModeNone) || mode == string(privexec.ModePassword) {
		p.SudoMode = string(privexec.ModePassword)
		p.SudoPassword = j.text()
		p.HelperSHA256 = ""
	}
	return p
}

// scanUID asks the host for the uid the scan runs as (before any elevation).
// Best effort: "" when it cannot be read.
func scanUID(ctx context.Context, exec agentinstall.Executor) string {
	out, err := exec.Run(ctx, "id", "-u")
	if err != nil {
		return ""
	}
	if u := strings.TrimSpace(string(out)); u != "" && len(u) < 12 && strings.Trim(u, "0123456789") == "" {
		return u
	}
	return ""
}

// sshTargetScanner runs agentless SSH discovery for one managed target.
type sshTargetScanner func(ctx context.Context, targetID string) scanner.ScanResult

// sshScanSetter is implemented by providers that can host the runner.
type sshScanSetter interface {
	SetSSHScanner(sshTargetScanner)
}

// isSSHDiscoveryTarget is what "ssh-mode" means for discovery: the TargetSetup
// wizard creates Linux targets as discovery "network" + install "ssh", so the
// predicate keys on install_mode (W24-10 must use it too).
func isSSHDiscoveryTarget(t ManagedTarget) bool {
	return t.InstallMode == "ssh" && t.DiscoveryMode != "none"
}

// liveSSHDial is the production dial: the same body as NewRenewalExecutor's.
func liveSSHDial(ctx context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
	exec, err := agentinstall.NewSSHExecutor(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return exec, exec.Close, nil
}

// newSSHTargetScanner resolves the target and its ssh_key credential, dials,
// and walks the host. The credential is resolved inside this call, zeroized
// on return, and never reaches a log line, an error string or the result.
//
// A host-key mismatch (W24-09) fails the scan before anything is read: 0 certs
// imported, and audit gets target.hostkey.mismatch with both fingerprints.
func newSSHTargetScanner(targets ManagedTargetStore, creds OutboundCredentialStore, audit AuditProvider, dial sshDialFunc) sshTargetScanner {
	return func(ctx context.Context, targetID string) scanner.ScanResult {
		started := time.Now().UTC()
		jit := jitSudoFrom(ctx)
		defer jit.zero()
		fail := func(host string, err error) scanner.ScanResult {
			logging.Infof("ssh discovery %s: %v", targetID, err)
			return scanner.ScanResult{Status: "failed", StartedAt: started, ErrorCount: 1,
				Endpoints: []scanner.DiscoveredEndpoint{{Host: host, Port: 22, Protocol: "ssh", Error: err.Error(), ScannedAt: started}}}
		}
		if targets == nil || creds == nil || dial == nil {
			return fail(targetID, fmt.Errorf("managed target or credential store not configured"))
		}
		t, err := targets.Get(ctx, targetID)
		if err != nil {
			return fail(targetID, fmt.Errorf("managed target %q not found", targetID))
		}
		if !isSSHDiscoveryTarget(t) {
			return fail(t.Host, fmt.Errorf("target %q is not an ssh-mode managed target", targetID))
		}
		if t.CredentialRef == "" {
			return fail(t.Host, fmt.Errorf("target %q has no credential_ref; SSH discovery needs an %s credential", targetID, CredentialTypeSSHKey))
		}
		meta, err := creds.Get(ctx, t.CredentialRef)
		if err != nil {
			return fail(t.Host, fmt.Errorf("credential %q not found", t.CredentialRef))
		}
		if meta.CredentialType != CredentialTypeSSHKey {
			return fail(t.Host, fmt.Errorf("credential %q is %s; SSH discovery needs %s", t.CredentialRef, meta.CredentialType, CredentialTypeSSHKey))
		}
		plaintext, err := creds.Resolve(ctx, t.CredentialRef)
		if err != nil {
			return fail(t.Host, fmt.Errorf("credential %q could not be resolved", t.CredentialRef))
		}
		defer zeroize(plaintext)
		var payload sshCredentialPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return fail(t.Host, fmt.Errorf("credential %q is not the documented ssh_key JSON shape", t.CredentialRef))
		}
		noSudo := payload.SudoMode == "" || payload.SudoMode == string(privexec.ModeNone)
		payload = payload.withJIT(jit)
		signer, credKey, err := payload.parse()
		if err != nil {
			return fail(t.Host, fmt.Errorf("credential %q: %w", t.CredentialRef, err))
		}
		// A stored ssh_host_key on the target wins over the credential's
		// host_public_key.
		pinned := pinnedHostKeyFor(t, credKey)
		port := payload.Port
		if port == 0 {
			port = 22
		}
		exec, closeConn, err := dial(ctx, agentinstall.SSHTarget{
			Host: t.Host, Port: port, User: payload.User, Signer: signer,
			HostKeyCallback:   agentinstall.PinnedHostKeyCallback(pinned),
			HostKeyAlgorithms: hostKeyAlgorithmsFor(pinned),
			DialTimeout:       10 * time.Second,
		})
		if err != nil {
			var mm *agentinstall.HostKeyMismatchError
			if errors.As(err, &mm) {
				recordHostKeyMismatch(ctx, audit, t.ID, mm)
				return fail(t.Host, mm)
			}
			return fail(t.Host, fmt.Errorf("ssh dial %s:%d: %w", t.Host, port, err))
		}
		defer func() { _ = closeConn() }()

		elevated, endPrivilege, err := payload.elevate(exec)
		if err != nil {
			return fail(t.Host, fmt.Errorf("credential %q: %w", t.CredentialRef, err))
		}
		defer endPrivilege()

		res := agentdiscovery.NewAgentlessSSHScanner(elevated, t.Host, nil).WithUnprivileged(exec).Scan(ctx)
		out := sshScanResult(t, port, started, res)
		markRenewalBlockedFindings(&out, t.AutoRenew, meta.Privileged)
		// Permission-denied paths become one INSUFFICIENT_PRIVILEGE finding
		// with the fix for the mode the scan ran in. A credential without sudo
		// and no one-off password also gets the "run it now with a password"
		// advice inside that fix.
		mode := payload.SudoMode
		if mode == "" {
			mode = string(privexec.ModeNone)
		}
		if noSudo && jit == nil && len(res.Errors) > 0 && out.Status == "failed" {
			out.Endpoints[0].Error += " (needs a password; run it now or switch mode)"
		}
		applyInsufficientPrivilege(&out, scanUID(ctx, exec), payload.User, mode)
		return out
	}
}

// sshScanResult maps one host's agentless output onto the scanner result
// shape. Per-path failures are warnings: only a scan that found nothing AND
// hit errors is a failed endpoint (upsertScanResults drops errored ones).
func sshScanResult(t ManagedTarget, port int, started time.Time, res agentdiscovery.AgentlessScanResult) scanner.ScanResult {
	ep := scanner.DiscoveredEndpoint{Host: t.Host, Port: port, Protocol: "ssh", Reachable: true, ScannedAt: time.Now().UTC()}
	seenAlg := map[string]bool{}
	for _, hk := range res.HostKeys {
		if !seenAlg[hk.Algorithm] {
			seenAlg[hk.Algorithm] = true
			ep.HostKeyAlgorithms = append(ep.HostKeyAlgorithms, hk.Algorithm)
		}
	}
	for i, c := range res.Parsed {
		dc := scanner.CertToDiscovered(c, t.Host, !c.IsCA)
		if i < len(res.Certs) {
			dc.SourcePath = strings.TrimPrefix(res.Certs[i].Source, "agentless-ssh:")
		}
		ep.Certs = append(ep.Certs, dc)
	}
	for i, e := range res.Errors {
		logging.Infof("ssh discovery %s: unreadable: %s", t.ID, e)
		if i < maxSSHUnreadableFindings {
			ep.Findings = append(ep.Findings, "UNREADABLE_PATH: "+e)
		}
	}
	ep.HostObs = &scanner.HostObservations{TargetID: t.ID, ListenersScanned: res.ListenersScanned,
		Listeners: listenerPortEvidence(res.Listeners), HiddenListeners: res.ListenersHidden}
	if res.FilesScanned {
		ep.HostObs.FilesScanned = true
		ep.HostObs.Files = hostFiles(res.Files)
		for _, f := range res.Files {
			for _, finding := range f.Findings {
				if len(ep.Findings) >= maxSSHPostureFindings+maxSSHUnreadableFindings {
					break
				}
				ep.Findings = append(ep.Findings, finding)
			}
		}
	}
	if res.ListenersErr != "" {
		logging.Infof("ssh discovery %s: listener sweep: %s", t.ID, res.ListenersErr)
	}
	result := scanner.ScanResult{Status: "completed", StartedAt: started, TotalScanned: 1, CertsFound: len(ep.Certs),
		ErrorCount: len(res.Errors), Endpoints: []scanner.DiscoveredEndpoint{ep}}
	if len(ep.Certs) == 0 && len(res.Errors) > 0 {
		ep.Error = res.Errors[0]
		result.Endpoints[0] = ep
		result.Status = "failed"
	}
	return result
}

// SetSSHScanner installs the runner on the DB provider's store.
func (p *dbDiscoveryProvider) SetSSHScanner(fn sshTargetScanner) {
	if s, ok := p.store.(sshScanSetter); ok {
		s.SetSSHScanner(fn)
	}
}

func (s *sqliteDiscoveryStore) SetSSHScanner(fn sshTargetScanner)   { s.sshScan = fn }
func (s *postgresDiscoveryStore) SetSSHScanner(fn sshTargetScanner) { s.sshScan = fn }

// SetSSHScanner remembers the runner and hands it to the DB provider
// whenever that provider is (lazily) constructed.
func (c *configuredDiscoveryProvider) SetSSHScanner(fn sshTargetScanner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sshScan = fn
	if s, ok := c.dbProvider.(sshScanSetter); ok && c.dbProvider != nil {
		s.SetSSHScanner(fn)
	}
}

// runTargetOrNetworkScan picks the runner for one scan_jobs row: ssh to the
// SSH runner, everything else to runWinRMOrNetworkScan.
func runTargetOrNetworkScan(ctx context.Context, winrm winRMTargetScanner, sshScan sshTargetScanner, jobID, target, scanType string, extraPorts []int) *scanner.ScanResult {
	if scanType != scanTypeSSH {
		return runWinRMOrNetworkScan(ctx, winrm, jobID, target, scanType, extraPorts)
	}
	if sshScan == nil {
		return &scanner.ScanResult{JobID: jobID, Status: "failed", ErrorCount: 1,
			Endpoints: []scanner.DiscoveredEndpoint{{Host: target, Port: 22, Protocol: "ssh", Error: "ssh discovery not wired on this provider", ScannedAt: time.Now().UTC()}}}
	}
	r := sshScan(ctx, target)
	r.JobID = jobID
	return &r
}

// hostFiles maps the agentless scanner's file facts onto the scanner shape.
func hostFiles(files []agentdiscovery.FileFact) []scanner.HostFile {
	out := make([]scanner.HostFile, 0, len(files))
	for _, f := range files {
		out = append(out, scanner.HostFile{
			Path: f.Path, Kind: f.Kind, OwnerUID: f.UID, OwnerGID: f.GID, Owner: f.Owner, Group: f.Group, Mode: f.Mode,
			Statted: f.Statted, ServiceTech: f.ServiceTech, ServiceName: f.ServiceName, ServiceUID: f.ServiceUID,
			Posture: f.Posture, Findings: f.Findings, CertFingerprints: f.CertFingerprints,
		})
	}
	return out
}

// markRenewalBlockedFindings raises PRIVILEGED_INSTALL_PATH to high severity
// when renewal will fail: the target renews on its own and the credential has
// privileged credential to replace a file the service account cannot write. Both the
// per-file rows and the endpoint's findings are rewritten the same way.
func markRenewalBlockedFindings(r *scanner.ScanResult, autoRenew, privilegedCredential bool) {
	if !autoRenew || privilegedCredential {
		return
	}
	for i := range r.Endpoints {
		ep := &r.Endpoints[i]
		for j, f := range ep.Findings {
			ep.Findings[j] = scanner.MarkPrivilegedPathHigh(f)
		}
		if ep.HostObs == nil {
			continue
		}
		for j := range ep.HostObs.Files {
			for k, f := range ep.HostObs.Files[j].Findings {
				ep.HostObs.Files[j].Findings[k] = scanner.MarkPrivilegedPathHigh(f)
			}
		}
	}
}
