// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/url"
	"strconv"
	"time"

	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/discovery/scanner"
)

// W18-12: discovery_mode=winrm was accepted by the managed_targets schema
// and the scanner was proven live (2026-09-10), but nothing in the hub
// ever invoked it -- the same schema-claims/build-does-not-ship shape as
// W18-07. This file is the missing caller: a "winrm" scan type whose
// target is a managed target id, run by the discovery stores through the
// same scan_jobs row, upsert and risk scoring every other scan uses.

const scanTypeWinRM = "winrm"

// winRMTargetScanner runs agentless discovery for one managed target and
// returns it in the network scanner's result shape.
type winRMTargetScanner func(ctx context.Context, targetID string) scanner.ScanResult

// winRMScanSetter is implemented by providers that can host the runner.
// Injected after construction because the DB provider is built lazily
// behind configuredDiscoveryProvider.
type winRMScanSetter interface {
	SetWinRMScanner(winRMTargetScanner)
}

// winRMEnumerator is the slice of agentdiscovery this needs; tests
// substitute one so no listener is required.
type winRMEnumerator func(ctx context.Context, cfg agentdiscovery.WinRMConfig, host string) agentdiscovery.AgentlessScanResult

func liveWinRMEnumerator(ctx context.Context, cfg agentdiscovery.WinRMConfig, host string) agentdiscovery.AgentlessScanResult {
	return agentdiscovery.NewAgentlessWinRMScanner(agentdiscovery.NewWSManShell(cfg, nil), host).Scan(ctx)
}

// newWinRMTargetScanner resolves the target and its credential, then
// enumerates the host's machine stores. The credential is resolved inside
// this call and never stored on the result.
func newWinRMTargetScanner(targets ManagedTargetStore, creds OutboundCredentialStore, enumerate winRMEnumerator) winRMTargetScanner {
	return func(ctx context.Context, targetID string) scanner.ScanResult {
		started := time.Now().UTC()
		fail := func(host string, err error) scanner.ScanResult {
			logging.Infof("winrm discovery %s: %v", targetID, err)
			return scanner.ScanResult{Status: "failed", StartedAt: started, ErrorCount: 1,
				Endpoints: []scanner.DiscoveredEndpoint{{Host: host, Port: 5986, Protocol: "winrm-https", Error: err.Error(), ScannedAt: started}}}
		}
		if targets == nil || creds == nil {
			return fail(targetID, fmt.Errorf("managed target or credential store not configured"))
		}
		t, err := targets.Get(ctx, targetID)
		if err != nil {
			return fail(targetID, fmt.Errorf("managed target %q not found", targetID))
		}
		if t.DiscoveryMode != "winrm" {
			return fail(t.Host, fmt.Errorf("target %q has discovery_mode=%s, not winrm", targetID, t.DiscoveryMode))
		}
		if t.CredentialRef == "" {
			return fail(t.Host, fmt.Errorf("target %q has no credential_ref; WinRM discovery needs a windows_password credential", targetID))
		}
		meta, err := creds.Get(ctx, t.CredentialRef)
		if err != nil {
			return fail(t.Host, fmt.Errorf("credential %q not found", t.CredentialRef))
		}
		if meta.CredentialType != CredentialTypeWindowsPassword {
			return fail(t.Host, fmt.Errorf("credential %q is %s; WinRM discovery needs %s", t.CredentialRef, meta.CredentialType, CredentialTypeWindowsPassword))
		}
		plaintext, err := creds.Resolve(ctx, t.CredentialRef)
		if err != nil {
			return fail(t.Host, resolveFailure(t.CredentialRef, err))
		}
		var payload struct {
			BaseURL  string `json:"base_url"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(plaintext, &payload); err != nil || payload.BaseURL == "" || payload.Username == "" {
			return fail(t.Host, fmt.Errorf("credential %q payload lacks base_url/username", t.CredentialRef))
		}
		roots, err := agentdiscovery.WinRMRootCAsFromEnv()
		if err != nil {
			return fail(t.Host, err)
		}
		host, port := t.Host, 5986
		if u, uerr := url.Parse(payload.BaseURL); uerr == nil && u.Hostname() != "" {
			host = u.Hostname()
			if p, perr := strconv.Atoi(u.Port()); perr == nil {
				port = p
			}
		}
		res := enumerate(ctx, agentdiscovery.WinRMConfig{EndpointURL: payload.BaseURL, Username: payload.Username, Password: payload.Password, RootCAs: roots}, host)
		ep := scanner.DiscoveredEndpoint{Host: host, Port: port, Protocol: "winrm-https", ScannedAt: time.Now().UTC()}
		// W18-17: ServerTech/RecommendedInstallMode used to be hardcoded to
		// "iis" for every WinRM target -- a guess based on the transport, not
		// the host. A Windows box with no IIS installed got an install
		// recommendation it could not honour. Only set these when the host
		// itself reports a W3SVC service (running or stopped both count --
		// installed-but-stopped is still IIS); "absent" or an empty marker
		// (older enumerator, or a probe that never reached the marker line)
		// leaves both empty.
		if res.IISService == "Running" || res.IISService == "Stopped" {
			ep.ServerTech = "iis"
			ep.RecommendedInstallMode = "iis"
		}
		for i, c := range res.Parsed {
			// Store membership is the leaf/CA signal here: Windows keeps
			// end-entity certs in My and issuers in Root/CA.
			isLeaf := i < len(res.Certs) && res.Certs[i].Source == "agentless-winrm:My"
			ep.Certs = append(ep.Certs, scanner.CertToDiscovered(c, host, isLeaf))
		}
		// W34-12: install posture. The posture pass only sees http.sys-bound
		// ports, so ListenersScanned stays false: absent listener evidence for
		// other ports must not be read as "nothing listens there".
		if res.FilesScanned {
			ep.HostObs = &scanner.HostObservations{TargetID: t.ID, FilesScanned: true, Files: hostFiles(res.Files),
				Listeners: winBindingEvidence(res.WinBindings)}
		} else if res.PostureErr != "" {
			logging.Infof("winrm discovery %s: posture pass: %s", targetID, res.PostureErr)
		}
		result := scanner.ScanResult{Status: "completed", StartedAt: started, TotalScanned: 1, CertsFound: len(ep.Certs), Endpoints: []scanner.DiscoveredEndpoint{ep}}
		if len(res.Errors) > 0 {
			result.ErrorCount = len(res.Errors)
			// upsertScanResults drops any endpoint carrying an Error, so a
			// per-cert parse warning (one legacy Windows root crypto/x509
			// rejects -- seen live) must NOT ride on an endpoint that found
			// 28 others. Only an enumeration that found nothing is a failed
			// endpoint; warnings are logged.
			if len(ep.Certs) == 0 {
				ep.Error = res.Errors[0]
				result.Endpoints[0] = ep
				result.Status = "failed"
			} else {
				logging.Infof("winrm discovery %s: %d warning(s), first: %s", targetID, len(res.Errors), res.Errors[0])
			}
		}
		return result
	}
}

// winBindingEvidence turns http.sys certificate bindings into listener
// evidence at full weight: the host itself says what serves the port.
func winBindingEvidence(bindings []agentdiscovery.WinBinding) []scanner.PortEvidence {
	var out []scanner.PortEvidence
	seen := map[string]bool{}
	for _, b := range bindings {
		tech := agentdiscovery.WinBindingTech(b)
		if b.Port == 0 || tech == "other" || seen[fmt.Sprint(b.Port, tech)] {
			continue
		}
		seen[fmt.Sprint(b.Port, tech)] = true
		out = append(out, scanner.PortEvidence{Port: b.Port, Evidence: scanner.ListenerEvidence("http.sys "+b.IPPort, tech, "", false)})
	}
	return out
}

// SetWinRMScanner installs the runner on the DB provider's store.
func (p *dbDiscoveryProvider) SetWinRMScanner(fn winRMTargetScanner) {
	if s, ok := p.store.(winRMScanSetter); ok {
		s.SetWinRMScanner(fn)
	}
}

func (s *sqliteDiscoveryStore) SetWinRMScanner(fn winRMTargetScanner)   { s.winrmScan = fn }
func (s *postgresDiscoveryStore) SetWinRMScanner(fn winRMTargetScanner) { s.winrmScan = fn }

// SetWinRMScanner remembers the runner and hands it to the DB provider
// whenever that provider is (lazily) constructed.
func (c *configuredDiscoveryProvider) SetWinRMScanner(fn winRMTargetScanner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.winrmScan = fn
	if s, ok := c.dbProvider.(winRMScanSetter); ok && c.dbProvider != nil {
		s.SetWinRMScanner(fn)
	}
}

// runWinRMOrNetworkScan picks the runner for one scan_jobs row.
func runWinRMOrNetworkScan(ctx context.Context, winrm winRMTargetScanner, jobID, target, scanType string, extraPorts []int) *scanner.ScanResult {
	if scanType == scanTypeWinRM {
		if winrm == nil {
			return &scanner.ScanResult{JobID: jobID, Status: "failed", ErrorCount: 1,
				Endpoints: []scanner.DiscoveredEndpoint{{Host: target, Protocol: "winrm-https", Error: "winrm discovery not wired on this provider", ScannedAt: time.Now().UTC()}}}
		}
		r := winrm(ctx, target)
		r.JobID = jobID
		return &r
	}
	return runDiscoveryScan(ctx, jobID, target, scanType, extraPorts)
}
