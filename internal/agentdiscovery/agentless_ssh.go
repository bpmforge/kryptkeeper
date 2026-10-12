// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"path"
	"strings"

	"kryptkeeper/internal/agentclient"
	"kryptkeeper/internal/agentinstall"
)

// W14-01: agentless Linux/Unix discovery. Reuses the hardened
// agentinstall SSH executor (the wiring dials it with the outbound
// credential machinery, exactly as renewal installs do) and the same
// PEM parsing the agent uses — identical DiscoveredCerts into the one
// inventory. This package stays transport-agnostic: it takes an
// Executor, so an in-memory one unit-tests it with no network.

// keySuffixes mark files that hold PRIVATE KEY material. They are
// enumerated by PATH ONLY — their content is never read or
// transmitted (the key-boundary law at the discovery layer).
var keySuffixes = []string{".key", "_rsa", "_ecdsa", "_ed25519", "_dsa"}

func looksLikeKeyFile(name string) bool {
	base := path.Base(name)
	if strings.HasPrefix(base, "id_") {
		return true
	}
	for _, suf := range keySuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// SSHHostKey is one captured SSH host public key.
type SSHHostKey struct {
	Path        string `json:"path"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"` // sha256:<hex> of the key blob
}

// AgentlessScanResult is one host's discovery output.
type AgentlessScanResult struct {
	Host         string                       `json:"host"`
	Certs        []agentclient.DiscoveredCert `json:"certs"`
	KeyFilePaths []string                     `json:"key_file_paths"` // paths only — never content
	HostKeys     []SSHHostKey                 `json:"host_keys"`
	Errors       []string                     `json:"errors"`
	// IISService is the W3SVC service Status as reported by the host
	// itself (WinRM only): "Running", "Stopped", "absent" (service not
	// installed), or "" when the marker line was missing from the
	// enumeration output. The install recommendation must come from what
	// the host reports, not from the transport used to reach it -- a
	// Windows box with no IIS gets no IIS recommendation just because it
	// answered on WinRM.
	IISService string `json:"iis_service,omitempty"`
	// Parsed carries the full certificates behind Certs (WinRM only) so the
	// hub can persist them through the discovery store's normal upsert,
	// which needs DNs, algorithms and raw DER that the agentclient shape
	// deliberately omits. Never serialized.
	Parsed []*x509.Certificate `json:"-"`
}

// AgentlessSSHScanner walks a remote host through an Executor.
type AgentlessSSHScanner struct {
	exec  agentinstall.Executor
	host  string
	paths []string
}

func NewAgentlessSSHScanner(exec agentinstall.Executor, host string, paths []string) *AgentlessSSHScanner {
	if len(paths) == 0 {
		paths = DefaultLinuxPaths
	}
	return &AgentlessSSHScanner{exec: exec, host: host, paths: paths}
}

// Scan enumerates certificates, key-file paths, and SSH host keys. Per
// -file failures append to Errors and never abort the sweep.
func (s *AgentlessSSHScanner) Scan(ctx context.Context) AgentlessScanResult {
	res := AgentlessScanResult{Host: s.host}
	seen := map[string]struct{}{}

	for _, root := range s.paths {
		// One bounded find per root; cert files and key files listed
		// separately so key files are recorded by path without ever
		// being read.
		out, err := s.exec.Run(ctx, "find", root, "-maxdepth", "4", "-type", "f",
			"(", "-name", "*.crt", "-o", "-name", "*.cer", "-o", "-name", "*.pem", "-o", "-name", "*.cert",
			"-o", "-name", "*.key", "-o", "-name", "id_*", "-o", "-name", "*_rsa", "-o", "-name", "*_ecdsa", "-o", "-name", "*_ed25519", ")")
		if err != nil {
			continue // root absent on this host — try the others
		}
		for _, line := range strings.Split(string(out), "\n") {
			file := strings.TrimSpace(line)
			if file == "" {
				continue
			}
			if looksLikeKeyFile(file) {
				res.KeyFilePaths = append(res.KeyFilePaths, file) // PATH ONLY
				continue
			}
			raw, err := s.exec.ReadFile(file)
			if err != nil {
				res.Errors = append(res.Errors, s.host+":"+file+": "+err.Error())
				continue
			}
			certs, hadKey := parseCertsSkippingKeys(raw, "agentless-ssh:"+file)
			if hadKey {
				// A cert bundle that also carries a private key: record
				// the path in the key list, keep only the cert blocks.
				res.KeyFilePaths = append(res.KeyFilePaths, file)
			}
			for _, c := range certs {
				if _, dup := seen[c.Fingerprint]; dup {
					continue
				}
				seen[c.Fingerprint] = struct{}{}
				res.Certs = append(res.Certs, c)
			}
		}
	}

	s.scanHostKeys(ctx, &res)
	return res
}

// parseCertsSkippingKeys returns the CERTIFICATE blocks only; hadKey is
// true if any PRIVATE KEY block was present (so the caller flags the
// path). Key bytes are never retained.
func parseCertsSkippingKeys(raw []byte, source string) (certs []agentclient.DiscoveredCert, hadKey bool) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			hadKey = true
			continue
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, certToDiscovered(cert, source))
	}
	return certs, hadKey
}

// scanHostKeys captures the PUBLIC halves of the host's SSH keys.
func (s *AgentlessSSHScanner) scanHostKeys(ctx context.Context, res *AgentlessScanResult) {
	out, err := s.exec.Run(ctx, "find", "/etc/ssh", "-maxdepth", "1", "-name", "*.pub", "-type", "f")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		file := strings.TrimSpace(line)
		if file == "" {
			continue
		}
		raw, err := s.exec.ReadFile(file)
		if err != nil {
			res.Errors = append(res.Errors, s.host+":"+file+": "+err.Error())
			continue
		}
		fields := strings.Fields(string(raw))
		if len(fields) < 2 {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			continue
		}
		sum := sha256.Sum256(blob)
		res.HostKeys = append(res.HostKeys, SSHHostKey{
			Path:        file,
			Algorithm:   fields[0],
			Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}
}
