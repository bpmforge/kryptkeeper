// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
	// Parsed carries the full certificates behind Certs (WinRM and SSH), in
	// lockstep with Certs, so the
	// hub can persist them through the discovery store's normal upsert,
	// which needs DNs, algorithms and raw DER that the agentclient shape
	// deliberately omits. Never serialized.
	Parsed []*x509.Certificate `json:"-"`
	// Listeners are the host's listening sockets with their owning process
	// (W34-07). ListenersHidden counts those the account could not see;
	// ListenersErr is why the sweep produced nothing (kept apart from Errors,
	// which become per-path findings).
	Listeners        []Listener `json:"-"`
	ListenersHidden  int        `json:"-"`
	ListenersScanned bool       `json:"-"`
	ListenersErr     string     `json:"-"`
	// Files are the certificate, key and keystore files with their owner,
	// mode and the service using them (W34-08). Key files are stat-ed, never
	// read.
	Files        []FileFact `json:"-"`
	FilesScanned bool       `json:"-"`
	// ConfigRefs maps a path a service's configuration names to that
	// service's technology; the agent forwards it so the hub can attribute
	// files the same way the scan does.
	ConfigRefs map[string]string `json:"-"`
	// WinBindings are the http.sys certificate bindings a WinRM scan saw
	// (W34-12); PostureErr is why its posture pass produced nothing, kept
	// apart from Errors so a posture failure never fails the certificate scan.
	WinBindings []WinBinding `json:"-"`
	PostureErr  string       `json:"-"`
}

// AgentlessSSHScanner walks a remote host through an Executor.
type AgentlessSSHScanner struct {
	exec  agentinstall.Executor
	plain agentinstall.Executor
	host  string
	paths []string
	// agent marks a scan run by the agent on its own host: it keeps the
	// agent's historical inventory shape (keystore and kubeconfig coverage,
	// "format:path" sources) that the SSH scan never had.
	agent bool
}

// ForAgent makes the scan produce the agent inventory shape: JKS/JCEKS/BCFKS,
// PKCS#12 and kubeconfig certificates parsed by ScanKeystoreFile and sourced
// "format:path", as the in-process walk did before W34-09 routed the agent
// through this scanner.
func (s *AgentlessSSHScanner) ForAgent() *AgentlessSSHScanner {
	s.agent = true
	return s
}

// WithUnprivileged supplies the unelevated executor behind exec. /proc is
// mostly world readable and the helper allowlist cannot read it, so process
// facts are read through this one first and fall back to exec.
func (s *AgentlessSSHScanner) WithUnprivileged(plain agentinstall.Executor) *AgentlessSSHScanner {
	s.plain = plain
	return s
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
	var found []foundFile

	// Listeners first: a running process names keystore directories the
	// default roots do not cover (/opt/tomcat/conf).
	s.sweepListeners(ctx, &res)
	roots := append(append([]string{}, s.paths...), extraScanRoots(res.Listeners, s.paths)...)

	for _, root := range roots {
		out, err := s.findRoot(ctx, s.exec, root)
		if s.plain != nil && sudoRefused(out) {
			// The sudo rule does not cover this root (or the account may not
			// use sudo for it), so sudo printed its own refusal instead of
			// listing. Scan the root with the account's own permissions: what
			// it can read is still discovered, and what it cannot is reported
			// as unreadable by find itself.
			out, err = s.findRoot(ctx, s.plain, root)
		}
		// find exits non-zero when any subdirectory is unreadable but still
		// prints everything it could reach, so a non-sudo user keeps the
		// readable certs; only a root that produced nothing is skipped.
		if err != nil && len(out) == 0 {
			res.Errors = append(res.Errors, s.host+":"+root+": "+err.Error())
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			file := strings.TrimSpace(line)
			if file == "" {
				continue
			}
			// SSHExecutor.Run returns combined stdout+stderr, so find's own
			// diagnostics ("find: '/x': Permission denied") arrive as lines.
			if strings.HasPrefix(file, "sudo: ") {
				continue // a refusal with no unprivileged fallback; not a path
			}
			if strings.HasPrefix(file, "find: ") {
				if strings.Contains(file, "No such file or directory") {
					continue // an absent default root is normal, not a warning
				}
				res.Errors = append(res.Errors, s.host+":"+file)
				continue
			}
			if looksLikeKeyFile(file) {
				res.KeyFilePaths = append(res.KeyFilePaths, file) // PATH ONLY
				found = append(found, foundFile{path: file, kind: FileKindKey})
				continue
			}
			raw, err := s.readCertFile(file)
			if err != nil {
				res.Errors = append(res.Errors, s.host+":"+file+": "+err.Error())
				found = append(found, foundFile{path: file, kind: kindOfFile(file, false)})
				continue
			}
			source := "agentless-ssh:" + file
			if s.agent {
				source = file
			}
			var certs []agentclient.DiscoveredCert
			var parsed []*x509.Certificate
			hadKeyBlock := false
			if s.agent && keystoreCandidate(file) && !hasPEMCertificates(raw) {
				var ks KeystoreScanResult
				ScanKeystoreFile(file, raw, nil, &ks)
				for _, u := range ks.UnreadableStores {
					res.Errors = append(res.Errors, s.host+":"+u)
				}
				certs = ks.Certs
			} else if kind := keystoreKind(file); kind != "" && hasPEMCertificates(raw) {
				// The privilege helper reads keystores with keytool on the host
				// and returns their certificates as PEM; parsing that as the
				// binary keystore failed with "bad magic" (W34-20).
				if s.agent {
					source = agentKeystoreLabel(kind) + ":" + file
				}
				certs, parsed, _ = parseCertsSkippingKeys(raw, source)
			} else if kind != "" {
				parsed, err = parseKeystore(kind, raw)
				if err != nil {
					res.Errors = append(res.Errors, s.host+":"+file+": "+err.Error())
					found = append(found, foundFile{path: file, kind: kindOfFile(file, false)})
					continue
				}
				for _, c := range parsed {
					certs = append(certs, certToDiscovered(c, source))
				}
			} else {
				var hadKey bool
				certs, parsed, hadKey = parseCertsSkippingKeys(raw, source)
				hadKeyBlock = hadKey
				if hadKey {
					// A cert bundle that also carries a private key: record
					// the path in the key list, keep only the cert blocks.
					res.KeyFilePaths = append(res.KeyFilePaths, file)
				}
			}
			ff := foundFile{path: file, kind: kindOfFile(file, hadKeyBlock)}
			for _, c := range certs {
				ff.certs = append(ff.certs, c.Fingerprint)
			}
			found = append(found, ff)
			for i, c := range certs {
				if _, dup := seen[c.Fingerprint]; dup {
					continue
				}
				seen[c.Fingerprint] = struct{}{}
				res.Certs = append(res.Certs, c)
				if i < len(parsed) { // ScanKeystoreFile yields certs only
					res.Parsed = append(res.Parsed, parsed[i])
				}
			}
		}
	}

	s.scanHostKeys(ctx, &res)
	s.scanPosture(ctx, &res, found)
	return res
}

// scanPosture stats every file the walk found and attributes it to a service.
// A file the account cannot stat is kept as posture unknown, with no finding:
// the privilege preflight, not this pass, explains what was out of reach.
func (s *AgentlessSSHScanner) scanPosture(ctx context.Context, res *AgentlessScanResult, found []foundFile) {
	if len(found) == 0 {
		return
	}
	if len(found) > maxStatFiles {
		res.Errors = append(res.Errors, fmt.Sprintf("%s: posture limited to the first %d of %d files", s.host, maxStatFiles, len(found)))
		found = found[:maxStatFiles]
	}
	plain := s.plain
	if plain == nil {
		plain = s.exec
	}
	paths := make([]string, len(found))
	for i, f := range found {
		paths[i] = f.path
	}
	stats := statFiles(ctx, s.exec, plain, paths)
	files := make([]FileFact, len(found))
	for i, f := range found {
		fact, ok := stats[f.path]
		if !ok {
			fact = FileFact{UID: UnknownID, GID: UnknownID}
		}
		fact.Path, fact.Kind, fact.CertFingerprints, fact.ServiceUID = f.path, f.kind, f.certs, UnknownID
		files[i] = fact
	}
	res.ConfigRefs = configRefs(ctx, plain, res.Listeners)
	attributeFiles(files, res.Listeners, res.ConfigRefs)
	res.Files = files
	res.FilesScanned = true
}

// sweepListeners runs on the same executor as the file walk, so it is
// privileged exactly when the scan is.
func (s *AgentlessSSHScanner) sweepListeners(ctx context.Context, res *AgentlessScanResult) {
	sweep, err := Listeners(ctx, s.exec, s.plain)
	if err != nil {
		res.ListenersErr = err.Error()
		return
	}
	res.ListenersScanned = true
	res.Listeners = sweep.Listeners
	res.ListenersHidden = sweep.Hidden
}

// hasPEMCertificates reports whether raw is PEM text carrying certificates,
// which a binary keystore never is.
func hasPEMCertificates(raw []byte) bool {
	return bytes.Contains(raw, []byte("-----BEGIN CERTIFICATE-----"))
}

// parseCertsSkippingKeys returns the CERTIFICATE blocks only; hadKey is
// true if any PRIVATE KEY block was present (so the caller flags the
// path). Key bytes are never retained.
func parseCertsSkippingKeys(raw []byte, source string) (certs []agentclient.DiscoveredCert, parsed []*x509.Certificate, hadKey bool) {
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
		parsed = append(parsed, cert)
	}
	return certs, parsed, hadKey
}

// keystoreKind classifies binary keystore files by suffix ("" = PEM walk).
// agentKeystoreLabel is the source prefix the agent inventory uses for a
// keystore kind from keystoreKind.
func agentKeystoreLabel(kind string) string {
	if kind == "p12" {
		return "pkcs12"
	}
	return kind
}

func keystoreKind(file string) string {
	switch strings.ToLower(path.Ext(file)) {
	case ".jks":
		return "jks"
	case ".p12", ".pfx":
		return "p12"
	}
	return ""
}

// parseKeystore extracts certificates only; JKS key blobs are never read and
// PKCS#12 keys are discarded by ParsePKCS12Certs.
func parseKeystore(kind string, raw []byte) ([]*x509.Certificate, error) {
	if kind == "jks" {
		return ParseJKSCerts(raw)
	}
	return ParsePKCS12Certs(raw, defaultP12Passwords)
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

// findRoot is the bounded find for one root: cert files and key files listed
// together so key files are recorded by path without ever being read.
func (s *AgentlessSSHScanner) findRoot(ctx context.Context, exec agentinstall.Executor, root string) ([]byte, error) {
	names := []string{"-name", "*.crt", "-o", "-name", "*.cer", "-o", "-name", "*.pem", "-o", "-name", "*.cert",
		"-o", "-name", "*.key", "-o", "-name", "id_*", "-o", "-name", "*_rsa", "-o", "-name", "*_ecdsa", "-o", "-name", "*_ed25519",
		"-o", "-name", "*.jks", "-o", "-name", "*.p12", "-o", "-name", "*.pfx"}
	if s.agent {
		names = append(names, "-o", "-name", "*.keystore", "-o", "-name", "*.jceks", "-o", "-name", "*.bcfks",
			"-o", "-name", "kubeconfig", "-o", "-name", "*.kubeconfig", "-o", "-path", "*/.kube/config")
	}
	args := append([]string{root, "-maxdepth", "4", "-type", "f", "("}, names...)
	return exec.Run(ctx, "find", append(args, ")")...)
}

// sudoRefused reports find output that is sudo's own refusal rather than a
// listing ("sudo: a password is required", "sudo: sorry, you are not allowed...").
func sudoRefused(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "sudo: ") {
			return true
		}
	}
	return false
}

// readCertFile reads through the scan's (possibly elevated) executor and, when
// that fails, through the account's own permissions: a world-readable file
// needs no sudo, and a root the sudoers rule does not cover is refused by sudo
// whatever the file's mode. When both fail and the account itself was denied,
// that denial is the error reported, so the file counts as unreadable for lack
// of privilege (INSUFFICIENT_PRIVILEGE) instead of as a sudo prompt.
func (s *AgentlessSSHScanner) readCertFile(file string) ([]byte, error) {
	raw, err := s.exec.ReadFile(file)
	if err == nil || s.plain == nil {
		return raw, err
	}
	plainRaw, plainErr := s.plain.ReadFile(file)
	if plainErr == nil {
		return plainRaw, nil
	}
	if strings.Contains(strings.ToLower(plainErr.Error()), "permission denied") {
		return nil, plainErr
	}
	return nil, err
}
