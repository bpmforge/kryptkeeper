// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package agentinstall installs renewed certificates where a web server reads
// them, validates the config, reloads the server, and rolls back on failure.
// It is the "install" half of the v1.3 Renewal Autopilot loop
// (discover → issue → install → verify); verification lives in a later wave.
//
// All privileged operations go through an Executor so the package is testable
// without root. There are two production executors with DIFFERENT privilege
// models -- do not assume one from the other:
//   - NewSudoExecutor (executor_sudo.go) is the agent-local path: it wraps
//     file placement and reload commands in a narrow sudo allowlist
//     (`install`, `nginx -t`, the reload command) per the v1.3 privilege
//     decision, run by the kryptkeeper-agent binary on the target itself.
//   - NewSSHExecutor (executor_ssh.go) is the agentless path
//     (internal/bootstrap/renewal_executor.go's ssh-mode targets): it issues
//     every Run/WriteFile command DIRECTLY over the SSH session with NO sudo
//     prefix at all. There is no narrow-allowlist model here -- the SSH
//     principal named in the target's credential must already hold
//     sufficient privilege on the host (root, or file ownership + a way to
//     run the reload command unprivileged) for install to succeed. Found
//     live proving W19-02: a non-root, sudo-only account does NOT work
//     against this executor as written; the fixture uses root over SSH.
package agentinstall

import (
	"context"
	"fmt"
	"os"
	"time"
)

// verifyRetryAttempts/verifyRetryDelay bound the retry-until-match loop in
// Install's verify step (below). `nginx -s reload` and `apachectl -k
// graceful` both return as soon as the signal is SENT, not once new workers
// are actually serving -- found live (W19-02): a verify dialed immediately
// after reload can still hit an old worker mid-handover and see the stale
// cert, which would otherwise trigger a spurious rollback of a perfectly
// good install. 6 attempts * 250ms = 1.5s worst case, well inside a
// renewal's normal budget, and only paid when a mismatch is actually seen.
const (
	verifyRetryAttempts = 6
	verifyRetryDelay    = 250 * time.Millisecond
)

// Executor performs the privileged side of an install. Implementations decide
// whether operations run directly (tests) or via sudo (production).
type Executor interface {
	// Exists reports whether a path exists.
	Exists(path string) bool
	// ReadFile reads a file's contents (used to back up the current cert/key).
	ReadFile(path string) ([]byte, error)
	// WriteFile atomically places content at path with the given mode.
	WriteFile(path string, content []byte, mode os.FileMode) error
	// Run executes a command and returns combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// InstallRequest describes one cert/key to install for a discovered endpoint.
type InstallRequest struct {
	ServerType string // "nginx" | "apache" | "haproxy"
	CertPath   string
	KeyPath    string
	CertPEM    []byte
	KeyPEM     []byte
	// ReloadMethod overrides reload selection ("systemctl" | "binary"); empty = auto.
	ReloadMethod string
	// HAProxyConfigPath is the config file `haproxy -c -f` validates
	// (W5-02); empty = /etc/haproxy/haproxy.cfg. HAProxy installs write
	// ONE combined chain+key file at CertPath and ignore KeyPath.
	HAProxyConfigPath string

	// Verify-after-install (v1.3 W2). When VerifyHostPort and ExpectedFingerprint
	// are set, the installer TLS-dials the endpoint after reload and confirms the
	// served leaf matches ExpectedFingerprint, rolling back if it doesn't.
	VerifyHostPort      string
	ExpectedFingerprint string // SHA-256 hex of the newly issued leaf
}

// InstallResult reports what happened. A renewal is "done" (Outcome
// "installed_verified") only when Installed, Reloaded, and Verified are all true
// and RolledBack is false.
type InstallResult struct {
	Installed         bool
	Reloaded          bool
	Verified          bool
	RolledBack        bool
	ServedFingerprint string
	Outcome           string // see outcome constants
	Detail            string
}

// Outcome values reported to the Hub.
const (
	OutcomeInstalledVerified = "installed_verified"
	OutcomeInstalled         = "installed" // installed + reloaded, verification not requested
	OutcomeConfigTestFailed  = "config_test_failed"
	OutcomeReloadFailed      = "reload_failed"
	OutcomeVerifyFailed      = "verify_failed"
	OutcomeWriteFailed       = "write_failed"
)

// Installer writes renewed certs, validates, reloads, and verifies — with rollback.
type Installer struct {
	exec   Executor
	verify Verifier
}

// New returns an Installer backed by the given executor and the default
// TLS-dial verifier.
func New(exec Executor) *Installer {
	return &Installer{exec: exec, verify: defaultVerifier}
}

// WithVerifier overrides the verifier (used in tests).
func (in *Installer) WithVerifier(v Verifier) *Installer {
	in.verify = v
	return in
}

// fileBackup holds the prior contents of a file so it can be restored.
type fileBackup struct {
	path    string
	content []byte
	existed bool
	mode    os.FileMode
}

// Install backs up the current cert/key, writes the renewed pair, validates the
// server config, and reloads. On any failure after writing, it restores the
// backups and reloads again (best effort), returning RolledBack=true.
func (in *Installer) Install(ctx context.Context, req InstallRequest) (InstallResult, error) {
	// W5-02: HAProxy has its own flow — combined single file, mandatory
	// `haproxy -c`, no blind fall-through into the generic reload.
	if req.ServerType == "haproxy" {
		return in.installHAProxy(ctx, req)
	}
	if req.CertPath == "" || len(req.CertPEM) == 0 {
		return InstallResult{}, fmt.Errorf("install: cert path and PEM are required")
	}

	// 1. Snapshot current files for rollback.
	backups := []fileBackup{
		in.snapshot(req.CertPath, 0o644),
	}
	if req.KeyPath != "" {
		backups = append(backups, in.snapshot(req.KeyPath, 0o600))
	}

	// 2. Write the renewed cert (and key) into place.
	if err := in.exec.WriteFile(req.CertPath, req.CertPEM, 0o644); err != nil {
		return InstallResult{}, fmt.Errorf("install: write cert: %w", err)
	}
	if req.KeyPath != "" && len(req.KeyPEM) > 0 {
		if err := in.exec.WriteFile(req.KeyPath, req.KeyPEM, 0o600); err != nil {
			in.rollback(ctx, backups, req)
			return InstallResult{RolledBack: true, Outcome: OutcomeWriteFailed}, fmt.Errorf("install: write key: %w", err)
		}
	}

	// 3. Validate config before reloading — never reload an invalid config.
	if name, args, ok := configTestCommand(req.ServerType); ok {
		if out, err := in.exec.Run(ctx, name, args...); err != nil {
			in.rollback(ctx, backups, req)
			return InstallResult{RolledBack: true, Outcome: OutcomeConfigTestFailed, Detail: string(out)},
				fmt.Errorf("install: config test failed, rolled back: %w", err)
		}
	}

	// 4. Reload to pick up the new cert.
	name, args := reloadCommand(req.ServerType, req.ReloadMethod)
	if out, err := in.exec.Run(ctx, name, args...); err != nil {
		in.rollback(ctx, backups, req)
		// Best-effort reload after restoring the old cert so the site keeps serving.
		_, _ = in.exec.Run(ctx, name, args...) // best-effort rollback reload; primary error already returned
		return InstallResult{Installed: true, RolledBack: true, Outcome: OutcomeReloadFailed, Detail: string(out)},
			fmt.Errorf("install: reload failed, rolled back: %w", err)
	}

	// 5. Verify-after-install (optional): confirm the renewed cert is actually
	// being served. A renewal isn't "done" until the new fingerprint is live.
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, err := in.verifyUntilMatchOrExhausted(ctx, req.VerifyHostPort, req.ExpectedFingerprint)
		if err != nil {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, name, args...) // best-effort rollback reload; primary error already returned
			return InstallResult{Installed: true, Reloaded: true, RolledBack: true, Outcome: OutcomeVerifyFailed, Detail: err.Error()},
				fmt.Errorf("install: verify failed, rolled back: %w", err)
		}
		if normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, name, args...) // best-effort rollback reload; primary error already returned
			return InstallResult{
					Installed: true, Reloaded: true, RolledBack: true,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
					Detail: "served fingerprint does not match renewed cert",
				},
				fmt.Errorf("install: verify mismatch (served %s, want %s), rolled back",
					served, req.ExpectedFingerprint)
		}
		return InstallResult{
			Installed: true, Reloaded: true, Verified: true,
			ServedFingerprint: served, Outcome: OutcomeInstalledVerified,
		}, nil
	}

	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// verifyUntilMatchOrExhausted calls verify up to verifyRetryAttempts times,
// stopping as soon as the served fingerprint matches expected. A dial error
// or a stale (mismatched) fingerprint both just mean "not there yet" during
// this window -- see verifyRetryAttempts's doc comment -- so both retry the
// same way; only the FINAL attempt's result is returned to the caller, which
// preserves Install's existing dial-error-vs-mismatch branching untouched.
func (in *Installer) verifyUntilMatchOrExhausted(ctx context.Context, hostPort, expected string) (served string, err error) {
	for attempt := 1; attempt <= verifyRetryAttempts; attempt++ {
		served, err = in.verify(ctx, hostPort)
		if err == nil && normalizeFingerprint(served) == normalizeFingerprint(expected) {
			return served, nil
		}
		if attempt < verifyRetryAttempts {
			select {
			case <-ctx.Done():
				return served, err
			case <-time.After(verifyRetryDelay):
			}
		}
	}
	return served, err
}

// snapshot reads the current contents of path (if any) for later rollback.
func (in *Installer) snapshot(path string, mode os.FileMode) fileBackup {
	b := fileBackup{path: path, mode: mode}
	if in.exec.Exists(path) {
		if content, err := in.exec.ReadFile(path); err == nil {
			b.content = content
			b.existed = true
		}
	}
	return b
}

// rollback restores backed-up files. Only files that existed before are
// restored; newly-created files are left as-is (removing them is risky without
// a delete primitive — restoring prior content is the safe, reversible action).
func (in *Installer) rollback(ctx context.Context, backups []fileBackup, _ InstallRequest) {
	for _, b := range backups {
		if b.existed {
			_ = in.exec.WriteFile(b.path, b.content, b.mode) // best-effort rollback reload; primary error already returned
		}
	}
}

// configTestCommand returns the validate-before-reload command for a server type.
func configTestCommand(serverType string) (name string, args []string, ok bool) {
	switch serverType {
	case "nginx":
		return "nginx", []string{"-t"}, true
	case "apache":
		return "apachectl", []string{"configtest"}, true
	default:
		return "", nil, false
	}
}

// reloadCommand returns the reload command for a server type. method overrides
// auto-selection: "systemctl" forces systemd, "binary" forces the server's own
// reload flag. Empty method defaults to systemctl (service-managed is the norm).
func reloadCommand(serverType, method string) (name string, args []string) {
	service := map[string]string{"nginx": "nginx", "apache": "apache2"}[serverType]
	if service == "" {
		service = serverType
	}
	switch method {
	case "binary":
		switch serverType {
		case "nginx":
			return "nginx", []string{"-s", "reload"}
		case "apache":
			return "apachectl", []string{"-k", "graceful"}
		}
	}
	// default / "systemctl"
	return "systemctl", []string{"reload", service}
}
