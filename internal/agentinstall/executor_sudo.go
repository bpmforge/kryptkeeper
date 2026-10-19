// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"os"

	"kryptkeeper/internal/privexec"
)

// SudoExecutor performs install operations on the local host through a narrow
// sudo allowlist (the v1.3 privilege model, D-114). It is privexec mode
// nopasswd over a local executor: the deployment-time sudoers drop-in should
// permit exactly the install binary into the cert directory, the config-test
// commands and the reload command, nothing more.
type SudoExecutor struct {
	// SudoPath is the sudo binary; empty disables sudo (e.g. agent already root).
	SudoPath string
	// InstallPath is the coreutils `install` binary used for atomic file placement.
	InstallPath string
	// TempDir is an agent-writable directory for staging files before `install`.
	TempDir string
}

var _ Executor = (*SudoExecutor)(nil)

// NewSudoExecutor returns an executor that wraps privileged operations in sudo.
func NewSudoExecutor() *SudoExecutor {
	return &SudoExecutor{
		SudoPath:    "sudo",
		InstallPath: "install",
		TempDir:     os.TempDir(),
	}
}

func (e *SudoExecutor) elevated() privexec.Executor {
	cfg := privexec.Config{Mode: privexec.ModeNoPasswd, SudoPath: e.SudoPath, InstallPath: e.InstallPath, TempDir: e.TempDir}
	if cfg.TempDir == "" {
		cfg.TempDir = os.TempDir()
	}
	if e.SudoPath == "" {
		cfg.Mode = privexec.ModeNone
	}
	x, err := privexec.Wrap(privexec.LocalExecutor{}, cfg)
	if err != nil {
		// Unreachable: nopasswd and none need nothing Wrap can reject.
		panic(err)
	}
	return x
}

func (e *SudoExecutor) Exists(path string) bool { return e.elevated().Exists(path) }

// ReadFile reads via sudo cat so root-owned certs/keys are readable for backup.
func (e *SudoExecutor) ReadFile(path string) ([]byte, error) { return e.elevated().ReadFile(path) }

// WriteFile stages content in TempDir then places it with an elevated `install`.
func (e *SudoExecutor) WriteFile(path string, content []byte, mode os.FileMode) error {
	return e.elevated().WriteFile(path, content, mode)
}

// Run executes name+args, prefixed with `sudo -n --` when configured.
func (e *SudoExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.elevated().Run(ctx, name, args...)
}
