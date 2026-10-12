// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// SudoExecutor performs install operations on a real host using a narrow sudo
// allowlist (the v1.3 privilege model). File placement uses `install` (atomic,
// sets mode); config-test and reload run their respective binaries. The
// deployment-time sudoers drop-in should permit exactly: the install binary
// writing into the cert directory, `nginx -t` / `apachectl configtest`, and the
// reload command — nothing more.
type SudoExecutor struct {
	// SudoPath is the sudo binary; empty disables sudo (e.g. agent already root).
	SudoPath string
	// InstallPath is the coreutils `install` binary used for atomic file placement.
	InstallPath string
	// TempDir is an agent-writable directory for staging files before `install`.
	TempDir string
}

// NewSudoExecutor returns an executor that wraps privileged operations in sudo.
func NewSudoExecutor() *SudoExecutor {
	return &SudoExecutor{
		SudoPath:    "sudo",
		InstallPath: "install",
		TempDir:     os.TempDir(),
	}
}

func (e *SudoExecutor) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ReadFile reads via sudo cat so root-owned certs/keys are readable for backup.
func (e *SudoExecutor) ReadFile(path string) ([]byte, error) {
	if e.SudoPath == "" {
		return os.ReadFile(path)
	}
	out, err := e.Run(context.Background(), "cat", path)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WriteFile stages content in TempDir then places it atomically with `install`
// (which creates parent perms-correct and sets mode in one step), under sudo.
func (e *SudoExecutor) WriteFile(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(e.TempDir, "kk-install-*")
	if err != nil {
		return fmt.Errorf("stage temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	modeArg := fmt.Sprintf("%#o", mode.Perm())
	args := []string{e.InstallPath, "-m", modeArg, tmpName, filepath.Clean(path)}
	if _, err := e.runRaw(context.Background(), args); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// Run executes name+args, prefixed with sudo when configured.
func (e *SudoExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.runRaw(ctx, append([]string{name}, args...))
}

func (e *SudoExecutor) runRaw(ctx context.Context, argv []string) ([]byte, error) {
	if e.SudoPath != "" {
		argv = append([]string{e.SudoPath, "-n"}, argv...)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}
