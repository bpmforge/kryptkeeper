// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// logSudo is a sudo stand-in that records its argv, then runs the command.
func logSudo(t *testing.T) (sudo, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "argv.log")
	sudo = filepath.Join(dir, "sudo")
	script := "#!/bin/sh\necho \"$*\" >> '" + log + "'\nshift 2\nexec \"$@\"\n"
	if err := os.WriteFile(sudo, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return sudo, log
}

func TestSudoExecutor_RunPrefixesSudoN(t *testing.T) {
	sudo, log := logSudo(t)
	e := &SudoExecutor{SudoPath: sudo, InstallPath: "install", TempDir: t.TempDir()}
	out, err := e.Run(context.Background(), "echo", "hi")
	if err != nil || strings.TrimSpace(string(out)) != "hi" {
		t.Fatalf("%q %v", out, err)
	}
	b, _ := os.ReadFile(log)
	if strings.TrimSpace(string(b)) != "-n -- echo hi" {
		t.Fatalf("sudo argv = %q", b)
	}
}

func TestSudoExecutor_WriteFileInstallsViaSudoAndCleansStage(t *testing.T) {
	sudo, log := logSudo(t)
	stage := t.TempDir()
	e := &SudoExecutor{SudoPath: sudo, InstallPath: "install", TempDir: stage}
	dst := filepath.Join(t.TempDir(), "site.pem")
	if err := e.WriteFile(dst, []byte("pem"), 0o640); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "pem" {
		t.Fatalf("content %q", b)
	}
	if st, _ := os.Stat(dst); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	if ents, _ := os.ReadDir(stage); len(ents) != 0 {
		t.Fatalf("staged file left behind: %v", ents)
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "-n -- install -m 0640 ") {
		t.Fatalf("sudo log = %q", b)
	}
}

func TestSudoExecutor_ReadFileViaSudoCatAndNoSudoPath(t *testing.T) {
	sudo, log := logSudo(t)
	src := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(src, []byte("body"), 0o600)
	e := &SudoExecutor{SudoPath: sudo, InstallPath: "install", TempDir: t.TempDir()}
	if b, err := e.ReadFile(src); err != nil || string(b) != "body" {
		t.Fatalf("%q %v", b, err)
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "-n -- cat "+src) {
		t.Fatalf("sudo log = %q", b)
	}
	if !e.Exists(src) {
		t.Fatal("Exists stays an unprivileged stat")
	}

	root := &SudoExecutor{}
	if b, err := root.ReadFile(src); err != nil || string(b) != "body" {
		t.Fatalf("no-sudo read: %q %v", b, err)
	}
	if err := root.WriteFile(filepath.Join(t.TempDir(), "x.pem"), []byte("a"), 0o600); err != nil {
		t.Fatalf("no-sudo write: %v", err)
	}
}
