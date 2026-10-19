// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package privexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from golden:\n%s", name, got)
	}
}

func visudoCheck(t *testing.T, text string) {
	t.Helper()
	bin, err := exec.LookPath("visudo")
	if err != nil {
		return // the golden file covers runners without visudo
	}
	f := filepath.Join(t.TempDir(), "kk")
	if err := os.WriteFile(f, []byte(text), 0o440); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-c", "-f", f).CombinedOutput(); err != nil {
		t.Fatalf("visudo rejected the drop-in: %v\n%s\n%s", err, out, text)
	}
}

func TestSudoersGoldenAndVisudo(t *testing.T) {
	cases := []struct {
		file, user string
		mode       Mode
		server     string
		paths      []string
	}{
		{"sudoers_helper.golden", "kkscan", ModeHelper, "", nil},
		{"sudoers_password.golden", "kkscan", ModePassword, "", nil},
		{"sudoers_nopasswd_nginx.golden", "kkscan", ModeNoPasswd, "nginx", []string{"/etc/nginx/ssl/site.pem", "/etc/nginx/ssl/site.key", "/etc/ssl/private"}},
		{"sudoers_nopasswd_default.golden", "kryptkeeper-agent", ModeNoPasswd, "", []string{"/etc/nginx/ssl", "/etc/apache2/ssl"}},
	}
	for _, c := range cases {
		got, err := Sudoers(c.user, c.mode, c.server, c.paths)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		golden(t, c.file, got)
		visudoCheck(t, got)
	}
}

func TestSudoersShape(t *testing.T) {
	h, _ := Sudoers("kkscan", ModeHelper, "", nil)
	if strings.Count(h, "NOPASSWD:") != 1 || !strings.Contains(h, "Defaults:kkscan !requiretty") || !strings.Contains(h, DefaultHelperPath) {
		t.Fatalf("helper drop-in: %s", h)
	}
	p, _ := Sudoers("kkscan", ModePassword, "", nil)
	if strings.Contains(p, "NOPASSWD") || !strings.Contains(p, "!requiretty") {
		t.Fatalf("password drop-in: %s", p)
	}
	n, _ := Sudoers("kkscan", ModeNoPasswd, "haproxy", []string{"/etc/haproxy/certs/a.pem"})
	for _, want := range []string{"/usr/bin/find /etc/haproxy/certs *", "/usr/bin/install -m * /etc/haproxy/certs/*", "haproxy -c -f", "root read/write"} {
		if !strings.Contains(n, want) {
			t.Errorf("nopasswd drop-in lacks %q", want)
		}
	}
}

func TestSudoersRejectsInjection(t *testing.T) {
	for _, u := range []string{"", "Root", "a b", "x\nALL ALL=(ALL) NOPASSWD: ALL", "1abc"} {
		if _, err := Sudoers(u, ModeHelper, "", nil); err == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	for _, p := range []string{"/etc/ssl/../shadow", "/etc/x y", "/etc/ssl,/bin/sh", "relative", "/etc/a\nb", "/"} {
		if _, err := Sudoers("kkscan", ModeNoPasswd, "", []string{p}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if _, err := Sudoers("kkscan", ModeNoPasswd, "iis", nil); err == nil {
		t.Error("unknown server type accepted")
	}
	if _, err := Sudoers("kkscan", ModeNone, "", nil); err == nil {
		t.Error("mode none has no drop-in")
	}
}
