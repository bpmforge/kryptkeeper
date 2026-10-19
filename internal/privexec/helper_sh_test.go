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

const fakeCert = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"

func writeHelper(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kryptkeeper-helper")
	if err := os.WriteFile(p, []byte(HelperScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func runHelper(t *testing.T, h string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{h}, args...)...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestHelperScriptShape(t *testing.T) {
	if n := strings.Count(HelperScript, "\n"); n >= 300 {
		t.Fatalf("helper is %d lines, limit 300", n)
	}
	if !strings.HasPrefix(HelperScript, "#!/bin/sh\n") {
		t.Fatal("missing shebang")
	}
	if len(HelperSHA256()) != 64 {
		t.Fatal("sha length")
	}
	if out, err := exec.Command("sh", "-n", writeHelper(t)).CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %s", out)
	}
}

func TestHelperVersionAndUnknownVerb(t *testing.T) {
	h := writeHelper(t)
	if out, code := runHelper(t, h, "version"); code != 0 || !strings.HasPrefix(out, "kryptkeeper-helper ") {
		t.Fatalf("%q %d", out, code)
	}
	if _, code := runHelper(t, h, "rm"); code == 0 {
		t.Fatal("unknown verb accepted")
	}
	if _, code := runHelper(t, h); code == 0 {
		t.Fatal("no verb accepted")
	}
}

func TestHelperReadCert(t *testing.T) {
	h := writeHelper(t)
	dir := t.TempDir()
	ok := filepath.Join(dir, "site.pem")
	os.WriteFile(ok, []byte("junk\n"+fakeCert+"trailing\n"), 0o600)
	out, code := runHelper(t, h, "read-cert", ok)
	if code != 0 || out != fakeCert {
		t.Fatalf("out=%q code=%d", out, code)
	}

	bundle := filepath.Join(dir, "bundle.pem")
	os.WriteFile(bundle, []byte(fakeCert+"-----BEGIN PRIVATE KEY-----\nSECRETKEYBYTES\n-----END PRIVATE KEY-----\n"), 0o600)
	out, code = runHelper(t, h, "read-cert", bundle)
	if code != 3 || strings.Contains(out, "SECRETKEYBYTES") || strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Fatalf("key bundle: out=%q code=%d", out, code)
	}

	key := filepath.Join(dir, "site.key")
	os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nSECRETKEYBYTES\n-----END PRIVATE KEY-----\n"), 0o600)
	if out, code = runHelper(t, h, "read-cert", key); code == 0 || strings.Contains(out, "SECRETKEYBYTES") {
		t.Fatalf(".key must be refused: %q %d", out, code)
	}
}

func TestHelperPathValidation(t *testing.T) {
	h := writeHelper(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "a.pem")
	os.WriteFile(good, []byte(fakeCert), 0o600)
	big := filepath.Join(dir, "big.pem")
	os.WriteFile(big, []byte(strings.Repeat("A", 1<<20+1)), 0o600)
	link := filepath.Join(dir, "link.pem")
	os.Symlink("/etc/shadow", link)
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o700)
	notReg := filepath.Join(dir, "d.pem")
	os.Mkdir(notReg, 0o700)

	for name, args := range map[string][]string{
		"relative":     {"read-cert", "a.pem"},
		"dotdot":       {"read-cert", sub + "/../a.pem"},
		"too big":      {"read-cert", big},
		"shadow link":  {"read-cert", link},
		"shadow":       {"stat", "/etc/shadow"},
		"sudoers":      {"stat", "/etc/sudoers"},
		"sudoers.d":    {"stat", "/etc/sudoers.d/x"},
		"root ssh":     {"stat", "/root/.ssh/authorized_keys"},
		"directory":    {"read-cert", notReg},
		"bad char":     {"read-cert", good + ";id"},
		"list file":    {"list", good},
		"stat no path": {"stat"},
	} {
		if out, code := runHelper(t, h, args...); code == 0 {
			t.Errorf("%s: accepted (%q)", name, out)
		}
	}
	if out, code := runHelper(t, h, "stat", good); code != 0 || !strings.Contains(out, "a.pem") {
		t.Fatalf("stat: %q %d", out, code)
	}
}

func TestHelperList(t *testing.T) {
	h := writeHelper(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.pem"), []byte(fakeCert), 0o600)
	os.WriteFile(filepath.Join(dir, "b.JKS"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("x"), 0o600)
	out, code := runHelper(t, h, "list", dir)
	if code != 0 || !strings.Contains(out, "a.pem") || !strings.Contains(out, "b.JKS") || strings.Contains(out, "c.txt") {
		t.Fatalf("%q %d", out, code)
	}
}

func TestHelperInstall(t *testing.T) {
	h := writeHelper(t)
	dst := t.TempDir()
	// the staging check wants /tmp or /var/tmp; t.TempDir may live elsewhere on macOS.
	stage, err := os.CreateTemp("/tmp", "kk-helper-test-*.pem")
	if err != nil {
		t.Skip("no /tmp")
	}
	defer os.Remove(stage.Name())
	stage.WriteString(fakeCert)
	stage.Close()
	target := filepath.Join(dst, "out.pem")
	// A staging file that is certainly outside /tmp and /var/tmp (t.TempDir
	// itself lives under /tmp on Linux, so it cannot play that role).
	elsewhere, err := filepath.Abs("helper_sh_test.go")
	if err != nil {
		t.Fatal(err)
	}

	if out, code := runHelper(t, h, "install", stage.Name(), target, "0644"); code != 0 {
		t.Fatalf("install: %q %d", out, code)
	}
	if st, err := os.Stat(target); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("target: %v %v", st, err)
	}
	for name, args := range map[string][]string{
		"setuid mode":   {"install", stage.Name(), target, "4755"},
		"bad ext":       {"install", stage.Name(), filepath.Join(dst, "x.sh"), "0644"},
		"staging elsew": {"install", elsewhere, filepath.Join(dst, "y.pem"), "0644"},
		"dst shadow":    {"install", stage.Name(), "/etc/shadow", "0644"},
		"missing dir":   {"install", stage.Name(), filepath.Join(dst, "no", "y.pem"), "0644"},
		"arg count":     {"install", stage.Name(), target},
	} {
		if out, code := runHelper(t, h, args...); code == 0 {
			t.Errorf("%s: accepted (%q)", name, out)
		}
	}
}

func TestHelperFixedTables(t *testing.T) {
	h := writeHelper(t)
	for _, args := range [][]string{
		{"reload", "sshd"}, {"reload", "nginx; id"}, {"config-test", "sshd"}, {"config-test"}, {"reload"},
	} {
		if out, code := runHelper(t, h, args...); code == 0 {
			t.Errorf("%v accepted (%q)", args, out)
		}
	}
}

func TestHelperBackupRestoreDiscard(t *testing.T) {
	h := writeHelper(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "site.key")
	os.WriteFile(key, []byte("OLD"), 0o640)

	if out, code := runHelper(t, h, "backup", key); code != 0 {
		t.Fatalf("backup: %q %d", out, code)
	}
	if b, _ := os.ReadFile(key + ".kk-prev"); string(b) != "OLD" {
		t.Fatalf("backup content %q", b)
	}
	if st, _ := os.Stat(key + ".kk-prev"); st.Mode().Perm() != 0o640 {
		t.Fatalf("cp -p must keep the mode: %v", st.Mode())
	}
	os.WriteFile(key, []byte("NEW"), 0o600)
	if out, code := runHelper(t, h, "restore", key); code != 0 {
		t.Fatalf("restore: %q %d", out, code)
	}
	if b, _ := os.ReadFile(key); string(b) != "OLD" {
		t.Fatalf("restored %q", b)
	}
	if _, err := os.Stat(key + ".kk-prev"); err == nil {
		t.Fatal("restore must consume the backup")
	}
	if _, code := runHelper(t, h, "restore", key); code == 0 {
		t.Fatal("restore without a backup must fail")
	}
	runHelper(t, h, "backup", key)
	if _, code := runHelper(t, h, "discard", key); code != 0 {
		t.Fatal("discard")
	}
	if _, err := os.Stat(key + ".kk-prev"); err == nil {
		t.Fatal("discard must remove the backup")
	}
	for _, p := range []string{"/etc/shadow", filepath.Join(dir, "notes.txt"), "relative.key"} {
		if _, code := runHelper(t, h, "backup", p); code == 0 {
			t.Errorf("backup of %s accepted", p)
		}
	}
	link := filepath.Join(dir, "other.key")
	os.WriteFile(link, []byte("x"), 0o600)
	os.Symlink("/etc/shadow", link+".kk-prev")
	if _, code := runHelper(t, h, "backup", link); code == 0 {
		t.Fatal("a symlinked backup target must be refused")
	}
}

func TestHelperInstallWithOwner(t *testing.T) {
	h := writeHelper(t)
	stage, err := os.CreateTemp("/tmp", "kk-helper-own-*.pem")
	if err != nil {
		t.Skip("no /tmp")
	}
	defer os.Remove(stage.Name())
	stage.WriteString(fakeCert)
	stage.Close()
	out, _ := exec.Command("id", "-un").Output()
	grp, _ := exec.Command("id", "-gn").Output()
	og := strings.TrimSpace(string(out)) + ":" + strings.TrimSpace(string(grp))
	dst := filepath.Join(t.TempDir(), "o.pem")
	if o, code := runHelper(t, h, "install", stage.Name(), dst, "0640", og); code != 0 {
		// group names with unusual characters are refused by design
		t.Skipf("owner:group %q not accepted here: %s", og, o)
	}
	for _, bad := range []string{"root", "a:b:c;id", ":grp", "Root:root", "x:"} {
		if _, code := runHelper(t, h, "install", stage.Name(), filepath.Join(filepath.Dir(dst), "p.pem"), "0640", bad); code == 0 {
			t.Errorf("owner:group %q accepted", bad)
		}
	}
}
