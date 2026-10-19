// Package homebrew tests render-formula.sh against a fixture checksums.txt.
package homebrew

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	shaArm = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaAmd = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func render(t *testing.T, checksums string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(path, []byte(checksums), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("bash", "render-formula.sh", path, "v1.2.3").CombinedOutput()
	return string(out), err
}

func TestRenderFormula_BothArchitectures(t *testing.T) {
	out, err := render(t, shaArm+"  kryptkeeper_1.2.3_darwin_arm64.tar.gz\n"+
		shaAmd+"  kryptkeeper_1.2.3_darwin_amd64.tar.gz\n"+
		"cccc  kryptkeeper_1.2.3_linux_amd64.tar.gz\n")
	if err != nil {
		t.Fatalf("render failed: %v\n%s", err, out)
	}
	for _, want := range []string{shaArm, shaAmd, "on_arm do", "on_intel do",
		"releases/download/v1.2.3/kryptkeeper_1.2.3_darwin_arm64.tar.gz",
		"releases/download/v1.2.3/kryptkeeper_1.2.3_darwin_amd64.tar.gz",
		`version "1.2.3"`} {
		if !strings.Contains(out, want) {
			t.Errorf("formula missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "__") {
		t.Errorf("placeholder left in formula:\n%s", out)
	}
	if strings.Contains(out, "depends_on arch") {
		t.Errorf("formula still restricts architecture:\n%s", out)
	}
}

func TestRenderFormula_MissingAmd64Fails(t *testing.T) {
	out, err := render(t, shaArm+"  kryptkeeper_1.2.3_darwin_arm64.tar.gz\n")
	if err == nil {
		t.Fatalf("expected failure when darwin_amd64 line is missing\n%s", out)
	}
	if !strings.Contains(out, "kryptkeeper_1.2.3_darwin_amd64.tar.gz") {
		t.Errorf("error should name the missing archive, got: %s", out)
	}
}

func TestRenderFormula_MissingArm64Fails(t *testing.T) {
	if out, err := render(t, shaAmd+"  kryptkeeper_1.2.3_darwin_amd64.tar.gz\n"); err == nil {
		t.Fatalf("expected failure when darwin_arm64 line is missing\n%s", out)
	}
}

func TestRenderFormula_MalformedShaFails(t *testing.T) {
	if out, err := render(t, "xyz  kryptkeeper_1.2.3_darwin_arm64.tar.gz\n"+
		shaAmd+"  kryptkeeper_1.2.3_darwin_amd64.tar.gz\n"); err == nil {
		t.Fatalf("expected failure on malformed sha\n%s", out)
	}
}
