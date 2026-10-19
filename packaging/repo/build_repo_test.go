// Package repo tests build-repo.sh. It needs apt-ftparchive, createrepo_c and
// gpg, which a macOS dev host lacks, so it skips there; run it in a Linux
// container (packaging/repo/README.md). The workflow's verify job is the real
// end-to-end proof against the hosted repo.
package repo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

func run(t *testing.T, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeDeb builds a minimal .deb: an ar archive of debian-binary,
// control.tar.gz and data.tar.gz.
func writeDeb(t *testing.T, path, version, arch string) {
	t.Helper()
	control := fmt.Sprintf("Package: kryptkeeper\nVersion: %s\nArchitecture: %s\nMaintainer: Test <test@example.invalid>\nDescription: fixture\n", version, arch)
	members := []struct {
		name string
		data []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", tgz(t, map[string]string{"./control": control})},
		{"data.tar.gz", tgz(t, map[string]string{"./usr/share/kryptkeeper-fixture": "x\n"})},
	}
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m.name+"/", 0, 0, 0, "100644", len(m.data))
		buf.Write(m.data)
		if len(m.data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newKey(t *testing.T) (gnupg, keyID string) {
	t.Helper()
	gnupg = t.TempDir()
	if err := os.Chmod(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{"GNUPGHOME=" + gnupg}
	run(t, env, "gpg", "--batch", "--passphrase", "", "--quick-generate-key",
		"Kryptkeeper Test <test@example.invalid>", "rsa2048", "sign", "1d")
	out := run(t, env, "gpg", "--batch", "--with-colons", "--list-keys")
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Split(l, ":"); f[0] == "fpr" {
			return gnupg, f[9]
		}
	}
	t.Fatal("no key fingerprint")
	return "", ""
}

func build(t *testing.T, gnupg, keyID, pkgs, out string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "build-repo.sh", pkgs, out)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupg, "GPG_KEY_ID="+keyID, "BASE_URL=https://pkg.example.invalid")
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func TestBuildRepoApt(t *testing.T) {
	need(t, "bash", "apt-ftparchive", "createrepo_c", "gpg")
	gnupg, keyID := newKey(t)
	pkgs, out := t.TempDir(), t.TempDir()
	writeDeb(t, filepath.Join(pkgs, "kryptkeeper_0.0.1_amd64.deb"), "0.0.1", "amd64")
	writeDeb(t, filepath.Join(pkgs, "kryptkeeper_0.0.1_arm64.deb"), "0.0.1", "arm64")
	if o, err := build(t, gnupg, keyID, pkgs, out); err != nil {
		t.Fatalf("build-repo.sh: %v\n%s", err, o)
	}
	env := []string{"GNUPGHOME=" + gnupg}
	dists := filepath.Join(out, "apt", "dists", "stable")

	run(t, env, "gpg", "--verify", filepath.Join(dists, "InRelease"))
	run(t, env, "gpg", "--verify", filepath.Join(dists, "Release.gpg"), filepath.Join(dists, "Release"))

	pk, err := os.ReadFile(filepath.Join(dists, "main", "binary-amd64", "Packages"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pk), "Package: kryptkeeper") ||
		!strings.Contains(string(pk), "Filename: pool/main/k/kryptkeeper/kryptkeeper_0.0.1_amd64.deb") {
		t.Fatalf("amd64 Packages missing fixture:\n%s", pk)
	}
	if strings.Contains(string(pk), "_arm64.deb") {
		t.Fatalf("amd64 Packages lists an arm64 package:\n%s", pk)
	}

	gz, err := os.ReadFile(filepath.Join(dists, "main", "binary-amd64", "Packages.gz"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gz)
	rel, _ := os.ReadFile(filepath.Join(dists, "Release"))
	var found bool
	for _, l := range strings.Split(string(rel), "\n") {
		if strings.Contains(l, "main/binary-amd64/Packages.gz") && strings.Contains(l, hex.EncodeToString(sum[:])) {
			found = true
		}
	}
	if !found {
		t.Fatalf("Release has no matching sha256 for Packages.gz:\n%s", rel)
	}

	for _, f := range []string{"kryptkeeper.asc", "kryptkeeper.gpg", "kryptkeeper.repo"} {
		if st, err := os.Stat(filepath.Join(out, f)); err != nil || st.Size() == 0 {
			t.Fatalf("%s missing or empty: %v", f, err)
		}
	}
	repo, _ := os.ReadFile(filepath.Join(out, "kryptkeeper.repo"))
	if !strings.Contains(string(repo), "repo_gpgcheck=1") ||
		!strings.Contains(string(repo), "baseurl=https://pkg.example.invalid/rpm") {
		t.Fatalf("bad kryptkeeper.repo:\n%s", repo)
	}

	// A tampered Release must fail verification: the signature is real.
	if err := os.WriteFile(filepath.Join(dists, "Release"), append(rel, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("env", "GNUPGHOME="+gnupg, "gpg", "--verify",
		filepath.Join(dists, "Release.gpg"), filepath.Join(dists, "Release")).Run(); err == nil {
		t.Fatal("tampered Release still verified")
	}
}

func TestBuildRepoRejectsEmptyAndMissingKey(t *testing.T) {
	need(t, "bash", "apt-ftparchive", "createrepo_c", "gpg")
	gnupg, keyID := newKey(t)
	if o, err := build(t, gnupg, keyID, t.TempDir(), t.TempDir()); err == nil {
		t.Fatalf("empty package dir must fail, got success:\n%s", o)
	}
	cmd := exec.Command("bash", "build-repo.sh", t.TempDir(), t.TempDir())
	cmd.Env = append(os.Environ(), "GPG_KEY_ID=")
	if err := cmd.Run(); err == nil {
		t.Fatal("missing GPG_KEY_ID must fail")
	}
}

func TestBuildRepoRpm(t *testing.T) {
	need(t, "bash", "apt-ftparchive", "createrepo_c", "gpg", "rpmbuild")
	gnupg, keyID := newKey(t)
	top := t.TempDir()
	spec := filepath.Join(top, "k.spec")
	body := "Name: kryptkeeper\nVersion: 0.0.1\nRelease: 1\nSummary: fixture\nLicense: Apache-2.0\nBuildArch: noarch\n%description\nfixture\n%files\n"
	if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, nil, "rpmbuild", "-bb", "--define", "_topdir "+top, spec)
	rpms, _ := filepath.Glob(filepath.Join(top, "RPMS", "*", "*.rpm"))
	if len(rpms) != 1 {
		t.Fatalf("expected one rpm, got %v", rpms)
	}
	pkgs, out := t.TempDir(), t.TempDir()
	data, _ := os.ReadFile(rpms[0])
	if err := os.WriteFile(filepath.Join(pkgs, "kryptkeeper_0.0.1_amd64.rpm"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if o, err := build(t, gnupg, keyID, pkgs, out); err != nil {
		t.Fatalf("build-repo.sh: %v\n%s", err, o)
	}
	rd := filepath.Join(out, "rpm", "repodata")
	run(t, []string{"GNUPGHOME=" + gnupg}, "gpg", "--verify",
		filepath.Join(rd, "repomd.xml.asc"), filepath.Join(rd, "repomd.xml"))
}
