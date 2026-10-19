// Package packaging tests packaging/install.sh against a local httptest
// fixture server -- no live network, per CLAUDE.md/PLAYBOOK's "no live
// network in unit tests" rule. install.sh itself does reach the network
// when a real user runs it (that's its job); these tests never do.
package packaging

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hostOSArch(t *testing.T) (string, string) {
	t.Helper()
	var os_ string
	switch runtime.GOOS {
	case "linux":
		os_ = "linux"
	case "darwin":
		os_ = "darwin"
	default:
		t.Skipf("install.sh only supports linux/darwin, host is %s", runtime.GOOS)
	}
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	default:
		t.Skipf("install.sh only supports amd64/arm64, host is %s", runtime.GOARCH)
	}
	return os_, arch
}

type installOpts struct {
	cosign     string // value for KRYPTKEEPER_INSTALL_COSIGN ("" = unset)
	skipCosign bool   // KRYPTKEEPER_INSTALL_SKIP_COSIGN=1
	path       string // if set, replaces PATH entirely
	extraEnv   []string
}

func runInstallSh(t *testing.T, baseURL, version, installDir, component string, o installOpts) ([]byte, error) {
	t.Helper()
	scriptPath, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatalf("resolve install.sh path: %v", err)
	}
	cmd := exec.Command("bash", scriptPath)
	env := os.Environ()
	if o.path != "" {
		env = append(env, "PATH="+o.path)
	}
	env = append(env,
		"KRYPTKEEPER_INSTALL_BASE_URL="+baseURL,
		"KRYPTKEEPER_VERSION="+version,
		"KRYPTKEEPER_INSTALL_DIR="+installDir,
		"KRYPTKEEPER_COMPONENT="+component,
	)
	if o.cosign != "" {
		env = append(env, "KRYPTKEEPER_INSTALL_COSIGN="+o.cosign)
	}
	if o.skipCosign {
		env = append(env, "KRYPTKEEPER_INSTALL_SKIP_COSIGN=1")
	}
	cmd.Env = append(env, o.extraEnv...)
	return cmd.CombinedOutput()
}

// fakeCosign writes an executable stand-in for cosign. It appends its argv to
// logPath and exits with exitCode. Tests never reach Sigstore.
func fakeCosign(t *testing.T, exitCode int) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "cosign")
	logPath = filepath.Join(dir, "argv.log")
	script := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do printf '%%s\\n' \"$a\" >> %q; done\nexit %d\n", logPath, exitCode)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	return bin, logPath
}

// tarGz builds a release archive holding a single file named binName.
func tarGz(t *testing.T, binName, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: binName, Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fixtureServer serves a goreleaser-shaped release: the .tar.gz archive,
// checksums.txt, checksums.txt.sig and checksums.txt.pem. If tamperChecksum is
// true, checksums.txt records the wrong hash for the archive -- the
// "break the subject, watch the test go red" check for the fail-closed
// checksum verification.
func fixtureServer(t *testing.T, version, binName, osName, arch, binContent string, tamperChecksum bool) *httptest.Server {
	t.Helper()
	archiveName := fmt.Sprintf("%s_%s_%s_%s.tar.gz", binName, strings.TrimPrefix(version, "v"), osName, arch)
	archive := tarGz(t, binName, binContent)
	sum := sha256.Sum256(archive)
	hexSum := hex.EncodeToString(sum[:])
	if tamperChecksum {
		hexSum = strings.Repeat("0", 64)
	}
	checksums := fmt.Sprintf("%s  %s\n", hexSum, archiveName)

	serve := map[string][]byte{
		archiveName:         archive,
		"checksums.txt":     []byte(checksums),
		"checksums.txt.sig": []byte("fake-sig"),
		"checksums.txt.pem": []byte("fake-pem"),
	}
	mux := http.NewServeMux()
	for name, body := range serve {
		body := body
		mux.HandleFunc("/"+version+"/"+name, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		})
	}
	return httptest.NewServer(mux)
}

func assertNotInstalled(t *testing.T, installDir, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(installDir, name)); err == nil {
		t.Fatalf("%s was installed despite a failed verification", name)
	}
}

const (
	testVersion = "v0.0.0-test"
	hubContent  = "#!/bin/sh\necho fake-hub-binary\n"
)

func TestInstallSh_VerifiesChecksumAndInstalls(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, false)
	defer srv.Close()
	cosign, _ := fakeCosign(t, 0)

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{cosign: cosign})
	if err != nil {
		t.Fatalf("install.sh failed on a correctly-checksummed asset: %v\noutput:\n%s", err, out)
	}

	installed := filepath.Join(installDir, "kryptkeeper")
	data, err := os.ReadFile(installed)
	if err != nil {
		t.Fatalf("expected binary at %s, got: %v", installed, err)
	}
	if string(data) != hubContent {
		t.Fatalf("installed binary content mismatch: got %q, want %q", data, hubContent)
	}
	info, err := os.Stat(installed)
	if err != nil {
		t.Fatalf("stat installed binary: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("installed binary is not executable: mode=%v", info.Mode())
	}
}

func TestInstallSh_FailsClosedOnChecksumMismatch(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, true)
	defer srv.Close()
	cosign, _ := fakeCosign(t, 0)

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{cosign: cosign})
	if err == nil {
		t.Fatalf("install.sh exited 0 against a tampered checksum -- expected it to fail closed\noutput:\n%s", out)
	}
	assertNotInstalled(t, installDir, "kryptkeeper")
}

func TestInstallSh_FailsClosedOnCosignFailure(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, false)
	defer srv.Close()
	cosign, _ := fakeCosign(t, 1)

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{cosign: cosign})
	if err == nil {
		t.Fatalf("install.sh exited 0 although cosign verification failed\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "cosign verification of checksums.txt FAILED") {
		t.Fatalf("missing cosign failure message:\n%s", out)
	}
	assertNotInstalled(t, installDir, "kryptkeeper")
}

// A failing cosign must not be bypassable by the opt-out: the opt-out only
// applies when cosign is absent.
func TestInstallSh_SkipCosignDoesNotBypassFailingCosign(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, false)
	defer srv.Close()
	cosign, _ := fakeCosign(t, 1)

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{cosign: cosign, skipCosign: true})
	if err == nil {
		t.Fatalf("opt-out bypassed a failing cosign\noutput:\n%s", out)
	}
	assertNotInstalled(t, installDir, "kryptkeeper")
}

// minimalPath exposes only the tools install.sh needs, none of them cosign,
// so the "cosign missing" tests do not depend on the host having (or lacking)
// a real cosign.
func minimalPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"curl", "tar", "grep", "sed", "awk", "mktemp", "uname",
		"sha256sum", "shasum", "cp", "chmod", "mkdir", "rm", "dirname", "cat", "gzip", "sudo", "env"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(dir, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func TestInstallSh_FailsClosedWhenCosignMissing(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, false)
	defer srv.Close()

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{path: minimalPath(t)})
	if err == nil {
		t.Fatalf("install.sh exited 0 with no cosign available\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "cosign not found") {
		t.Fatalf("expected install instructions, got:\n%s", out)
	}
	assertNotInstalled(t, installDir, "kryptkeeper")
}

func TestInstallSh_SkipCosignOptIn(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, false)
	defer srv.Close()

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{path: minimalPath(t), skipCosign: true})
	if err != nil {
		t.Fatalf("install.sh failed with the explicit opt-out: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "WARNING") {
		t.Fatalf("opt-out must print a loud WARNING, got:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(installDir, "kryptkeeper")); err != nil {
		t.Fatalf("binary not installed: %v", err)
	}
}

func TestInstallSh_SkipCosignStillChecksArchive(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, true)
	defer srv.Close()

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "hub", installOpts{path: minimalPath(t), skipCosign: true})
	if err == nil {
		t.Fatalf("opt-out skipped the archive checksum too\noutput:\n%s", out)
	}
	assertNotInstalled(t, installDir, "kryptkeeper")
}

func TestInstallSh_PassesDocumentedIdentityToCosign(t *testing.T) {
	osName, arch := hostOSArch(t)
	srv := fixtureServer(t, testVersion, "kryptkeeper", osName, arch, hubContent, false)
	defer srv.Close()
	cosign, logPath := fakeCosign(t, 0)

	if out, err := runInstallSh(t, srv.URL, testVersion, t.TempDir(), "hub", installOpts{cosign: cosign}); err != nil {
		t.Fatalf("install.sh failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("fake cosign was never invoked: %v", err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	valueOf := func(flag string) string {
		for i, a := range args {
			if a == flag && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	if args[0] != "verify-blob" {
		t.Errorf("first arg = %q, want verify-blob", args[0])
	}
	wantID := `^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v`
	if got := valueOf("--certificate-identity-regexp"); got != wantID {
		t.Errorf("identity regexp = %q, want %q", got, wantID)
	}
	if got := valueOf("--certificate-oidc-issuer"); got != "https://token.actions.githubusercontent.com" {
		t.Errorf("issuer = %q", got)
	}
	if last := args[len(args)-1]; filepath.Base(last) != "checksums.txt" {
		t.Errorf("cosign verified %q, want checksums.txt", last)
	}
	if filepath.Base(valueOf("--signature")) != "checksums.txt.sig" || filepath.Base(valueOf("--certificate")) != "checksums.txt.pem" {
		t.Errorf("signature/certificate args wrong: %v", args)
	}
}

func TestInstallSh_AgentComponent(t *testing.T) {
	osName, arch := hostOSArch(t)
	const agentContent = "#!/bin/sh\necho fake-agent-binary\n"
	srv := fixtureServer(t, testVersion, "kryptkeeper-agent", osName, arch, agentContent, false)
	defer srv.Close()
	cosign, _ := fakeCosign(t, 0)

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, testVersion, installDir, "agent", installOpts{cosign: cosign})
	if err != nil {
		t.Fatalf("install.sh (agent) failed: %v\noutput:\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(installDir, "kryptkeeper-agent")); statErr != nil {
		t.Fatalf("expected agent binary: %v", statErr)
	}
}

func TestInstallSh_RejectsUnknownComponent(t *testing.T) {
	installDir := t.TempDir()
	out, err := runInstallSh(t, "http://127.0.0.1:1", testVersion, installDir, "not-a-real-component", installOpts{})
	if err == nil {
		t.Fatalf("install.sh accepted an invalid KRYPTKEEPER_COMPONENT\noutput:\n%s", out)
	}
}
