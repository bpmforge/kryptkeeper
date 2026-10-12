// Package packaging tests packaging/install.sh against a local httptest
// fixture server -- no live network, per CLAUDE.md/PLAYBOOK's "no live
// network in unit tests" rule. install.sh itself does reach the network
// when a real user runs it (that's its job); these tests never do.
package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func runInstallSh(t *testing.T, baseURL, version, installDir, component string) ([]byte, error) {
	t.Helper()
	scriptPath, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatalf("resolve install.sh path: %v", err)
	}
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = append(os.Environ(),
		"KRYPTKEEPER_INSTALL_BASE_URL="+baseURL,
		"KRYPTKEEPER_VERSION="+version,
		"KRYPTKEEPER_INSTALL_DIR="+installDir,
		"KRYPTKEEPER_COMPONENT="+component,
	)
	return cmd.CombinedOutput()
}

// fixtureServer serves a fake release asset + a SHA256SUMS.txt. If
// tamperChecksum is true, the sums file records the wrong hash for the
// asset -- the install_test.go equivalent of "break the subject, watch the
// test go red" for install.sh's fail-closed checksum verification.
func fixtureServer(t *testing.T, version, assetName, assetContent string, tamperChecksum bool) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256([]byte(assetContent))
	hexSum := hex.EncodeToString(sum[:])
	if tamperChecksum {
		hexSum = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	sumsLine := fmt.Sprintf("%s  %s\n", hexSum, assetName)

	mux := http.NewServeMux()
	assetPath := "/" + version + "/" + assetName
	sumsPath := "/" + version + "/SHA256SUMS.txt"
	mux.HandleFunc(assetPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(assetContent))
	})
	mux.HandleFunc(sumsPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sumsLine))
	})
	return httptest.NewServer(mux)
}

func TestInstallSh_VerifiesChecksumAndInstalls(t *testing.T) {
	osName, arch := hostOSArch(t)
	const version = "v0.0.0-test"
	assetName := "kryptkeeper-" + osName + "-" + arch
	const assetContent = "#!/bin/sh\necho fake-hub-binary\n"

	srv := fixtureServer(t, version, assetName, assetContent, false)
	defer srv.Close()

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, version, installDir, "hub")
	if err != nil {
		t.Fatalf("install.sh failed on a correctly-checksummed asset: %v\noutput:\n%s", err, out)
	}

	installed := filepath.Join(installDir, "kryptkeeper")
	data, err := os.ReadFile(installed)
	if err != nil {
		t.Fatalf("expected binary at %s, got: %v", installed, err)
	}
	if string(data) != assetContent {
		t.Fatalf("installed binary content mismatch: got %q, want %q", data, assetContent)
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
	const version = "v0.0.0-test"
	assetName := "kryptkeeper-" + osName + "-" + arch
	const assetContent = "#!/bin/sh\necho fake-hub-binary\n"

	// This is the RED check: tamperChecksum=true reproduces exactly what
	// a corrupted download or a tampered SHA256SUMS.txt looks like.
	srv := fixtureServer(t, version, assetName, assetContent, true)
	defer srv.Close()

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, version, installDir, "hub")
	if err == nil {
		t.Fatalf("install.sh exited 0 against a tampered checksum -- expected it to fail closed\noutput:\n%s", out)
	}

	installed := filepath.Join(installDir, "kryptkeeper")
	if _, statErr := os.Stat(installed); statErr == nil {
		t.Fatalf("install.sh left %s in place despite a checksum mismatch", installed)
	}
}

func TestInstallSh_AgentComponent(t *testing.T) {
	osName, arch := hostOSArch(t)
	const version = "v0.0.0-test"
	assetName := "kryptkeeper-agent-" + osName + "-" + arch
	const assetContent = "#!/bin/sh\necho fake-agent-binary\n"

	srv := fixtureServer(t, version, assetName, assetContent, false)
	defer srv.Close()

	installDir := t.TempDir()
	out, err := runInstallSh(t, srv.URL, version, installDir, "agent")
	if err != nil {
		t.Fatalf("install.sh (agent) failed: %v\noutput:\n%s", err, out)
	}

	installed := filepath.Join(installDir, "kryptkeeper-agent")
	if _, statErr := os.Stat(installed); statErr != nil {
		t.Fatalf("expected agent binary at %s, got: %v", installed, statErr)
	}
}

func TestInstallSh_RejectsUnknownComponent(t *testing.T) {
	installDir := t.TempDir()
	out, err := runInstallSh(t, "http://127.0.0.1:1", "v0.0.0-test", installDir, "not-a-real-component")
	if err == nil {
		t.Fatalf("install.sh accepted an invalid KRYPTKEEPER_COMPONENT\noutput:\n%s", out)
	}
}
