// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const stubToken = "stub-token-do-not-leak"

type stubCert struct {
	FP        string `json:"fingerprint_sha256"`
	Origin    string `json:"origin"`
	OwnerTeam string `json:"owner_team,omitempty"`
}

func fingerprints(n int) []string {
	out := make([]string, n)
	for i := range out {
		sum := sha256.Sum256([]byte(fmt.Sprintf("mig-%03d.lab.example", i)))
		out[i] = hex.EncodeToString(sum[:])
	}
	return out
}

func imported(fps []string, owner string) []stubCert {
	out := make([]stubCert, len(fps))
	for i, fp := range fps {
		out[i] = stubCert{FP: fp, Origin: "imported", OwnerTeam: owner}
	}
	return out
}

// stubHub serves certs in pages of at most 100 using the hub's offset cursor.
func stubHub(t *testing.T, certs []stubCert, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			http.Error(w, "nope", status)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+stubToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		off, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		end := min(off+100, len(certs))
		var next *string
		if end < len(certs) {
			s := strconv.Itoa(end)
			next = &s
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": certs[off:end],
			"meta": map[string]any{"total": len(certs), "next_cursor": next},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runVerify(t *testing.T, srv *httptest.Server, manifest []string, extra ...string) (stdout, stderr string, code int) {
	t.Helper()
	script, err := filepath.Abs("../../../scripts/migration-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(t.TempDir(), "manifest.txt")
	body := "# manifest\n\n" + strings.Join(manifest, "\n") + "\n"
	if err := os.WriteFile(mf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{script, "--manifest", mf, "--hub", srv.URL}, extra...)
	cmd := exec.Command("bash", args...)
	cmd.Env = append(os.Environ(), "KK_TOKEN="+stubToken)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run script: %v", err)
	}
	return so.String(), se.String(), code
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func TestVerifyAll200Mapped(t *testing.T) {
	fps := fingerprints(200)
	out, errOut, code := runVerify(t, stubHub(t, imported(fps, ""), 0), fps)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	if got := lastLine(out); got != "total=200 mapped=200 unmatched=0 percent=100.0" {
		t.Fatalf("last line = %q", got)
	}
}

func TestVerifyOneMissingFails(t *testing.T) {
	fps := fingerprints(200)
	out, errOut, code := runVerify(t, stubHub(t, imported(fps[:199], ""), 0), fps)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errOut, fps[199]) {
		t.Fatalf("stderr does not name the missing fingerprint: %s", errOut)
	}
	if !strings.Contains(out, "unmatched=1") {
		t.Fatalf("stdout = %q", out)
	}
}

func TestVerifyWrongOriginIsUnmatched(t *testing.T) {
	fps := fingerprints(3)
	certs := imported(fps, "")
	certs[1].Origin = "internal"
	out, _, code := runVerify(t, stubHub(t, certs, 0), fps)
	if code != 1 || !strings.Contains(out, "mapped=2 unmatched=1") {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
}

func TestVerifyRequireOwner(t *testing.T) {
	fps := fingerprints(2)
	srv := stubHub(t, imported(fps, ""), 0)
	if _, _, code := runVerify(t, srv, fps, "--require-owner"); code != 1 {
		t.Fatalf("with --require-owner exit %d, want 1", code)
	}
	if _, _, code := runVerify(t, srv, fps); code != 0 {
		t.Fatalf("without flag exit %d, want 0", code)
	}
}

func TestVerifyNormalisesColonsAndCase(t *testing.T) {
	fps := fingerprints(1)
	upper := strings.ToUpper(fps[0])
	var colon []string
	for i := 0; i < len(upper); i += 2 {
		colon = append(colon, upper[i:i+2])
	}
	_, errOut, code := runVerify(t, stubHub(t, imported(fps, ""), 0), []string{strings.Join(colon, ":")})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestVerifyAuthErrorExits2(t *testing.T) {
	fps := fingerprints(1)
	out, errOut, code := runVerify(t, stubHub(t, nil, http.StatusUnauthorized), fps)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if strings.Contains(out+errOut, stubToken) {
		t.Fatal("token leaked into output")
	}
}

func TestVerifyEmptyManifestExits1(t *testing.T) {
	_, _, code := runVerify(t, stubHub(t, nil, 0), nil)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}
