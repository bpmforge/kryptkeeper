// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

func TestSanitize(t *testing.T) {
	if got := sanitize("key -----BEGIN PRIVATE KEY----- x", nil); strings.Contains(got, "BEGIN") {
		t.Errorf("PEM not withheld: %q", got)
	}
	if got := sanitize("token=s3cr3t-value here", []string{"s3cr3t-value"}); strings.Contains(got, "s3cr3t") {
		t.Errorf("secret not redacted: %q", got)
	}
	if got := sanitize(strings.Repeat("a", 1000), nil); len(got) > maxLogLine+3 {
		t.Errorf("line not capped: %d", len(got))
	}
	if got := sanitize("a\nb", nil); strings.Contains(got, "\n") {
		t.Errorf("newline kept: %q", got)
	}
}

func TestAllowedHostAndPaths(t *testing.T) {
	st := &callState{
		env: Env{Credential: map[string]string{"base_url": "https://bigip.example.com"}},
		granted: abi.Capabilities{
			Network:   &abi.Network{HostsFromCredential: "base_url", Hosts: []string{"api.cdn.example"}},
			FileWrite: []string{"/etc/ssl/kk"},
		},
	}
	for host, want := range map[string]bool{"bigip.example.com": true, "BIGIP.example.com": true, "api.cdn.example": true, "evil.example.com": false} {
		if got := st.allowedHost(host, 443); got != want {
			t.Errorf("allowedHost(%s) = %v", host, got)
		}
	}
	if st.allowedHost("bigip.example.com", 8443) {
		t.Error("an undeclared port was allowed")
	}
	for p, want := range map[string]bool{"/etc/ssl/kk": true, "/etc/ssl/kk/a.pem": true, "/etc/ssl/kkevil": false, "/etc/ssl/kk/../shadow": false, "/etc/passwd": false} {
		if got := st.pathAllowed(p); got != want {
			t.Errorf("pathAllowed(%s) = %v", p, got)
		}
	}
}

type recordingExecutor struct{ ran [][]string }

func (r *recordingExecutor) Exists(string) bool                          { return true }
func (r *recordingExecutor) ReadFile(string) ([]byte, error)             { return []byte("x"), nil }
func (r *recordingExecutor) WriteFile(string, []byte, os.FileMode) error { return nil }
func (r *recordingExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.ran = append(r.ran, append([]string{name}, args...))
	return nil, nil
}

func TestExecNeedsGrants(t *testing.T) {
	ex := &recordingExecutor{}
	st := &callState{env: Env{Executor: ex}, granted: abi.Capabilities{RemoteExec: true, FileWrite: []string{"/srv/certs"}}}
	if _, err := st.exec(context.Background(), abi.HostExecRun, []byte(`{"argv":["sudo","systemctl","reload","nginx"]}`)); err == nil {
		t.Error("sudo ran without elevated_exec")
	}
	if _, err := st.exec(context.Background(), abi.HostExecRun, []byte(`{"argv":["/usr/bin/doas","id"]}`)); err == nil {
		t.Error("doas ran without elevated_exec")
	}
	if _, err := st.exec(context.Background(), abi.HostExecRun, []byte(`{"argv":["nginx","-t"]}`)); err != nil {
		t.Errorf("plain command refused: %v", err)
	}
	if _, err := st.exec(context.Background(), abi.HostExecWrite, []byte(`{"path":"/etc/cron.d/x","content":"eA=="}`)); err == nil {
		t.Error("write outside file_write allowed")
	}
	st.granted = abi.Capabilities{}
	if _, err := st.exec(context.Background(), abi.HostExecRun, []byte(`{"argv":["nginx","-t"]}`)); err == nil {
		t.Error("exec without remote_exec allowed")
	}
	if len(ex.ran) != 1 {
		t.Errorf("ran %v, want only the plain command", ex.ran)
	}
}
