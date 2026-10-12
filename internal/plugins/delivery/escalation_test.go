// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

var escalating = [][]string{
	{"sh", "-c", "sudo systemctl reload nginx"},
	{"bash", "-lc", "id"},
	{"/bin/bash", "-o", "pipefail", "-c", "id"},
	{"env", "sudo", "id"},
	{"env", "FOO=1", "bash", "-c", "id"},
	{"env", "-S", "sudo id"},
	{"/usr/bin/sudo", "id"},
	{"/usr/bin/../bin/sudo", "id"},
	{"su", "-c", "id"},
	{"pkexec", "id"},
	{"runuser", "-u", "root", "id"},
	{"setpriv", "--reuid=0", "id"},
	{"chroot", "/", "id"},
	{"nsenter", "-t", "1", "-m", "id"},
	{"doas", "id"},
	{"python3", "-c", "import os"},
	{"python3.12", "-c", "import os"},
	{"perl", "-e", "system 'id'"},
	{"ruby", "-e", "system 'id'"},
	{"node", "-e", "1"},
	{"busybox", "sh", "-c", "id"},
	{"nohup", "sudo", "id"},
	{"timeout", "5", "sh", "-c", "id"},
	{`C:\tools\SUDO.exe`, "id"},
	{"cmd", "/c", "dir"},
	{"powershell", "-Command", "id"},
}

func runArgv(t *testing.T, granted abi.Capabilities, argv []string) (*recordingExecutor, error) {
	t.Helper()
	ex := &recordingExecutor{}
	st := &callState{env: Env{Executor: ex}, granted: granted}
	in, _ := json.Marshal(map[string]any{"argv": argv})
	_, err := st.exec(context.Background(), abi.HostExecRun, in)
	return ex, err
}

// OWASP-A08-001: without elevated_exec, escalation tools and shells or
// interpreters with an inline command are refused however they are spelled.
func TestExecRefusesEscalationWithoutElevatedExec(t *testing.T) {
	for _, argv := range escalating {
		ex, err := runArgv(t, abi.Capabilities{RemoteExec: true}, argv)
		if err == nil || len(ex.ran) != 0 {
			t.Errorf("%v ran without elevated_exec (err=%v)", argv, err)
		}
	}
}

func TestExecAllowsConcretePrograms(t *testing.T) {
	for _, argv := range [][]string{
		{"nginx", "-t"},
		{"systemctl", "reload", "nginx"},
		{"/usr/sbin/nginx", "-s", "reload"},
		{"openssl", "x509", "-noout", "-in", "/srv/certs/a.pem"},
		{"python3", "/opt/deploy.py", "--check"},
		{"sh", "/opt/reload.sh"},
		{"env", "FOO=1", "nginx", "-t"},
	} {
		if _, err := runArgv(t, abi.Capabilities{RemoteExec: true}, argv); err != nil {
			t.Errorf("%v refused: %v", argv, err)
		}
	}
}

func TestExecAllowsEscalationWithElevatedExec(t *testing.T) {
	for _, argv := range escalating {
		if _, err := runArgv(t, abi.Capabilities{RemoteExec: true, ElevatedExec: true}, argv); err != nil {
			t.Errorf("%v refused despite elevated_exec: %v", argv, err)
		}
	}
}
