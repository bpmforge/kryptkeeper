// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// psCall is one powershell invocation the installer made.
type psCall struct {
	script string
	args   []string
}

// winFake is an Executor for the PowerShell-driven Windows modes. Handlers
// are matched in order by a substring of the SCRIPT (the part that identifies
// the step), so a test scripts "Restart-Service fails" without reproducing
// the whole command line.
type winFake struct {
	files    map[string][]byte
	ran      []string // every command, WRITE entries included, in order
	calls    []psCall
	handlers []*winHandler
}

type winHandler struct {
	contains string
	// nth restricts the handler to the nth matching call (1-based); 0 = all.
	nth  int
	out  string
	err  error
	seen int
}

func newWinFake() *winFake { return &winFake{files: map[string][]byte{}} }

// on registers a handler; later registrations are consulted first so a test
// can override a default.
func (f *winFake) on(contains, out string, err error) *winHandler {
	h := &winHandler{contains: contains, out: out, err: err}
	f.handlers = append([]*winHandler{h}, f.handlers...)
	return h
}

func (f *winFake) Exists(path string) bool { _, ok := f.files[path]; return ok }

func (f *winFake) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("not found: %s", path)
	}
	return b, nil
}

func (f *winFake) WriteFile(path string, content []byte, _ os.FileMode) error {
	f.files[path] = append([]byte(nil), content...)
	f.ran = append(f.ran, "WRITE "+path)
	return nil
}

func (f *winFake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.ran = append(f.ran, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if name == "cmd" && len(args) >= 2 && args[0] == "/C" && args[1] == "rmdir" {
		dir := args[len(args)-1]
		for p := range f.files {
			if strings.HasPrefix(p, dir) {
				delete(f.files, p)
			}
		}
		return []byte("ok"), nil
	}
	if name != "powershell" {
		return []byte("ok"), nil
	}
	// args: -NonInteractive -NoProfile -Command <script> <positional...>
	call := psCall{script: args[3], args: append([]string(nil), args[4:]...)}
	f.calls = append(f.calls, call)
	for _, h := range f.handlers {
		if !strings.Contains(call.script, h.contains) {
			continue
		}
		h.seen++
		if h.nth != 0 && h.seen != h.nth {
			continue
		}
		return []byte(h.out), h.err
	}
	return []byte(""), nil
}

// callsMatching returns the powershell calls whose script contains s.
func (f *winFake) callsMatching(s string) []psCall {
	var out []psCall
	for _, c := range f.calls {
		if strings.Contains(c.script, s) {
			out = append(out, c)
		}
	}
	return out
}

// importedThumbprintOutput makes the Import-PfxCertificate step echo whatever
// the installer expects: the thumbprint of the cert it was given. The fake
// cannot compute it from the PFX, so tests pass the known value.
func (f *winFake) importReturns(thumbprint string) {
	f.on("Import-PfxCertificate", thumbprint, nil)
}

var errAccessDenied = errors.New("winrm run powershell: exit status 1: Access is denied. HRESULT 0x80070005")

// stubVerifier returns a Verifier reporting a fixed fingerprint or error, and
// counts calls.
type stubVerifier struct {
	fp    string
	err   error
	calls int
}

func (s *stubVerifier) verify(_ context.Context, _ string) (string, error) {
	s.calls++
	return s.fp, s.err
}
