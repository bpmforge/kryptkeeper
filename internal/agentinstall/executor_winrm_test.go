// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

// W18-02: the adapter that makes the IIS installer reachable. The fake
// shell stands in for a Windows host, so none of this needs WinRM.

type fakeShell struct {
	lastCommand string
	// out is returned verbatim; tests append the exit sentinel themselves
	// so they control the simulated exit status.
	out string
	err error
}

// exitSentinel lets a test fixture state the simulated exit status inline
// in `out`; RunExit splits it off the way WS-Man would report ExitCode.
const exitSentinel = "__KK_EXIT__"

// RunExit records the command with -EncodedCommand decoded, so assertions
// can read the script the host would have executed.
func (f *fakeShell) RunExit(_ context.Context, command string, args ...string) (string, string, int, error) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-EncodedCommand" {
			args[i+1] = decodePowerShell(args[i+1])
		}
	}
	f.lastCommand = command + " " + strings.Join(args, " ")
	if f.err != nil {
		return "", "", 0, f.err
	}
	body, code, found := splitExitStatus(f.out)
	if !found {
		return f.out, "", 0, nil
	}
	return body, "", code, nil
}

// splitExitStatus pulls the sentinel line out of a fixture's stdout.
func splitExitStatus(out string) (body string, code int, found bool) {
	idx := strings.LastIndex(out, exitSentinel)
	if idx < 0 {
		return out, 0, false
	}
	body = out[:idx]
	rest := strings.TrimSpace(out[idx+len(exitSentinel):])
	if nl := strings.IndexAny(rest, "\r\n"); nl >= 0 {
		rest = rest[:nl]
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil {
		return body, 0, false
	}
	return body, parsed, true
}

func decodePowerShell(enc string) string {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw)%2 != 0 {
		return enc
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u16))
}

func withExit(body string, code int) string {
	return body + "\r\n" + exitSentinel + string(rune('0'+code)) + "\r\n"
}

// THE headline property: WSManShell discards the remote exit code, so a
// failed netsh would otherwise read as success and the installer would
// report an install that never happened.
func TestWinRMRunSurfacesNonZeroExitStatus(t *testing.T) {
	sh := &fakeShell{out: withExit("The parameter is incorrect.", 1)}
	_, err := NewWinRMExecutor(sh).Run(context.Background(), "netsh", "http", "add", "sslcert")
	if err == nil {
		t.Fatal("a non-zero remote exit status must be an error, not silent success")
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("the error must name the status: %v", err)
	}
	// And it must carry the remote output, or the operator cannot diagnose.
	if !strings.Contains(err.Error(), "parameter is incorrect") {
		t.Fatalf("the error must carry the remote output: %v", err)
	}
}

func TestWinRMRunReturnsOutputOnSuccess(t *testing.T) {
	sh := &fakeShell{out: withExit("SSL Certificate bindings:", 0)}
	out, err := NewWinRMExecutor(sh).Run(context.Background(), "netsh", "http", "show", "sslcert")
	if err != nil {
		t.Fatalf("exit 0 must succeed: %v", err)
	}
	if !strings.Contains(string(out), "SSL Certificate bindings") {
		t.Fatalf("output lost: %q", out)
	}
	// The sentinel is bookkeeping and must not leak into what callers parse.
	if strings.Contains(string(out), exitSentinel) {
		t.Fatal("the exit sentinel must be stripped from returned output")
	}
}

// A transport/auth failure means the command never ran; it must be an
// error, never read as "ran and printed nothing".
func TestWinRMRunTransportFailureIsAnError(t *testing.T) {
	_, err := NewWinRMExecutor(&fakeShell{err: errors.New("HTTP 401")}).Run(context.Background(), "netsh", "http", "show", "sslcert")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("transport failure must surface: %v", err)
	}
}

func TestWinRMRunPropagatesTransportError(t *testing.T) {
	sh := &fakeShell{err: errors.New("connection refused")}
	if _, err := NewWinRMExecutor(sh).Run(context.Background(), "whoami"); err == nil {
		t.Fatal("a transport failure must surface")
	}
}

// Binary must survive the round trip — a DER certificate is not text.
func TestWinRMReadFileDecodesBinary(t *testing.T) {
	raw := []byte{0x30, 0x82, 0x01, 0x0a, 0x00, 0xff, 0xfe}
	sh := &fakeShell{out: withExit(base64.StdEncoding.EncodeToString(raw), 0)}
	got, err := NewWinRMExecutor(sh).ReadFile(`C:\certs\a.cer`)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("binary corrupted: % x", got)
	}
}

func TestWinRMWriteFileSendsBase64AndPath(t *testing.T) {
	sh := &fakeShell{out: withExit("", 0)}
	content := []byte{0x00, 0x01, 0xfe}
	if err := NewWinRMExecutor(sh).WriteFile(`C:\certs\b.cer`, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(sh.lastCommand, base64.StdEncoding.EncodeToString(content)) {
		t.Fatalf("content not sent as base64: %s", sh.lastCommand)
	}
	if !strings.Contains(sh.lastCommand, `C:\certs\b.cer`) {
		t.Fatalf("path missing: %s", sh.lastCommand)
	}
}

// Unknown must not be reported as present: callers use Exists to decide
// whether to take a backup, and a false positive loses it.
func TestWinRMExistsIsFalseWhenUnknown(t *testing.T) {
	if NewWinRMExecutor(&fakeShell{err: errors.New("boom")}).Exists(`C:\x`) {
		t.Fatal("a failed check must not report the path as existing")
	}
	if NewWinRMExecutor(&fakeShell{out: withExit("no", 0)}).Exists(`C:\x`) {
		t.Fatal("'no' must be false")
	}
	if !NewWinRMExecutor(&fakeShell{out: withExit("yes", 0)}).Exists(`C:\x`) {
		t.Fatal("'yes' must be true")
	}
}

// A path is data, never script: single-quoted PowerShell literals do not
// expand, and an embedded quote is doubled rather than escaping out.
func TestWinRMQuotesPathsAgainstInjection(t *testing.T) {
	if got := psQuote(`C:\a'b`); got != `'C:\a''b'` {
		t.Fatalf("embedded quote not doubled: %s", got)
	}
	if got := psQuote(`C:\$env:temp`); !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("path must be a single-quoted literal: %s", got)
	}
}

// The adapter exists to satisfy Executor — if it stops doing so, the IIS
// installer is unreachable again.
func TestWinRMExecutorSatisfiesExecutor(t *testing.T) {
	var _ Executor = (*WinRMExecutor)(nil)
}

// A script failure must carry the Win32 code, not only the localized
// message, or elevationRequired cannot classify a denied ProgramData write
// as "authenticated but not an Administrator" (captured live 2026-09-10).
func TestWinRMScriptFailureEmitsHResult(t *testing.T) {
	sh := &fakeShell{out: withExit("", 0)}
	_ = NewWinRMExecutor(sh).WriteFile(`C:\x`, []byte("a"), 0o600)
	if !strings.Contains(sh.lastCommand, "HRESULT 0x{0:X8}") || !strings.Contains(sh.lastCommand, "InnerException") {
		t.Fatalf("catch block must emit the innermost HResult: %s", sh.lastCommand)
	}
}

// A `-Command <script> args...` invocation must reach the host as an
// encoded script with $args bound, never as a quoted argument a parent
// PowerShell re-parses (live: the PFX build died on its first line).
func TestWinRMInlinePowerShellScriptIsEncodedWithArgs(t *testing.T) {
	sh := &fakeShell{out: withExit("", 0)}
	script := "$ErrorActionPreference = 'Stop'\n[IO.File]::ReadAllBytes($args[0])"
	_, err := NewWinRMExecutor(sh).Run(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", script, `C:\stage\cert.der`, "p'w")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sh.lastCommand, "-Command") {
		t.Fatalf("script must not be passed through -Command: %s", sh.lastCommand)
	}
	if !strings.Contains(sh.lastCommand, `$args = @('C:\stage\cert.der', 'p''w')`) || !strings.Contains(sh.lastCommand, "ReadAllBytes($args[0])") {
		t.Fatalf("script must bind $args and be carried verbatim: %s", sh.lastCommand)
	}
	if _, err := NewWinRMExecutor(&fakeShell{out: withExit("", 0)}).Run(context.Background(), "netsh", "http", "show", "sslcert"); err != nil {
		t.Fatal(err)
	}
}

// powershell.exe writes CLIXML to a redirected stderr; the error text must
// come back as text so certutil-style codes inside it stay matchable.
func TestCLIXMLStderrIsRenderedAsText(t *testing.T) {
	raw := "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Access to the path &#39;C:\\x&#39; is denied._x000D__x000A_</S><S S=\"Error\">HRESULT 0x80070005_x000D__x000A_</S><Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T></TN></Obj></Objs>"
	got := clixmlToText(raw)
	if !strings.Contains(got, "Access to the path 'C:\\x' is denied.") || !strings.Contains(got, "HRESULT 0x80070005") || strings.Contains(got, "progress") {
		t.Fatalf("rendered: %q", got)
	}
	if clixmlToText("plain certutil error") != "plain certutil error" {
		t.Fatal("non-CLIXML stderr must pass through")
	}
}
