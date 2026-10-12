// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html"
	"io/fs"
	"regexp"
	"strings"
	"unicode/utf16"
)

// W18-02: an Executor backed by WinRM, so the IIS installer can drive a
// real Windows host.
//
// iis_windows.go was complete and unreachable: it takes an Executor, the
// only Executor was SSH, and agentdiscovery's WSManShell does not satisfy
// the interface — it exposes Run(ctx, cmd, args) (string, error) and has
// no file operations at all. This is the adapter that closes that gap.
//
// Two things it deliberately does NOT paper over:
//
//  1. WSManShell.Run returns stdout and reports an error only for
//     transport/SOAP failures — the remote EXIT CODE is discarded. A
//     failed `netsh http add sslcert` would otherwise read as success and
//     the installer would report an install that never happened. Every
//     command here is wrapped so the exit status comes back and a
//     non-zero one becomes a Go error.
//  2. Windows has no POSIX file modes. WriteFile takes an fs.FileMode
//     because the interface says so; it is ignored, and that is stated
//     rather than simulated with a bogus icacls translation.

// winRMShell is the slice of agentdiscovery.WSManShell this adapter needs.
// Declared here so tests substitute a fake and CI needs no Windows host;
// *WSManShell satisfies it structurally.
type winRMShell interface {
	RunExit(ctx context.Context, command string, args ...string) (stdout, stderr string, exitCode int, err error)
}

// WinRMExecutor implements Executor over a WinRM shell.
type WinRMExecutor struct {
	shell winRMShell
}

func NewWinRMExecutor(shell winRMShell) *WinRMExecutor {
	return &WinRMExecutor{shell: shell}
}

// Run executes a command and returns its combined output. The exit code
// comes from WS-Man's own CommandState report, so a native command runs
// exactly as given and a `powershell -Command <script> args` invocation is
// re-encoded ONCE (see encodeInlinePowerShell) -- no wrapper process, no
// second encoding, no command-line-length cliff.
func (e *WinRMExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	args = encodeInlinePowerShell(name, args)
	stdout, stderr, code, err := e.shell.RunExit(ctx, name, args...)
	if err != nil {
		return nil, fmt.Errorf("winrm run %s: %w", name, err)
	}
	// stderr is folded in as text: certutil prints its error line there,
	// and powershell.exe emits CLIXML there, which is rendered back to the
	// error records' text so the Win32 code W18-10 keys on stays visible.
	body := stdout + clixmlToText(stderr)
	if code != 0 {
		// A non-zero EXIT means the command RAN and reported failure (e.g.
		// netsh "no binding exists"). This is distinct from a transport or
		// auth failure above, where the command never ran — a distinction
		// callers like showBinding must honor so a 401 is not silently
		// treated as "nothing there".
		return []byte(body), &WinRMExitError{Command: name, Code: code, Output: strings.TrimSpace(body)}
	}
	return []byte(body), nil
}

// encodeInlinePowerShell rewrites `powershell ... -Command <script> [args]`
// into `powershell ... -EncodedCommand <base64>` with the positional args
// bound to $args inside the script. Callers like the IIS installer hand
// over a multi-line script that reads $args[0..n]; as a plain argument
// that text is re-parsed by cmd.exe and powershell and does not survive
// (captured live 2026-09-10: the PFX build failed with only the script's
// first line as output). Non-PowerShell commands pass through.
func encodeInlinePowerShell(name string, args []string) []string {
	base := strings.ToLower(strings.TrimSuffix(name, ".exe"))
	if base != "powershell" && base != "pwsh" {
		return args
	}
	for i, a := range args {
		if !strings.EqualFold(a, "-Command") && !strings.EqualFold(a, "-c") || i+1 >= len(args) {
			continue
		}
		var sb strings.Builder
		sb.WriteString("$args = @(")
		for j, p := range args[i+2:] {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(psQuote(p))
		}
		sb.WriteString(")\n")
		sb.WriteString(args[i+1])
		out := append([]string{}, args[:i]...)
		return append(out, "-EncodedCommand", encodePowerShell(sb.String()))
	}
	return args
}

// encodePowerShell renders -EncodedCommand's documented form: UTF-16LE,
// base64. It is the only way to hand powershell.exe a script that no
// intermediate shell gets to re-parse.
func encodePowerShell(script string) string {
	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// clixmlErrorRecord matches one serialized error/output string in the
// CLIXML powershell.exe writes to a redirected stderr.
var clixmlErrorRecord = regexp.MustCompile(`<S S="(?:Error|Warning)">([^<]*)</S>`)

// clixmlToText renders powershell.exe's CLIXML stderr as the plain lines
// it encodes; any other stderr passes through unchanged. Progress records
// ("Preparing modules for first use") are dropped -- they are not errors.
func clixmlToText(stderr string) string {
	if !strings.HasPrefix(strings.TrimSpace(stderr), "#< CLIXML") {
		return stderr
	}
	var sb strings.Builder
	for _, m := range clixmlErrorRecord.FindAllStringSubmatch(stderr, -1) {
		t := strings.ReplaceAll(m[1], "_x000D__x000A_", "\n")
		t = strings.ReplaceAll(t, "_x000A_", "\n")
		sb.WriteString(html.UnescapeString(t))
	}
	return sb.String()
}

// WinRMExitError is returned when a remote command RAN and exited non-zero,
// as opposed to a transport/authentication failure where the command never
// executed. Callers use errors.As to tell the two apart.
type WinRMExitError struct {
	Command string
	Code    int
	Output  string
}

func (e *WinRMExitError) Error() string {
	return fmt.Sprintf("winrm run %s: exit status %d: %s", e.Command, e.Code, e.Output)
}

// Exists reports whether a path exists on the remote host.
func (e *WinRMExecutor) Exists(path string) bool {
	out, err := e.powershell(context.Background(),
		fmt.Sprintf("if (Test-Path -LiteralPath %s) { 'yes' } else { 'no' }", psQuote(path)))
	if err != nil {
		// Unknown is not "yes": callers use this to decide whether to back
		// something up, and a false positive loses the backup.
		return false
	}
	return strings.Contains(out, "yes")
}

// ReadFile reads a remote file. Content moves as base64 so binary
// (a DER certificate, a PFX) survives the round trip intact.
func (e *WinRMExecutor) ReadFile(path string) ([]byte, error) {
	out, err := e.powershell(context.Background(),
		fmt.Sprintf("[Convert]::ToBase64String([IO.File]::ReadAllBytes(%s))", psQuote(path)))
	if err != nil {
		return nil, fmt.Errorf("winrm read %s: %w", path, err)
	}
	decoded, derr := base64.StdEncoding.DecodeString(stripWhitespace(out))
	if derr != nil {
		return nil, fmt.Errorf("winrm read %s: response was not base64: %w", path, derr)
	}
	return decoded, nil
}

// WriteFile places content at path.
//
// mode is accepted to satisfy Executor and IGNORED: Windows uses ACLs,
// not POSIX permission bits, and translating 0600 into an icacls
// invocation would be a guess dressed as a guarantee. Callers that need
// a specific ACL must set it explicitly.
func (e *WinRMExecutor) WriteFile(path string, content []byte, _ fs.FileMode) error {
	encoded := base64.StdEncoding.EncodeToString(content)
	script := fmt.Sprintf(
		"$d=[Convert]::FromBase64String('%s'); [IO.File]::WriteAllBytes(%s,$d)",
		encoded, psQuote(path))
	if _, err := e.powershell(context.Background(), script); err != nil {
		return fmt.Errorf("winrm write %s: %w", path, err)
	}
	return nil
}

// powershell runs a script and returns trimmed stdout. A thrown .NET
// exception (WriteAllBytes on a path the account cannot write, say) is the
// failure signal for a script, reported through the process exit code;
// the innermost HResult is emitted alongside the message because the
// message is localized prose and the HResult is not (0x80070005 is the
// same Win32 access-denied code elevationRequired keys on for
// certutil/netsh; captured live 2026-09-10 on the ProgramData staging
// write, which is the FIRST thing a non-administrator fails).
func (e *WinRMExecutor) powershell(ctx context.Context, script string) (string, error) {
	wrapped := `try { ` + script + ` } catch { ` +
		`$e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; ` +
		`"$_"; ('HRESULT 0x{0:X8}' -f $e.HResult); exit 1 }`
	out, err := e.Run(ctx, "powershell", "-NonInteractive", "-NoProfile", "-Command", wrapped)
	return strings.TrimSpace(string(out)), err
}

// psQuote renders a PowerShell single-quoted literal, escaping embedded
// quotes by doubling them. Single quotes mean PowerShell performs no
// expansion, so a path containing $ or ` cannot become an injection.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
}
