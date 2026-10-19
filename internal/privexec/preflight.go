// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package privexec

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Role is what the account will be asked to do; install needs more than scan.
type Role string

const (
	RoleScan    Role = "scan"
	RoleInstall Role = "install"
)

// Report is what an account can do; every false field has a Missing line.
type Report struct {
	SudoPresent   bool     `json:"sudo_present"`
	RequireTTY    bool     `json:"require_tty"`
	NoPasswdOK    bool     `json:"nopasswd_ok"` // helper mode: sudo -n <helper> version worked
	PasswordOK    bool     `json:"password_ok"`
	HelperPresent bool     `json:"helper_present"`
	HelperSHAOK   bool     `json:"helper_sha_ok"`
	Missing       []string `json:"missing"`
	PrivilegedAll bool     `json:"privileged_all"`
	// HighImpact is set when sudo -l shows the account can run anything as
	// root or cat/install on globbed paths; HighImpactReason says which. It is
	// what the credential's privileged flag (W34-11) is derived from, and is
	// independent of PrivilegedAll (which only means "has what the scan needs").
	HighImpact       bool   `json:"high_impact"`
	HighImpactReason string `json:"high_impact_reason,omitempty"`
	// RequireTTYFix is the sudoers line that clears RequireTTY.
	RequireTTYFix string `json:"require_tty_fix,omitempty"`
}

var requiredCommands = map[Role][]string{
	RoleScan:    {"find", "stat", "cat", "ss"},
	RoleInstall: {"find", "stat", "cat", "ss", "install", "systemctl"},
}

// Preflight probes inner with the credential's privilege config. It builds the
// sudo probes itself (not via Wrap) so a failure reports which step broke. The
// sudo -l parse is best-effort: a missing or unparsable listing adds nothing
// to Missing.
func Preflight(ctx context.Context, inner Executor, cfg Config, role Role) Report {
	var r Report
	miss := func(s string) { r.Missing = append(r.Missing, s) }
	sudo := cfg.sudo()

	if _, err := inner.Run(ctx, "sh", "-c", "command -v "+sudo); err == nil {
		r.SudoPresent = true
	}
	if cfg.Mode == ModeNone {
		return r
	}
	if !r.SudoPresent {
		miss("sudo is not installed or not on PATH")
		return r
	}

	var probe []byte
	var probeErr error
	switch cfg.Mode {
	case ModeNoPasswd:
		probe, probeErr = inner.Run(ctx, sudo, "-n", "true")
		r.NoPasswdOK = probeErr == nil
		if !r.NoPasswdOK {
			miss("sudo -n true failed: add a NOPASSWD sudoers rule for this account")
		}
	case ModePassword:
		runner, ok := inner.(StdinRunner)
		if !ok || len(cfg.Password) == 0 {
			miss("password mode needs a stored sudo password and an SSH transport")
			break
		}
		pw := append(append([]byte{}, cfg.Password...), '\n')
		probe, probeErr = runner.RunStdin(ctx, pw, sudo, "-S", "-p", "", "-k", "-v")
		zero(pw)
		r.PasswordOK = probeErr == nil
		if !r.PasswordOK {
			miss("sudo rejected the stored password (or the account may not use sudo)")
		}
	case ModeHelper:
		r.HelperPresent, r.HelperSHAOK, probe, probeErr = probeHelper(ctx, inner, cfg, &r)
		if !r.HelperPresent {
			miss("helper not found or not executable at " + cfg.helperPath())
		} else if !r.HelperSHAOK {
			miss("helper sha256 differs from the pinned value (HELPER_TAMPERED)")
		}
		if r.HelperPresent && !r.NoPasswdOK {
			miss("sudo -n " + cfg.helperPath() + " version failed: add the NOPASSWD sudoers line for the helper")
		}
	}

	if strings.Contains(strings.ToLower(string(probe)), "you must have a tty") {
		r.RequireTTY = true
		user := "<user>"
		if out, err := inner.Run(ctx, "id", "-un"); err == nil && strings.TrimSpace(string(out)) != "" {
			user = strings.TrimSpace(string(out))
		}
		r.RequireTTYFix = fmt.Sprintf("Defaults:%s !requiretty", user)
		miss("sudo requires a tty: add the line " + r.RequireTTYFix)
	}

	if (cfg.Mode == ModeNoPasswd && r.NoPasswdOK) || (cfg.Mode == ModePassword && r.PasswordOK) {
		text := sudoListing(ctx, inner, cfg)
		r.HighImpact, r.HighImpactReason = classifySudoListing(text)
		if cfg.Mode == ModeNoPasswd {
			r.Missing = append(r.Missing, rawAllowlistGaps(text, role)...)
		}
	}

	switch cfg.Mode {
	case ModeNoPasswd:
		r.PrivilegedAll = r.NoPasswdOK && len(r.Missing) == 0
	case ModePassword:
		r.PrivilegedAll = r.PasswordOK && len(r.Missing) == 0
	case ModeHelper:
		r.PrivilegedAll = r.HelperPresent && r.HelperSHAOK && r.NoPasswdOK && len(r.Missing) == 0
	}
	return r
}

// probeHelper checks presence, hash and the sudo rule for helper mode.
func probeHelper(ctx context.Context, inner Executor, cfg Config, r *Report) (present, shaOK bool, probe []byte, err error) {
	hp := cfg.helperPath()
	if _, e := inner.Run(ctx, "test", "-x", hp); e != nil {
		return false, false, nil, e
	}
	present = true
	if out, e := inner.Run(ctx, "sha256sum", hp); e == nil && cfg.HelperSHA != "" {
		shaOK = sha256Matches(out, cfg.HelperSHA)
	}
	probe, err = inner.Run(ctx, cfg.sudo(), "-n", "--", hp, "version")
	r.NoPasswdOK = err == nil
	return present, shaOK, probe, err
}

// rawAllowlistGaps reads sudo -l and names required commands it does not list.
func rawAllowlistGaps(text string, role Role) []string {
	if isSudoAll(text) {
		return nil
	}
	listed := map[string]bool{}
	for _, tok := range strings.FieldsFunc(text, func(c rune) bool { return c == ' ' || c == ',' || c == '\n' || c == '\t' }) {
		if strings.HasPrefix(tok, "/") {
			listed[path.Base(tok)] = true
		}
	}
	if len(listed) == 0 {
		return nil
	}
	var gaps []string
	for _, c := range requiredCommands[role] {
		if !listed[c] {
			gaps = append(gaps, "sudo -l does not list "+c+" (best-effort)")
		}
	}
	return gaps
}

// sudoListing returns `sudo -l` output for the raw modes ("" when it cannot be
// read; the parse is best-effort).
func sudoListing(ctx context.Context, inner Executor, cfg Config) string {
	if cfg.Mode == ModePassword {
		runner, ok := inner.(StdinRunner)
		if !ok || len(cfg.Password) == 0 {
			return ""
		}
		pw := append(append([]byte{}, cfg.Password...), '\n')
		defer zero(pw)
		out, err := runner.RunStdin(ctx, pw, cfg.sudo(), "-S", "-p", "", "-k", "-l")
		if err != nil {
			return ""
		}
		return string(out)
	}
	out, err := inner.Run(ctx, cfg.sudo(), "-n", "-l")
	if err != nil {
		return ""
	}
	return string(out)
}

func isSudoAll(text string) bool {
	return strings.Contains(text, "NOPASSWD: ALL") || strings.Contains(text, "(ALL) ALL") || strings.Contains(text, "(ALL : ALL) ALL")
}

var reBroadGlob = regexp.MustCompile(`^(?:\*|/\*|/[^/*]+/\*)$`)

// broadGlobbedReadWrite reports a cat or install rule whose path glob is
// unbounded (`*`, `/*`, `/etc/*`). The shipped raw allowlist names specific
// directories (`/etc/ssl/certs/*`) and must not trip it. Option values such as
// `install -m *` are skipped.
func broadGlobbedReadWrite(text string) (string, bool) {
	for _, cmd := range strings.FieldsFunc(text, func(c rune) bool { return c == ',' || c == '\n' }) {
		f := strings.Fields(cmd)
		for i, tok := range f {
			base := path.Base(tok)
			if !strings.HasPrefix(tok, "/") || (base != "cat" && base != "install") {
				continue
			}
			for k := i + 1; k < len(f); k++ {
				if f[k-1] == "-m" || f[k-1] == "-o" || f[k-1] == "-g" {
					continue
				}
				if reBroadGlob.MatchString(f[k]) {
					return base, true
				}
			}
		}
	}
	return "", false
}

// classifySudoListing says whether a sudo -l listing makes the account
// high-impact on the host (D-208): run-anything, or cat/install on globbed paths.
func classifySudoListing(text string) (bool, string) {
	if isSudoAll(text) {
		return true, "sudo -l grants (ALL) ALL"
	}
	if cmd, ok := broadGlobbedReadWrite(text); ok {
		return true, "sudo allows " + cmd + " on globbed paths"
	}
	return false, ""
}
