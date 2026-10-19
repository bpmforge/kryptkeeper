// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package privexec is the single privilege layer for hub-over-SSH and the
// agent: it wraps an executor so Run/ReadFile/Exists/WriteFile are elevated
// per Mode (none, nopasswd, password, helper). W34-00-DESIGN §3.2.
//
// The package defines its own Executor interface instead of importing
// agentinstall so agentinstall.SudoExecutor can build on it without an import
// cycle; agentinstall.Executor is structurally identical.
package privexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Mode selects how a command is elevated.
type Mode string

const (
	ModeNone     Mode = "none"
	ModeNoPasswd Mode = "nopasswd"
	ModePassword Mode = "password"
	ModeHelper   Mode = "helper"
)

// DefaultHelperPath is where the customer installs the embedded helper.
const DefaultHelperPath = "/usr/local/sbin/kryptkeeper-helper"

// ErrHelperTampered is returned when the installed helper's sha256 differs
// from the pinned value; the hub must not run it.
var ErrHelperTampered = errors.New("privexec: HELPER_TAMPERED: installed helper sha256 does not match the pinned value")

// ErrNotHelperVerb is returned by helper mode for a command the helper does not implement.
var ErrNotHelperVerb = errors.New("privexec: helper mode only runs helper verbs")

// ParseMode validates s; the empty string is ModeNone.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case "":
		return ModeNone, nil
	case ModeNone, ModeNoPasswd, ModePassword, ModeHelper:
		return m, nil
	}
	return "", fmt.Errorf("privexec: unknown mode %q (want none|nopasswd|password|helper)", s)
}

// Executor mirrors agentinstall.Executor.
type Executor interface {
	Exists(path string) bool
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, content []byte, mode os.FileMode) error
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// StdinRunner is the optional capability password mode needs: running a
// command with bytes on stdin. It is a separate interface so the Executor
// contract is not widened; WinRM does not implement it.
type StdinRunner interface {
	RunStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// Config selects and parameterises the privilege mode.
type Config struct {
	Mode Mode
	// Password is the sudo password (password mode). The caller zeroizes it
	// after use; Wrap never retains or logs it.
	Password   []byte
	HelperPath string // default DefaultHelperPath
	HelperSHA  string // required in helper mode
	// SudoPath and InstallPath default to "sudo" and "install".
	SudoPath    string
	InstallPath string
	// TempDir is where files are staged before a privileged install; default /tmp.
	TempDir string
	// ElevateExists makes nopasswd Exists fall back to an elevated stat, so a
	// file in a directory the SSH user cannot traverse is still seen. Off for
	// the agent's narrow allowlist (D-114), which has no stat rule.
	ElevateExists bool
}

func (c Config) sudo() string       { return orDefault(c.SudoPath, "sudo") }
func (c Config) install() string    { return orDefault(c.InstallPath, "install") }
func (c Config) tempDir() string    { return orDefault(c.TempDir, "/tmp") }
func (c Config) helperPath() string { return orDefault(c.HelperPath, DefaultHelperPath) }

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// Wrap returns an Executor elevated per cfg.Mode. Password mode requires
// inner to implement StdinRunner so the password never reaches argv.
func Wrap(inner Executor, cfg Config) (Executor, error) {
	if inner == nil {
		return nil, errors.New("privexec: nil inner executor")
	}
	mode, err := ParseMode(string(cfg.Mode))
	if err != nil {
		return nil, err
	}
	cfg.Mode = mode
	e := &elevated{inner: inner, cfg: cfg}
	switch mode {
	case ModeNone:
		return inner, nil
	case ModePassword:
		r, ok := inner.(StdinRunner)
		if !ok {
			return nil, errors.New("privexec: password mode needs an executor that can pipe stdin (not supported for this transport)")
		}
		if len(cfg.Password) == 0 {
			return nil, errors.New("privexec: password mode requires a password")
		}
		e.stdin = r
	case ModeHelper:
		if cfg.HelperSHA == "" {
			return nil, errors.New("privexec: helper mode requires the pinned helper sha256")
		}
	}
	return e, nil
}

type elevated struct {
	inner Executor
	stdin StdinRunner
	cfg   Config

	mu       sync.Mutex
	verified bool
}

var helperVerbs = map[string]bool{
	"version": true, "list": true, "stat": true, "read-cert": true,
	"listeners": true, "install": true, "config-test": true, "reload": true,
	"backup": true, "restore": true, "discard": true,
}

func (e *elevated) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	switch e.cfg.Mode {
	case ModeNoPasswd:
		return e.inner.Run(ctx, e.cfg.sudo(), append([]string{"-n", "--", name}, args...)...)
	case ModePassword:
		pw := make([]byte, 0, len(e.cfg.Password)+1)
		pw = append(append(pw, e.cfg.Password...), '\n')
		defer zero(pw)
		return e.stdin.RunStdin(ctx, pw, e.cfg.sudo(), append([]string{"-S", "-p", "", "-k", "--", name}, args...)...)
	case ModeHelper:
		name, args = helperTranslate(name, args)
		if !helperVerbs[name] {
			return nil, fmt.Errorf("%w: %q", ErrNotHelperVerb, name)
		}
		if err := e.verifyHelper(ctx); err != nil {
			return nil, err
		}
		out, err := e.inner.Run(ctx, e.cfg.sudo(), append([]string{"-n", "--", e.cfg.helperPath(), name}, args...)...)
		if err != nil && name == "list" && len(args) == 1 {
			out = findDiagnostic(args[0], out)
		}
		return out, err
	}
	return e.inner.Run(ctx, name, args...)
}

// helperTranslate maps the commands the scanner and installer already issue
// onto helper verbs, so helper mode works with them unchanged. Anything else
// falls through and is refused: the verb table is the allowlist.
func helperTranslate(name string, args []string) (string, []string) {
	switch {
	case name == "find" && len(args) > 0 && strings.HasPrefix(args[0], "/"):
		return "list", args[:1]
	case name == "nginx" && len(args) == 1 && args[0] == "-t":
		return "config-test", []string{"nginx"}
	case name == "apachectl" && len(args) == 1 && args[0] == "configtest":
		return "config-test", []string{"apache"}
	case name == "ss" && len(args) == 1 && args[0] == "-ltnp":
		return "listeners", nil
	case name == "systemctl" && len(args) == 2 && (args[0] == "reload" || args[0] == "restart"):
		return "reload", args[1:]
	case name == "haproxy" && len(args) == 3 && args[0] == "-c" && args[1] == "-f" && args[2] == "/etc/haproxy/haproxy.cfg":
		return "config-test", []string{"haproxy"}
	case name == "/opt/tomcat/bin/catalina.sh" && len(args) == 1 && args[0] == "configtest":
		return "config-test", []string{"tomcat"}
	}
	return name, args
}

// findDiagnostic rewrites a failed helper `list` into the line GNU find prints,
// because `list` stands in for `find` and the scanner reads find's output line
// by line as file paths. Without this, the helper's own refusal text
// ("kryptkeeper-helper: not a directory") was taken for a certificate path and
// "read" as one (found against a real host in W34-20). A root that is absent is
// find's "No such file or directory"; any other refusal is reported against the
// root, never as a path.
func findDiagnostic(root string, helperOut []byte) []byte {
	msg := strings.ToLower(string(helperOut))
	if strings.Contains(msg, "not a directory") || strings.Contains(msg, "no such path") {
		return []byte(fmt.Sprintf("find: '%s': No such file or directory\n", root))
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(helperOut)), "\n")
	return []byte(fmt.Sprintf("find: '%s': Permission denied (%s)\n", root, strings.TrimSpace(line)))
}

// verifyHelper checks the installed helper against the pinned hash once per
// executor; the helper is root-owned, so a later swap needs root already.
func (e *elevated) verifyHelper(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.verified {
		return nil
	}
	out, err := e.inner.Run(ctx, "sha256sum", e.cfg.helperPath())
	if err != nil {
		return fmt.Errorf("privexec: helper %s not readable: %w", e.cfg.helperPath(), err)
	}
	if !sha256Matches(out, e.cfg.HelperSHA) {
		return ErrHelperTampered
	}
	e.verified = true
	return nil
}

func sha256Matches(sumOutput []byte, want string) bool {
	f := strings.Fields(string(sumOutput))
	return len(f) > 0 && strings.EqualFold(f[0], strings.TrimSpace(want))
}

func (e *elevated) Exists(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch e.cfg.Mode {
	case ModeHelper:
		_, err := e.Run(ctx, "stat", path)
		return err == nil
	case ModePassword:
		if e.inner.Exists(path) {
			return true
		}
		_, err := e.Run(ctx, "test", "-e", path)
		return err == nil
	}
	if e.inner.Exists(path) {
		return true
	}
	if e.cfg.ElevateExists {
		_, err := e.Run(ctx, "stat", "-c", "%U", path)
		return err == nil
	}
	// nopasswd keeps the narrow-allowlist behaviour (D-114): no `stat` rule is assumed.
	return false
}

func (e *elevated) ReadFile(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	verb, args := "cat", []string{path}
	if e.cfg.Mode == ModeHelper {
		verb = "read-cert"
	}
	out, err := e.Run(ctx, verb, args...)
	// The helper refuses any path outside its conservative character set, and
	// system trust stores hold files named in other scripts (ca-certificates
	// has NetLock "Főtanúsítvány"). Those are world-readable, so the account
	// can read them itself; reading through the account exposes nothing the
	// helper exists to protect, and the refusal would otherwise surface as an
	// unreadable path on every Debian host (found in W34-20).
	if err != nil && e.cfg.Mode == ModeHelper && strings.Contains(string(out), "unsupported character in path") {
		if plain, perr := e.inner.ReadFile(path); perr == nil {
			return plain, nil
		}
	}
	return out, err
}

// WriteFile stages content unprivileged, then places it with an elevated
// install so the staged file never needs to be root-readable.
func (e *elevated) WriteFile(path string, content []byte, mode os.FileMode) error {
	return e.writeFile(path, content, mode, "", "")
}

func (e *elevated) writeFile(path string, content []byte, mode os.FileMode, owner, group string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("privexec: temp name: %w", err)
	}
	tmp := filepath.Join(e.cfg.tempDir(), "kk-priv-"+hex.EncodeToString(b))
	if err := e.inner.WriteFile(tmp, content, 0o600); err != nil {
		return fmt.Errorf("privexec: stage %s: %w", path, err)
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_, _ = e.inner.Run(cctx, "rm", "-f", tmp) // best-effort; the staged copy may hold key material
	}()
	modeArg := fmt.Sprintf("%#o", mode.Perm())
	var err error
	if e.cfg.Mode == ModeHelper {
		args := []string{tmp, filepath.Clean(path), modeArg}
		if owner != "" {
			args = append(args, owner+":"+group)
		}
		_, err = e.Run(ctx, "install", args...)
	} else {
		args := []string{"-m", modeArg}
		if owner != "" {
			args = append(args, "-o", owner, "-g", group)
		}
		_, err = e.Run(ctx, e.cfg.install(), append(args, tmp, filepath.Clean(path))...)
	}
	if err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// FileMeta is a file's owner, group and permission bits.
type FileMeta struct {
	Owner, Group string
	Mode         os.FileMode
}

// Statter reports a file's ownership so an install can restore it.
type Statter interface {
	StatMeta(ctx context.Context, path string) (FileMeta, error)
}

// OwnedWriter places a file with an explicit owner and group.
type OwnedWriter interface {
	WriteFileOwned(path string, content []byte, mode os.FileMode, owner, group string) error
}

// HostBackuper keeps the rollback copy of a file on the host itself, so the
// hub never reads a private key just to be able to put it back. supported is
// false when the mode cannot do it and the caller should snapshot by content.
type HostBackuper interface {
	BackupFile(ctx context.Context, path string) (supported bool, err error)
	RestoreFile(ctx context.Context, path string) error
	DropBackup(ctx context.Context, path string) error
}

var (
	_ Statter      = (*elevated)(nil)
	_ OwnedWriter  = (*elevated)(nil)
	_ HostBackuper = (*elevated)(nil)
)

// StatMeta reads owner, group and mode through the elevated path. Helper mode
// parses the helper's stat line; the others use GNU stat.
func (e *elevated) StatMeta(ctx context.Context, path string) (FileMeta, error) {
	if e.cfg.Mode == ModeHelper {
		out, err := e.Run(ctx, "stat", path)
		if err != nil {
			return FileMeta{}, err
		}
		f := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(f) < 4 {
			return FileMeta{}, fmt.Errorf("privexec: unexpected stat output")
		}
		return parseMeta(f[2], f[3], f[1])
	}
	out, err := e.Run(ctx, "stat", "-c", "%U %G %a", path)
	if err != nil {
		return FileMeta{}, err
	}
	f := strings.Fields(string(out))
	if len(f) != 3 {
		return FileMeta{}, fmt.Errorf("privexec: unexpected stat output")
	}
	return parseMeta(f[0], f[1], f[2])
}

func parseMeta(owner, group, octal string) (FileMeta, error) {
	m, err := strconv.ParseUint(strings.TrimSpace(octal), 8, 32)
	if err != nil || !safeAccountName(owner) || !safeAccountName(group) {
		return FileMeta{}, fmt.Errorf("privexec: unexpected stat fields")
	}
	return FileMeta{Owner: owner, Group: group, Mode: os.FileMode(m) & os.ModePerm}, nil
}

var accountNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

func safeAccountName(s string) bool { return accountNameRE.MatchString(s) }

// WriteFileOwned is WriteFile that also sets owner and group, so a privileged
// push does not turn a tomcat-owned file into a root-owned one.
func (e *elevated) WriteFileOwned(path string, content []byte, mode os.FileMode, owner, group string) error {
	if !safeAccountName(owner) || !safeAccountName(group) {
		return fmt.Errorf("privexec: unusable owner %q or group %q", owner, group)
	}
	return e.writeFile(path, content, mode, owner, group)
}

func (e *elevated) BackupFile(ctx context.Context, path string) (bool, error) {
	if e.cfg.Mode != ModeHelper {
		return false, nil
	}
	_, err := e.Run(ctx, "backup", path)
	return true, err
}

func (e *elevated) RestoreFile(ctx context.Context, path string) error {
	_, err := e.Run(ctx, "restore", path)
	return err
}

func (e *elevated) DropBackup(ctx context.Context, path string) error {
	_, err := e.Run(ctx, "discard", path)
	return err
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HelperSHA256 is the sha256 of the embedded helper script; the privilege
// bundle publishes it and the credential pins it.
func HelperSHA256() string {
	s := sha256.Sum256([]byte(HelperScript))
	return hex.EncodeToString(s[:])
}

// LocalExecutor runs on the local host with no elevation; it is the inner
// executor for the agent.
type LocalExecutor struct{}

var (
	_ Executor    = LocalExecutor{}
	_ StdinRunner = LocalExecutor{}
)

func (LocalExecutor) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (LocalExecutor) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile replaces path atomically (temp in the same directory, then rename).
func (LocalExecutor) WriteFile(path string, content []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".kk-write-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name) // no-op once renamed
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode.Perm()); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (l LocalExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return l.RunStdin(ctx, nil, name, args...)
}

func (LocalExecutor) RunStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}
