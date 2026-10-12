// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshOperationTimeout bounds Exists/ReadFile/WriteFile, which -- unlike Run --
// have no context.Context parameter to receive a caller-supplied deadline
// (the Executor interface in installer.go declares it that way; matching it
// exactly is deliberate, see docs/board/specs/W5-11.md's premise corrections).
// Without an internal bound, a stalled connection mid-operation would hang
// forever -- DialTimeout only covers the initial handshake.
const sshOperationTimeout = 60 * time.Second

// SSHTarget configures a remote host SSHExecutor connects to. The Signer is
// expected to come from the W5-10 outbound credential store -- this package
// never reads a raw private key file itself.
type SSHTarget struct {
	Host string
	Port int
	User string

	// Signer authenticates to the remote host. Required.
	Signer ssh.Signer

	// HostKeyCallback verifies the remote host's key. Required -- there is no
	// default and no trust-on-first-use helper in this package. Never pass
	// ssh.InsecureIgnoreHostKey; use ssh.FixedHostKey or a knownhosts-backed
	// callback built from a pinned key obtained out of band.
	HostKeyCallback ssh.HostKeyCallback

	// HostKeyAlgorithms restricts which host-key algorithm the handshake will
	// accept during KEX negotiation. Required whenever HostKeyCallback is a
	// pinned single key (ssh.FixedHostKey): most real sshd installs offer
	// rsa+ecdsa+ed25519 host keys simultaneously, and golang.org/x/crypto/ssh's
	// default negotiation order does not know which one the caller pinned --
	// left unset, the client can negotiate a DIFFERENT key type than the one
	// FixedHostKey was built from, and a legitimately-trusted host then fails
	// with "ssh: host key mismatch" even though its pinned key is correct
	// (found live against a real multi-hostkey sshd, W19-02). Callers building
	// a FixedHostKey callback should set this to []string{hostKey.Type()}.
	HostKeyAlgorithms []string

	// DialTimeout bounds the initial TCP connect + SSH handshake. Zero uses a
	// 10s default.
	DialTimeout time.Duration
}

// SSHExecutor implements Executor (installer.go) by running each operation
// over a real SSH connection, so Installer's snapshot/write/config-test/
// reload/verify/rollback sequence runs unchanged against a remote host with
// no agent installed there.
type SSHExecutor struct {
	client *ssh.Client
}

var _ Executor = (*SSHExecutor)(nil)

// NewSSHExecutor dials host and returns an SSHExecutor backed by that
// connection. It refuses to dial without both a Signer and a
// HostKeyCallback -- see SSHTarget's doc comment.
func NewSSHExecutor(ctx context.Context, cfg SSHTarget) (*SSHExecutor, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("ssh executor: Signer is required")
	}
	if cfg.HostKeyCallback == nil {
		return nil, fmt.Errorf("ssh executor: HostKeyCallback is required -- refusing to dial with no host-key verification (never use ssh.InsecureIgnoreHostKey)")
	}

	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh executor: dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(cfg.Signer)},
		HostKeyCallback:   cfg.HostKeyCallback,
		HostKeyAlgorithms: cfg.HostKeyAlgorithms,
		Timeout:           timeout,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh executor: handshake %s: %w", addr, err)
	}

	return &SSHExecutor{client: ssh.NewClient(sshConn, chans, reqs)}, nil
}

// Close releases the underlying SSH connection.
func (e *SSHExecutor) Close() error {
	return e.client.Close()
}

// Exists reports whether path exists on the remote host.
func (e *SSHExecutor) Exists(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), sshOperationTimeout)
	defer cancel()
	_, err := e.Run(ctx, "test", "-e", path)
	return err == nil
}

// ReadFile reads path's contents over a stdout-only session. Deliberately
// NOT routed through the combined-output Run helper: ReadFile's only caller
// is installer.go's snapshot(), whose bytes get written back verbatim by
// rollback() -- any stderr byte mixed into a combined read would silently
// corrupt the backup, and rollback would then restore a corrupted cert/key.
// For a backup read, stderr is noise, not data.
func (e *SSHExecutor) ReadFile(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshOperationTimeout)
	defer cancel()

	session, err := e.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh executor: new session: %w", err)
	}
	defer session.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	// session.Output (not a manually-wired Stdout buffer) is used
	// deliberately: it's the ssh package's own stdout-only helper, so there
	// is no second goroutine touching this buffer the way there would be if
	// Stderr were also wired up.
	go func() {
		out, err := session.Output(shellJoin("cat", []string{path}))
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("ssh executor: read %s: %w", path, r.err)
		}
		return r.out, nil
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL) // best-effort kill on timeout; ctx error is already returned
		return nil, fmt.Errorf("ssh executor: read %s: %w", path, ctx.Err())
	}
}

// WriteFile stages content at a random remote temp path via `cat`, then
// places it atomically with mode via `install` -- mirroring SudoExecutor's
// own install-based atomic placement, just executed remotely. There is no
// sftp dependency in go.mod; adding one is a separate call, not made here.
//
// content is often private key material, so the staged temp file is treated
// as sensitive for its entire (brief) life: `umask 077` on the staging
// command keeps it 0600 rather than the ambient umask's default (typically
// 0644, world-readable), and the temp path is unconditionally removed on
// EVERY exit path, not only on install failure -- `install` copies rather
// than moves, so a success-path leak here would leave world-readable key
// plaintext accumulating in /tmp on every renewal.
func (e *SSHExecutor) WriteFile(path string, content []byte, mode os.FileMode) error {
	ctx, cancel := context.WithTimeout(context.Background(), sshOperationTimeout)
	defer cancel()

	tmp, err := randomRemoteTempPath()
	if err != nil {
		return fmt.Errorf("ssh executor: generate temp path: %w", err)
	}
	defer func() {
		// A fresh, short-lived context: ctx may already be past its
		// deadline if the staging/install step above timed out, and cleanup
		// must still run.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = e.Run(cleanupCtx, "rm", "-f", tmp) // best-effort remote cleanup; install already succeeded or failed
	}()

	if _, err := e.runStdin(ctx, content, "sh", "-c", "umask 077; cat > "+shellQuote(tmp)); err != nil {
		return fmt.Errorf("ssh executor: stage %s: %w", path, err)
	}

	modeArg := fmt.Sprintf("%#o", mode.Perm())
	if _, err := e.Run(ctx, "install", "-m", modeArg, tmp, path); err != nil {
		return fmt.Errorf("ssh executor: install %s: %w", path, err)
	}
	return nil
}

// Run executes name+args on the remote host and returns combined
// stdout+stderr, matching the Executor interface's documented contract (used
// for config-test/reload, where stderr belongs in the failure Detail). A
// non-zero remote exit surfaces as a Go error via *ssh.ExitError.
func (e *SSHExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.runStdin(ctx, nil, name, args...)
}

func (e *SSHExecutor) runStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	session, err := e.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh executor: new session: %w", err)
	}
	defer session.Close()

	if stdin != nil {
		session.Stdin = bytes.NewReader(stdin)
	}

	cmd := shellJoin(name, args)
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	// session.CombinedOutput (not manually wiring Stdout/Stderr to the same
	// buffer) is used deliberately: the ssh package copies each stream in
	// its own goroutine, so a plain shared bytes.Buffer would race between
	// them -- CombinedOutput's internal singleWriter is what actually
	// serializes the two writers safely.
	go func() {
		out, err := session.CombinedOutput(cmd)
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return r.out, fmt.Errorf("ssh executor: run %q: %w", cmd, r.err)
		}
		return r.out, nil
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL) // best-effort kill on timeout; ctx error is already returned
		return nil, fmt.Errorf("ssh executor: run %q: %w", cmd, ctx.Err())
	}
}

func randomRemoteTempPath() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "/tmp/kk-ssh-install-" + hex.EncodeToString(b), nil
}

// shellQuote single-quotes s for safe inclusion in a remote `sh -c` command,
// escaping any embedded single quote. Every remote command argument is
// quoted unconditionally -- a cert/key path or mode string is never
// attacker-controlled today, but an unquoted join is still a latent
// injection footgun.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(name))
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}
