// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/privexec"
)

// startTestSSHServer runs a minimal in-process SSH server that executes any
// "exec" request via the real local shell (`sh -c <cmd>`), piping
// stdin/stdout/stderr through the channel. The "remote" filesystem is just
// this test process's own filesystem -- this exercises SSHExecutor's real
// wire protocol without needing a live remote host.
func startTestSSHServer(t *testing.T) (addr string, hostPublicKey ssh.PublicKey, clientSigner ssh.Signer) {
	t.Helper()

	hostPub, hostPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	hostPublicKey, err = ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatalf("host pubkey: %v", err)
	}

	clientPub, clientPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	clientSigner, err = ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	clientAuthorized, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("client pubkey: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientAuthorized.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	config.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(nConn, config)
		}
	}()

	return ln.Addr().String(), hostPublicKey, clientSigner
}

func handleTestSSHConn(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go handleTestSSHSession(channel, requests)
	}
}

func handleTestSSHSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		_ = req.Reply(true, nil)

		cmd := exec.Command("sh", "-c", payload.Command)
		cmd.Stdin = channel
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()

		exitStatus := 0
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitStatus = exitErr.ExitCode()
			} else {
				exitStatus = 1
			}
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{uint32(exitStatus)}))
		return
	}
}

func newTestSSHExecutor(t *testing.T) *SSHExecutor {
	t.Helper()
	addr, hostPublicKey, clientSigner := startTestSSHServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	sshExec, err := NewSSHExecutor(context.Background(), SSHTarget{
		Host:   host,
		Port:   port,
		User:   "testuser",
		Signer: clientSigner,
		// A real pinned-host-key callback (ssh.FixedHostKey), not
		// InsecureIgnoreHostKey -- this exercises the actual production
		// verification path (present key -> compare against the pinned
		// key -> accept), not a stub that would pass regardless of whether
		// verification code path works at all.
		HostKeyCallback: ssh.FixedHostKey(hostPublicKey),
		DialTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSSHExecutor: %v", err)
	}
	t.Cleanup(func() { sshExec.Close() })
	return sshExec
}

func TestSSHExecutor_WriteFileThenReadFile(t *testing.T) {
	e := newTestSSHExecutor(t)
	path := filepath.Join(t.TempDir(), "cert.pem")

	if err := e.WriteFile(path, []byte("hello-over-ssh"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := e.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello-over-ssh" {
		t.Fatalf("unexpected content: %q", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("unexpected mode: %o, want 0640", info.Mode().Perm())
	}
}

func TestSSHExecutor_Exists(t *testing.T) {
	e := newTestSSHExecutor(t)
	dir := t.TempDir()
	present := filepath.Join(dir, "present.txt")
	if err := e.WriteFile(present, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if !e.Exists(present) {
		t.Error("expected Exists to be true for a file just written")
	}
	if e.Exists(filepath.Join(dir, "absent.txt")) {
		t.Error("expected Exists to be false for a file that was never written")
	}
}

func TestSSHExecutor_Run_ReturnsOutputAndErrorsOnNonZeroExit(t *testing.T) {
	e := newTestSSHExecutor(t)

	out, err := e.Run(context.Background(), "echo", "hi")
	if err != nil {
		t.Fatalf("Run(echo): %v", err)
	}
	if string(bytes.TrimSpace(out)) != "hi" {
		t.Fatalf("unexpected output: %q", out)
	}

	if _, err := e.Run(context.Background(), "false"); err == nil {
		t.Fatal("expected an error from a non-zero exit, got none")
	}
}

func TestNewSSHExecutor_RequiresSigner(t *testing.T) {
	if _, err := NewSSHExecutor(context.Background(), SSHTarget{
		Host:            "127.0.0.1",
		Port:            22,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // proving Signer is checked first, never dials
	}); err == nil {
		t.Fatal("expected an error with no Signer, got none")
	}
}

func TestNewSSHExecutor_RequiresHostKeyCallback(t *testing.T) {
	_, _, clientSigner := startTestSSHServer(t)
	if _, err := NewSSHExecutor(context.Background(), SSHTarget{
		Host:   "127.0.0.1",
		Port:   22,
		Signer: clientSigner,
	}); err == nil {
		t.Fatal("expected an error with no HostKeyCallback, got none")
	}
}

// TestInstaller_OverRealSSH_KeyWriteFailureRestoresOriginalCert is the real
// acceptance-#2 proof: a genuine Installer backed by a genuine SSHExecutor,
// over a real (if loopback) SSH connection. Phase 1 installs a valid cert+key
// pair. Phase 2 installs a new cert (succeeds) paired with a key path whose
// parent is a regular file, not a directory -- `install` deterministically
// fails there on every POSIX system regardless of privilege level, so this
// doesn't depend on nginx/apache/systemd being present in the test
// environment. Asserts not just RolledBack:true but that the cert file on
// disk still holds phase 1's bytes, not phase 2's -- the actual proof that
// rollback restored the backup, not just that the flag was set.
func TestInstaller_OverRealSSH_KeyWriteFailureRestoresOriginalCert(t *testing.T) {
	e := newTestSSHExecutor(t)
	installer := New(e)
	ctx := context.Background()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "site.crt")

	// Seed the "already installed" cert directly through the executor,
	// simulating a prior successful install. Installer.Install's reload step
	// unconditionally shells out to systemctl regardless of ServerType, which
	// this test environment has no way to satisfy -- so the pre-existing
	// state is staged directly rather than via a first successful Install()
	// call; what this test actually proves (rollback restores a real prior
	// file over a real SSH connection) doesn't depend on how that file got
	// there.
	certV1 := []byte("cert-version-1")
	if err := e.WriteFile(certPath, certV1, 0o644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("i am a file, not a dir"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	badKeyPath := filepath.Join(blocker, "site.key") // parent is a regular file, install fails here deterministically

	certV2 := []byte("cert-version-2-should-not-survive")
	res, err := installer.Install(ctx, InstallRequest{
		ServerType: "unrecognized-server-type",
		CertPath:   certPath,
		CertPEM:    certV2,
		KeyPath:    badKeyPath,
		KeyPEM:     []byte("key-version-2"),
	})
	if err == nil {
		t.Fatal("expected an error from the doomed key write, got none")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack=true, got %+v", res)
	}
	if res.Outcome != OutcomeWriteFailed {
		t.Fatalf("expected outcome %q, got %q", OutcomeWriteFailed, res.Outcome)
	}

	restored, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert after rollback: %v", err)
	}
	if string(restored) != string(certV1) {
		t.Fatalf("rollback did not restore the original cert: got %q, want %q", restored, certV1)
	}
}

// TestSSHExecutor_HostKeyAlgorithms_RequiredForMultiHostKeyServer reproduces
// a defect found live in W19-02: a real sshd (Ubuntu's default) serves
// rsa+ecdsa+ed25519 host keys simultaneously, and
// golang.org/x/crypto/ssh's default negotiation order prefers RSA over
// Ed25519 (see supportedHostKeyAlgos in its common.go). A caller that pins
// an Ed25519 host key via ssh.FixedHostKey but leaves HostKeyAlgorithms
// unset gets RSA negotiated instead, and the pinned key never matches --
// "ssh: host key mismatch" against a host that is, in fact, the correct,
// previously-verified host. Setting HostKeyAlgorithms to the pinned key's
// own type is what makes pinning actually pin.
func TestSSHExecutor_HostKeyAlgorithms_RequiredForMultiHostKeyServer(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa host key: %v", err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatalf("rsa signer: %v", err)
	}

	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen ed25519 host key: %v", err)
	}
	ed25519Signer, err := ssh.NewSignerFromKey(ed25519Priv)
	if err != nil {
		t.Fatalf("ed25519 signer: %v", err)
	}
	ed25519Pubkey, err := ssh.NewPublicKey(ed25519Pub)
	if err != nil {
		t.Fatalf("ed25519 pubkey: %v", err)
	}

	clientPub, clientPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	clientAuthorized, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("client pubkey: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientAuthorized.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	// Order matters for realism (Ubuntu's ssh-keygen -A writes rsa before
	// ed25519), but the negotiation outcome below is driven by the
	// CLIENT's preferred algorithm order, not this one.
	config.AddHostKey(rsaSigner)
	config.AddHostKey(ed25519Signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(nConn, config)
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	t.Run("unset HostKeyAlgorithms negotiates the wrong key type and mismatches", func(t *testing.T) {
		_, err := NewSSHExecutor(context.Background(), SSHTarget{
			Host:            host,
			Port:            port,
			User:            "testuser",
			Signer:          clientSigner,
			HostKeyCallback: ssh.FixedHostKey(ed25519Pubkey),
			DialTimeout:     5 * time.Second,
		})
		if err == nil {
			t.Fatal("expected a host key mismatch (RSA negotiated over the pinned Ed25519 key), got success")
		}
	})

	t.Run("HostKeyAlgorithms pinned to the key's own type connects", func(t *testing.T) {
		exec, err := NewSSHExecutor(context.Background(), SSHTarget{
			Host:              host,
			Port:              port,
			User:              "testuser",
			Signer:            clientSigner,
			HostKeyCallback:   ssh.FixedHostKey(ed25519Pubkey),
			HostKeyAlgorithms: []string{ed25519Pubkey.Type()},
			DialTimeout:       5 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewSSHExecutor with HostKeyAlgorithms set: %v", err)
		}
		exec.Close()
	})

	// An RSA ssh.PublicKey's Type() is "ssh-rsa", the legacy SHA-1 signature
	// scheme. x/crypto/ssh's client will still negotiate it if a caller
	// explicitly asks (verified: it does, below) -- the exclusion from
	// supportedHostKeyAlgos in common.go only governs the library's own
	// DEFAULT preference order, not an explicit override. But
	// internal/bootstrap's hostKeyAlgorithmsFor deliberately prefers the
	// modern rsa-sha2-512/256 names for an RSA key instead of passing
	// Type() straight through, since those sign with the exact same key
	// under a stronger scheme; proven end-to-end here, not just as a
	// string check.
	t.Run("RSA pinned key connects via the preferred SHA-2 algorithm names", func(t *testing.T) {
		rsaPubkey := rsaSigner.PublicKey()

		exec, err := NewSSHExecutor(context.Background(), SSHTarget{
			Host:              host,
			Port:              port,
			User:              "testuser",
			Signer:            clientSigner,
			HostKeyCallback:   ssh.FixedHostKey(rsaPubkey),
			HostKeyAlgorithms: []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
			DialTimeout:       5 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewSSHExecutor with rsa-sha2 algorithms: %v", err)
		}
		exec.Close()
	})
}

func TestSSHExecutor_RunStdin_PipesBytes(t *testing.T) {
	e := newTestSSHExecutor(t)
	out, err := e.RunStdin(context.Background(), []byte("piped-bytes"), "cat")
	if err != nil {
		t.Fatalf("RunStdin: %v", err)
	}
	if string(out) != "piped-bytes" {
		t.Fatalf("unexpected output: %q", out)
	}
}

// fakeSudo stands in for sudo on the test "remote": in -S mode it requires the
// password on the first stdin line, otherwise it only accepts -n.
func installFakeSudo(t *testing.T, password string) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = -S ]; then read -r pw; [ \"$pw\" = '" + password + "' ] || { echo 'Sorry, try again.' >&2; exit 1; }; shift 5; " +
		"else [ \"$1\" = -n ] || exit 1; shift 2; fi\n" +
		"exec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestPrivexecPasswordOverSSH(t *testing.T) {
	const pw = "Sup3r-Secret-pw"
	installFakeSudo(t, pw)
	e := newTestSSHExecutor(t)

	good, err := privexec.Wrap(e, privexec.Config{Mode: privexec.ModePassword, Password: []byte(pw)})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "site.pem")
	if err := good.WriteFile(dst, []byte("cert"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if b, err := good.ReadFile(dst); err != nil || string(b) != "cert" {
		t.Fatalf("ReadFile: %q %v", b, err)
	}

	bad, _ := privexec.Wrap(e, privexec.Config{Mode: privexec.ModePassword, Password: []byte("wrong-pw")})
	_, err = bad.Run(context.Background(), "true")
	if err == nil {
		t.Fatal("wrong password accepted")
	}
	if strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), "wrong-pw") {
		t.Fatalf("password leaked in error: %v", err)
	}
}

// W34-20: a failed remote read keeps cat's own diagnostic, so the scan can tell
// "this account may not read it" from "this file is broken".
func TestSSHExecutor_ReadFileErrorCarriesStderr(t *testing.T) {
	e := newTestSSHExecutor(t)
	dir := t.TempDir()
	_, err := e.ReadFile(filepath.Join(dir, "absent.jks"))
	if err == nil || !strings.Contains(err.Error(), "No such file or directory") {
		t.Fatalf("missing file error = %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	locked := filepath.Join(dir, "locked.jks")
	if werr := os.WriteFile(locked, []byte("x"), 0o000); werr != nil {
		t.Fatal(werr)
	}
	if _, err := e.ReadFile(locked); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("unreadable file error = %v", err)
	}
}

func TestCappedBufferKeepsTheFirstLineOnly(t *testing.T) {
	c := &cappedBuffer{max: 16}
	n, _ := c.Write([]byte("cat: /x: Permission denied\nsecond line\n"))
	if n != 39 || c.firstLine() != "cat: /x: Permiss" {
		t.Fatalf("n=%d line=%q", n, c.firstLine())
	}
}
