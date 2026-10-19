// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package agentinstall installs renewed certificates where a web server reads
// them, validates the config, reloads the server, and rolls back on failure.
// It is the "install" half of the v1.3 Renewal Autopilot loop
// (discover → issue → install → verify); verification lives in a later wave.
//
// All privileged operations go through an Executor so the package is testable
// without root. There are two production executors with DIFFERENT privilege
// models -- do not assume one from the other:
//   - NewSudoExecutor (executor_sudo.go) is the agent-local path: it wraps
//     file placement and reload commands in a narrow sudo allowlist
//     (`install`, `nginx -t`, the reload command) per the v1.3 privilege
//     decision, run by the kryptkeeper-agent binary on the target itself.
//   - NewSSHExecutor (executor_ssh.go) is the agentless path
//     (internal/bootstrap/renewal_executor.go's ssh-mode targets): it issues
//     every Run/WriteFile command DIRECTLY over the SSH session with NO sudo
//     prefix at all. There is no narrow-allowlist model here -- the SSH
//     principal named in the target's credential must already hold
//     sufficient privilege on the host (root, or file ownership + a way to
//     run the reload command unprivileged) for install to succeed. Found
//     live proving W19-02: a non-root, sudo-only account does NOT work
//     against this executor as written; the fixture uses root over SSH.
//
// The two-phase API (Stage/Flip/Discard/Restore/Commit, W27-14) needs
// `cp`, `mv` and `rm` through Run, so it works only with NewSSHExecutor;
// NewSudoExecutor's narrow allowlist rejects those commands by design, and
// Install/installHAProxy remain the agent-local path. Staged files sit beside
// the live ones as `<live>.kk-staged`; a wildcard `include` of the cert
// directory may therefore pick them up while a stage is pending.
package agentinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/privexec"
)

// verifyRetryAttempts/verifyRetryDelay bound the retry-until-match loop in
// Install's verify step (below). `nginx -s reload` and `apachectl -k
// graceful` both return as soon as the signal is SENT, not once new workers
// are actually serving -- found live (W19-02): a verify dialed immediately
// after reload can still hit an old worker mid-handover and see the stale
// cert, which would otherwise trigger a spurious rollback of a perfectly
// good install. 6 attempts * 250ms = 1.5s worst case, well inside a
// renewal's normal budget, and only paid when a mismatch is actually seen.
const (
	verifyRetryAttempts = 6
	verifyRetryDelay    = 250 * time.Millisecond
)

// Executor performs the privileged side of an install. Implementations decide
// whether operations run directly (tests) or via sudo (production).
type Executor interface {
	// Exists reports whether a path exists.
	Exists(path string) bool
	// ReadFile reads a file's contents (used to back up the current cert/key).
	ReadFile(path string) ([]byte, error)
	// WriteFile atomically places content at path with the given mode.
	WriteFile(path string, content []byte, mode os.FileMode) error
	// Run executes a command and returns combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// InstallRequest describes one cert/key to install for a discovered endpoint.
type InstallRequest struct {
	ServerType string // "nginx" | "apache" | "haproxy" | "tomcat"
	CertPath   string
	KeyPath    string
	CertPEM    []byte
	KeyPEM     []byte
	// ReloadMethod overrides reload selection ("systemctl" | "binary"); empty = auto.
	ReloadMethod string
	// HAProxyConfigPath is the config file `haproxy -c -f` validates
	// (W5-02); empty = /etc/haproxy/haproxy.cfg. HAProxy installs write
	// ONE combined chain+key file at CertPath and ignore KeyPath.
	HAProxyConfigPath string

	// Tomcat keystore install (W27-07). CertPath is the keystore file;
	// KeyPath is ignored. KeystorePassword comes from the credential store
	// and must never be logged, so do not print an InstallRequest with %+v.
	KeystoreFormat   string // "pkcs12" (default) | "pkcs12-legacy" | "jks"
	KeystorePassword string
	KeystoreAlias    string // default "tomcat"
	TomcatHome       string // default "/opt/tomcat"; config test is <home>/bin/catalina.sh configtest
	ServiceName      string // default "tomcat"; reload = systemctl restart <ServiceName>

	// Verify-after-install (v1.3 W2). When VerifyHostPort and ExpectedFingerprint
	// are set, the installer TLS-dials the endpoint after reload and confirms the
	// served leaf matches ExpectedFingerprint, rolling back if it doesn't.
	VerifyHostPort      string
	ExpectedFingerprint string // SHA-256 hex of the newly issued leaf
}

// InstallResult reports what happened. A renewal is "done" (Outcome
// "installed_verified") only when Installed, Reloaded, and Verified are all true
// and RolledBack is false.
type InstallResult struct {
	Installed         bool
	Reloaded          bool
	Verified          bool
	RolledBack        bool
	RollbackFailed    bool
	ServedFingerprint string
	Outcome           string // see outcome constants
	Detail            string
}

// Outcome values reported to the Hub.
const (
	OutcomeInstalledVerified = "installed_verified"
	OutcomeInstalled         = "installed" // installed + reloaded, verification not requested
	OutcomeConfigTestFailed  = "config_test_failed"
	OutcomeReloadFailed      = "reload_failed"
	OutcomeVerifyFailed      = "verify_failed"
	OutcomeWriteFailed       = "write_failed"
	// OutcomeRollbackFailed means the install failed AND putting the previous
	// files back failed too: the host may hold a half-installed state, so the
	// caller must stop retrying and flag the target for an operator.
	OutcomeRollbackFailed = "rollback_failed"
)

// Installer writes renewed certs, validates, reloads, and verifies — with rollback.
type Installer struct {
	exec   Executor
	verify Verifier
}

// New returns an Installer backed by the given executor and the default
// TLS-dial verifier.
func New(exec Executor) *Installer {
	return &Installer{exec: exec, verify: defaultVerifier}
}

// WithVerifier overrides the verifier (used in tests).
func (in *Installer) WithVerifier(v Verifier) *Installer {
	in.verify = v
	return in
}

// fileBackup holds what is needed to put a file back: its contents, or, when
// the executor can keep the copy on the host (helper mode), only a marker so
// the hub never reads a private key just for rollback. meta is the prior owner,
// group and mode, re-applied on write and restore so a privileged push never
// flips tomcat:tomcat to root:root.
type fileBackup struct {
	path    string
	content []byte
	existed bool
	onHost  bool
	mode    os.FileMode
	meta    *privexec.FileMeta
	err     error
}

type rollbackKey struct{}

// rollbackLog collects what Install needs to report after its inner flow:
// restore failures and which host-side copies still exist.
type rollbackLog struct {
	mu       sync.Mutex
	err      error
	hostCopy map[string]bool // path -> copy still on host
}

func rollbackFrom(ctx context.Context) *rollbackLog {
	rl, _ := ctx.Value(rollbackKey{}).(*rollbackLog)
	return rl
}

func (rl *rollbackLog) note(path string, onHost bool) {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.hostCopy == nil {
		rl.hostCopy = map[string]bool{}
	}
	rl.hostCopy[path] = onHost
}

func (rl *rollbackLog) fail(err error) {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.err = errors.Join(rl.err, err)
}

// Install backs up the current cert/key, writes the renewed pair, validates the
// server config, and reloads. On any failure after writing, it restores the
// backups and reloads again (best effort), returning RolledBack=true.
func (in *Installer) Install(ctx context.Context, req InstallRequest) (InstallResult, error) {
	rl := &rollbackLog{}
	res, err := in.install(context.WithValue(ctx, rollbackKey{}, rl), req)
	if rl.err != nil && res.RolledBack {
		res.Outcome = OutcomeRollbackFailed
		res.RollbackFailed = true
		res.Detail = strings.TrimSpace(res.Detail + "; rollback failed: " + rl.err.Error())
		err = fmt.Errorf("%w (rollback failed: %v)", err, rl.err)
	}
	// A host-side copy that was not consumed by a restore holds a superseded
	// private key: drop it.
	if hb, ok := in.exec.(privexec.HostBackuper); ok {
		for p, left := range rl.hostCopy {
			if left {
				_ = hb.DropBackup(context.WithoutCancel(ctx), p) // best-effort: nothing more to do if it fails
			}
		}
	}
	return res, err
}

func (in *Installer) install(ctx context.Context, req InstallRequest) (InstallResult, error) {
	// W5-02: HAProxy has its own flow — combined single file, mandatory
	// `haproxy -c`, no blind fall-through into the generic reload.
	if req.ServerType == "haproxy" {
		return in.installHAProxy(ctx, req)
	}
	if req.ServerType == "tomcat" {
		return in.installTomcat(ctx, req)
	}
	if req.CertPath == "" || len(req.CertPEM) == 0 {
		return InstallResult{}, fmt.Errorf("install: cert path and PEM are required")
	}

	// 1. Snapshot current files for rollback.
	backups := []fileBackup{
		in.snapshot(ctx, req.CertPath, 0o644),
	}
	if req.KeyPath != "" {
		backups = append(backups, in.snapshot(ctx, req.KeyPath, 0o600))
	}
	if err := snapshotError(backups); err != nil {
		return InstallResult{Outcome: OutcomeWriteFailed, Detail: err.Error()}, err
	}

	// 2. Write the renewed cert (and key) into place.
	if err := in.place(req.CertPath, req.CertPEM, 0o644, backups[0]); err != nil {
		return InstallResult{}, fmt.Errorf("install: write cert: %w", err)
	}
	if req.KeyPath != "" && len(req.KeyPEM) > 0 {
		if err := in.place(req.KeyPath, req.KeyPEM, 0o600, backups[1]); err != nil {
			in.rollback(ctx, backups, req)
			return InstallResult{RolledBack: true, Outcome: OutcomeWriteFailed}, fmt.Errorf("install: write key: %w", err)
		}
	}

	// 3. Validate config before reloading — never reload an invalid config.
	if name, args, ok := configTestCommand(req.ServerType); ok {
		if out, err := in.exec.Run(ctx, name, args...); err != nil {
			in.rollback(ctx, backups, req)
			return InstallResult{RolledBack: true, Outcome: OutcomeConfigTestFailed, Detail: string(out)},
				fmt.Errorf("install: config test failed, rolled back: %w", err)
		}
	}

	// 4. Reload to pick up the new cert.
	name, args := reloadCommand(req.ServerType, req.ReloadMethod)
	if out, err := in.exec.Run(ctx, name, args...); err != nil {
		in.rollback(ctx, backups, req)
		// Best-effort reload after restoring the old cert so the site keeps serving.
		_, _ = in.exec.Run(ctx, name, args...) // best-effort rollback reload; primary error already returned
		return InstallResult{Installed: true, RolledBack: true, Outcome: OutcomeReloadFailed, Detail: string(out)},
			fmt.Errorf("install: reload failed, rolled back: %w", err)
	}

	// 5. Verify-after-install (optional): confirm the renewed cert is actually
	// being served. A renewal isn't "done" until the new fingerprint is live.
	if req.VerifyHostPort != "" && req.ExpectedFingerprint != "" {
		served, err := in.verifyUntilMatchOrExhausted(ctx, req.VerifyHostPort, req.ExpectedFingerprint)
		if err != nil {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, name, args...) // best-effort rollback reload; primary error already returned
			return InstallResult{Installed: true, Reloaded: true, RolledBack: true, Outcome: OutcomeVerifyFailed, Detail: err.Error()},
				fmt.Errorf("install: verify failed, rolled back: %w", err)
		}
		if normalizeFingerprint(served) != normalizeFingerprint(req.ExpectedFingerprint) {
			in.rollback(ctx, backups, req)
			_, _ = in.exec.Run(ctx, name, args...) // best-effort rollback reload; primary error already returned
			return InstallResult{
					Installed: true, Reloaded: true, RolledBack: true,
					ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
					Detail: "served fingerprint does not match renewed cert",
				},
				fmt.Errorf("install: verify mismatch (served %s, want %s), rolled back",
					served, req.ExpectedFingerprint)
		}
		return InstallResult{
			Installed: true, Reloaded: true, Verified: true,
			ServedFingerprint: served, Outcome: OutcomeInstalledVerified,
		}, nil
	}

	return InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// verifyUntilMatchOrExhausted calls verify up to verifyRetryAttempts times,
// stopping as soon as the served fingerprint matches expected. A dial error
// or a stale (mismatched) fingerprint both just mean "not there yet" during
// this window -- see verifyRetryAttempts's doc comment -- so both retry the
// same way; only the FINAL attempt's result is returned to the caller, which
// preserves Install's existing dial-error-vs-mismatch branching untouched.
func (in *Installer) verifyUntilMatchOrExhausted(ctx context.Context, hostPort, expected string) (served string, err error) {
	for attempt := 1; attempt <= verifyRetryAttempts; attempt++ {
		served, err = in.verify(ctx, hostPort)
		if err == nil && normalizeFingerprint(served) == normalizeFingerprint(expected) {
			return served, nil
		}
		if attempt < verifyRetryAttempts {
			select {
			case <-ctx.Done():
				return served, err
			case <-time.After(verifyRetryDelay):
			}
		}
	}
	return served, err
}

// snapshot records what rollback needs for path. With a privileged executor it
// also captures the prior owner, group and mode; in helper mode the copy stays
// on the host. A host-side backup that fails is a snapshot error: continuing
// would mean destroying a key that cannot be put back.
func (in *Installer) snapshot(ctx context.Context, path string, mode os.FileMode) fileBackup {
	b := fileBackup{path: path, mode: mode}
	if !in.exec.Exists(path) {
		return b
	}
	if st, ok := in.exec.(privexec.Statter); ok {
		if m, err := st.StatMeta(ctx, path); err == nil {
			b.meta = &m
			b.mode = m.Mode
		}
	}
	if hb, ok := in.exec.(privexec.HostBackuper); ok {
		supported, err := hb.BackupFile(ctx, path)
		if supported {
			if err != nil {
				b.err = fmt.Errorf("back up %s on the host: %w", path, err)
				return b
			}
			b.existed, b.onHost = true, true
			rollbackFrom(ctx).note(path, true)
			return b
		}
	}
	if content, err := in.exec.ReadFile(path); err == nil {
		b.content = content
		b.existed = true
	}
	return b
}

func snapshotError(backups []fileBackup) error {
	for _, b := range backups {
		if b.err != nil {
			return b.err
		}
	}
	return nil
}

// place writes content, re-applying the prior owner, group and mode when the
// executor can and the file existed.
func (in *Installer) place(path string, content []byte, mode os.FileMode, b fileBackup) error {
	if b.meta != nil {
		if ow, ok := in.exec.(privexec.OwnedWriter); ok {
			return ow.WriteFileOwned(path, content, b.meta.Mode, b.meta.Owner, b.meta.Group)
		}
	}
	return in.exec.WriteFile(path, content, mode)
}

// rollback restores backed-up files. Only files that existed before are
// restored; newly-created files are left as-is (removing them is risky without
// a delete primitive -- restoring prior content is the safe, reversible
// action). A failed restore is recorded so Install reports rollback_failed.
func (in *Installer) rollback(ctx context.Context, backups []fileBackup, _ InstallRequest) {
	rl := rollbackFrom(ctx)
	for _, b := range backups {
		if !b.existed {
			continue
		}
		var err error
		if b.onHost {
			if hb, ok := in.exec.(privexec.HostBackuper); ok {
				err = hb.RestoreFile(context.WithoutCancel(ctx), b.path)
				if err == nil {
					rl.note(b.path, false)
				}
			}
		} else {
			err = in.place(b.path, b.content, b.mode, b)
		}
		if err != nil {
			rl.fail(fmt.Errorf("restore %s: %w", b.path, err))
		}
	}
}

// configTestCommand returns the validate-before-reload command for a server type.
func configTestCommand(serverType string) (name string, args []string, ok bool) {
	switch serverType {
	case "nginx":
		return "nginx", []string{"-t"}, true
	case "apache":
		return "apachectl", []string{"configtest"}, true
	default:
		return "", nil, false
	}
}

// reloadCommand returns the reload command for a server type. method overrides
// auto-selection: "systemctl" forces systemd, "binary" forces the server's own
// reload flag. Empty method defaults to systemctl (service-managed is the norm).
func reloadCommand(serverType, method string) (name string, args []string) {
	service := map[string]string{"nginx": "nginx", "apache": "apache2"}[serverType]
	if service == "" {
		service = serverType
	}
	switch method {
	case "binary":
		switch serverType {
		case "nginx":
			return "nginx", []string{"-s", "reload"}
		case "apache":
			return "apachectl", []string{"-k", "graceful"}
		}
	}
	// default / "systemctl"
	return "systemctl", []string{"reload", service}
}

// --- Two-phase (stage-then-flip) install, W27-14 / D09-1 ---

const (
	stagedSuffix = ".kk-staged"
	prevSuffix   = ".kk-prev"

	// OutcomeStaged is the InstallResult.Outcome of a successful Stage: the
	// new material sits beside the live files and nothing was reloaded.
	OutcomeStaged = "staged"
)

type stagedFile struct {
	live, staged string
	mode         os.FileMode
}

// StagedInstall records paths and verify parameters only -- never PEM bytes.
type StagedInstall struct {
	serverType, reloadMethod, haproxyConfig string
	files                                   []stagedFile
	verifyHostPort, expectedFingerprint     string
}

type flippedFile struct {
	live, prev string
	hadPrior   bool
}

// FlippedInstall is a successful Flip awaiting Commit (drop the predecessor
// copies) or Restore (cluster rollback). The predecessor key copy lives only on
// the target host, never on the hub.
type FlippedInstall struct {
	st    *StagedInstall
	files []flippedFile
}

// Stage writes the new material beside the live files, proves the bytes landed
// intact and that the CURRENT config still passes its test. Live files are
// untouched and nothing reloads. It cannot prove the new cert itself loads;
// that is Flip's post-rename config test + reload + verify.
func (in *Installer) Stage(ctx context.Context, req InstallRequest) (*StagedInstall, InstallResult, error) {
	st := &StagedInstall{
		serverType: req.ServerType, reloadMethod: req.ReloadMethod,
		verifyHostPort: req.VerifyHostPort, expectedFingerprint: req.ExpectedFingerprint,
	}
	contents := map[string][]byte{}
	add := func(live string, content []byte, mode os.FileMode) {
		st.files = append(st.files, stagedFile{live: live, staged: live + stagedSuffix, mode: mode})
		contents[live] = content
	}
	switch req.ServerType {
	case "haproxy":
		cfg, err := haproxyStageFiles(req, add)
		if err != nil {
			return nil, InstallResult{}, err
		}
		st.haproxyConfig = cfg
	case "nginx", "apache":
		if req.CertPath == "" || len(req.CertPEM) == 0 {
			return nil, InstallResult{}, fmt.Errorf("stage: cert path and PEM are required")
		}
		add(req.CertPath, req.CertPEM, 0o644)
		if req.KeyPath != "" && len(req.KeyPEM) > 0 {
			add(req.KeyPath, req.KeyPEM, 0o600)
		}
	default:
		return nil, InstallResult{}, fmt.Errorf("stage: server type %q does not support staged install", req.ServerType)
	}

	for _, f := range st.files {
		if err := in.exec.WriteFile(f.staged, contents[f.live], f.mode); err != nil {
			_ = in.Discard(ctx, st) // best-effort: the write error is the one reported
			return nil, InstallResult{Outcome: OutcomeWriteFailed}, fmt.Errorf("stage: write %s: %w", f.staged, err)
		}
		back, err := in.exec.ReadFile(f.staged)
		if err != nil || !bytes.Equal(back, contents[f.live]) {
			_ = in.Discard(ctx, st) // best-effort: the read-back failure is the one reported
			return nil, InstallResult{Outcome: OutcomeWriteFailed, Detail: "staged file read-back mismatch"},
				fmt.Errorf("stage: staged file %s did not read back intact", f.staged)
		}
	}
	if name, args, ok := st.configTest(); ok {
		if out, err := in.exec.Run(ctx, name, args...); err != nil {
			_ = in.Discard(ctx, st) // best-effort: the config-test error is the one reported
			return nil, InstallResult{Outcome: OutcomeConfigTestFailed, Detail: string(out)},
				fmt.Errorf("stage: config test failed, staged files discarded: %w", err)
		}
	}
	return st, InstallResult{Outcome: OutcomeStaged}, nil
}

func (st *StagedInstall) configTest() (name string, args []string, ok bool) {
	if st.serverType == "haproxy" {
		return "haproxy", []string{"-c", "-f", st.haproxyConfig}, true
	}
	return configTestCommand(st.serverType)
}

func (st *StagedInstall) reload() (name string, args []string) {
	if st.serverType == "haproxy" {
		return "systemctl", []string{"reload", "haproxy"}
	}
	return reloadCommand(st.serverType, st.reloadMethod)
}

func (in *Installer) rm(ctx context.Context, paths ...string) error {
	var first error
	for _, p := range paths {
		if _, err := in.exec.Run(ctx, "rm", "-f", "--", p); err != nil && first == nil {
			first = fmt.Errorf("rm %s: %w", p, err)
		}
	}
	return first
}

// restoreFlipped puts predecessors back (or removes first-install files),
// attempting every file and returning the first error.
func (in *Installer) restoreFlipped(ctx context.Context, files []flippedFile) error {
	var first error
	for _, f := range files {
		var err error
		if f.hadPrior {
			_, err = in.exec.Run(ctx, "mv", "-f", "--", f.prev, f.live)
		} else {
			_, err = in.exec.Run(ctx, "rm", "-f", "--", f.live)
		}
		if err != nil && first == nil {
			first = fmt.Errorf("restore %s: %w", f.live, err)
		}
	}
	return first
}

// Flip renames the staged files over the live ones (keeping a `.kk-prev` copy
// of each predecessor on the host), then runs config test, reload and the
// optional verify. Any failure restores the snapshot. On success the caller
// must Commit or Restore.
func (in *Installer) Flip(ctx context.Context, st *StagedInstall) (*FlippedInstall, InstallResult, error) {
	fl := &FlippedInstall{st: st}
	for _, f := range st.files {
		ff := flippedFile{live: f.live, prev: f.live + prevSuffix, hadPrior: in.exec.Exists(f.live)}
		if ff.hadPrior {
			if _, err := in.exec.Run(ctx, "cp", "-p", "--", ff.live, ff.prev); err != nil {
				return nil, in.abortFlip(ctx, st, fl.files, ff, 0, "snapshot"), fmt.Errorf("flip: snapshot %s: %w", f.live, err)
			}
		}
		fl.files = append(fl.files, ff)
	}
	for i, f := range st.files {
		if _, err := in.exec.Run(ctx, "mv", "-f", "--", f.staged, f.live); err != nil {
			return nil, in.abortFlip(ctx, st, fl.files, flippedFile{}, i, "rename"), fmt.Errorf("flip: rename %s: %w", f.staged, err)
		}
	}

	rbName, rbArgs := st.reload()
	// fail restores the snapshot; the reload after it is best-effort so the
	// host keeps serving the predecessor.
	fail := func(res InstallResult, reloadAfter bool, err error) (*FlippedInstall, InstallResult, error) {
		res.RolledBack = true
		if rerr := in.restoreFlipped(ctx, fl.files); rerr != nil {
			res.Detail = strings.TrimSpace(res.Detail + "; " + rerr.Error())
			err = fmt.Errorf("%w (restore failed: %v)", err, rerr)
		}
		if reloadAfter {
			_, _ = in.exec.Run(ctx, rbName, rbArgs...) // best-effort rollback reload; primary error already returned
		}
		return nil, res, err
	}

	if name, args, ok := st.configTest(); ok {
		if out, err := in.exec.Run(ctx, name, args...); err != nil {
			return fail(InstallResult{Outcome: OutcomeConfigTestFailed, Detail: string(out)}, false,
				fmt.Errorf("flip: config test failed, rolled back: %w", err))
		}
	}
	if out, err := in.exec.Run(ctx, rbName, rbArgs...); err != nil {
		return fail(InstallResult{Installed: true, Outcome: OutcomeReloadFailed, Detail: string(out)}, true,
			fmt.Errorf("flip: reload failed, rolled back: %w", err))
	}
	if st.verifyHostPort != "" && st.expectedFingerprint != "" {
		served, err := in.verifyUntilMatchOrExhausted(ctx, st.verifyHostPort, st.expectedFingerprint)
		if err != nil {
			return fail(InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeVerifyFailed, Detail: err.Error()}, true,
				fmt.Errorf("flip: verify failed, rolled back: %w", err))
		}
		if normalizeFingerprint(served) != normalizeFingerprint(st.expectedFingerprint) {
			return fail(InstallResult{
				Installed: true, Reloaded: true, ServedFingerprint: served, Outcome: OutcomeVerifyFailed,
				Detail: "served fingerprint does not match renewed cert",
			}, true, fmt.Errorf("flip: verify mismatch (served %s, want %s), rolled back", served, st.expectedFingerprint))
		}
		return fl, InstallResult{Installed: true, Reloaded: true, Verified: true, ServedFingerprint: served, Outcome: OutcomeInstalledVerified}, nil
	}
	return fl, InstallResult{Installed: true, Reloaded: true, Outcome: OutcomeInstalled}, nil
}

// abortFlip unwinds a Flip that failed before any reload: files[0:renamed] were
// renamed over live, everything else is still staged. cur is a file whose
// snapshot copy may be partial (snapshot failure) and is cleaned too.
func (in *Installer) abortFlip(ctx context.Context, st *StagedInstall, snap []flippedFile, cur flippedFile, renamed int, phase string) InstallResult {
	res := InstallResult{Outcome: OutcomeWriteFailed, RolledBack: true}
	var errs []string
	if phase == "rename" {
		if err := in.restoreFlipped(ctx, snap[:renamed]); err != nil {
			errs = append(errs, err.Error())
		}
	}
	var drop []string
	for _, f := range st.files {
		drop = append(drop, f.staged)
	}
	for i, f := range snap {
		if phase == "snapshot" || i >= renamed {
			if f.hadPrior {
				drop = append(drop, f.prev)
			}
		}
	}
	if cur.live != "" {
		drop = append(drop, cur.prev)
	}
	if err := in.rm(ctx, drop...); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		res.Detail = strings.Join(errs, "; ")
	}
	return res
}

// Discard removes the staged files; live files are never touched. Idempotent.
func (in *Installer) Discard(ctx context.Context, st *StagedInstall) error {
	paths := make([]string, 0, len(st.files))
	for _, f := range st.files {
		paths = append(paths, f.staged)
	}
	return in.rm(ctx, paths...)
}

// Restore undoes a SUCCESSFUL Flip (cluster rollback): predecessors return,
// first-install files are removed, then the server reloads.
func (in *Installer) Restore(ctx context.Context, fl *FlippedInstall) error {
	err := in.restoreFlipped(ctx, fl.files)
	name, args := fl.st.reload()
	if _, rerr := in.exec.Run(ctx, name, args...); rerr != nil && err == nil {
		err = fmt.Errorf("restore reload: %w", rerr)
	}
	return err
}

// Commit deletes the predecessor copies, so no superseded private key remains
// on the host. Idempotent.
func (in *Installer) Commit(ctx context.Context, fl *FlippedInstall) error {
	var paths []string
	for _, f := range fl.files {
		if f.hadPrior {
			paths = append(paths, f.prev)
		}
	}
	return in.rm(ctx, paths...)
}
