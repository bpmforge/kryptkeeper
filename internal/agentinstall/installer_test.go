// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"kryptkeeper/internal/privexec"
)

// fakeExecutor is an in-memory Executor for tests: a virtual filesystem plus a
// scripted command runner.
type fakeExecutor struct {
	files map[string][]byte
	// failCmd, when it matches "name arg0 arg1...", makes Run return an error.
	failCmd string
	// ran records every command Run executed, in order.
	ran []string
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{files: map[string][]byte{}}
}

func (f *fakeExecutor) Exists(path string) bool { _, ok := f.files[path]; return ok }

func (f *fakeExecutor) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (f *fakeExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	cp := make([]byte, len(content))
	copy(cp, content)
	f.files[path] = cp
	return nil
}

func (f *fakeExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, cmd)
	if f.failCmd != "" && strings.HasPrefix(cmd, f.failCmd) {
		return []byte("simulated failure: " + cmd), fmt.Errorf("command failed: %s", cmd)
	}
	// Emulate the file commands the staged API issues (W27-14).
	switch {
	case name == "cp" && len(args) == 4 && args[0] == "-p" && args[1] == "--":
		b, ok := f.files[args[2]]
		if !ok {
			return []byte("cp: no such file"), fmt.Errorf("cp: %s: no such file", args[2])
		}
		f.files[args[3]] = append([]byte(nil), b...)
	case name == "mv" && len(args) == 4 && args[0] == "-f" && args[1] == "--":
		b, ok := f.files[args[2]]
		if !ok {
			return []byte("mv: no such file"), fmt.Errorf("mv: %s: no such file", args[2])
		}
		f.files[args[3]] = b
		delete(f.files, args[2])
	case name == "rm" && len(args) == 3 && args[0] == "-f" && args[1] == "--":
		delete(f.files, args[2])
	}
	return []byte("ok"), nil
}

func nginxReq() InstallRequest {
	return InstallRequest{
		ServerType: "nginx",
		CertPath:   "/etc/nginx/ssl/site.crt",
		KeyPath:    "/etc/nginx/ssl/site.key",
		CertPEM:    []byte("NEW-CERT"),
		KeyPEM:     []byte("NEW-KEY"),
	}
}

func TestInstall_HappyPath(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")

	res, err := New(f).Install(context.Background(), nginxReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Installed || !res.Reloaded || res.RolledBack {
		t.Fatalf("unexpected result: %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "NEW-CERT" {
		t.Errorf("cert not written: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	if string(f.files["/etc/nginx/ssl/site.key"]) != "NEW-KEY" {
		t.Errorf("key not written: %q", f.files["/etc/nginx/ssl/site.key"])
	}
	// config test must precede reload.
	if len(f.ran) != 2 || f.ran[0] != "nginx -t" || f.ran[1] != "systemctl reload nginx" {
		t.Fatalf("unexpected command order: %v", f.ran)
	}
}

func TestInstall_ConfigTestFailsRollsBack(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	f.failCmd = "nginx -t"

	res, err := New(f).Install(context.Background(), nginxReq())
	if err == nil {
		t.Fatal("expected error when config test fails")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack, got %+v", res)
	}
	// Old contents must be restored; never reloaded.
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Errorf("cert not rolled back: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	if string(f.files["/etc/nginx/ssl/site.key"]) != "OLD-KEY" {
		t.Errorf("key not rolled back: %q", f.files["/etc/nginx/ssl/site.key"])
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl reload") {
			t.Fatalf("must NOT reload after failed config test; ran %v", f.ran)
		}
	}
}

func TestInstall_ReloadFailsRollsBackAndReloads(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	f.failCmd = "systemctl reload nginx"

	res, err := New(f).Install(context.Background(), nginxReq())
	if err == nil {
		t.Fatal("expected error when reload fails")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack, got %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Errorf("cert not rolled back: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	// reload attempted twice: once for the new cert, once after rollback.
	reloads := 0
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl reload") {
			reloads++
		}
	}
	if reloads != 2 {
		t.Fatalf("expected 2 reload attempts (install + post-rollback), got %d: %v", reloads, f.ran)
	}
}

func TestInstall_FirstTimeNoBackup(t *testing.T) {
	f := newFakeExecutor() // no pre-existing files
	res, err := New(f).Install(context.Background(), nginxReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Installed || !res.Reloaded {
		t.Fatalf("unexpected result: %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "NEW-CERT" {
		t.Errorf("cert not written on first install")
	}
}

func TestInstall_BinaryReloadMethod(t *testing.T) {
	f := newFakeExecutor()
	req := nginxReq()
	req.ReloadMethod = "binary"
	if _, err := New(f).Install(context.Background(), req); err != nil {
		t.Fatalf("install: %v", err)
	}
	if f.ran[len(f.ran)-1] != "nginx -s reload" {
		t.Fatalf("expected binary reload, got %v", f.ran)
	}
}

func TestInstall_RequiresCert(t *testing.T) {
	f := newFakeExecutor()
	_, err := New(f).Install(context.Background(), InstallRequest{ServerType: "nginx"})
	if err == nil {
		t.Fatal("expected error with no cert")
	}
}

func TestInstall_ApacheUsesConfigtest(t *testing.T) {
	f := newFakeExecutor()
	req := InstallRequest{
		ServerType: "apache",
		CertPath:   "/etc/apache2/ssl/site.crt",
		KeyPath:    "/etc/apache2/ssl/site.key",
		CertPEM:    []byte("C"),
		KeyPEM:     []byte("K"),
	}
	if _, err := New(f).Install(context.Background(), req); err != nil {
		t.Fatalf("install: %v", err)
	}
	if f.ran[0] != "apachectl configtest" || f.ran[1] != "systemctl reload apache2" {
		t.Fatalf("unexpected apache commands: %v", f.ran)
	}
}

// fakeVerifier returns a Verifier that yields servedFP (or err).
func fakeVerifier(servedFP string, err error) Verifier {
	return func(_ context.Context, _ string) (string, error) {
		return servedFP, err
	}
}

func verifyReq() InstallRequest {
	r := nginxReq()
	r.VerifyHostPort = "localhost:443"
	r.ExpectedFingerprint = "ABCD1234"
	return r
}

func TestInstall_VerifySuccess(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD")
	in := New(f).WithVerifier(fakeVerifier("abcd1234", nil)) // case-insensitive match

	res, err := in.Install(context.Background(), verifyReq())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Verified || res.Outcome != OutcomeInstalledVerified {
		t.Fatalf("expected verified outcome, got %+v", res)
	}
	if res.ServedFingerprint != "abcd1234" {
		t.Errorf("served fingerprint: %q", res.ServedFingerprint)
	}
}

func TestInstall_VerifyMismatchRollsBack(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	f.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	in := New(f).WithVerifier(fakeVerifier("deadbeef", nil)) // wrong cert served

	res, err := in.Install(context.Background(), verifyReq())
	if err == nil {
		t.Fatal("expected error on fingerprint mismatch")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed {
		t.Fatalf("expected verify_failed rollback, got %+v", res)
	}
	if string(f.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Errorf("cert not rolled back after verify mismatch: %q", f.files["/etc/nginx/ssl/site.crt"])
	}
	// reload happens for install, then again after rollback.
	reloads := 0
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl reload") {
			reloads++
		}
	}
	if reloads != 2 {
		t.Fatalf("expected 2 reloads (install + post-rollback), got %d: %v", reloads, f.ran)
	}
}

func TestInstall_VerifyDialErrorRollsBack(t *testing.T) {
	f := newFakeExecutor()
	f.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	in := New(f).WithVerifier(fakeVerifier("", fmt.Errorf("connection refused")))

	res, err := in.Install(context.Background(), verifyReq())
	if err == nil {
		t.Fatal("expected error when verify dial fails")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed {
		t.Fatalf("expected verify_failed rollback, got %+v", res)
	}
}

func TestInstall_NoVerifyWhenNotRequested(t *testing.T) {
	f := newFakeExecutor()
	// Verifier that would fail if called — proves it's skipped.
	in := New(f).WithVerifier(fakeVerifier("", fmt.Errorf("should not be called")))
	res, err := in.Install(context.Background(), nginxReq()) // no VerifyHostPort
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Verified || res.Outcome != OutcomeInstalled {
		t.Fatalf("expected installed (unverified) outcome, got %+v", res)
	}
}

func TestFingerprintSHA256(t *testing.T) {
	// SHA-256 of empty input is well-known.
	got := FingerprintSHA256(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("FingerprintSHA256(nil) = %q, want %q", got, want)
	}
}

// --- W27-14: two-phase staged install ---

func stagedReq(serverType string) InstallRequest {
	dir := map[string]string{"nginx": "/etc/nginx/ssl", "apache": "/etc/apache2/ssl"}[serverType]
	return InstallRequest{
		ServerType: serverType,
		CertPath:   dir + "/site.crt", KeyPath: dir + "/site.key",
		CertPEM: []byte("NEW-CERT"), KeyPEM: []byte("NEW-KEY"),
	}
}

func stagedFixture(serverType string) (*fakeExecutor, InstallRequest) {
	f := newFakeExecutor()
	req := stagedReq(serverType)
	f.files[req.CertPath] = []byte("OLD-CERT")
	f.files[req.KeyPath] = []byte("OLD-KEY")
	return f, req
}

func (f *fakeExecutor) paths() []string {
	out := make([]string, 0, len(f.files))
	for p := range f.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (f *fakeExecutor) anyContains(sub string) bool {
	for _, b := range f.files {
		if strings.Contains(string(b), sub) {
			return true
		}
	}
	return false
}

func (f *fakeExecutor) ranContains(sub string) bool {
	for _, c := range f.ran {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

var stagedServerTypes = []struct{ typ, test, reload string }{
	{"nginx", "nginx -t", "systemctl reload nginx"},
	{"apache", "apachectl configtest", "systemctl reload apache2"},
}

func TestStage_LeavesLiveUntouched(t *testing.T) {
	for _, sv := range stagedServerTypes {
		t.Run(sv.typ, func(t *testing.T) {
			f, req := stagedFixture(sv.typ)
			st, res, err := New(f).Stage(context.Background(), req)
			if err != nil || st == nil || res.Outcome != OutcomeStaged {
				t.Fatalf("stage: %+v %v", res, err)
			}
			if string(f.files[req.CertPath]) != "OLD-CERT" || string(f.files[req.KeyPath]) != "OLD-KEY" {
				t.Fatal("live files must be untouched")
			}
			if string(f.files[req.CertPath+stagedSuffix]) != "NEW-CERT" || string(f.files[req.KeyPath+stagedSuffix]) != "NEW-KEY" {
				t.Fatal("staged files missing")
			}
			if !f.ranContains(sv.test) || f.ranContains("reload") {
				t.Fatalf("stage must run the config test and never reload: %v", f.ran)
			}
		})
	}
}

func TestDiscard_AfterStage_LiveByteIdentical(t *testing.T) {
	for _, sv := range stagedServerTypes {
		t.Run(sv.typ, func(t *testing.T) {
			f, req := stagedFixture(sv.typ)
			before := map[string]string{}
			for p, b := range f.files {
				before[p] = string(b)
			}
			in := New(f)
			st, _, err := in.Stage(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if err := in.Discard(context.Background(), st); err != nil {
				t.Fatal(err)
			}
			if err := in.Discard(context.Background(), st); err != nil {
				t.Fatalf("discard must be idempotent: %v", err)
			}
			if len(f.files) != len(before) {
				t.Fatalf("leftover files: %v", f.paths())
			}
			for p, b := range before {
				if string(f.files[p]) != b {
					t.Fatalf("%s changed", p)
				}
			}
		})
	}
}

func TestStage_ConfigTestFailure_Discards(t *testing.T) {
	for _, sv := range stagedServerTypes {
		t.Run(sv.typ, func(t *testing.T) {
			f, req := stagedFixture(sv.typ)
			f.failCmd = strings.Fields(sv.test)[0]
			st, res, err := New(f).Stage(context.Background(), req)
			if err == nil || st != nil || res.Outcome != OutcomeConfigTestFailed {
				t.Fatalf("want config_test_failed: %+v %v", res, err)
			}
			if len(f.files) != 2 {
				t.Fatalf("staged files must be discarded: %v", f.paths())
			}
		})
	}
}

func TestFlip_HappyPath_CommitLeavesOnlyLiveFiles(t *testing.T) {
	for _, sv := range stagedServerTypes {
		t.Run(sv.typ, func(t *testing.T) {
			f, req := stagedFixture(sv.typ)
			in := New(f)
			st, _, err := in.Stage(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			fl, res, err := in.Flip(context.Background(), st)
			if err != nil || res.Outcome != OutcomeInstalled {
				t.Fatalf("flip: %+v %v", res, err)
			}
			if string(f.files[req.CertPath]) != "NEW-CERT" || string(f.files[req.KeyPath]) != "NEW-KEY" {
				t.Fatal("live files must hold the new material")
			}
			if string(f.files[req.CertPath+prevSuffix]) != "OLD-CERT" {
				t.Fatal("predecessor kept on host until Commit")
			}
			if !f.ranContains(sv.reload) {
				t.Fatalf("flip must reload: %v", f.ran)
			}
			if err := in.Commit(context.Background(), fl); err != nil {
				t.Fatal(err)
			}
			want := []string{req.CertPath, req.KeyPath}
			sort.Strings(want)
			if strings.Join(f.paths(), ",") != strings.Join(want, ",") {
				t.Fatalf("after commit want only live files, got %v", f.paths())
			}
		})
	}
}

func TestNoSupersededKeyRetained(t *testing.T) {
	for _, sv := range stagedServerTypes {
		t.Run(sv.typ, func(t *testing.T) {
			f, req := stagedFixture(sv.typ)
			in := New(f)
			st, _, _ := in.Stage(context.Background(), req)
			fl, _, err := in.Flip(context.Background(), st)
			if err != nil {
				t.Fatal(err)
			}
			if err := in.Commit(context.Background(), fl); err != nil {
				t.Fatal(err)
			}
			if f.anyContains("OLD-KEY") {
				t.Fatalf("superseded key retained: %v", f.paths())
			}
		})
	}
}

func TestFlip_ReloadFailure_RestoresSnapshot(t *testing.T) {
	for _, sv := range stagedServerTypes {
		t.Run(sv.typ, func(t *testing.T) {
			f, req := stagedFixture(sv.typ)
			in := New(f)
			st, _, _ := in.Stage(context.Background(), req)
			f.failCmd = sv.reload
			fl, res, err := in.Flip(context.Background(), st)
			if err == nil || fl != nil || !res.RolledBack || res.Outcome != OutcomeReloadFailed {
				t.Fatalf("want reload_failed rollback: %+v %v", res, err)
			}
			if string(f.files[req.CertPath]) != "OLD-CERT" || string(f.files[req.KeyPath]) != "OLD-KEY" || len(f.files) != 2 {
				t.Fatalf("snapshot not restored cleanly: %v", f.paths())
			}
		})
	}
}

func TestFlip_ConfigTestFailure_RestoresWithoutReload(t *testing.T) {
	f, req := stagedFixture("nginx")
	in := New(f)
	st, _, _ := in.Stage(context.Background(), req)
	f.failCmd, f.ran = "nginx -t", nil
	_, res, err := in.Flip(context.Background(), st)
	if err == nil || res.Outcome != OutcomeConfigTestFailed || !res.RolledBack {
		t.Fatalf("got %+v %v", res, err)
	}
	if f.ranContains("reload") || string(f.files[req.CertPath]) != "OLD-CERT" || len(f.files) != 2 {
		t.Fatalf("restore without reload expected: ran=%v files=%v", f.ran, f.paths())
	}
}

func TestFlip_VerifyMismatch_RestoresSnapshot(t *testing.T) {
	f, req := stagedFixture("nginx")
	req.VerifyHostPort, req.ExpectedFingerprint = "h:443", "aa11"
	in := New(f).WithVerifier(func(context.Context, string) (string, error) { return "bb22", nil })
	st, _, _ := in.Stage(context.Background(), req)
	_, res, err := in.Flip(context.Background(), st)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("got %+v %v", res, err)
	}
	if string(f.files[req.CertPath]) != "OLD-CERT" || string(f.files[req.KeyPath]) != "OLD-KEY" || len(f.files) != 2 {
		t.Fatalf("snapshot not restored: %v", f.paths())
	}
}

func TestFlip_SecondRenameFails_RestoresFirst(t *testing.T) {
	f, req := stagedFixture("nginx")
	in := New(f)
	st, _, _ := in.Stage(context.Background(), req)
	f.failCmd = "mv -f -- " + req.KeyPath + stagedSuffix
	_, res, err := in.Flip(context.Background(), st)
	if err == nil || res.Outcome != OutcomeWriteFailed || !res.RolledBack {
		t.Fatalf("got %+v %v", res, err)
	}
	if string(f.files[req.CertPath]) != "OLD-CERT" || string(f.files[req.KeyPath]) != "OLD-KEY" || len(f.files) != 2 {
		t.Fatalf("first rename not undone: %v", f.paths())
	}
}

func TestRestore_AfterSuccessfulFlip_ReturnsToOld(t *testing.T) {
	f, req := stagedFixture("apache")
	in := New(f)
	st, _, _ := in.Stage(context.Background(), req)
	fl, _, err := in.Flip(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	f.ran = nil
	if err := in.Restore(context.Background(), fl); err != nil {
		t.Fatal(err)
	}
	if string(f.files[req.CertPath]) != "OLD-CERT" || string(f.files[req.KeyPath]) != "OLD-KEY" || len(f.files) != 2 {
		t.Fatalf("restore did not return to old: %v", f.paths())
	}
	if !f.ranContains("systemctl reload apache2") {
		t.Fatalf("restore must reload: %v", f.ran)
	}
}

func TestFlip_FirstInstall_RestoreRemovesNewFiles(t *testing.T) {
	f := newFakeExecutor()
	req := stagedReq("nginx")
	in := New(f)
	st, _, err := in.Stage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	fl, _, err := in.Flip(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Restore(context.Background(), fl); err != nil {
		t.Fatal(err)
	}
	if len(f.files) != 0 {
		t.Fatalf("first-install files must be removed: %v", f.paths())
	}
}

func TestStage_Refusals(t *testing.T) {
	f := newFakeExecutor()
	in := New(f)
	for name, req := range map[string]InstallRequest{
		"no cert path": {ServerType: "nginx", CertPEM: []byte("x")},
		"no cert pem":  {ServerType: "nginx", CertPath: "/a"},
		"tomcat":       {ServerType: "tomcat", CertPath: "/a", CertPEM: []byte("x")},
	} {
		if st, _, err := in.Stage(context.Background(), req); err == nil || st != nil {
			t.Fatalf("%s: expected refusal", name)
		}
	}
	if len(f.files) != 0 {
		t.Fatal("refusals must write nothing")
	}
}

// ---- W34-18: privileged executor (ownership, host-side backup, rollback failure) ----

// privFakeExecutor is a fakeExecutor that also implements the privexec
// capabilities a privileged SSH executor has.
type privFakeExecutor struct {
	*fakeExecutor
	meta        map[string]privexec.FileMeta
	owned       []string // "path owner:group mode" per WriteFileOwned
	hostBackups map[string][]byte
	hostMode    bool // helper-like: backups stay on the host
	reads       []string
	failRestore bool
	failBackup  bool
	dropped     []string
}

func newPrivFake() *privFakeExecutor {
	return &privFakeExecutor{fakeExecutor: newFakeExecutor(), meta: map[string]privexec.FileMeta{}, hostBackups: map[string][]byte{}}
}

func (p *privFakeExecutor) ReadFile(path string) ([]byte, error) {
	p.reads = append(p.reads, path)
	return p.fakeExecutor.ReadFile(path)
}

func (p *privFakeExecutor) StatMeta(_ context.Context, path string) (privexec.FileMeta, error) {
	m, ok := p.meta[path]
	if !ok {
		return privexec.FileMeta{}, os.ErrNotExist
	}
	return m, nil
}

func (p *privFakeExecutor) WriteFileOwned(path string, content []byte, mode os.FileMode, owner, group string) error {
	p.owned = append(p.owned, fmt.Sprintf("%s %s:%s %04o", path, owner, group, mode))
	return p.fakeExecutor.WriteFile(path, content, mode)
}

func (p *privFakeExecutor) BackupFile(_ context.Context, path string) (bool, error) {
	if !p.hostMode {
		return false, nil
	}
	if p.failBackup {
		return true, fmt.Errorf("cp: permission denied")
	}
	p.hostBackups[path] = append([]byte(nil), p.files[path]...)
	return true, nil
}

func (p *privFakeExecutor) RestoreFile(_ context.Context, path string) error {
	if p.failRestore {
		return fmt.Errorf("mv: permission denied")
	}
	b, ok := p.hostBackups[path]
	if !ok {
		return fmt.Errorf("no backup")
	}
	p.files[path] = b
	delete(p.hostBackups, path)
	return nil
}

func (p *privFakeExecutor) DropBackup(_ context.Context, path string) error {
	p.dropped = append(p.dropped, path)
	delete(p.hostBackups, path)
	return nil
}

func TestInstall_PreservesOwnerGroupAndMode(t *testing.T) {
	p := newPrivFake()
	p.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	p.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	p.meta["/etc/nginx/ssl/site.crt"] = privexec.FileMeta{Owner: "tomcat", Group: "tomcat", Mode: 0o640}
	p.meta["/etc/nginx/ssl/site.key"] = privexec.FileMeta{Owner: "root", Group: "ssl-cert", Mode: 0o640}

	if _, err := New(p).Install(context.Background(), nginxReq()); err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/nginx/ssl/site.crt tomcat:tomcat 0640", "/etc/nginx/ssl/site.key root:ssl-cert 0640"}
	if strings.Join(p.owned, "|") != strings.Join(want, "|") {
		t.Fatalf("ownership not re-applied: %v", p.owned)
	}
}

func TestInstall_ConfigTestFailureRestoresOwnership(t *testing.T) {
	p := newPrivFake()
	p.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	p.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	p.meta["/etc/nginx/ssl/site.key"] = privexec.FileMeta{Owner: "svc", Group: "svc", Mode: 0o600}
	p.failCmd = "nginx -t"
	res, err := New(p).Install(context.Background(), nginxReq())
	if err == nil || !res.RolledBack || res.RollbackFailed {
		t.Fatalf("%+v %v", res, err)
	}
	if string(p.files["/etc/nginx/ssl/site.key"]) != "OLD-KEY" {
		t.Fatal("key not restored")
	}
	last := p.owned[len(p.owned)-1]
	if last != "/etc/nginx/ssl/site.key svc:svc 0600" {
		t.Fatalf("rollback must restore ownership too: %v", p.owned)
	}
}

func TestInstall_HostSideBackupNeverReadsTheKey(t *testing.T) {
	p := newPrivFake()
	p.hostMode = true
	p.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	p.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	p.failCmd = "nginx -t"
	res, err := New(p).Install(context.Background(), nginxReq())
	if err == nil || !res.RolledBack || res.RollbackFailed {
		t.Fatalf("%+v %v", res, err)
	}
	if len(p.reads) != 0 {
		t.Fatalf("hub must not read the files it backs up on the host: %v", p.reads)
	}
	if string(p.files["/etc/nginx/ssl/site.key"]) != "OLD-KEY" || string(p.files["/etc/nginx/ssl/site.crt"]) != "OLD-CERT" {
		t.Fatal("host-side restore did not put the old files back")
	}
	if len(p.hostBackups) != 0 {
		t.Fatalf("restored backups must be consumed: %v", p.hostBackups)
	}
}

func TestInstall_SuccessDropsHostBackups(t *testing.T) {
	p := newPrivFake()
	p.hostMode = true
	p.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	p.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	if _, err := New(p).Install(context.Background(), nginxReq()); err != nil {
		t.Fatal(err)
	}
	if len(p.dropped) != 2 || len(p.hostBackups) != 0 {
		t.Fatalf("a superseded private key must not stay on the host: dropped=%v left=%v", p.dropped, p.hostBackups)
	}
}

func TestInstall_RollbackFailureIsDistinct(t *testing.T) {
	p := newPrivFake()
	p.hostMode = true
	p.failRestore = true
	p.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	p.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	p.failCmd = "nginx -t"
	res, err := New(p).Install(context.Background(), nginxReq())
	if err == nil || res.Outcome != OutcomeRollbackFailed || !res.RollbackFailed || !res.RolledBack {
		t.Fatalf("want rollback_failed, got %+v err=%v", res, err)
	}
	if !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(res.Detail, "restore /etc/nginx/ssl/site.") {
		t.Fatalf("error/detail should name the restore failure: %v / %q", err, res.Detail)
	}
}

func TestInstall_FailedHostBackupAbortsBeforeTouchingTheKey(t *testing.T) {
	p := newPrivFake()
	p.hostMode = true
	p.failBackup = true
	p.files["/etc/nginx/ssl/site.crt"] = []byte("OLD-CERT")
	p.files["/etc/nginx/ssl/site.key"] = []byte("OLD-KEY")
	res, err := New(p).Install(context.Background(), nginxReq())
	if err == nil || res.Outcome != OutcomeWriteFailed {
		t.Fatalf("%+v %v", res, err)
	}
	if string(p.files["/etc/nginx/ssl/site.key"]) != "OLD-KEY" || len(p.owned) != 0 {
		t.Fatal("nothing may be written when the rollback copy could not be made")
	}
}

func TestTomcatInstall_PreservesKeystoreOwnership(t *testing.T) {
	p := newPrivFake()
	p.files[tomcatKS] = []byte("OLD-KEYSTORE")
	p.meta[tomcatKS] = privexec.FileMeta{Owner: "tomcat", Group: "tomcat", Mode: 0o640}
	req, _ := tomcatReq(t)
	if res, err := New(p).Install(context.Background(), req); err != nil || !res.Installed {
		t.Fatalf("%+v %v", res, err)
	}
	if len(p.owned) != 1 || p.owned[0] != tomcatKS+" tomcat:tomcat 0640" {
		t.Fatalf("keystore must keep tomcat:tomcat 0640: %v", p.owned)
	}
}
