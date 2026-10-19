// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package privexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPassword = "S3cr3t-Pa55w0rd!"

type call struct {
	argv  []string
	stdin []byte
}

// fakeExec is an in-memory Executor + StdinRunner covering every mode with no network.
type fakeExec struct {
	calls   []call
	files   map[string][]byte
	respond func(argv []string, stdin []byte) ([]byte, error)
}

func newFake() *fakeExec { return &fakeExec{files: map[string][]byte{}} }

func (f *fakeExec) Exists(p string) bool { _, ok := f.files[p]; return ok }
func (f *fakeExec) ReadFile(p string) ([]byte, error) {
	b, ok := f.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (f *fakeExec) WriteFile(p string, c []byte, _ os.FileMode) error { f.files[p] = c; return nil }
func (f *fakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunStdin(ctx, nil, name, args...)
}
func (f *fakeExec) RunStdin(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	f.calls = append(f.calls, call{argv: argv, stdin: append([]byte(nil), stdin...)})
	if f.respond != nil {
		return f.respond(argv, stdin)
	}
	return nil, nil
}

// noStdin hides RunStdin, like the WinRM executor.
type noStdin struct{ Executor }

func (f *fakeExec) lastArgv() string { return strings.Join(f.calls[len(f.calls)-1].argv, " ") }

func (f *fakeExec) assertNoSecret(t *testing.T, secret string, extra ...string) {
	t.Helper()
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c.argv, " "), secret) {
			t.Fatalf("secret in argv: %v", c.argv)
		}
	}
	for _, s := range extra {
		if strings.Contains(s, secret) {
			t.Fatalf("secret in log/error text: %q", s)
		}
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeNone, "none": ModeNone, "nopasswd": ModeNoPasswd, "password": ModePassword, "helper": ModeHelper} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q)=%q,%v", in, got, err)
		}
	}
	if _, err := ParseMode("root"); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestWrapNoneReturnsInner(t *testing.T) {
	f := newFake()
	e, err := Wrap(f, Config{Mode: ModeNone})
	if err != nil || e != Executor(f) {
		t.Fatalf("none must be the inner executor: %v", err)
	}
}

func TestNoPasswdPrefix(t *testing.T) {
	f := newFake()
	e, _ := Wrap(f, Config{Mode: ModeNoPasswd})
	if _, err := e.Run(context.Background(), "nginx", "-t"); err != nil {
		t.Fatal(err)
	}
	if got := f.lastArgv(); got != "sudo -n -- nginx -t" {
		t.Fatalf("argv = %q", got)
	}
	f.files["/etc/x"] = []byte("x")
	if !e.Exists("/etc/x") || len(f.calls) != 1 {
		t.Fatal("nopasswd Exists must stay unelevated (D-114)")
	}
}

func TestPasswordOnStdinNeverArgv(t *testing.T) {
	f := newFake()
	pw := []byte(testPassword)
	e, err := Wrap(f, Config{Mode: ModePassword, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), "cat", "/etc/ssl/a.pem"); err != nil {
		t.Fatal(err)
	}
	if got := f.lastArgv(); got != "sudo -S -p  -k -- cat /etc/ssl/a.pem" {
		t.Fatalf("argv = %q", got)
	}
	if string(f.calls[0].stdin) != testPassword+"\n" {
		t.Fatalf("stdin = %q", f.calls[0].stdin)
	}
	f.assertNoSecret(t, testPassword)
}

func TestPasswordWriteFileStagesUnprivileged(t *testing.T) {
	f := newFake()
	e, _ := Wrap(f, Config{Mode: ModePassword, Password: []byte(testPassword)})
	if err := e.WriteFile("/etc/ssl/site.pem", []byte("PEM"), 0o640); err != nil {
		t.Fatal(err)
	}
	var sawInstall, sawRm bool
	for _, c := range f.calls {
		j := strings.Join(c.argv, " ")
		sawInstall = sawInstall || strings.HasPrefix(j, "sudo -S -p  -k -- install -m 0640 /tmp/kk-priv-") && strings.HasSuffix(j, " /etc/ssl/site.pem")
		sawRm = sawRm || strings.HasPrefix(j, "rm -f /tmp/kk-priv-")
	}
	if !sawInstall || !sawRm {
		t.Fatalf("install=%v rm=%v calls=%v", sawInstall, sawRm, f.calls)
	}
	f.assertNoSecret(t, testPassword)
}

func TestPasswordRefusedWithoutStdin(t *testing.T) {
	if _, err := Wrap(noStdin{newFake()}, Config{Mode: ModePassword, Password: []byte("x")}); err == nil {
		t.Fatal("password mode must be refused for a transport without stdin")
	}
	if _, err := Wrap(newFake(), Config{Mode: ModePassword}); err == nil {
		t.Fatal("password mode without password accepted")
	}
}

func TestPasswordErrorTextHasNoSecret(t *testing.T) {
	f := newFake()
	f.respond = func([]string, []byte) ([]byte, error) {
		return []byte("Sorry, try again."), errors.New("exit status 1")
	}
	e, _ := Wrap(f, Config{Mode: ModePassword, Password: []byte(testPassword)})
	err := e.WriteFile("/etc/ssl/a.pem", []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected error")
	}
	f.assertNoSecret(t, testPassword, err.Error())
}

func TestHelperVerifiesHashOnce(t *testing.T) {
	sha := HelperSHA256()
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sha256sum" {
			return []byte(sha + "  " + DefaultHelperPath + "\n"), nil
		}
		return []byte("ok"), nil
	}
	e, err := Wrap(f, Config{Mode: ModeHelper, HelperSHA: sha})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := e.Run(context.Background(), "list", "/opt"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.lastArgv(); got != "sudo -n -- "+DefaultHelperPath+" list /opt" {
		t.Fatalf("argv = %q", got)
	}
	n := 0
	for _, c := range f.calls {
		if c.argv[0] == "sha256sum" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sha256sum ran %d times, want 1", n)
	}
}

func TestHelperTamperedAndNonVerb(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		return []byte(strings.Repeat("0", 64) + "  h\n"), nil
	}
	e, _ := Wrap(f, Config{Mode: ModeHelper, HelperSHA: HelperSHA256()})
	if _, err := e.Run(context.Background(), "stat", "/etc/x"); !errors.Is(err, ErrHelperTampered) {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.Run(context.Background(), "cat", "/etc/shadow"); !errors.Is(err, ErrNotHelperVerb) {
		t.Fatalf("err = %v", err)
	}
	for _, c := range f.calls {
		if c.argv[0] == "sudo" {
			t.Fatalf("sudo ran despite tamper: %v", c.argv)
		}
	}
	if _, err := Wrap(f, Config{Mode: ModeHelper}); err == nil {
		t.Fatal("helper mode without pinned sha accepted")
	}
}

func TestHelperReadWriteExists(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sha256sum" {
			return []byte(HelperSHA256() + "  h\n"), nil
		}
		return []byte("out"), nil
	}
	e, _ := Wrap(f, Config{Mode: ModeHelper, HelperSHA: HelperSHA256()})
	if b, err := e.ReadFile("/opt/tomcat/conf/keystore.jks"); err != nil || string(b) != "out" {
		t.Fatalf("read: %q %v", b, err)
	}
	if !e.Exists("/opt/x.pem") {
		t.Fatal("exists via stat")
	}
	if err := e.WriteFile("/etc/nginx/ssl/a.pem", []byte("c"), 0o644); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	for _, c := range f.calls {
		if c.argv[0] == "sudo" {
			verbs = append(verbs, c.argv[4])
		}
	}
	if strings.Join(verbs, ",") != "read-cert,stat,install" {
		t.Fatalf("verbs = %v", verbs)
	}
}

func TestLocalExecutor(t *testing.T) {
	dir := t.TempDir()
	l := LocalExecutor{}
	p := filepath.Join(dir, "a.pem")
	if err := l.WriteFile(p, []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 || !l.Exists(p) {
		t.Fatalf("mode %v", st.Mode())
	}
	if b, _ := l.ReadFile(p); string(b) != "hello" {
		t.Fatal("read back")
	}
	out, err := l.RunStdin(context.Background(), []byte("piped"), "cat")
	if err != nil || string(out) != "piped" {
		t.Fatalf("stdin: %q %v", out, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp file leaked: %v", ents)
	}
}

func TestHelperTranslatesScannerAndInstallerCommands(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sha256sum" {
			return []byte(HelperSHA256() + "  h\n"), nil
		}
		return nil, nil
	}
	e, _ := Wrap(f, Config{Mode: ModeHelper, HelperSHA: HelperSHA256()})
	for _, c := range [][]string{
		{"find", "/etc/ssl/certs", "-maxdepth", "4", "-type", "f"},
		{"nginx", "-t"},
		{"apachectl", "configtest"},
		{"systemctl", "reload", "nginx"},
		{"ss", "-ltnp"},
	} {
		if _, err := e.Run(context.Background(), c[0], c[1:]...); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
	}
	var got []string
	for _, c := range f.calls {
		if c.argv[0] == "sudo" {
			got = append(got, strings.Join(c.argv[4:], " "))
		}
	}
	want := "list /etc/ssl/certs|config-test nginx|config-test apache|reload nginx|listeners"
	if strings.Join(got, "|") != want {
		t.Fatalf("got %v", got)
	}
	if _, err := e.Run(context.Background(), "find", "relative"); !errors.Is(err, ErrNotHelperVerb) {
		t.Fatalf("relative find must be refused: %v", err)
	}
}

func TestElevatedOwnershipAndExists(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sudo" && argv[3] == "stat" {
			return []byte("tomcat tomcat 640\n"), nil
		}
		return nil, nil
	}
	e, _ := Wrap(f, Config{Mode: ModeNoPasswd, ElevateExists: true})
	m, err := e.(Statter).StatMeta(context.Background(), "/opt/tomcat/conf/keystore.jks")
	if err != nil || m.Owner != "tomcat" || m.Group != "tomcat" || m.Mode != 0o640 {
		t.Fatalf("%+v %v", m, err)
	}
	if !e.Exists("/root-only/dir/key.pem") {
		t.Fatal("ElevateExists must see files the ssh user cannot traverse")
	}
	if err := e.(OwnedWriter).WriteFileOwned("/opt/tomcat/conf/keystore.jks", []byte("ks"), 0o640, "tomcat", "tomcat"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range f.calls {
		if strings.HasPrefix(strings.Join(c.argv, " "), "sudo -n -- install -m 0640 -o tomcat -g tomcat /tmp/kk-priv-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("calls: %v", f.calls)
	}
	if err := e.(OwnedWriter).WriteFileOwned("/x/y.pem", nil, 0o600, "root;id", "root"); err == nil {
		t.Fatal("unsafe owner accepted")
	}
	// Without ElevateExists the narrow allowlist is left alone (D-114).
	n, _ := Wrap(newFake(), Config{Mode: ModeNoPasswd})
	if n.Exists("/nope") {
		t.Fatal("unexpected")
	}
	if ok, _ := e.(HostBackuper).BackupFile(context.Background(), "/x.pem"); ok {
		t.Fatal("raw modes keep content snapshots")
	}
}

func TestHelperHostBackupAndOwner(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		switch {
		case argv[0] == "sha256sum":
			return []byte(HelperSHA256() + "  h\n"), nil
		case argv[0] == "sudo" && argv[4] == "stat":
			return []byte("regular file|640|tomcat|tomcat|123|/opt/tomcat/conf/keystore.jks\n"), nil
		}
		return nil, nil
	}
	e, _ := Wrap(f, Config{Mode: ModeHelper, HelperSHA: HelperSHA256()})
	hb := e.(HostBackuper)
	if ok, err := hb.BackupFile(context.Background(), "/opt/tomcat/conf/keystore.jks"); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if err := hb.RestoreFile(context.Background(), "/opt/tomcat/conf/keystore.jks"); err != nil {
		t.Fatal(err)
	}
	if err := hb.DropBackup(context.Background(), "/opt/tomcat/conf/keystore.jks"); err != nil {
		t.Fatal(err)
	}
	m, err := e.(Statter).StatMeta(context.Background(), "/opt/tomcat/conf/keystore.jks")
	if err != nil || m.Owner != "tomcat" || m.Mode != 0o640 {
		t.Fatalf("%+v %v", m, err)
	}
	if err := e.(OwnedWriter).WriteFileOwned("/opt/tomcat/conf/keystore.jks", []byte("k"), 0o640, "tomcat", "tomcat"); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	for _, c := range f.calls {
		if c.argv[0] == "sudo" {
			verbs = append(verbs, c.argv[4])
			if c.argv[4] == "install" && c.argv[len(c.argv)-1] != "tomcat:tomcat" {
				t.Errorf("install must pass owner:group: %v", c.argv)
			}
		}
	}
	if strings.Join(verbs, ",") != "backup,restore,discard,stat,install" {
		t.Fatalf("verbs %v", verbs)
	}
}

// W34-20: the helper's refusal for a `list` must not look like file paths to the
// scanner that reads find's output line by line.
func TestHelperListRefusalReadsLikeFind(t *testing.T) {
	sha := HelperSHA256()
	for _, tc := range []struct{ helperSays, want string }{
		{"kryptkeeper-helper: not a directory\n", "find: '/etc/pki/tls/certs': No such file or directory\n"},
		{"kryptkeeper-helper: path denied\n", "find: '/etc/pki/tls/certs': Permission denied (kryptkeeper-helper: path denied)\n"},
	} {
		f := newFake()
		f.respond = func(argv []string, _ []byte) ([]byte, error) {
			if argv[0] == "sha256sum" {
				return []byte(sha + "  " + DefaultHelperPath + "\n"), nil
			}
			return []byte(tc.helperSays), errors.New("exit status 2")
		}
		e, err := Wrap(f, Config{Mode: ModeHelper, HelperSHA: sha})
		if err != nil {
			t.Fatal(err)
		}
		out, err := e.Run(context.Background(), "find", "/etc/pki/tls/certs", "-maxdepth", "4")
		if err == nil || string(out) != tc.want {
			t.Fatalf("out=%q err=%v, want %q", out, err, tc.want)
		}
	}
}

func TestHelperReadFallsBackForPathsOutsideItsCharset(t *testing.T) {
	sha := HelperSHA256()
	f := newFake()
	f.files["/usr/share/ca-certificates/NetLock_Főtanúsítvány.crt"] = []byte("PEM")
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sha256sum" {
			return []byte(sha + "  " + DefaultHelperPath + "\n"), nil
		}
		return []byte("kryptkeeper-helper: unsupported character in path\n"), errors.New("exit status 2")
	}
	e, err := Wrap(f, Config{Mode: ModeHelper, HelperSHA: sha})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := e.ReadFile("/usr/share/ca-certificates/NetLock_Főtanúsítvány.crt"); err != nil || string(b) != "PEM" {
		t.Fatalf("world-readable file with an unusual name: %q %v", b, err)
	}
	// Any other helper refusal stays a refusal: no unprivileged retry hides it.
	f.files["/etc/ssl/x.pem"] = []byte("SECRET")
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sha256sum" {
			return []byte(sha + "  " + DefaultHelperPath + "\n"), nil
		}
		return []byte("kryptkeeper-helper: path denied\n"), errors.New("exit status 2")
	}
	if b, err := e.ReadFile("/etc/ssl/x.pem"); err == nil {
		t.Fatalf("a denied path must stay denied, got %q", b)
	}
}
