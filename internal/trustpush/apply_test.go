// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package trustpush

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type call struct {
	stdin string
	argv  string
}

var stagedDirRE = regexp.MustCompile(`kryptkeeper-trust-[0-9]+/`)

type fakeRunner struct {
	calls []call
	fail  map[string]error  // substring of argv -> error
	out   map[string]string // substring of argv -> output
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	argv := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, call{string(stdin), argv})
	for k, e := range f.fail {
		if strings.Contains(argv, k) {
			return []byte("boom"), e
		}
	}
	for k, o := range f.out {
		if strings.Contains(argv, k) {
			return []byte(o), nil
		}
	}
	return nil, nil
}

func (f *fakeRunner) argvs() []string {
	var out []string
	for _, c := range f.calls {
		// writeTemp stages into a random private dir; normalise to the flat name.
		out = append(out, stagedDirRE.ReplaceAllString(c.argv, "kryptkeeper-trust-"))
	}
	return out
}

func mkCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fp(c *x509.Certificate) string { return mustCA(c).SHA256 }

func mustCA(c *x509.Certificate) CA {
	cas, err := ParseCAs(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})), time.Now(), false)
	if err != nil {
		panic(err)
	}
	return cas[0]
}

func linuxApplier(t *testing.T, osRelease string, r Runner) *Applier {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	return &Applier{GOOS: "linux", Root: root, StatePath: filepath.Join(root, "state.json"), TempDir: root, Runner: r}
}

func TestParseCAsRefusals(t *testing.T) {
	root, rootKey, rootPEM := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	_, _, leafPEM := mkCert(t, "leaf", false, root, rootKey, time.Now().Add(time.Hour))
	_, _, expiredPEM := mkCert(t, "Old", true, nil, nil, time.Now().Add(-time.Minute))
	keyDER, _ := x509.MarshalECPrivateKey(rootKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	if _, err := ParseCAs(rootPEM, time.Now(), true); err != nil {
		t.Fatalf("a valid CA must pass: %v", err)
	}
	if _, err := ParseCAs(leafPEM, time.Now(), true); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("a leaf must be refused as a non-CA, got %v", err)
	}
	if _, err := ParseCAs(expiredPEM, time.Now(), true); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired CA must be refused for add, got %v", err)
	}
	if _, err := ParseCAs(expiredPEM, time.Now(), false); err != nil {
		t.Fatalf("an expired CA may be named for removal: %v", err)
	}
	_, err := ParseCAs(rootPEM+keyPEM, time.Now(), true)
	if err == nil || !strings.Contains(err.Error(), "only CERTIFICATE") {
		t.Fatalf("a key block must reject the whole bundle, got %v", err)
	}
	if strings.Contains(err.Error(), keyPEM[40:80]) {
		t.Fatal("the error must never echo key bytes")
	}
	if _, err := ParseCAs("garbage", time.Now(), true); err == nil {
		t.Fatal("garbage must be refused")
	}
}

func TestLinuxDebianAddRemoveExactCommands(t *testing.T) {
	c, _, p := mkCert(t, "Corp Root", true, nil, nil, time.Now().Add(time.Hour))
	r := &fakeRunner{}
	a := linuxApplier(t, "ID=ubuntu\nID_LIKE=debian\n", r)

	res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: p})
	if res.Outcome != OutcomeApplied {
		t.Fatalf("add: %+v", res)
	}
	file := filepath.Join(a.Root, "/usr/local/share/ca-certificates", "kryptkeeper-"+fp(c)+".crt")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("anchor file missing: %v", err)
	}
	if got := r.argvs(); len(got) != 1 || got[0] != "/usr/sbin/update-ca-certificates" {
		t.Fatalf("add commands = %v", got)
	}

	// A second add changes nothing and runs nothing.
	r.calls = nil
	if res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: p}); res.Outcome != OutcomeApplied || len(r.calls) != 0 {
		t.Fatalf("idempotent add: %+v %v", res, r.argvs())
	}

	res = a.ApplyLocal(context.Background(), Request{Action: ActionRemove, CertPEM: p})
	if res.Outcome != OutcomeApplied {
		t.Fatalf("remove: %+v", res)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("anchor file should be gone")
	}
	if got := r.argvs(); len(got) != 1 || got[0] != "/usr/sbin/update-ca-certificates --fresh" {
		t.Fatalf("remove commands = %v", got)
	}
}

func TestLinuxRHELCommands(t *testing.T) {
	c, _, p := mkCert(t, "Corp Root", true, nil, nil, time.Now().Add(time.Hour))
	r := &fakeRunner{}
	a := linuxApplier(t, "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", r)
	if res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: p}); res.Outcome != OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(a.Root, "/etc/pki/ca-trust/source/anchors", "kryptkeeper-"+fp(c)+".crt")); err != nil {
		t.Fatal(err)
	}
	a.ApplyLocal(context.Background(), Request{Action: ActionRemove, CertPEM: p})
	for _, got := range r.argvs() {
		if got != "/usr/bin/update-ca-trust extract" {
			t.Fatalf("command = %q", got)
		}
	}
	if len(r.calls) != 2 {
		t.Fatalf("want add+remove runs, got %v", r.argvs())
	}
}

func TestLinuxRemoveLeavesCertificatesItDidNotAdd(t *testing.T) {
	_, _, p := mkCert(t, "Hand installed", true, nil, nil, time.Now().Add(time.Hour))
	r := &fakeRunner{}
	a := linuxApplier(t, "ID=debian\n", r)
	res := a.ApplyLocal(context.Background(), Request{Action: ActionRemove, CertPEM: p})
	if res.Outcome != OutcomeApplied || !strings.Contains(res.Detail, "not added by Kryptkeeper") {
		t.Fatalf("%+v", res)
	}
	if len(r.calls) != 0 {
		t.Fatalf("nothing owned, so nothing may run: %v", r.argvs())
	}
}

func TestLinuxUpdateFailureRollsBack(t *testing.T) {
	c, _, p := mkCert(t, "Corp Root", true, nil, nil, time.Now().Add(time.Hour))
	r := &fakeRunner{fail: map[string]error{"update-ca-certificates": errors.New("exit 1")}}
	a := linuxApplier(t, "ID=debian\n", r)
	res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: p})
	if res.Outcome != OutcomeFailed || !strings.Contains(res.Detail, "update-ca-certificates") {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(a.Root, "/usr/local/share/ca-certificates", "kryptkeeper-"+fp(c)+".crt")); !os.IsNotExist(err) {
		t.Fatal("a failed update must not leave the anchor behind")
	}
	if st, _ := loadState(a.StatePath); len(st.Certs) != 0 {
		t.Fatal("a failed apply must not be recorded as ours")
	}
}

func TestLinuxUnsupportedDistro(t *testing.T) {
	_, _, p := mkCert(t, "R", true, nil, nil, time.Now().Add(time.Hour))
	a := linuxApplier(t, "ID=arch\n", &fakeRunner{})
	if res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: p}); res.Outcome != OutcomeFailed || !strings.Contains(res.Detail, "unsupported") {
		t.Fatalf("%+v", res)
	}
}

func TestWindowsRootAndIntermediate(t *testing.T) {
	root, rootKey, rootPEM := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	inter, _, interPEM := mkCert(t, "Inter", true, root, rootKey, time.Now().Add(time.Hour))
	dir := t.TempDir()
	r := &fakeRunner{fail: map[string]error{"-store ": errors.New("not found")}}
	a := &Applier{GOOS: "windows", StatePath: filepath.Join(dir, "s.json"), TempDir: dir, Runner: r}

	if res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: rootPEM + interPEM}); res.Outcome != OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	rootFile := filepath.Join(dir, "kryptkeeper-trust-"+fp(root)+".pem")
	interFile := filepath.Join(dir, "kryptkeeper-trust-"+fp(inter)+".pem")
	want := []string{
		"certutil -store Root " + mustCA(root).SHA1,
		"certutil -addstore -f Root " + rootFile,
		"certutil -store CA " + mustCA(inter).SHA1,
		"certutil -addstore -f CA " + interFile,
	}
	if got := r.argvs(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands\n got %v\nwant %v", got, want)
	}
	if _, err := os.Stat(rootFile); !os.IsNotExist(err) {
		t.Fatal("the staged certificate file must be removed")
	}

	r.calls = nil
	if res := a.ApplyLocal(context.Background(), Request{Action: ActionRemove, CertPEM: rootPEM + interPEM}); res.Outcome != OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	want = []string{"certutil -delstore Root " + mustCA(root).SHA1, "certutil -delstore CA " + mustCA(inter).SHA1}
	if got := r.argvs(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("remove commands\n got %v\nwant %v", got, want)
	}
}

func TestWindowsPreexistingRootIsNotOwned(t *testing.T) {
	root, _, rootPEM := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	dir := t.TempDir()
	r := &fakeRunner{} // the -store probe succeeds: already trusted
	a := &Applier{GOOS: "windows", StatePath: filepath.Join(dir, "s.json"), TempDir: dir, Runner: r}
	a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: rootPEM})
	r.calls = nil
	a.ApplyLocal(context.Background(), Request{Action: ActionRemove, CertPEM: rootPEM})
	if len(r.calls) != 0 {
		t.Fatalf("a root we never added must not be deleted: %v (fp %s)", r.argvs(), fp(root))
	}
}

func TestDarwinRootAndIntermediate(t *testing.T) {
	root, rootKey, rootPEM := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	inter, _, interPEM := mkCert(t, "Inter", true, root, rootKey, time.Now().Add(time.Hour))
	dir := t.TempDir()
	r := &fakeRunner{out: map[string]string{"find-certificate": "SHA-1 hash: 0000"}}
	a := &Applier{GOOS: "darwin", StatePath: filepath.Join(dir, "s.json"), TempDir: dir, Runner: r}
	if res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: rootPEM + interPEM}); res.Outcome != OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	kc := "/Library/Keychains/System.keychain"
	want := []string{
		"/usr/bin/security find-certificate -a -Z " + kc,
		"/usr/bin/security add-trusted-cert -d -r trustRoot -k " + kc + " " + filepath.Join(dir, "kryptkeeper-trust-"+fp(root)+".pem"),
		"/usr/bin/security add-certificates -k " + kc + " " + filepath.Join(dir, "kryptkeeper-trust-"+fp(inter)+".pem"),
	}
	if got := r.argvs(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands\n got %v\nwant %v", got, want)
	}
	r.calls = nil
	a.ApplyLocal(context.Background(), Request{Action: ActionRemove, CertPEM: rootPEM + interPEM})
	want = []string{
		"/usr/bin/security remove-trusted-cert -d " + filepath.Join(dir, "kryptkeeper-trust-"+fp(root)+".pem"),
		"/usr/bin/security delete-certificate -Z " + mustCA(root).SHA1 + " " + kc,
		"/usr/bin/security delete-certificate -Z " + mustCA(inter).SHA1 + " " + kc,
	}
	if got := r.argvs(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("remove commands\n got %v\nwant %v", got, want)
	}
}

func TestDarwinSkipsCertificateAlreadyInKeychain(t *testing.T) {
	root, _, rootPEM := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	dir := t.TempDir()
	r := &fakeRunner{out: map[string]string{"find-certificate": "SHA-1 hash: " + strings.ToLower(mustCA(root).SHA1)}}
	a := &Applier{GOOS: "darwin", StatePath: filepath.Join(dir, "s.json"), TempDir: dir, Runner: r}
	a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: rootPEM})
	if len(r.calls) != 1 {
		t.Fatalf("only the probe may run: %v", r.argvs())
	}
}

func TestDispatchUsesTheOneSudoRule(t *testing.T) {
	_, _, p := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	reply, _ := json.Marshal(Result{Outcome: OutcomeApplied, Detail: "added 1 certificate(s)"})
	r := &fakeRunner{out: map[string]string{"sudo": string(reply)}}
	a := &Applier{GOOS: "linux", Runner: r}
	res := a.Dispatch(context.Background(), Request{Action: ActionAdd, CertPEM: p})
	if res.Outcome != OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	if got := r.argvs(); len(got) != 1 || got[0] != "sudo -n /usr/local/bin/kryptkeeper-agent --trust-store-apply" {
		t.Fatalf("dispatch command = %v", got)
	}
	var sent Request
	if err := json.Unmarshal([]byte(r.calls[0].stdin), &sent); err != nil || sent.Action != ActionAdd || sent.CertPEM != p {
		t.Fatalf("the request travels on stdin, never argv: %v %+v", err, sent)
	}

	r2 := &fakeRunner{fail: map[string]error{"sudo": errors.New("a password is required")}}
	a2 := &Applier{GOOS: "linux", Runner: r2}
	if res := a2.Dispatch(context.Background(), Request{Action: ActionAdd, CertPEM: p}); res.Outcome != OutcomeFailed || !strings.Contains(res.Detail, "privileged helper failed") {
		t.Fatalf("%+v", res)
	}
}

func TestHelperRevalidatesWhatItIsGiven(t *testing.T) {
	root, rootKey, _ := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	_, _, leafPEM := mkCert(t, "leaf", false, root, rootKey, time.Now().Add(time.Hour))
	a := linuxApplier(t, "ID=debian\n", &fakeRunner{})
	res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: leafPEM})
	if res.Outcome != OutcomeFailed || !strings.Contains(res.Detail, "not a CA") {
		t.Fatalf("the root side must not trust the agent's validation: %+v", res)
	}
}

func TestWriteTempIgnoresPlantedSymlinkAndCleansUp(t *testing.T) {
	root, _, rootPEM := mkCert(t, "Root", true, nil, nil, time.Now().Add(time.Hour))
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The old predictable names, pre-planted as symlinks.
	for _, n := range []string{"kryptkeeper-trust-" + fp(root) + ".pem", "kryptkeeper-trust-" + fp(root)} {
		if err := os.Symlink(victim, filepath.Join(dir, n)); err != nil {
			t.Skip("symlinks unavailable:", err)
		}
	}
	r := &fakeRunner{fail: map[string]error{"-store ": errors.New("not found")}}
	a := &Applier{GOOS: "windows", StatePath: filepath.Join(dir, "s.json"), TempDir: dir, Runner: r}
	if res := a.ApplyLocal(context.Background(), Request{Action: ActionAdd, CertPEM: rootPEM}); res.Outcome != OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("planted symlink target was written through")
	}
	ents, _ := filepath.Glob(filepath.Join(dir, "kryptkeeper-trust-*"))
	if len(ents) != 2 {
		t.Fatalf("staging dir not cleaned up: %v", ents)
	}
	p, err := a.writeTemp(mustCA(root))
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("staging dir mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("staged file mode %v", fi.Mode().Perm())
	}
}

func TestStateSaveRefusesSymlinks(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o600)

	// symlink at the old fixed .tmp name is not followed
	dir := filepath.Join(base, "state")
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "s.json")
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	st := &state{Certs: map[string]entry{"ab": {SHA1: "x"}}}
	if err := st.save(path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("symlinked .tmp was written through")
	}
	if _, err := loadState(path); err != nil {
		t.Fatal(err)
	}

	// symlinked state dir is refused
	link := filepath.Join(base, "link")
	_ = os.Symlink(dir, link)
	if err := st.save(filepath.Join(link, "s.json")); err == nil {
		t.Fatal("expected refusal for symlinked state dir")
	}
}
