// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // test compares against the same lookup-key hash the installer computes
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// iisExecutor is a fake Executor with scripted outputs keyed by exact
// command string, needed to exercise showBinding's `netsh http show sslcert`
// output parsing. fakeExecutor (installer_test.go) only ever returns a fixed
// "ok" response, which can't stand in for that.
//
// WriteFile calls are appended into the SAME ordered `ran` log as Run calls
// (as "WRITE <path>" entries), not just recorded into `files` separately —
// otherwise the ACL-before-write ordering that createLockedStageDir exists to
// guarantee (icacls runs before any key bytes are staged) would be
// unobservable from these tests.
type iisExecutor struct {
	files   map[string][]byte
	outputs map[string][]byte
	failCmd string
	// failCmdAfter lets a test fail a command only on its Nth occurrence,
	// so the ROLLBACK's netsh add can fail while the initial one succeeds.
	failCmdAfter int
	failCmdSeen  int
	// exitErrCmd returns a WinRMExitError (command ran, non-zero exit) —
	// the benign "no binding" shape, distinct from failCmd's transport error.
	exitErrCmd string
	// errCmd fails a command prefix with a SPECIFIC error, so tests can
	// replay verbatim Windows failure text (W18-10) rather than a generic
	// "command failed" that could never exercise error classification.
	errCmd map[string]error
	ran    []string
}

func newIISExecutor() *iisExecutor {
	return &iisExecutor{files: map[string][]byte{}, outputs: map[string][]byte{}, errCmd: map[string]error{}}
}

func (f *iisExecutor) Exists(path string) bool { _, ok := f.files[path]; return ok }

func (f *iisExecutor) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("not found: %s", path)
	}
	return b, nil
}

func (f *iisExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	cp := make([]byte, len(content))
	copy(cp, content)
	f.files[path] = cp
	f.ran = append(f.ran, "WRITE "+path)
	return nil
}

func (f *iisExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, cmd)
	if f.exitErrCmd != "" && strings.HasPrefix(cmd, f.exitErrCmd) {
		return []byte("no binding"), &WinRMExitError{Command: name, Code: 1, Output: "no binding"}
	}
	for prefix, err := range f.errCmd {
		if strings.HasPrefix(cmd, prefix) {
			return []byte(err.Error()), err
		}
	}
	if f.failCmd != "" && strings.HasPrefix(cmd, f.failCmd) {
		f.failCmdSeen++
		if f.failCmdSeen > f.failCmdAfter {
			return []byte("simulated failure: " + cmd), fmt.Errorf("command failed: %s", cmd)
		}
	}
	// Simulate `cmd /C rmdir /S /Q <dir>` actually removing whatever was
	// staged under <dir>, so tests can assert on f.files post-cleanup instead
	// of only on the Run call having been made.
	if name == "cmd" && len(args) >= 2 && args[0] == "/C" && args[1] == "rmdir" {
		dir := args[len(args)-1]
		for path := range f.files {
			if strings.HasPrefix(path, dir) {
				delete(f.files, path)
			}
		}
	}
	if out, ok := f.outputs[cmd]; ok {
		return out, nil
	}
	return []byte("ok"), nil
}

const showSSLCertCmdPrefix = "netsh http show sslcert ipport="

// existingBindingOutput renders a canned `netsh http show sslcert` response
// carrying certHash/appID/storeName, matching the field layout documented
// for that command (label, whitespace, colon, value).
func existingBindingOutput(certHash, appID, storeName string) []byte {
	return []byte(fmt.Sprintf(`SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash              : %s
    Application ID                : %s
    Certificate Store Name        : %s
`, certHash, appID, storeName))
}

func noBindingOutput() []byte {
	return []byte("SSL Certificate bindings:\n-------------------------\n\nNo SSL certificate bindings exist.\n")
}

func countPrefix(ran []string, prefix string) int {
	n := 0
	for _, c := range ran {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// --- key/cert fixtures -------------------------------------------------

func genECKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func genRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func genPKCS8KeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8 key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// genSelfSignedCertPEM returns a self-signed leaf cert (PEM) for the given
// EC private key, plus the raw DER bytes for thumbprint comparison.
func genSelfSignedCertPEM(t *testing.T) (certPEM []byte, certDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "iis-test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func iisReq(t *testing.T) IISInstallRequest {
	certPEM, _ := genSelfSignedCertPEM(t)
	return IISInstallRequest{
		IPPort:  "0.0.0.0:443",
		AppID:   "{4dc3e181-e14b-4a21-b022-59fc669b0914}",
		CertPEM: certPEM,
		KeyPEM:  genECKeyPEM(t),
	}
}

// --- normalizeKeyToPKCS8 / thumbprintSHA1 (pure crypto, no Executor) ----

func TestNormalizeKeyToPKCS8_ECInput(t *testing.T) {
	der, alg, err := normalizeKeyToPKCS8(genECKeyPEM(t))
	if err != nil {
		t.Fatalf("normalize EC key: %v", err)
	}
	if alg != "ECDSA" {
		t.Fatalf("alg = %q, want ECDSA", alg)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("re-parse pkcs8: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("re-parsed key is %T, want *ecdsa.PrivateKey", key)
	}
}

func TestNormalizeKeyToPKCS8_RSAInput(t *testing.T) {
	der, alg, err := normalizeKeyToPKCS8(genRSAKeyPEM(t))
	if err != nil {
		t.Fatalf("normalize RSA key: %v", err)
	}
	if alg != "RSA" {
		t.Fatalf("alg = %q, want RSA", alg)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("re-parse pkcs8: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatalf("re-parsed key is %T, want *rsa.PrivateKey", key)
	}
}

func TestNormalizeKeyToPKCS8_PKCS8Input(t *testing.T) {
	_, alg, err := normalizeKeyToPKCS8(genPKCS8KeyPEM(t))
	if err != nil {
		t.Fatalf("normalize pkcs8 key: %v", err)
	}
	if alg != "ECDSA" {
		t.Fatalf("alg = %q, want ECDSA", alg)
	}
}

func TestNormalizeKeyToPKCS8_RejectsGarbage(t *testing.T) {
	if _, _, err := normalizeKeyToPKCS8([]byte("not a pem block")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestThumbprintSHA1_MatchesRawSHA1OfDER(t *testing.T) {
	_, certDER := genSelfSignedCertPEM(t)
	got := thumbprintSHA1(certDER)
	sum := sha1.Sum(certDER)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	if got != want {
		t.Fatalf("thumbprintSHA1 = %q, want %q", got, want)
	}
	if len(got) != 40 {
		t.Fatalf("thumbprint length = %d, want 40 (SHA-1 hex)", len(got))
	}
}

// --- splitBindingLine ----------------------------------------------------

func TestSplitBindingLine(t *testing.T) {
	cases := []struct {
		line    string
		wantKey string
		wantVal string
		wantOK  bool
	}{
		{"    Certificate Hash              : ABCD1234", "Certificate Hash", "ABCD1234", true},
		{"    IP:port                      : 0.0.0.0:443", "IP", "port                      : 0.0.0.0:443", true},
		{"no colon here", "", "", false},
		{"", "", "", false},
	}
	for i, c := range cases {
		key, val, ok := splitBindingLine(c.line)
		if key != c.wantKey || val != c.wantVal || ok != c.wantOK {
			t.Errorf("case %d: splitBindingLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				i, c.line, key, val, ok, c.wantKey, c.wantVal, c.wantOK)
		}
	}
}

// --- Install: orchestration, using iisExecutor --------------------------

func TestIISInstall_RequiresIPPortCertKey(t *testing.T) {
	f := newIISExecutor()
	_, err := NewIISInstaller(f).Install(context.Background(), IISInstallRequest{})
	if err == nil {
		t.Fatal("expected error with empty request")
	}
	if len(f.ran) != 0 {
		t.Fatalf("expected no commands run on validation failure, got %v", f.ran)
	}
}

func TestIISInstall_MissingAppIDNoPriorErrors(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	req := iisReq(t)
	req.AppID = ""

	_, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when appid is required and no prior binding exists")
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "certutil") || strings.HasPrefix(c, "powershell") ||
			strings.HasPrefix(c, "cmd /C mkdir") || strings.HasPrefix(c, "icacls") || strings.HasPrefix(c, "WRITE") {
			t.Fatalf("cert import must not run before appid validation; ran %v", f.ran)
		}
	}
}

func TestIISInstall_HappyPath_NoPriorBinding(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	req := iisReq(t)

	res, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Installed || !res.Reloaded || res.RolledBack || res.Outcome != OutcomeInstalled {
		t.Fatalf("unexpected result: %+v", res)
	}
	if countPrefix(f.ran, "netsh http delete sslcert") != 0 {
		t.Fatalf("must not delete a binding that never existed; ran %v", f.ran)
	}
	if countPrefix(f.ran, "netsh http add sslcert") != 1 {
		t.Fatalf("expected exactly 1 add sslcert, ran %v", f.ran)
	}
	if countPrefix(f.ran, "certutil") != 1 {
		t.Fatalf("expected exactly 1 certutil import, ran %v", f.ran)
	}
	if countPrefix(f.ran, "iisreset") != 1 {
		t.Fatalf("expected exactly 1 iisreset, ran %v", f.ran)
	}
	if countPrefix(f.ran, "icacls") != 1 {
		t.Fatalf("expected exactly 1 icacls (stage dir lockdown), ran %v", f.ran)
	}
	// order: show -> mkdir stage dir -> lock down its ACL -> stage the PFX
	// (built hub-side; the key never lands on the host in plaintext) ->
	// certutil import -> remove stage dir -> add sslcert -> iisreset. The ACL
	// lockdown (icacls) MUST precede the WRITE: that ordering is exactly what
	// createLockedStageDir exists to guarantee.
	wantOrderPrefixes := []string{
		"netsh http show sslcert", "cmd /C mkdir", "icacls", "WRITE",
		"certutil", "cmd /C rmdir", "netsh http add sslcert", "iisreset",
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "powershell") || strings.HasSuffix(c, "key.der") {
			t.Fatalf("the key must never be staged or merged on the host: %v", f.ran)
		}
	}
	if len(f.ran) < len(wantOrderPrefixes) {
		t.Fatalf("too few commands ran: %v", f.ran)
	}
	for i, want := range wantOrderPrefixes {
		if !strings.HasPrefix(f.ran[i], want) {
			t.Fatalf("command %d = %q, want prefix %q (full sequence: %v)", i, f.ran[i], want, f.ran)
		}
	}
}

func TestIISInstall_HappyPath_ReplacesPriorBinding_InheritsAppID(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput(
		"0000000000000000000000000000000000000000",
		"{11111111-1111-1111-1111-111111111111}",
		"My",
	)
	req := iisReq(t)
	req.AppID = "" // must be inherited from the prior binding

	res, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Outcome != OutcomeInstalled {
		t.Fatalf("unexpected outcome: %+v", res)
	}
	if countPrefix(f.ran, "netsh http delete sslcert") != 1 {
		t.Fatalf("expected exactly 1 delete of the prior binding, ran %v", f.ran)
	}
	found := false
	for _, c := range f.ran {
		if strings.HasPrefix(c, "netsh http add sslcert") && strings.Contains(c, "appid={11111111-1111-1111-1111-111111111111}") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected new binding to inherit prior appid; ran %v", f.ran)
	}
}

func TestIISInstall_CertImportFails_BindingUntouched(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	f.failCmd = "certutil"
	req := iisReq(t)

	res, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when cert import fails")
	}
	if res.Outcome != OutcomeCertImportFailed || res.Installed {
		t.Fatalf("unexpected result: %+v", res)
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "netsh http add sslcert") || strings.HasPrefix(c, "netsh http delete sslcert") {
			t.Fatalf("binding must not change when cert import fails; ran %v", f.ran)
		}
	}
	if countPrefix(f.ran, "iisreset") != 0 {
		t.Fatalf("must not reload when cert import fails; ran %v", f.ran)
	}
}

func TestIISInstall_BindingAddFails_RestoresPriorBinding(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput(
		"1111111111111111111111111111111111111111",
		"{22222222-2222-2222-2222-222222222222}",
		"My",
	)
	f.failCmd = "netsh http add sslcert"
	req := iisReq(t)

	res, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when binding add fails")
	}
	if res.Outcome != OutcomeBindingFailed || !res.RolledBack {
		t.Fatalf("unexpected result: %+v", res)
	}
	if countPrefix(f.ran, "iisreset") != 0 {
		t.Fatalf("must not reload when binding never succeeded; ran %v", f.ran)
	}
	// two add attempts: the failing new-cert add, and the restore-prior add.
	if countPrefix(f.ran, "netsh http add sslcert") != 2 {
		t.Fatalf("expected 2 add attempts (new + restore), ran %v", f.ran)
	}
	restored := false
	for _, c := range f.ran {
		if strings.HasPrefix(c, "netsh http add sslcert") &&
			strings.Contains(c, "certhash=1111111111111111111111111111111111111111") {
			restored = true
		}
	}
	if !restored {
		t.Fatalf("expected the prior binding to be restored; ran %v", f.ran)
	}
}

func TestIISInstall_ReloadFailsRollsBackBinding(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput(
		"2222222222222222222222222222222222222222",
		"{33333333-3333-3333-3333-333333333333}",
		"My",
	)
	f.failCmd = "iisreset"
	req := iisReq(t)

	res, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when reload fails")
	}
	if res.Outcome != OutcomeReloadFailed || !res.RolledBack {
		t.Fatalf("unexpected result: %+v", res)
	}
	if countPrefix(f.ran, "netsh http delete sslcert") != 2 {
		t.Fatalf("expected 2 deletes (install + rollback), ran %v", f.ran)
	}
	if countPrefix(f.ran, "netsh http add sslcert") != 2 {
		t.Fatalf("expected 2 adds (install + rollback restore), ran %v", f.ran)
	}
	if countPrefix(f.ran, "iisreset") != 2 {
		t.Fatalf("expected 2 reload attempts (failing install + post-rollback), ran %v", f.ran)
	}
}

func TestIISInstall_VerifySuccess(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	req := iisReq(t)
	req.VerifyHostPort = "iis-test.example.com:443"
	req.ExpectedFingerprint = "ABCD1234"

	in := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifier(fakeVerifier("abcd1234", nil))
	res, err := in.Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Verified || res.Outcome != OutcomeInstalledVerified {
		t.Fatalf("expected verified outcome, got %+v", res)
	}
}

// TestIISInstall_VerifyMismatchRollsBack proves the rollback-on-mismatch
// path. Red-checked in a scratch copy of this package with the windows build
// tag stripped (the logic here is Executor-only, no Windows syscalls, so it
// runs natively on darwin): removing the restorePriorBinding call on the
// mismatch branch made the delete-count assertion below fail; the call was
// then restored and this test confirmed green again. See the W5-01 commit
// body for the full verification method.
func TestIISInstall_VerifyMismatchRollsBack(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput(
		"3333333333333333333333333333333333333333",
		"{44444444-4444-4444-4444-444444444444}",
		"My",
	)
	req := iisReq(t)
	req.VerifyHostPort = "iis-test.example.com:443"
	req.ExpectedFingerprint = "ABCD1234"

	in := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifier(fakeVerifier("deadbeef", nil))
	res, err := in.Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on fingerprint mismatch")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed {
		t.Fatalf("expected verify_failed rollback, got %+v", res)
	}
	if countPrefix(f.ran, "netsh http delete sslcert") != 2 {
		t.Fatalf("expected 2 deletes (install + rollback), ran %v", f.ran)
	}
	restored := false
	for _, c := range f.ran {
		if strings.HasPrefix(c, "netsh http add sslcert") &&
			strings.Contains(c, "certhash=3333333333333333333333333333333333333333") {
			restored = true
		}
	}
	if !restored {
		t.Fatalf("expected prior binding restored after verify mismatch; ran %v", f.ran)
	}
	if countPrefix(f.ran, "iisreset") != 2 {
		t.Fatalf("expected 2 reloads (install + post-rollback), ran %v", f.ran)
	}
}

func TestIISInstall_VerifyDialErrorRollsBack(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	req := iisReq(t)
	req.VerifyHostPort = "iis-test.example.com:443"
	req.ExpectedFingerprint = "ABCD1234"

	in := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifier(fakeVerifier("", fmt.Errorf("connection refused")))
	res, err := in.Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when verify dial fails")
	}
	if !res.RolledBack || res.Outcome != OutcomeVerifyFailed {
		t.Fatalf("expected verify_failed rollback, got %+v", res)
	}
}

func TestIISInstall_NoVerifyWhenNotRequested(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	in := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifier(fakeVerifier("", fmt.Errorf("should not be called")))

	res, err := in.Install(context.Background(), iisReq(t)) // no VerifyHostPort
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Verified || res.Outcome != OutcomeInstalled {
		t.Fatalf("expected installed (unverified) outcome, got %+v", res)
	}
}

func TestIISInstall_TempFilesCleanedUp(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	if _, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), iisReq(t)); err != nil {
		t.Fatalf("install: %v", err)
	}
	found := false
	for _, c := range f.ran {
		if strings.HasPrefix(c, "cmd /C rmdir /S /Q") && strings.Contains(c, "kk-iis-stage-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the whole per-install stage directory to be removed; ran %v", f.ran)
	}
}

// TestIISInstall_StageDirLockedDownBeforeKeyWritten proves the fix for the
// unencrypted-key-in-a-shared-world-writable-directory finding: the stage
// directory's ACL is locked down (icacls) BEFORE any key bytes are written
// into it, and nothing in the stage tree survives the install. Red-checked
// by reordering createLockedStageDir's call after the WriteFile calls in a
// scratch copy of importCert: the icacls-before-WRITE assertion below went
// RED, confirming it actually observes the ordering; the code was then
// restored and this test confirmed GREEN again.
func TestIISInstall_StageDirLockedDownBeforeKeyWritten(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = noBindingOutput()
	if _, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), iisReq(t)); err != nil {
		t.Fatalf("install: %v", err)
	}

	icaclsIdx, firstWriteIdx := -1, -1
	for i, c := range f.ran {
		if icaclsIdx == -1 && strings.HasPrefix(c, "icacls") {
			icaclsIdx = i
		}
		if firstWriteIdx == -1 && strings.HasPrefix(c, "WRITE") {
			firstWriteIdx = i
		}
	}
	if icaclsIdx == -1 {
		t.Fatalf("expected an icacls call locking down the stage dir; ran %v", f.ran)
	}
	if firstWriteIdx == -1 {
		t.Fatalf("expected staged key/cert WriteFile calls; ran %v", f.ran)
	}
	if icaclsIdx > firstWriteIdx {
		t.Fatalf("icacls (index %d) must run before the first staged file WRITE (index %d); ran %v", icaclsIdx, firstWriteIdx, f.ran)
	}

	for path := range f.files {
		if strings.Contains(path, `C:\fake\tmp`) {
			t.Fatalf("stage file %q was not removed after install", path)
		}
	}
}

// W18-03: the staging paths belong to the TARGET, not the host running
// the hub. filepath.Join uses the host's separator, so joining on a Linux
// hub produced "C:\ProgramData\...\iis-stage/kk-iis-stage-x" — mixed
// separators for a path certutil and `cmd /C rmdir` must parse. This is
// only reachable now that the installer compiles off Windows.
func TestIISStagePathsUseWindowsSeparators(t *testing.T) {
	got := winJoin(`C:\ProgramData\Kryptkeeper\iis-stage`, "kk-iis-stage-abc", "cert.der")
	want := `C:\ProgramData\Kryptkeeper\iis-stage\kk-iis-stage-abc\cert.der`
	if got != want {
		t.Fatalf("remote Windows path built with the host separator:\n got %s\nwant %s", got, want)
	}
	if strings.Contains(got, "/") {
		t.Fatalf("a remote Windows path must not contain a forward slash: %s", got)
	}
	// A trailing separator on the root must not double up.
	if got := winJoin(`C:\temp\`, "x"); got != `C:\temp\x` {
		t.Fatalf("trailing separator not normalised: %s", got)
	}
}

// W18-03: a rollback that FAILED must not be reported as a rollback.
// The host is then serving neither the new certificate nor the old one,
// and "rolled back" would send the operator to look somewhere else. Same
// rule the F5 and K8s pushers were corrected to follow.
func TestIISInstall_RollbackFailureReportedHonestly(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput(
		"3333333333333333333333333333333333333333",
		"{44444444-4444-4444-4444-444444444444}",
		"My",
	)
	// Let the INITIAL binding succeed; fail the rollback's restore.
	f.failCmd = "netsh http add sslcert"
	f.failCmdAfter = 1

	req := iisReq(t)
	req.VerifyHostPort = "iis-test.example.com:443"
	req.ExpectedFingerprint = "ABCD1234"

	in := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifier(fakeVerifier("deadbeef", nil))
	res, err := in.Install(context.Background(), req)
	if err == nil {
		t.Fatal("a verify mismatch must still error")
	}
	if res.RolledBack {
		t.Fatalf("a FAILED restore must not report RolledBack: %+v", res)
	}
	if !strings.Contains(res.Detail, "ROLLBACK FAILED") {
		t.Fatalf("the detail must name the failed rollback: %q", res.Detail)
	}
}

// Regression (found live): showBinding swallowed EVERY error from
// `netsh http show sslcert`, so a WinRM transport/auth failure (a 401)
// was masked as "no binding" and then surfaced as the misleading
// "appid required" — sending operators to chase an appid when discovery
// simply could not authenticate. A transport error (not a WinRMExitError)
// must now surface as a connectivity failure BEFORE the appid check.
func TestIISInstall_TransportErrorSurfacesNotMaskedAsAppID(t *testing.T) {
	f := newIISExecutor()
	f.failCmd = "netsh http show sslcert" // fake returns a PLAIN error (transport-like)
	req := iisReq(t)
	req.AppID = "" // even with no appid, the transport error must win

	_, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected a connectivity error")
	}
	if strings.Contains(err.Error(), "appid required") {
		t.Fatalf("a transport failure must NOT be reported as 'appid required': %v", err)
	}
	if !strings.Contains(err.Error(), "existing binding") {
		t.Fatalf("expected the binding-query connectivity error, got: %v", err)
	}
	// Nothing destructive should have run past the failed pre-check.
	for _, c := range f.ran {
		if strings.HasPrefix(c, "certutil") || strings.HasPrefix(c, "netsh http add") {
			t.Fatalf("no install step may run after a failed connectivity pre-check; ran %v", f.ran)
		}
	}
}

// A netsh non-zero EXIT (the benign "no binding exists" case) IS a
// WinRMExitError and must be treated as "nothing there", so an install with
// an appid supplied still proceeds.
func TestIISInstall_NetshExitErrorIsBenignNoBinding(t *testing.T) {
	f := newIISExecutor()
	f.exitErrCmd = "netsh http show sslcert"
	_, err := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).Install(context.Background(), iisReq(t))
	// A benign no-binding exit must NOT abort at the pre-check — the install
	// proceeds to the cert import (which may then fail on the fake's
	// unconfigured certutil, but that is past the point under test).
	if err != nil && strings.Contains(err.Error(), "existing binding") {
		t.Fatalf("a netsh no-binding exit must be benign, not a connectivity error: %v", err)
	}
	ranCertutil := false
	for _, c := range f.ran {
		if strings.HasPrefix(c, "certutil") {
			ranCertutil = true
		}
	}
	if !ranCertutil {
		t.Fatalf("install should have reached cert import past the benign no-binding check; ran %v", f.ran)
	}
}

// realNetshShowSSLCert is VERBATIM `netsh http show sslcert` output captured
// from the live Windows host on 2026-08-27 (the W18 lab target).
// The hand-written fixture above carries four fields; real output carries
// twenty-plus, including "Extended Properties" blocks whose PropertyId /
// Receive Window lines are shaped exactly like the ones we DO parse. Pinning
// the parser to real output is the difference between "handles our fixture"
// and "handles Windows".
const realNetshShowSSLCert = `
SSL Certificate bindings:
-------------------------



    IP:port                      : 0.0.0.0:443
    Certificate Hash             : 755a28df395e655c07c3af2d866fa2c561c564d3
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : My
    Verify Client Certificate Revocation : Enabled
    Verify Revocation Using Cached Client Certificate Only : Disabled
    Usage Check                  : Enabled
    Revocation Freshness Time    : 0
    URL Retrieval Timeout        : 0
    Ctl Identifier               : (null)
    Ctl Store Name               : (null)
    DS Mapper Usage              : Disabled
    Negotiate Client Certificate : Disabled
    Reject Connections           : Disabled
    Disable HTTP2                : Not Set
    Disable QUIC                 : Not Set
    Disable TLS1.2               : Not Set
    Disable TLS1.3               : Not Set
    Disable OCSP Stapling        : Not Set
    Enable Token Binding         : Not Set
    Log Extended Events          : Not Set
    Disable Legacy TLS Versions  : Not Set
    Enable Session Ticket        : Not Set
    Disable Session ID           : Not Set
    Enable Caching Client Hello  : Not Set
 Extended Properties:
    PropertyId                   : 0
    Receive Window               : 1048576
 Extended Properties:
    PropertyId                   : 1
    Max Settings Per Frame       : 2796202
    Max Settings Per Minute      : 4294967295
 Extended Properties:
    PropertyId                   : 2
 Extended Properties:
    PropertyId                   : 3
 Extended Properties:
    PropertyId                   : 4
 Extended Properties:
    PropertyId                   : 5
`

func TestShowBindingParsesRealWindowsOutput(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = []byte(realNetshShowSSLCert)

	b, err := NewIISInstaller(f).showBinding(context.Background(), "0.0.0.0:443")
	if err != nil {
		t.Fatalf("real netsh output must parse: %v", err)
	}
	if !b.existed {
		t.Fatal("a binding IS present in this output; existed=false would make the installer skip the restore path entirely")
	}
	if want := "755a28df395e655c07c3af2d866fa2c561c564d3"; b.certHash != want {
		t.Errorf("certHash = %q, want %q", b.certHash, want)
	}
	// The appid the W18 'appid required (no prior binding to inherit from)'
	// report claimed was missing. It was here the whole time.
	if want := "{4dc3e181-e14b-4a21-b022-59fc669b0914}"; b.appID != want {
		t.Errorf("appID = %q, want %q", b.appID, want)
	}
	// Case is preserved verbatim: storeName is handed straight back to
	// netsh as certstorename=, so normalizing it here would be a guess.
	// Note the live host reports "My" on :443 and "MY" on its IIS Express
	// ports — Windows itself is not consistent, so we must not be either.
	if want := "My"; b.storeName != want {
		t.Errorf("storeName = %q, want %q (verbatim, not normalized)", b.storeName, want)
	}
}

// W18-10: the non-administrator catch, built from output CAPTURED on the live
// host on 2026-08-27 with a confirmed standard user (whoami /groups showed no
// S-1-5-32-544), not from reconstructed message text.
//
// The capture established the asymmetry the product has to honour: reads
// SUCCEED for a standard user (Cert:\LocalMachine\My enumerated, and
// `netsh http show sslcert` returned the full binding) and only WRITES fail.
const (
	// Verbatim from the capture.
	realNetshElevationErr = "SSL Certificate add failed, Error: 5\nThe requested operation requires elevation (Run as administrator)."
	// certutil's shape. The install path reaches THIS before any netsh call,
	// because importCert precedes setBinding.
	realCertutilElevationErr = "CertUtil: -importPFX command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)"
)

func TestNonAdminFailsAtCertImportNotBinding(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput("1111111111111111111111111111111111111111", "{22222222-2222-2222-2222-222222222222}", "My")
	f.errCmd["certutil"] = errors.New(realCertutilElevationErr)

	res, err := NewIISInstaller(f).Install(context.Background(), iisReq(t))
	if err == nil {
		t.Fatal("a non-admin install must fail")
	}
	if res.Outcome != OutcomeCertImportFailed {
		t.Errorf("outcome = %v, want %v: importCert precedes setBinding, so a non-admin never reaches netsh at all", res.Outcome, OutcomeCertImportFailed)
	}
	// The netsh WRITE must never have been attempted.
	if countPrefix(f.ran, "netsh http add sslcert") != 0 {
		t.Error("install must not reach netsh add when the store write already failed")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not a local Administrator") {
		t.Errorf("error must name the real cause, got: %s", msg)
	}
	// The operator must not be sent after a password that is already correct.
	if !strings.Contains(msg, "DISCOVERY") {
		t.Errorf("error must say discovery still works with this credential, got: %s", msg)
	}
}

// The inversion this fixes: delete and add BOTH fail for a non-admin, so the
// binding is untouched — but the old code ran a restore anyway and reported
// its failure, which by restorePriorBinding's contract means "the host is
// serving nothing". It said the endpoint was broken when nothing had happened.
func TestNonAdminBindingFailureDoesNotClaimAPhantomRollback(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput("1111111111111111111111111111111111111111", "{22222222-2222-2222-2222-222222222222}", "My")
	elevErr := errors.New(realNetshElevationErr)
	f.errCmd["netsh http add sslcert"] = elevErr
	f.errCmd["netsh http delete sslcert"] = elevErr

	res, err := NewIISInstaller(f).Install(context.Background(), iisReq(t))
	if err == nil {
		t.Fatal("the install must fail")
	}
	if res.RolledBack {
		t.Error("RolledBack must be false: the delete failed, so nothing was ever removed")
	}
	if strings.Contains(err.Error(), "restore prior sslcert binding") {
		t.Errorf("must NOT report a restore failure — the prior binding is still serving, untouched. Got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "not a local Administrator") {
		t.Errorf("error must name elevation as the cause, got: %s", err.Error())
	}
}

// Red-check the locale trap: the numeric Win32 code is the anchor, because
// the English sentence is translated on non-English Windows.
func TestElevationDetectedByNumericCodeNotEnglishProse(t *testing.T) {
	// A German host: prose translated, numeric code identical.
	localized := errors.New("Fehler beim Hinzufuegen des SSL-Zertifikats, Error: 5\nFuer den Vorgang ist eine Erhoehung erforderlich.")
	if !elevationRequired(localized) {
		t.Error("a localized elevation failure must still be detected — the numeric code is the contract, not the sentence")
	}
	for _, e := range []error{
		errors.New(realNetshElevationErr),
		errors.New(realCertutilElevationErr),
	} {
		if !elevationRequired(e) {
			t.Errorf("real captured output must be detected: %v", e)
		}
	}
	if elevationRequired(errors.New("The system cannot find the file specified.")) {
		t.Error("an unrelated failure must not be reported as an elevation problem")
	}
	if elevationRequired(nil) {
		t.Error("nil is not an elevation failure")
	}
}

// Values read back from the host become netsh arguments (the inherited appid,
// the rollback restore), so a malformed one is refused before anything on the
// host changes, like a malformed request field.
func TestIISInstallRefusesMalformedPriorBinding(t *testing.T) {
	cases := map[string][]byte{
		"appid": existingBindingOutput("1111111111111111111111111111111111111111", `{x}" & calc & "`, "My"),
		"hash":  existingBindingOutput("abc&calc", "{22222222-2222-2222-2222-222222222222}", "My"),
		"store": existingBindingOutput("1111111111111111111111111111111111111111", "{22222222-2222-2222-2222-222222222222}", "My&calc"),
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			f := newIISExecutor()
			f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = out
			_, err := NewIISInstaller(f).Install(context.Background(), iisReq(t))
			if err == nil || !strings.Contains(err.Error(), "existing binding at 0.0.0.0:443") {
				t.Fatalf("Install = %v, want a refusal naming the existing binding", err)
			}
			for _, c := range f.ran {
				if !strings.HasPrefix(c, showSSLCertCmdPrefix) {
					t.Fatalf("ran %q after a malformed prior binding; only the show may run", c)
				}
			}
		})
	}
}
