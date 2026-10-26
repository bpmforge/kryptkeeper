// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
)

// exchangeFake is an Executor that records every command (powershell argv kept
// whole, so tests can assert the exact script and arguments sent) and answers
// the Exchange scripts from a scripted prior state.
type exchangeFake struct {
	ran      [][]string // name + args per Run
	order    []string   // coarse log: "WRITE", "certutil", "prior", "enable:<tp>:<svcs>", "iisreset", ...
	prior    string     // stdout of exchangePriorScript
	enableFn func(thumbprint, services string) error
	certutil error
}

func (f *exchangeFake) Exists(string) bool              { return false }
func (f *exchangeFake) ReadFile(string) ([]byte, error) { return nil, os.ErrNotExist }
func (f *exchangeFake) WriteFile(string, []byte, os.FileMode) error {
	f.order = append(f.order, "WRITE")
	return nil
}

func (f *exchangeFake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.ran = append(f.ran, append([]string{name}, args...))
	switch name {
	case "powershell":
		script := args[3]
		switch script {
		case exchangePriorScript:
			f.order = append(f.order, "prior")
			return []byte(f.prior), nil
		case exchangeEnableScript:
			f.order = append(f.order, "enable:"+args[4]+":"+args[5])
			if f.enableFn != nil {
				if err := f.enableFn(args[4], args[5]); err != nil {
					return []byte(err.Error()), err
				}
			}
			return nil, nil
		}
		return nil, errors.New("unexpected powershell script")
	case "certutil":
		f.order = append(f.order, "certutil")
		if f.certutil != nil {
			return []byte(f.certutil.Error()), f.certutil
		}
	case "iisreset":
		f.order = append(f.order, "iisreset")
	}
	return []byte("ok"), nil
}

const (
	oldIIS  = "1111111111111111111111111111111111111111"
	oldSMTP = "2222222222222222222222222222222222222222"
)

func priorBoth() string {
	return "KKPRIOR:IIS:" + oldIIS + "\r\nKKPRIOR:SMTP:" + oldSMTP + "\r\n"
}

func exchangeReq(t *testing.T) (ExchangeInstallRequest, string, string) {
	t.Helper()
	certPEM, der := genSelfSignedCertPEM(t)
	return ExchangeInstallRequest{
		CertPEM: certPEM, KeyPEM: genECKeyPEM(t),
		VerifyHostPort:      "mail.example.com:443",
		SMTPVerifyHostPorts: []string{"mail.example.com:25", "mail.example.com:587"},
		ExpectedFingerprint: FingerprintSHA256(der),
	}, thumbprintSHA1(der), FingerprintSHA256(der)
}

func constVerifier(fp string, err error) Verifier {
	return func(context.Context, string) (string, error) { return fp, err }
}

func newExchange(f *exchangeFake, https, smtp Verifier) *ExchangeInstaller {
	return NewExchangeInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifiers(https, smtp)
}

func TestExchangeInstall_HappyPath_ExactPowerShell(t *testing.T) {
	f := &exchangeFake{prior: priorBoth()}
	req, tp, fp := exchangeReq(t)

	res, err := newExchange(f, constVerifier(fp, nil), constVerifier(fp, nil)).Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Installed || !res.Verified || res.RolledBack || res.Outcome != OutcomeInstalledVerified {
		t.Fatalf("unexpected result: %+v", res)
	}
	want := []string{"prior", "WRITE", "certutil", "enable:" + tp + ":IIS,SMTP", "iisreset"}
	if strings.Join(f.order, " ") != strings.Join(want, " ") {
		t.Fatalf("order = %v, want %v", f.order, want)
	}
	// The exact argv of the enable call: thumbprint and services travel as
	// $args, never spliced into the script text.
	seen := false
	for _, r := range f.ran {
		if r[0] != "powershell" || r[4] != exchangeEnableScript {
			continue
		}
		seen = true
		if len(r) != 7 || r[1] != "-NoProfile" || r[2] != "-NonInteractive" || r[3] != "-Command" || r[5] != tp || r[6] != "IIS,SMTP" {
			t.Fatalf("enable argv = %q", r)
		}
	}
	if !seen {
		t.Fatal("enable was never sent")
	}
	for _, needle := range []string{"Enable-ExchangeCertificate -Thumbprint $args[0] -Services $svc -Force -DoNotRequireSsl", "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn"} {
		if !strings.Contains(exchangeEnableScript, needle) {
			t.Errorf("enable script lacks %q", needle)
		}
	}
	if strings.Contains(exchangeEnableScript+exchangePriorScript, tp) {
		t.Error("scripts must be constant text")
	}
}

func TestExchangeInstall_PFXPasswordNeverEscapesTheImportCall(t *testing.T) {
	f := &exchangeFake{prior: priorBoth()}
	req, _, fp := exchangeReq(t)
	if _, err := newExchange(f, constVerifier(fp, nil), constVerifier(fp, nil)).Install(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var pw string
	for _, r := range f.ran {
		if r[0] == "certutil" {
			for i, a := range r {
				if a == "-p" {
					pw = r[i+1]
				}
			}
		}
	}
	if len(pw) < 16 {
		t.Fatalf("expected a random one-time password on the certutil call, got %q", pw)
	}
	for _, r := range f.ran {
		if r[0] != "certutil" && strings.Contains(strings.Join(r, " "), pw) {
			t.Fatalf("password leaked into %q", r[0])
		}
	}
}

func TestExchangeInstall_HTTPSMismatchRollsBackToPriorThumbprints(t *testing.T) {
	f := &exchangeFake{prior: priorBoth()}
	req, tp, _ := exchangeReq(t)

	res, err := newExchange(f, constVerifier("deadbeef", nil), constVerifier("deadbeef", nil)).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack || res.Verified {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	// IIS and SMTP had different certificates, so each is restored separately.
	want := []string{"prior", "WRITE", "certutil", "enable:" + tp + ":IIS,SMTP", "iisreset",
		"enable:" + oldIIS + ":IIS", "enable:" + oldSMTP + ":SMTP", "iisreset"}
	if strings.Join(f.order, " ") != strings.Join(want, " ") {
		t.Fatalf("order = %v\nwant    %v", f.order, want)
	}
	for _, r := range f.ran {
		j := strings.Join(r, " ")
		if strings.Contains(j, "Remove-ExchangeCertificate") || strings.Contains(j, "-delstore") {
			t.Fatalf("the previous certificate must never be deleted: %q", j)
		}
	}
}

func TestExchangeInstall_SMTPServingOldLeafRollsBack(t *testing.T) {
	f := &exchangeFake{prior: priorBoth()}
	req, _, fp := exchangeReq(t)
	res, err := newExchange(f, constVerifier(fp, nil), constVerifier("0ld", nil)).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack || !strings.Contains(res.Detail, "smtp starttls") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestExchangeInstall_UnreachableSubmissionPortIsSkippedButOneMustAnswer(t *testing.T) {
	req, _, fp := exchangeReq(t)
	smtp := func(_ context.Context, hp string) (string, error) {
		if strings.HasSuffix(hp, ":587") {
			return "", errSMTPUnreachable
		}
		return fp, nil
	}
	f := &exchangeFake{prior: priorBoth()}
	if res, err := newExchange(f, constVerifier(fp, nil), smtp).Install(context.Background(), req); err != nil || !res.Verified {
		t.Fatalf("587 closed must not fail the install: %+v %v", res, err)
	}

	f = &exchangeFake{prior: priorBoth()}
	res, err := newExchange(f, constVerifier(fp, nil), constVerifier("", errSMTPUnreachable)).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("no answering SMTP port must fail and roll back: %+v %v", res, err)
	}
}

func TestExchangeInstall_NoPriorCertificateDoesNotClaimRollback(t *testing.T) {
	f := &exchangeFake{prior: "KKPRIOR:IIS:\r\nKKPRIOR:SMTP:\r\n"}
	req, _, _ := exchangeReq(t)
	res, err := newExchange(f, constVerifier("x", nil), constVerifier("x", nil)).Install(context.Background(), req)
	if err == nil || res.RolledBack || !strings.Contains(res.Detail, "nothing was restored") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestExchangeInstall_AccessDeniedAtImportNeverEnables(t *testing.T) {
	f := &exchangeFake{prior: priorBoth(), certutil: errors.New(realCertutilElevationErr)}
	req, _, _ := exchangeReq(t)
	res, err := newExchange(f, nil, nil).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeCertImportFailed || res.Installed || res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	for _, o := range f.order {
		if strings.HasPrefix(o, "enable:") {
			t.Fatal("must not enable a certificate that was never imported")
		}
	}
	if !strings.Contains(err.Error(), "not a local Administrator") {
		t.Fatalf("error must name the cause: %v", err)
	}
}

func TestExchangeInstall_EnableDeniedRestoresAndExplainsRole(t *testing.T) {
	f := &exchangeFake{prior: priorBoth()}
	req, tp, _ := exchangeReq(t)
	f.enableFn = func(thumb, _ string) error {
		if thumb == tp {
			return errors.New("CategoryInfo : ObjectNotFound: (Enable-ExchangeCertificate:String) [], CommandNotFoundException")
		}
		return nil
	}
	res, err := newExchange(f, nil, nil).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeBindingFailed || !res.Installed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !strings.Contains(err.Error(), "Organization Management or Server Management") {
		t.Fatalf("error must name the role: %v", err)
	}
}

func TestExchangeInstall_RollbackFailureReportedHonestly(t *testing.T) {
	f := &exchangeFake{prior: priorBoth()}
	req, tp, _ := exchangeReq(t)
	f.enableFn = func(thumb, _ string) error {
		if thumb != tp {
			return errors.New("restore failed")
		}
		return nil
	}
	res, err := newExchange(f, constVerifier("bad", nil), constVerifier("bad", nil)).Install(context.Background(), req)
	if err == nil || res.RolledBack || !strings.Contains(res.Detail, "ROLLBACK FAILED") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestExchangeInstall_RefusesBadInputBeforeTouchingTheHost(t *testing.T) {
	req, _, _ := exchangeReq(t)
	req.Services = []string{"IIS;calc"}
	f := &exchangeFake{prior: priorBoth()}
	if _, err := newExchange(f, nil, nil).Install(context.Background(), req); err == nil || len(f.ran) != 0 {
		t.Fatalf("injection-shaped service must be refused with no host contact: %v ran=%v", err, f.ran)
	}

	req.Services = nil
	f = &exchangeFake{prior: "KKPRIOR:IIS:abc'; calc\r\n"}
	if _, err := newExchange(f, nil, nil).Install(context.Background(), req); err == nil || countCmd(f, "certutil") != 0 {
		t.Fatalf("malformed prior thumbprint must stop before import: %v", err)
	}
}

func countCmd(f *exchangeFake, name string) int {
	n := 0
	for _, r := range f.ran {
		if r[0] == name {
			n++
		}
	}
	return n
}

func TestNormalizeExchangeServices(t *testing.T) {
	got, err := NormalizeExchangeServices([]string{" smtp", "iis", "SMTP"})
	if err != nil || strings.Join(got, ",") != "IIS,SMTP" {
		t.Fatalf("got %v %v", got, err)
	}
	if d, _ := NormalizeExchangeServices(nil); strings.Join(d, ",") != "IIS,SMTP" {
		t.Fatalf("default = %v", d)
	}
	for _, bad := range []string{"UM", "Federation", ""} {
		if _, err := NormalizeExchangeServices([]string{bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestExchangeInstall_IISOnlySkipsSMTPProbeAndSMTPOnlySkipsReset(t *testing.T) {
	req, _, fp := exchangeReq(t)
	req.Services = []string{"SMTP"}
	f := &exchangeFake{prior: "KKPRIOR:SMTP:" + oldSMTP + "\r\n"}
	httpsCalled := false
	https := func(context.Context, string) (string, error) { httpsCalled = true; return fp, nil }
	if _, err := newExchange(f, https, constVerifier(fp, nil)).Install(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if httpsCalled || countCmd(f, "iisreset") != 0 {
		t.Fatalf("SMTP-only install must not probe HTTPS or reset IIS (https=%v)", httpsCalled)
	}
}

// --- SMTP STARTTLS verifier against a fake server ------------------------

func startFakeSMTP(t *testing.T, starttls bool) (hostPort, fp string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "smtp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tp := textproto.NewConn(c)
		_ = tp.PrintfLine("220 mail.test ESMTP")
		_, _ = tp.ReadLine() // EHLO
		_ = tp.PrintfLine("250 mail.test")
		_, _ = tp.ReadLine() // STARTTLS
		if !starttls {
			_ = tp.PrintfLine("502 not offered")
			return
		}
		_ = tp.PrintfLine("220 go ahead")
		s := tls.Server(c, cfg)
		_ = s.Handshake()
	}()
	return ln.Addr().String(), FingerprintSHA256(der)
}

func TestSMTPVerifier_ReturnsServedLeafAndClassifiesFailures(t *testing.T) {
	v := smtpVerifierWithPolicy(egress.Policy{AllowPrivate: true, AllowLoopback: true})
	hp, want := startFakeSMTP(t, true)
	got, err := v(context.Background(), hp)
	if err != nil || got != want {
		t.Fatalf("got %q %v, want %q", got, err, want)
	}

	hp, _ = startFakeSMTP(t, false)
	if _, err := v(context.Background(), hp); err == nil || errors.Is(err, errSMTPUnreachable) {
		t.Fatalf("a refused STARTTLS is a verify failure, not an unreachable port: %v", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if _, err := v(context.Background(), closed); !errors.Is(err, errSMTPUnreachable) {
		t.Fatalf("closed port must be errSMTPUnreachable, got %v", err)
	}
}
