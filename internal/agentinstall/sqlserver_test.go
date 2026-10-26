// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	sqlTestInstanceOut = "ID=MSSQL16.MSSQLSERVER\r\nSERVICE=MSSQLSERVER\r\nACCOUNT=NT Service\\MSSQLSERVER\r\n"
	sqlTestRegPath     = `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib`
	sqlPriorThumb      = "aabbccddeeff00112233445566778899aabbccdd"
)

// sqlFixture wires a fake host with a resolvable default instance and returns
// the request plus the SHA-1 thumbprint the import step must report.
func sqlFixture(t *testing.T) (*winFake, SQLServerInstallRequest, string, string) {
	t.Helper()
	certPEM, certDER := genSelfSignedCertPEM(t)
	f := newWinFake()
	thumb := thumbprintSHA1(certDER)
	f.importReturns(thumb)
	f.on("Instance Names", sqlTestInstanceOut, nil)
	f.on("-Name Certificate -ErrorAction", sqlPriorThumb, nil)
	fp := FingerprintSHA256(certDER)
	return f, SQLServerInstallRequest{
		CertPEM: certPEM, KeyPEM: genECKeyPEM(t),
		VerifyHostPort: "sql.example.com:1433", ExpectedFingerprint: fp,
	}, thumb, fp
}

func indexOfRan(ran []string, sub string, from int) int {
	for i := from; i < len(ran); i++ {
		if strings.Contains(ran[i], sub) {
			return i
		}
	}
	return -1
}

func TestSQLServerInstall_HappyPath_ExactSteps(t *testing.T) {
	f, req, thumb, fp := sqlFixture(t)
	v := &stubVerifier{fp: fp}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified || !res.Verified || res.RolledBack {
		t.Fatalf("result = %+v", res)
	}
	if v.calls != 1 {
		t.Errorf("verifier calls = %d, want 1", v.calls)
	}

	// Order: stage dir locked BEFORE the pfx is written, import, key ACL,
	// registry, restart.
	mk := indexOfRan(f.ran, "mkdir", 0)
	icacls := indexOfRan(f.ran, "icacls "+defaultWinStageRoot, 0)
	wr := indexOfRan(f.ran, "WRITE ", 0)
	imp := indexOfRan(f.ran, "Import-PfxCertificate", 0)
	acl := indexOfRan(f.ran, "icacls.exe $f /grant", 0)
	reg := indexOfRan(f.ran, "Set-ItemProperty", 0)
	rst := indexOfRan(f.ran, "Restart-Service", 0)
	for name, i := range map[string]int{"mkdir": mk, "stage icacls": icacls, "write": wr, "import": imp, "key acl": acl, "registry": reg, "restart": rst} {
		if i < 0 {
			t.Fatalf("step %q never ran: %v", name, f.ran)
		}
	}
	if !(mk < icacls && icacls < wr && wr < imp && imp < acl && acl < reg && reg < rst) {
		t.Errorf("steps out of order: mkdir=%d icacls=%d write=%d import=%d acl=%d reg=%d restart=%d", mk, icacls, wr, imp, acl, reg, rst)
	}

	// Exact registry write: path and LOWERCASE thumbprint travel as args,
	// never inside the script text.
	set := f.callsMatching("Set-ItemProperty")
	if len(set) != 1 {
		t.Fatalf("registry writes = %d", len(set))
	}
	if !strings.Contains(set[0].script, "Set-ItemProperty -LiteralPath $args[0] -Name Certificate -Value $args[1] -Type String") {
		t.Errorf("registry script = %s", set[0].script)
	}
	if set[0].args[0] != sqlTestRegPath || set[0].args[1] != strings.ToLower(thumb) {
		t.Errorf("registry args = %q", set[0].args)
	}
	if strings.Contains(set[0].script, thumb) || strings.Contains(set[0].script, "MSSQL16") {
		t.Error("values must be arguments, not spliced into the script")
	}

	// Key ACL: thumbprint and the service account, as arguments.
	grant := f.callsMatching("icacls.exe $f /grant")
	if len(grant) != 1 || grant[0].args[0] != thumb || grant[0].args[1] != `NT Service\MSSQLSERVER` {
		t.Errorf("key grant = %+v", grant)
	}
	restart := f.callsMatching("Restart-Service")
	if len(restart) != 1 || restart[0].args[0] != "MSSQLSERVER" {
		t.Errorf("restart = %+v", restart)
	}
	if !strings.Contains(restart[0].script, "-DependentServices") {
		t.Error("dependents (SQL Agent) must be restarted too")
	}
}

func TestSQLServerInstall_PFXPasswordNeverEscapesTheImportCall(t *testing.T) {
	// A host can echo the command line, arguments included, into an error.
	f, req, _, fp := sqlFixture(t)
	hook := &echoPasswordExec{winFake: f}
	res, err := NewSQLServerInstaller(hook).WithVerifier((&stubVerifier{fp: fp}).verify).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected failure")
	}
	if hook.password == "" {
		t.Fatal("test never captured the password")
	}
	if strings.Contains(err.Error(), hook.password) || strings.Contains(res.Detail, hook.password) {
		t.Errorf("one-time pfx password leaked into error/detail: %v / %s", err, res.Detail)
	}
}

// echoPasswordExec fails the import with an error that echoes its own
// arguments, including the password.
type echoPasswordExec struct {
	*winFake
	password string
}

func (e *echoPasswordExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "powershell" && strings.Contains(args[3], "Import-PfxCertificate") {
		e.password = args[5]
		e.ran = append(e.ran, "powershell Import-PfxCertificate")
		return []byte("failed: " + strings.Join(args[4:], " ")), errors.New("exit 1: " + strings.Join(args[4:], " "))
	}
	return e.winFake.Run(ctx, name, args...)
}

func TestSQLServerInstall_VerifyMismatchRollsBackToPriorThumbprint(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	v := &stubVerifier{fp: "deadbeef"}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err == nil {
		t.Fatal("a mismatched served leaf must fail")
	}
	if res.Outcome != OutcomeVerifyFailed || !res.RolledBack || res.RollbackFailed {
		t.Fatalf("result = %+v", res)
	}
	set := f.callsMatching("Set-ItemProperty")
	if len(set) != 2 {
		t.Fatalf("registry writes = %d, want install + restore", len(set))
	}
	if set[1].args[1] != sqlPriorThumb {
		t.Errorf("restored %q, want the prior thumbprint %q", set[1].args[1], sqlPriorThumb)
	}
	if n := len(f.callsMatching("Restart-Service")); n != 2 {
		t.Errorf("restarts = %d, want 2 (install + rollback)", n)
	}
}

func TestSQLServerInstall_VerifyDialErrorRollsBack(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	v := &stubVerifier{err: errors.New("no certificate served at the verify address")}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestSQLServerInstall_NoPriorValueIsRemovedOnRollback(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("-Name Certificate -ErrorAction", "", nil)
	v := &stubVerifier{fp: "deadbeef"}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err == nil || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.callsMatching("Remove-ItemProperty")) != 1 {
		t.Error("a prior state of 'no certificate configured' is restored by removing the value")
	}
}

func TestSQLServerInstall_RollbackFailureIsReportedHonestly(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("Set-ItemProperty", "", errors.New("registry locked")).nth = 2
	v := &stubVerifier{fp: "deadbeef"}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err == nil {
		t.Fatal("expected failure")
	}
	if res.RolledBack || !res.RollbackFailed || !strings.Contains(res.Detail, "ROLLBACK FAILED") {
		t.Errorf("must not claim a rollback that did not happen: %+v", res)
	}
}

func TestSQLServerInstall_RestartFailureRollsBackAndRestartsAgain(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("Restart-Service", "", errors.New("service did not start")).nth = 1
	v := &stubVerifier{}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeReloadFailed || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if v.calls != 0 {
		t.Error("verify must not run against a service that failed to restart")
	}
	if n := len(f.callsMatching("Restart-Service")); n != 2 {
		t.Errorf("restarts = %d: the service must be started again on the old certificate", n)
	}
}

func TestSQLServerInstall_AccessDeniedOnImportTouchesNothing(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("Import-PfxCertificate", "", errAccessDenied)
	res, err := NewSQLServerInstaller(f).WithVerifier((&stubVerifier{}).verify).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeCertImportFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !strings.Contains(err.Error(), "not a local Administrator") {
		t.Errorf("access denied must name the real cause: %v", err)
	}
	if len(f.callsMatching("Set-ItemProperty")) != 0 || len(f.callsMatching("Restart-Service")) != 0 {
		t.Error("nothing live may change when the store write was refused")
	}
	for p := range f.files {
		t.Errorf("staged file %s left behind", p)
	}
}

func TestSQLServerInstall_KeyACLFailureStopsBeforeRegistry(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("icacls.exe $f /grant", "", errAccessDenied)
	res, err := NewSQLServerInstaller(f).WithVerifier((&stubVerifier{}).verify).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeKeyACLFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.callsMatching("Set-ItemProperty")) != 0 || len(f.callsMatching("Restart-Service")) != 0 {
		t.Error("the instance must not be pointed at a key its account cannot read")
	}
}

func TestSQLServerInstall_NoPlaintextKeyOnHost(t *testing.T) {
	f, req, _, fp := sqlFixture(t)
	if _, err := NewSQLServerInstaller(f).WithVerifier((&stubVerifier{fp: fp}).verify).Install(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(f.files) != 0 {
		t.Errorf("staging left files behind: %v", f.files)
	}
	for _, r := range f.ran {
		if strings.Contains(r, "PRIVATE KEY") {
			t.Fatal("key PEM reached a command line")
		}
	}
}

func TestSQLServerInstall_NamedInstance(t *testing.T) {
	f, req, _, fp := sqlFixture(t)
	f.on("Instance Names", "ID=MSSQL15.SALES\nSERVICE=MSSQL$SALES\nACCOUNT=CORP\\svc-sql\n", nil)
	req.Instance = "SALES"
	if _, err := NewSQLServerInstaller(f).WithVerifier((&stubVerifier{fp: fp}).verify).Install(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := f.callsMatching("Instance Names")[0].args[0]; got != "SALES" {
		t.Errorf("instance arg = %q", got)
	}
	if got := f.callsMatching("Restart-Service")[0].args[0]; got != "MSSQL$SALES" {
		t.Errorf("service = %q", got)
	}
	if got := f.callsMatching("icacls.exe $f /grant")[0].args[1]; got != `CORP\svc-sql` {
		t.Errorf("account = %q", got)
	}
}

func TestSQLServerInstall_RefusesUnsafeInput(t *testing.T) {
	for _, inst := range []string{"a'b", "x;calc", "", "1bad", strings.Repeat("a", 17), "a b"} {
		f, req, _, _ := sqlFixture(t)
		req.Instance = inst
		req.VerifyHostPort = ""
		_, err := NewSQLServerInstaller(f).Install(context.Background(), req)
		if inst == "" {
			if err != nil {
				t.Errorf("empty instance means MSSQLSERVER: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("instance %q accepted", inst)
		}
		if len(f.calls) != 0 {
			t.Errorf("instance %q reached the host", inst)
		}
	}
}

func TestSQLServerInstall_RefusesMalformedHostReports(t *testing.T) {
	for name, out := range map[string]string{
		"bad id":      "ID=MSSQL16.X';calc\nSERVICE=MSSQLSERVER\nACCOUNT=LocalSystem",
		"bad service": "ID=MSSQL16.MSSQLSERVER\nSERVICE=evil svc\nACCOUNT=LocalSystem",
		"bad account": "ID=MSSQL16.MSSQLSERVER\nSERVICE=MSSQLSERVER\nACCOUNT=a'; calc",
	} {
		f, req, _, _ := sqlFixture(t)
		f.on("Instance Names", out, nil)
		if _, err := NewSQLServerInstaller(f).Install(context.Background(), req); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(f.callsMatching("Import-PfxCertificate")) != 0 {
			t.Errorf("%s: host changed before the report was validated", name)
		}
	}
}

func TestSQLServerInstall_NoVerifyWhenNotRequested(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	req.VerifyHostPort, req.ExpectedFingerprint = "", ""
	v := &stubVerifier{}
	res, err := NewSQLServerInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err != nil || res.Outcome != OutcomeInstalled || v.calls != 0 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, v.calls)
	}
}

func TestSQLServerInstall_ThumbprintMismatchFromHostIsRefused(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("Import-PfxCertificate", "0000000000000000000000000000000000000000", nil)
	res, err := NewSQLServerInstaller(f).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeCertImportFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestMapSQLAccount(t *testing.T) {
	cases := map[string]string{
		"LocalSystem":                 "*S-1-5-18",
		`NT AUTHORITY\NetworkService`: "*S-1-5-20",
		`NT Service\MSSQLSERVER`:      `NT Service\MSSQLSERVER`,
		` CORP\svc `:                  `CORP\svc`,
		`NT AUTHORITY\LOCAL SERVICE`:  `NT AUTHORITY\LOCAL SERVICE`,
		`NT AUTHORITY\LocalService`:   "*S-1-5-19",
	}
	for in, want := range cases {
		if got := mapSQLAccount(in); got != want {
			t.Errorf("mapSQLAccount(%q) = %q, want %q", in, got, want)
		}
	}
}
