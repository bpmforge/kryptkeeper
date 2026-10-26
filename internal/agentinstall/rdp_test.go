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

const rdpPriorHash = "AABBCCDDEEFF00112233445566778899AABBCCDD"

func rdpFixture(t *testing.T) (*winFake, RDPInstallRequest, string, string) {
	t.Helper()
	certPEM, certDER := genSelfSignedCertPEM(t)
	f := newWinFake()
	thumb := thumbprintSHA1(certDER)
	f.importReturns(thumb)
	f.on("'HASH=' +", "HASH="+rdpPriorHash+"\r\nTYPE=3\r\n", nil)
	fp := FingerprintSHA256(certDER)
	return f, RDPInstallRequest{
		CertPEM: certPEM, KeyPEM: genECKeyPEM(t),
		VerifyHostPort: "win.example.com:3389", ExpectedFingerprint: fp,
	}, thumb, fp
}

func TestRDPInstall_HappyPath_ExactSteps(t *testing.T) {
	f, req, thumb, fp := rdpFixture(t)
	v := &stubVerifier{fp: fp}
	res, err := NewRDPInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified || !res.Verified || res.RolledBack {
		t.Fatalf("result = %+v", res)
	}
	imp := indexOfRan(f.ran, "Import-PfxCertificate", 0)
	acl := indexOfRan(f.ran, "icacls.exe $f /grant", 0)
	set := indexOfRan(f.ran, "Set-CimInstance", 0)
	if !(imp >= 0 && imp < acl && acl < set) {
		t.Fatalf("order import=%d acl=%d set=%d: %v", imp, acl, set, f.ran)
	}

	grant := f.callsMatching("icacls.exe $f /grant")
	if len(grant) != 1 || grant[0].args[0] != thumb || grant[0].args[1] != "*S-1-5-20" {
		t.Errorf("key grant = %+v, want NETWORK SERVICE (S-1-5-20) read", grant)
	}
	if !strings.Contains(grant[0].script, "(R)") || strings.Contains(grant[0].script, ":(F)") {
		t.Error("the grant must be read-only")
	}
	sets := f.callsMatching("Set-CimInstance")
	if len(sets) != 1 {
		t.Fatalf("hash writes = %d", len(sets))
	}
	if !strings.Contains(sets[0].script, "-Namespace 'root/cimv2/TerminalServices' -ClassName Win32_TSGeneralSetting") ||
		!strings.Contains(sets[0].script, "TerminalName='RDP-Tcp'") ||
		!strings.Contains(sets[0].script, "Set-CimInstance -InputObject $s -Property @{ SSLCertificateSHA1Hash = $args[0] }") {
		t.Errorf("hash script = %s", sets[0].script)
	}
	if sets[0].args[0] != thumb || strings.Contains(sets[0].script, thumb) {
		t.Errorf("the hash must be an argument: %q", sets[0].args)
	}
	if len(f.callsMatching("Restart-Service")) != 0 {
		t.Error("the RDP service must not be restarted; that drops every session")
	}
	if len(f.files) != 0 {
		t.Errorf("staging left files behind: %v", f.files)
	}
}

func TestRDPInstall_VerifyMismatchRestoresPriorHash(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	res, err := NewRDPInstaller(f).WithVerifier((&stubVerifier{fp: "deadbeef"}).verify).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeVerifyFailed || !res.RolledBack || res.RollbackFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	sets := f.callsMatching("Set-CimInstance")
	if len(sets) != 2 || sets[1].args[0] != rdpPriorHash {
		t.Fatalf("hash writes = %+v, want install then restore of %s", sets, rdpPriorHash)
	}
}

func TestRDPInstall_DefaultCertificateIsRestoredByRemovingTheValue(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	f.on("'HASH=' +", "HASH=\r\nTYPE=1\r\n", nil)
	res, err := NewRDPInstaller(f).WithVerifier((&stubVerifier{err: errors.New("no certificate served at the verify address")}).verify).Install(context.Background(), req)
	if err == nil || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	rm := f.callsMatching("Remove-ItemProperty")
	if len(rm) != 1 || rm[0].args[0] != rdpWinStationKey {
		t.Fatalf("removal = %+v", rm)
	}
	if len(f.callsMatching("Set-CimInstance")) != 1 {
		t.Error("with no prior hash there is nothing to set back")
	}
}

func TestRDPInstall_RollbackFailureIsReportedHonestly(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	f.on("Set-CimInstance", "", errors.New("wmi busy")).nth = 2
	res, err := NewRDPInstaller(f).WithVerifier((&stubVerifier{fp: "deadbeef"}).verify).Install(context.Background(), req)
	if err == nil || res.RolledBack || !res.RollbackFailed || !strings.Contains(res.Detail, "ROLLBACK FAILED") {
		t.Fatalf("must not claim a rollback that did not happen: res=%+v err=%v", res, err)
	}
}

func TestRDPInstall_GroupPolicyEnforcedCertificateIsRefusedBeforeAnyChange(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	f.on("'HASH=' +", "HASH="+rdpPriorHash+"\r\nTYPE=2\r\n", nil)
	res, err := NewRDPInstaller(f).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeConfigFailed || !strings.Contains(err.Error(), "group policy") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.callsMatching("Import-PfxCertificate")) != 0 || len(f.ran) == 0 {
		t.Error("nothing may change on the host")
	}
}

func TestRDPInstall_AccessDeniedOnImportTouchesNothing(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	f.on("Import-PfxCertificate", "", errAccessDenied)
	res, err := NewRDPInstaller(f).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeCertImportFailed || !strings.Contains(err.Error(), "not a local Administrator") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.callsMatching("Set-CimInstance")) != 0 {
		t.Error("the listener setting must not change when the store write was refused")
	}
}

func TestRDPInstall_AccessDeniedOnKeyACLTouchesNothing(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	f.on("icacls.exe $f /grant", "", errAccessDenied)
	res, err := NewRDPInstaller(f).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeKeyACLFailed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.callsMatching("Set-CimInstance")) != 0 {
		t.Error("the listener must not be pointed at a key NETWORK SERVICE cannot read")
	}
}

func TestRDPInstall_SetFailureDoesNotVerify(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	f.on("Set-CimInstance", "", errAccessDenied)
	v := &stubVerifier{}
	res, err := NewRDPInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err == nil || res.Outcome != OutcomeConfigFailed || v.calls != 0 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, v.calls)
	}
}

func TestRDPInstall_RefusesMalformedHostReports(t *testing.T) {
	for name, out := range map[string]string{
		"bad hash": "HASH=zz';calc\nTYPE=3",
		"bad type": "HASH=\nTYPE=x",
	} {
		f, req, _, _ := rdpFixture(t)
		f.on("'HASH=' +", out, nil)
		if _, err := NewRDPInstaller(f).Install(context.Background(), req); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(f.callsMatching("Import-PfxCertificate")) != 0 {
			t.Errorf("%s: host changed before the report was validated", name)
		}
	}
}

func TestRDPInstall_NoVerifyWhenNotRequested(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	req.VerifyHostPort, req.ExpectedFingerprint = "", ""
	v := &stubVerifier{}
	res, err := NewRDPInstaller(f).WithVerifier(v.verify).Install(context.Background(), req)
	if err != nil || res.Outcome != OutcomeInstalled || v.calls != 0 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, v.calls)
	}
}

func TestRDPInstall_RequiresCertAndKey(t *testing.T) {
	if _, err := NewRDPInstaller(newWinFake()).Install(context.Background(), RDPInstallRequest{}); err == nil {
		t.Fatal("empty request accepted")
	}
}

// The protocol verifiers must answer with a generic error, never a raw dial
// error, and refuse a malformed address without dialing.
func TestProtocolVerifiersRefuseBadAddresses(t *testing.T) {
	for name, v := range map[string]Verifier{"tds": NewTDSVerifier(), "rdp": NewRDPVerifier()} {
		for _, addr := range []string{"nohostport", "h:0", "h:99999", "h:x"} {
			if _, err := v(context.Background(), addr); err == nil {
				t.Errorf("%s accepted %q", name, addr)
			}
		}
		// Loopback is refused by the scanner's dial policy, with the same
		// generic text as the TLS verifier's refusal.
		if _, err := v(context.Background(), "127.0.0.1:1"); err == nil {
			t.Errorf("%s dialed loopback", name)
		}
	}
}
