// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// W34-20-verify: the netsh and certutil text below is modelled on documented
// output, not captured from a host; the live Windows run must confirm it.
const fixtureNetsh = `
SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash             : aabbccddeeff00112233445566778899aabbccdd
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : My

    IP:port                      : 0.0.0.0:5986
    Certificate Hash             : 1111111111111111111111111111111111111111
    Application ID               : {ffffffff-0000-0000-0000-000000000001}
    Certificate Store Name       : My

    IP:port                      : 0.0.0.0:8443
    Certificate Hash             : 2222222222222222222222222222222222222222
    Application ID               : {abcdef00-0000-0000-0000-000000000002}
    Certificate Store Name       : My
`

func postureOut(thumbIIS, thumbWinRM, thumbApp, thumbKeyOnly string) string {
	return strings.Join([]string{
		"__KK_KEY__\t" + thumbIIS + "\tC:\\ProgramData\\Microsoft\\Crypto\\Keys\\iis-key\tNT AUTHORITY\\SYSTEM;BUILTIN\\Administrators;BUILTIN\\Users",
		"__KK_KEY__\t" + thumbWinRM + "\tC:\\ProgramData\\Microsoft\\Crypto\\Keys\\winrm-key\tNT AUTHORITY\\SYSTEM",
		"__KK_KEY__\t" + thumbApp + "\tC:\\ProgramData\\Microsoft\\Crypto\\Keys\\app-key\tNT AUTHORITY\\SYSTEM;Everyone",
		"__KK_KEY__\t" + thumbKeyOnly + "\tC:\\ProgramData\\Microsoft\\Crypto\\Keys\\lonely-key\tNT AUTHORITY\\SYSTEM",
		"__KK_NETSH_BEGIN__",
		fixtureNetsh,
		"__KK_NETSH_END__",
		"__KK_IIS__\tDefault Web Site\t*:443:\t" + thumbIIS + "\tDefaultAppPool\tLocalSystem",
		"__KK_SVC__\t8443\tAcmeAppServer\tLocalSystem",
		"__KK_POSTURE_DONE__",
	}, "\r\n")
}

func TestParseWinPosture(t *testing.T) {
	p := ParseWinPosture(postureOut("AABBCCDDEEFF00112233445566778899AABBCCDD", "1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222", "3333333333333333333333333333333333333333"))
	if !p.Complete || len(p.Keys) != 4 || len(p.Bindings) != 3 || len(p.IIS) != 1 || len(p.Services) != 1 {
		t.Fatalf("%+v", p)
	}
	if p.Keys[0].ReadPrincipals[2] != "BUILTIN\\Users" {
		t.Errorf("principals: %v", p.Keys[0].ReadPrincipals)
	}
	b := p.Bindings[0]
	if b.Port != 443 || b.Thumbprint != "AABBCCDDEEFF00112233445566778899AABBCCDD" || b.AppID != iisAppID {
		t.Errorf("binding: %+v", b)
	}
	if p.IIS[0].Identity != "LocalSystem" || p.IIS[0].AppPool != "DefaultAppPool" {
		t.Errorf("iis: %+v", p.IIS[0])
	}
	if got := ParseWinPosture("noise\n__KK_KEY__\tonly-two"); got.Complete || len(got.Keys) != 0 {
		t.Errorf("malformed input must be ignored: %+v", got)
	}
}

func TestWindowsFileFactsMapsPosture(t *testing.T) {
	thumbs := map[string]string{
		"AABBCCDDEEFF00112233445566778899AABBCCDD": "fp-iis",
		"1111111111111111111111111111111111111111": "fp-winrm",
		"2222222222222222222222222222222222222222": "fp-app",
	}
	p := ParseWinPosture(postureOut("AABBCCDDEEFF00112233445566778899AABBCCDD", "1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222", "3333333333333333333333333333333333333333"))
	facts := WindowsFileFacts(p, thumbs)
	by := map[string]FileFact{}
	for _, f := range facts {
		key := ""
		if len(f.CertFingerprints) > 0 {
			key = f.CertFingerprints[0]
		}
		by[key] = f
	}
	iis, winrm, app, lonely := by["fp-iis"], by["fp-winrm"], by["fp-app"], by[""]
	for _, f := range facts {
		if f.Kind != FileKindCNGKey || f.UID != UnknownID || !f.Statted {
			t.Errorf("shape: %+v", f)
		}
	}
	// BUILTIN\Users can read the IIS cert's key.
	if len(iis.Findings) != 1 || !strings.HasPrefix(iis.Findings[0], FindingKeyWorldReadable+":") || iis.ServiceTech != "iis" || iis.ServiceName != "DefaultAppPool" {
		t.Errorf("iis: %+v", iis)
	}
	// IIS under LocalSystem is a Microsoft server: not SERVICE_RUNS_AS_ROOT.
	for _, f := range iis.Findings {
		if strings.HasPrefix(f, FindingServiceRunsAsRoot) {
			t.Error("IIS must not raise SERVICE_RUNS_AS_ROOT")
		}
	}
	if winrm.ServiceTech != "winrm" || len(winrm.Findings) != 0 {
		t.Errorf("winrm: %+v", winrm)
	}
	// Non-Microsoft service on the bound port, running as LocalSystem, key readable by Everyone.
	var codes []string
	for _, f := range app.Findings {
		codes = append(codes, strings.SplitN(f, ":", 2)[0])
	}
	if strings.Join(codes, ",") != FindingKeyWorldReadable+","+FindingServiceRunsAsRoot || app.Posture != PostureRootService || app.ServiceName != "AcmeAppServer" || !strings.HasPrefix(app.ServiceTech, "other:") {
		t.Errorf("app: %+v", app)
	}
	if lonely.Posture != PostureStandard || len(lonely.Findings) != 0 || len(lonely.CertFingerprints) != 0 {
		t.Errorf("lonely: %+v", lonely)
	}
}

func TestPostureScriptNeverTouchesKeyMaterial(t *testing.T) {
	for _, bad := range []string{".PrivateKey", "GetRSAPrivateKey", "GetECDsaPrivateKey", "Export", "PFX", "Copy-Item", "Get-Content"} {
		if strings.Contains(winPostureScript, bad) {
			t.Errorf("posture script contains %q", bad)
		}
	}
	for _, want := range []string{"HasPrivateKey", "Get-Acl", "netsh http show sslcert", "__KK_POSTURE_DONE__"} {
		if !strings.Contains(winPostureScript, want) {
			t.Errorf("posture script lacks %q", want)
		}
	}
}

func TestWinRMScanEmitsPostureFromFixtureServer(t *testing.T) {
	der := certDER(t, "srv.corp.example")
	cert, _ := x509.ParseCertificate(der)
	thumb := winThumbprint(cert)
	f := newWSManFixture(t, base64.StdEncoding.EncodeToString(der)+" My\n")
	f.postureOut = postureOut(thumb, strings.Repeat("A", 40), strings.Repeat("B", 40), strings.Repeat("C", 40))

	res := f.scanner().Scan(context.Background())
	if !res.FilesScanned || res.PostureErr != "" || len(res.Files) != 4 {
		t.Fatalf("files=%d scanned=%v err=%q", len(res.Files), res.FilesScanned, res.PostureErr)
	}
	linked := 0
	for _, fl := range res.Files {
		linked += len(fl.CertFingerprints)
		if len(fl.CertFingerprints) == 1 && fl.CertFingerprints[0] != res.Certs[0].Fingerprint {
			t.Errorf("fingerprint format must match the cert row: %q vs %q", fl.CertFingerprints[0], res.Certs[0].Fingerprint)
		}
	}
	if linked != 1 || len(res.WinBindings) != 3 {
		t.Fatalf("linked=%d bindings=%d", linked, len(res.WinBindings))
	}
	// No key bytes anywhere in the result.
	if strings.Contains(strings.ToUpper(strings.Join(func() []string {
		var s []string
		for _, fl := range res.Files {
			s = append(s, fl.Path)
		}
		return s
	}(), " ")), "PRIVATE KEY") {
		t.Fatal("key material in result")
	}
}

func TestWinRMScanPostureFailureDoesNotFailTheScan(t *testing.T) {
	der := certDER(t, "srv.corp.example")
	f := newWSManFixture(t, base64.StdEncoding.EncodeToString(der)+" My\n")
	// posture script returns text without the end marker: certutil rights missing, say.
	f.postureOut = "garbage"
	res := f.scanner().Scan(context.Background())
	if len(res.Certs) != 1 || len(res.Errors) != 0 || res.FilesScanned || res.PostureErr == "" {
		t.Fatalf("%+v", res)
	}
}
