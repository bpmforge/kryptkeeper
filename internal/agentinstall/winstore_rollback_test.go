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

// W39 live R1: after a verify failure and rollback the newly imported leaf
// (and its private key) must not stay in Cert:\LocalMachine\My, and the
// restored previous certificate must never be removed.

func TestSQLServerInstall_RollbackRemovesTheNewCertificate(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	res, err := NewSQLServerInstaller(f).WithVerifier((&stubVerifier{fp: "deadbeef"}).verify).Install(context.Background(), req)
	if err == nil || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	rm := f.callsMatching("-DeleteKey")
	if len(rm) != 1 || rm[0].args[len(rm[0].args)-2] != "My" {
		t.Fatalf("removal = %+v", rm)
	}
	got := rm[0].args[len(rm[0].args)-1]
	if strings.EqualFold(got, sqlPriorThumb) || len(got) != 40 {
		t.Fatalf("removed %q, want the new thumbprint only", got)
	}
}

func TestSQLServerInstall_FailedRollbackKeepsTheNewCertificate(t *testing.T) {
	f, req, _, _ := sqlFixture(t)
	f.on("Set-ItemProperty", "", errors.New("registry locked")).nth = 2
	_, _ = NewSQLServerInstaller(f).WithVerifier((&stubVerifier{fp: "deadbeef"}).verify).Install(context.Background(), req)
	if n := len(f.callsMatching("-DeleteKey")); n != 0 {
		t.Errorf("the service may still reference the new certificate; removals = %d", n)
	}
}

func TestRDPInstall_RollbackRemovesTheNewCertificate(t *testing.T) {
	f, req, _, _ := rdpFixture(t)
	res, err := NewRDPInstaller(f).WithVerifier((&stubVerifier{fp: "deadbeef"}).verify).Install(context.Background(), req)
	if err == nil || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	rm := f.callsMatching("-DeleteKey")
	if len(rm) != 1 {
		t.Fatalf("removal = %+v", rm)
	}
	got := rm[0].args[len(rm[0].args)-1]
	if strings.EqualFold(got, rdpPriorHash) || len(got) != 40 {
		t.Fatalf("removed %q", got)
	}
}

func TestIISInstall_VerifyMismatchRemovesTheNewCertificate(t *testing.T) {
	f := newIISExecutor()
	f.outputs[showSSLCertCmdPrefix+"0.0.0.0:443"] = existingBindingOutput(
		"3333333333333333333333333333333333333333", "{44444444-4444-4444-4444-444444444444}", "My")
	req := iisReq(t)
	req.VerifyHostPort = "iis-test.example.com:443"
	req.ExpectedFingerprint = "ABCD1234"
	in := NewIISInstaller(f).WithTempDir(`C:\fake\tmp`).WithVerifier(fakeVerifier("deadbeef", nil))
	if res, err := in.Install(context.Background(), req); err == nil || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	n := 0
	for _, c := range f.ran {
		if strings.Contains(c, "-DeleteKey") {
			n++
			if strings.Contains(c, "3333333333333333333333333333333333333333") {
				t.Fatalf("the restored previous certificate must not be removed: %s", c)
			}
		}
	}
	if n != 1 {
		t.Fatalf("removals = %d, ran %v", n, f.ran)
	}
}

func TestRemoveRolledBackCert_SkipsTheRestoredCertificate(t *testing.T) {
	f := newIISExecutor()
	tp := strings.Repeat("ab", 20)
	if d := removeRolledBackCert(context.Background(), f, "My", tp, strings.ToUpper(tp)); d != "" || len(f.ran) != 0 {
		t.Fatalf("same thumbprint as the restored one must not be removed: %q %v", d, f.ran)
	}
}
