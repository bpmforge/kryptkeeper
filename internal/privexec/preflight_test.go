// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package privexec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPreflightNone(t *testing.T) {
	f := newFake()
	r := Preflight(context.Background(), f, Config{Mode: ModeNone}, RoleScan)
	if r.PrivilegedAll || len(r.Missing) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightNoPasswdOK(t *testing.T) {
	f := newFake()
	r := Preflight(context.Background(), f, Config{Mode: ModeNoPasswd}, RoleScan)
	if !r.SudoPresent || !r.NoPasswdOK || !r.PrivilegedAll {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightRequireTTY(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		switch {
		case argv[0] == "sudo":
			return []byte("sudo: sorry, you must have a tty to run sudo"), errors.New("exit 1")
		case argv[0] == "id":
			return []byte("kkscan\n"), nil
		}
		return nil, nil
	}
	r := Preflight(context.Background(), f, Config{Mode: ModeNoPasswd}, RoleScan)
	if !r.RequireTTY || r.RequireTTYFix != "Defaults:kkscan !requiretty" || r.PrivilegedAll {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(strings.Join(r.Missing, "|"), "!requiretty") {
		t.Fatalf("missing = %v", r.Missing)
	}
}

func TestPreflightNoSudo(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) { return nil, errors.New("not found") }
	r := Preflight(context.Background(), f, Config{Mode: ModeNoPasswd}, RoleScan)
	if r.SudoPresent || r.PrivilegedAll || len(r.Missing) == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightPassword(t *testing.T) {
	f := newFake()
	r := Preflight(context.Background(), f, Config{Mode: ModePassword, Password: []byte(testPassword)}, RoleScan)
	if !r.PasswordOK || !r.PrivilegedAll {
		t.Fatalf("%+v", r)
	}
	last := f.calls[len(f.calls)-1]
	if got := strings.Join(last.argv, " "); got != "sudo -S -p  -k -l" || string(last.stdin) != testPassword+"\n" {
		t.Fatalf("probe = %q", got)
	}
	f.assertNoSecret(t, testPassword)

	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sudo" {
			return []byte("Sorry, try again."), errors.New("exit 1")
		}
		return nil, nil
	}
	r = Preflight(context.Background(), f, Config{Mode: ModePassword, Password: []byte(testPassword)}, RoleScan)
	if r.PasswordOK || r.PrivilegedAll {
		t.Fatalf("%+v", r)
	}
	f.assertNoSecret(t, testPassword, strings.Join(r.Missing, "|"))

	r = Preflight(context.Background(), noStdin{newFake()}, Config{Mode: ModePassword, Password: []byte("x")}, RoleScan)
	if r.PasswordOK || len(r.Missing) == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightHelper(t *testing.T) {
	sha := HelperSHA256()
	mk := func(reported string) *fakeExec {
		f := newFake()
		f.respond = func(argv []string, _ []byte) ([]byte, error) {
			if argv[0] == "sha256sum" {
				return []byte(reported + "  h\n"), nil
			}
			return nil, nil
		}
		return f
	}
	r := Preflight(context.Background(), mk(sha), Config{Mode: ModeHelper, HelperSHA: sha}, RoleInstall)
	if !r.HelperPresent || !r.HelperSHAOK || !r.NoPasswdOK || !r.PrivilegedAll {
		t.Fatalf("%+v", r)
	}
	r = Preflight(context.Background(), mk(strings.Repeat("a", 64)), Config{Mode: ModeHelper, HelperSHA: sha}, RoleInstall)
	if r.HelperSHAOK || r.PrivilegedAll || !strings.Contains(strings.Join(r.Missing, "|"), "HELPER_TAMPERED") {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightRawAllowlistGaps(t *testing.T) {
	f := newFake()
	f.respond = func(argv []string, _ []byte) ([]byte, error) {
		if len(argv) > 2 && argv[2] == "-l" {
			return []byte("User kkscan may run the following commands:\n    (root) NOPASSWD: /usr/bin/find, /usr/bin/stat, /usr/bin/cat, /usr/sbin/ss\n"), nil
		}
		return nil, nil
	}
	if r := Preflight(context.Background(), f, Config{Mode: ModeNoPasswd}, RoleScan); !r.PrivilegedAll {
		t.Fatalf("scan: %+v", r)
	}
	r := Preflight(context.Background(), f, Config{Mode: ModeNoPasswd}, RoleInstall)
	if r.PrivilegedAll || len(r.Missing) != 2 {
		t.Fatalf("install: %+v", r)
	}
}

func TestClassifySudoListing(t *testing.T) {
	cases := map[string]bool{
		"    (ALL) ALL":                                true,
		"    (ALL : ALL) ALL":                          true,
		"    (root) NOPASSWD: ALL":                     true,
		"    (root) NOPASSWD: /usr/bin/install -m * *": true,
		"    (root) NOPASSWD: /usr/bin/stat -c * /etc/nginx/ssl/*, /usr/bin/ss -ltnp": false,
		"    (root) NOPASSWD: /opt/kryptkeeper/helper":                                false,
		"": false,
	}
	for in, want := range cases {
		if got, why := classifySudoListing(in); got != want || (got && why == "") {
			t.Errorf("%q: got %v %q, want %v", in, got, why, want)
		}
	}
}
