// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentinstall"
)

// preflightFakeExec answers the probes privexec.Preflight issues.
type preflightFakeExec struct {
	respond func(argv []string, stdin []byte) ([]byte, error)
	argv    []string
}

func (f *preflightFakeExec) Exists(string) bool                          { return false }
func (f *preflightFakeExec) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (f *preflightFakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *preflightFakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunStdin(ctx, nil, name, args...)
}
func (f *preflightFakeExec) RunStdin(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	f.argv = append(f.argv, strings.Join(argv, " "))
	if f.respond != nil {
		return f.respond(argv, stdin)
	}
	return nil, nil
}

type markingCreds struct {
	*sqliteOutboundCredentialStore
}

type preflightFixture struct {
	mux     *http.ServeMux
	admin   string
	viewer  string
	other   string
	audit   *sshRecordingAudit
	creds   *markingCreds
	targets *sqliteManagedTargetStore
	exec    *preflightFakeExec
	dialCfg agentinstall.SSHTarget
	dialErr error
}

func newPreflightFixture(t *testing.T, sudo map[string]string, autoRenew bool) *preflightFixture {
	t.Helper()
	_, auth, _, tenants, _ := newTargetsTestMux(t)
	t.Setenv("MULTI_TENANCY", "on")
	f := &preflightFixture{audit: &sshRecordingAudit{}, exec: &preflightFakeExec{}}
	var cs *sqliteOutboundCredentialStore
	f.targets, cs = winrmTestStores(t)
	f.creds = &markingCreds{sqliteOutboundCredentialStore: cs}
	if _, err := f.creds.Create(context.Background(), "cred-pf", "kkscan", CredentialTypeSSHKey, "tenant-a", sshPayloadWithPrivilege(t, sudo)); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []string{"tenant-a", "tenant-b"} {
		if _, err := tenants.CreateTenant(t.Context(), tn, tn); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.targets.Create(context.Background(), ManagedTarget{ID: "target-pf", Name: "web", Host: "192.0.2.50", DiscoveryMode: "network",
		InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-pf", AutoRenew: autoRenew, Tenant: "tenant-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.targets.Create(context.Background(), ManagedTarget{ID: "target-agent", Name: "ag", Host: "h", DiscoveryMode: "agent",
		InstallMode: "agent", RenewalMethod: "manual", Tenant: "tenant-a"}); err != nil {
		t.Fatal(err)
	}
	f.mux = http.NewServeMux()
	registerTargetHandlers(f.mux, auth, f.targets, tenants, f.audit, targetEgressDeps{credentials: f.creds})
	key := func(id, role, tenant string, scopes []string) string {
		_, tok, err := auth.CreateAPIKey(id, id, role, scopes, "", tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	f.admin = key("adm", "pki-admin", "tenant-a", []string{"*"})
	f.viewer = key("vw", "viewer", "tenant-a", nil)
	f.other = key("adm-b", "pki-admin", "tenant-b", []string{"*"})

	old := preflightDial
	t.Cleanup(func() { preflightDial = old })
	preflightDial = func(_ context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		f.dialCfg = cfg
		if f.dialErr != nil {
			return nil, nil, f.dialErr
		}
		return f.exec, func() error { return nil }, nil
	}
	return f
}

func (f *preflightFixture) post(token string) (*preflightReport, int) {
	rec := doTargetsRequest(f.mux, http.MethodPost, "/api/v1/targets/target-pf/preflight", token, "")
	var out struct {
		Data preflightReport `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return &out.Data, rec.Code
}

func rowStatus(r *preflightReport, capability string) string {
	for _, row := range r.Rows {
		if row.Capability == capability {
			return row.Status
		}
	}
	return "absent"
}

func TestPreflightNoPasswdOKStoresReport(t *testing.T) {
	f := newPreflightFixture(t, map[string]string{"sudo_mode": "nopasswd"}, true)
	rep, code := f.post(f.admin)
	if code != http.StatusOK || !rep.OK || !rep.PrivilegedAll {
		t.Fatalf("%d %+v", code, rep)
	}
	for _, c := range []string{"ssh_auth", "sudo_present", "requiretty", "nopasswd", "command:find", "command:cat", "command:install", "command:systemctl"} {
		if rowStatus(rep, c) != "ok" {
			t.Errorf("%s = %s", c, rowStatus(rep, c))
		}
	}
	if strings.Join(rep.Roles, ",") != "scan,install" {
		t.Errorf("auto_renew must add the install role: %v", rep.Roles)
	}
	if f.dialCfg.DialTimeout != 8*time.Second || f.dialCfg.User != "deploy" {
		t.Errorf("dial cap/user: %+v", f.dialCfg)
	}
	if m, _ := f.creds.Get(context.Background(), "cred-pf"); m.Privileged {
		t.Errorf("a narrow allowlist must not flag the credential: %+v", m)
	}
	rec := doTargetsRequest(f.mux, http.MethodGet, "/api/v1/targets/target-pf/preflight", f.admin, "")
	var got struct{ Data preflightReport }
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got.Data.CheckedAt != rep.CheckedAt || len(got.Data.Rows) != len(rep.Rows) {
		t.Fatalf("stored report not returned: %d %s", rec.Code, rec.Body.String())
	}
	assertAudit(t, f.audit, "target.privilege.preflight", AuditOutcomeSuccess)
}

func TestPreflightScanOnlyWithoutAutoRenew(t *testing.T) {
	f := newPreflightFixture(t, map[string]string{"sudo_mode": "nopasswd"}, false)
	rep, _ := f.post(f.admin)
	if strings.Join(rep.Roles, ",") != "scan" || rowStatus(rep, "command:install") != "absent" {
		t.Fatalf("%+v", rep)
	}
}

func TestPreflightRequireTTYShowsExactLine(t *testing.T) {
	f := newPreflightFixture(t, map[string]string{"sudo_mode": "nopasswd"}, false)
	f.exec.respond = func(argv []string, _ []byte) ([]byte, error) {
		switch argv[0] {
		case "sudo":
			return []byte("sudo: sorry, you must have a tty to run sudo"), errors.New("exit 1")
		case "id":
			return []byte("kkscan\n"), nil
		}
		return nil, nil
	}
	rep, _ := f.post(f.admin)
	var fix string
	for _, r := range rep.Rows {
		if r.Capability == "requiretty" {
			fix = r.Fix
		}
	}
	if rowStatus(rep, "requiretty") != "fail" || fix != "Defaults:kkscan !requiretty" || rep.OK || rep.PrivilegedAll {
		t.Fatalf("%+v", rep)
	}
	if m, _ := f.creds.Get(context.Background(), "cred-pf"); m.Privileged {
		t.Fatal("a failing preflight must not flag the credential")
	}
}

func TestPreflightPasswordNeverLeaks(t *testing.T) {
	const pw = "Pf-Sudo-Pw-5521"
	f := newPreflightFixture(t, map[string]string{"sudo_mode": "password", "sudo_password": pw}, false)
	f.exec.respond = func(argv []string, stdin []byte) ([]byte, error) {
		if argv[0] == "sudo" && argv[1] == "-S" && string(stdin) != pw+"\n" {
			return []byte("Sorry, try again."), errors.New("exit 1")
		}
		return nil, nil
	}
	rep, code := f.post(f.admin)
	if code != http.StatusOK || rowStatus(rep, "password") != "ok" || !rep.PrivilegedAll {
		t.Fatalf("%d %+v", code, rep)
	}
	body, _ := json.Marshal(rep)
	if strings.Contains(string(body), pw) || strings.Contains(strings.Join(f.exec.argv, "\n"), pw) {
		t.Fatal("password leaked into the report or argv")
	}
	raw, _ := f.targets.GetLastPreflight(context.Background(), "target-pf")
	if strings.Contains(raw, pw) {
		t.Fatal("password stored with the report")
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for _, e := range f.audit.entries {
		if b, _ := json.Marshal(e); strings.Contains(string(b), pw) {
			t.Fatalf("password in audit: %s", b)
		}
	}
}

func TestPreflightHelperTamperedRows(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	f := newPreflightFixture(t, map[string]string{"sudo_mode": "helper", "helper_sha256": sha}, false)
	f.exec.respond = func(argv []string, _ []byte) ([]byte, error) {
		if argv[0] == "sha256sum" {
			return []byte(strings.Repeat("00", 32) + "  h\n"), nil
		}
		return nil, nil
	}
	rep, _ := f.post(f.admin)
	if rowStatus(rep, "helper_present") != "ok" || rowStatus(rep, "helper_sha") != "fail" || rep.PrivilegedAll || rep.OK {
		t.Fatalf("%+v", rep)
	}
	if rowStatus(rep, "verb:read-cert") != "skipped" {
		t.Errorf("verbs behind a tampered helper must not read ok: %+v", rep.Rows)
	}
}

func TestPreflightDialFailureIsARowNotAnError(t *testing.T) {
	f := newPreflightFixture(t, nil, false)
	f.dialErr = errors.New("dial tcp 192.0.2.50:22: i/o timeout")
	rep, code := f.post(f.admin)
	if code != http.StatusOK || len(rep.Rows) != 1 || rowStatus(rep, "ssh_auth") != "fail" || rep.Rows[0].Fix == "" {
		t.Fatalf("%d %+v", code, rep)
	}
	assertAudit(t, f.audit, "target.privilege.preflight", AuditOutcomeFailure)
}

func TestPreflightModeNone(t *testing.T) {
	f := newPreflightFixture(t, nil, false)
	rep, _ := f.post(f.admin)
	if rowStatus(rep, "ssh_auth") != "ok" || rowStatus(rep, "privilege") != "fail" || rep.PrivilegedAll {
		t.Fatalf("%+v", rep)
	}
}

func TestPreflightGates(t *testing.T) {
	f := newPreflightFixture(t, nil, false)
	if _, code := f.post(""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous %d", code)
	}
	if _, code := f.post(f.viewer); code != http.StatusForbidden {
		t.Fatalf("viewer %d", code)
	}
	if _, code := f.post(f.other); code != http.StatusForbidden {
		t.Fatalf("other tenant %d", code)
	}
	assertAudit(t, f.audit, "target.privilege.preflight", AuditOutcomeDenied)
	if rec := doTargetsRequest(f.mux, http.MethodPost, "/api/v1/targets/target-agent/preflight", f.admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-ssh target %d", rec.Code)
	}
	if rec := doTargetsRequest(f.mux, http.MethodGet, "/api/v1/targets/target-pf/preflight", f.admin, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("no report yet should be 404, got %d", rec.Code)
	}
	if rec := doTargetsRequest(f.mux, http.MethodDelete, "/api/v1/targets/target-pf/preflight", f.admin, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE %d", rec.Code)
	}
}

func TestPreflightMarksCredentialPrivilegedFromSudoListing(t *testing.T) {
	cases := map[string]struct {
		listing string
		reason  string
	}{
		"sudo ALL":         {"    (ALL) ALL", "(ALL) ALL"},
		"broad cat glob":   {"    (root) NOPASSWD: /usr/bin/cat /etc/*", "cat on globbed paths"},
		"narrow allowlist": {"    (root) NOPASSWD: /usr/bin/cat /etc/ssl/certs/*, /usr/bin/stat -c * /etc/ssl/certs/*", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPreflightFixture(t, map[string]string{"sudo_mode": "nopasswd"}, false)
			f.exec.respond = func(argv []string, _ []byte) ([]byte, error) {
				if len(argv) >= 3 && argv[0] == "sudo" && argv[2] == "-l" {
					return []byte(c.listing), nil
				}
				return nil, nil
			}
			if _, code := f.post(f.admin); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			m, err := f.creds.Get(context.Background(), "cred-pf")
			if err != nil {
				t.Fatal(err)
			}
			if c.reason == "" {
				if m.Privileged {
					t.Fatalf("flagged: %+v", m)
				}
				return
			}
			if !m.Privileged || !strings.Contains(m.PrivilegedReason, c.reason) || m.PrivilegedSetBy != "auto:preflight" || m.PrivilegedSetAt == "" {
				t.Fatalf("not flagged as expected: %+v", m)
			}
			var n int
			for _, e := range f.audit.entries {
				if e.Action == "credential.privileged.set" && e.ResourceID == "cred-pf" && strings.Contains(e.ChangeSummary, `"source":"auto"`) {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("want one auto audit row, got %d", n)
			}
			// A second preflight neither rewrites the reason nor repeats the audit row.
			f.post(f.admin)
			n = 0
			for _, e := range f.audit.entries {
				if e.Action == "credential.privileged.set" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("repeat preflight re-audited: %d", n)
			}
		})
	}
}
