// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/agentinstall"
)

// zeroizeSpyExecutor is an in-memory target that honours `rm -f -- path` and
// records every command, so tests can prove what is left behind on the host.
type zeroizeSpyExecutor struct {
	files       map[string][]byte
	failCommand string
	commands    []string
}

func (f *zeroizeSpyExecutor) Exists(path string) bool { _, ok := f.files[path]; return ok }
func (f *zeroizeSpyExecutor) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (f *zeroizeSpyExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	f.files[path] = append([]byte(nil), content...)
	return nil
}
func (f *zeroizeSpyExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, strings.Join(append([]string{name}, args...), " "))
	if name == "rm" && len(args) == 3 && args[0] == "-f" && args[1] == "--" {
		delete(f.files, args[2])
		return nil, nil
	}
	if f.failCommand != "" && name == f.failCommand {
		return []byte("scripted failure"), errors.New("scripted failure")
	}
	return []byte("ok"), nil
}

func (f *zeroizeSpyExecutor) ran(cmd string) bool {
	for _, c := range f.commands {
		if c == cmd {
			return true
		}
	}
	return false
}

func (f *zeroizeSpyExecutor) anyRm() bool {
	for _, c := range f.commands {
		if strings.HasPrefix(c, "rm ") {
			return true
		}
	}
	return false
}

type zeroizeAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (r *zeroizeAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (r *zeroizeAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	return nil
}
func (r *zeroizeAudit) actions() []string {
	var out []string
	for _, e := range r.entries {
		out = append(out, e.Action)
	}
	return out
}
func (r *zeroizeAudit) find(action string) (AuditEntry, bool) {
	for _, e := range r.entries {
		if e.Action == action {
			return e, true
		}
	}
	return AuditEntry{}, false
}

type zeroizeHarness struct {
	exec   *RenewalExecutor
	target *zeroizeSpyExecutor
	audit  *zeroizeAudit
	wiped  []byte
	fp     string
	logs   *bytes.Buffer
}

func newZeroizeHarness(t *testing.T, failCommand string, seed map[string][]byte) *zeroizeHarness {
	t.Helper()
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "zeroize.example.com", "zeroize.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-zeroize",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	return buildZeroizeHarness(t, provider, issued.CertificateItem.FingerprintSHA256, failCommand, seed)
}

func buildZeroizeHarness(t *testing.T, certs CertificateProvider, fp, failCommand string, seed map[string][]byte) *zeroizeHarness {
	t.Helper()
	files := map[string][]byte{}
	for k, v := range seed {
		files[k] = v
	}
	h := &zeroizeHarness{
		target: &zeroizeSpyExecutor{files: files, failCommand: failCommand},
		audit:  &zeroizeAudit{},
		fp:     fp,
		logs:   &bytes.Buffer{},
	}
	h.exec = newRenewalTestEngine(t, certs, &renewalFakeExecutor{files: files}, testSSHCredentialJSON(t))
	h.exec.dial = func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		return h.target, func() error { return nil }, nil
	}
	h.exec.pluginAudit = h.audit
	h.exec.keyWipeSpy = func(b []byte) { h.wiped = b }
	log.SetOutput(h.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return h
}

func (h *zeroizeHarness) noPrivateKeyOnTarget(t *testing.T) {
	t.Helper()
	for path, b := range h.target.files {
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatalf("private key bytes left on target at %s", path)
		}
	}
}

func TestFailedInstallLeavesNoKeyBytesOnTarget(t *testing.T) {
	h := newZeroizeHarness(t, "nginx", nil)
	res, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("partial state must not be an error: %v", err)
	}
	if res.InstallOutcome != agentinstall.OutcomeConfigTestFailed {
		t.Fatalf("expected config_test_failed, got %+v", res)
	}
	h.noPrivateKeyOnTarget(t)
	if !h.target.ran("rm -f -- /etc/nginx/tls/renewed.key") {
		t.Fatalf("expected key cleanup rm, commands: %v", h.target.commands)
	}
}

func TestFailedInstallKeyBufferIsZeroized(t *testing.T) {
	h := newZeroizeHarness(t, "nginx", nil)
	if _, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), sshTestProfile()); err != nil {
		t.Fatal(err)
	}
	if len(h.wiped) == 0 {
		t.Fatal("spy saw an empty slice: a real key was not wiped")
	}
	for i, b := range h.wiped {
		if b != 0 {
			t.Fatalf("key buffer byte %d not zeroized", i)
		}
	}
}

func TestFailedInstallKeepsPreviousKeyWhenOneExisted(t *testing.T) {
	h := newZeroizeHarness(t, "nginx", map[string][]byte{"/etc/nginx/tls/renewed.key": []byte("OLD-KEY")})
	if _, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), sshTestProfile()); err != nil {
		t.Fatal(err)
	}
	if string(h.target.files["/etc/nginx/tls/renewed.key"]) != "OLD-KEY" {
		t.Fatalf("previous key not preserved: %q", h.target.files["/etc/nginx/tls/renewed.key"])
	}
	if h.target.anyRm() {
		t.Fatalf("rm must not run when a key pre-existed: %v", h.target.commands)
	}
	if _, ok := h.audit.find("renewal.install_failed_key_cleanup"); ok || strings.Contains(h.logs.String(), "ALERT") {
		t.Fatal("no cleanup alert expected when a key pre-existed")
	}
}

func TestLifecycleAuditAndCleanupAlert(t *testing.T) {
	h := newZeroizeHarness(t, "nginx", nil)
	if _, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), sshTestProfile()); err != nil {
		t.Fatal(err)
	}
	want := []string{"key.generate_for_renewal", "renewal.install_failed_key_cleanup", "key.zeroize"}
	if got := h.audit.actions(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions = %v, want %v", got, want)
	}
	row, _ := h.audit.find("renewal.install_failed_key_cleanup")
	if row.Outcome != AuditOutcomeFailure || !strings.Contains(row.ChangeSummary, "removed=true") {
		t.Fatalf("cleanup row wrong: %+v", row)
	}
	if !strings.Contains(h.logs.String(), "ALERT renewal.install_failed_key_cleanup") {
		t.Fatalf("alert log line missing: %q", h.logs.String())
	}
	zr, _ := h.audit.find("key.zeroize")
	if !strings.Contains(zr.ChangeSummary, "installed=false") {
		t.Fatalf("zeroize row should record installed=false: %+v", zr)
	}
	for _, e := range h.audit.entries {
		if strings.Contains(e.ChangeSummary, "PRIVATE") {
			t.Fatalf("audit leaked key material: %+v", e)
		}
	}
}

func TestSuccessfulInstallZeroizesWithoutCleanupAlert(t *testing.T) {
	h := newZeroizeHarness(t, "", nil)
	res, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	if !installSucceeded(res.InstallOutcome) {
		t.Fatalf("install should have succeeded: %+v", res)
	}
	if len(h.wiped) == 0 {
		t.Fatal("no key wiped")
	}
	for _, b := range h.wiped {
		if b != 0 {
			t.Fatal("key buffer not zeroized")
		}
	}
	if _, ok := h.audit.find("renewal.install_failed_key_cleanup"); ok || h.target.anyRm() {
		t.Fatalf("no cleanup expected on success: %v %v", h.audit.actions(), h.target.commands)
	}
	zr, ok := h.audit.find("key.zeroize")
	if !ok || !strings.Contains(zr.ChangeSummary, "installed=true") {
		t.Fatalf("zeroize row wrong: %+v", zr)
	}
}

type failingRenewProvider struct{ CertificateProvider }

func (failingRenewProvider) RenewCertificate(context.Context, string, CertificateRenewRequest) (CertificateIssueResult, error) {
	return CertificateIssueResult{}, errors.New("CA unavailable")
}

func TestRenewMaterialErrorStillZeroizes(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "zeroize2.example.com", "zeroize2.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-zeroize",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := buildZeroizeHarness(t, failingRenewProvider{provider}, issued.CertificateItem.FingerprintSHA256, "", nil)
	if _, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), sshTestProfile()); err == nil {
		t.Fatal("expected renewal error")
	}
	if len(h.wiped) == 0 {
		t.Fatal("spy saw no key")
	}
	for _, b := range h.wiped {
		if b != 0 {
			t.Fatal("key buffer not zeroized on renew error")
		}
	}
	if _, ok := h.audit.find("key.zeroize"); !ok {
		t.Fatalf("key.zeroize row missing: %v", h.audit.actions())
	}
}

func TestHAProxyCleanupTargetsCombinedFile(t *testing.T) {
	h := newZeroizeHarness(t, "haproxy", nil)
	profile := RenewalInstallProfile{ServerType: "haproxy", CertPath: "/etc/haproxy/certs/site.pem", KeyPath: "/etc/haproxy/certs/unused.key"}
	res, err := h.exec.ExecuteRenewal(context.Background(), h.fp, sshTestTarget(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if installSucceeded(res.InstallOutcome) {
		t.Fatalf("install should have failed: %+v", res)
	}
	if !h.target.ran("rm -f -- /etc/haproxy/certs/site.pem") {
		t.Fatalf("rm should target the combined CertPath: %v", h.target.commands)
	}
	h.noPrivateKeyOnTarget(t)
}
