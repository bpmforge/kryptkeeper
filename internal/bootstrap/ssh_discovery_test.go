// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/discovery/scanner"
)

// W24-08: agentless SSH discovery wired into the hub.

// sshDiscFakeExec is an in-memory agentinstall.Executor whose find output
// is scripted per root.
type sshDiscFakeExec struct {
	files   map[string][]byte
	findOut map[string]string
	findErr error
}

func (f *sshDiscFakeExec) Exists(p string) bool { _, ok := f.files[p]; return ok }
func (f *sshDiscFakeExec) ReadFile(p string) ([]byte, error) {
	b, ok := f.files[p]
	if !ok {
		return nil, os.ErrPermission
	}
	return b, nil
}
func (f *sshDiscFakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *sshDiscFakeExec) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "find" || len(args) == 0 {
		return nil, fmt.Errorf("unexpected command %s", name)
	}
	if out, ok := f.findOut[args[0]]; ok {
		return []byte(out), f.findErr
	}
	// What real find prints (combined stdout+stderr) for an absent root.
	return []byte(fmt.Sprintf("find: '%s': No such file or directory\n", args[0])), errors.New("exit status 1")
}

func certFilePEM(t *testing.T, cn string) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testX509(t, cn).Raw})
}

// sshCredentialJSONWithMarker is testSSHCredentialJSON with a unique marker
// carried in the private key PEM's headers (ignored by the key parser), so a
// leak anywhere is detectable by substring.
func sshCredentialJSONWithMarker(t *testing.T, marker string) []byte {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"X-Marker": marker}, Bytes: der})
	hostKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hostPub, err := ssh.NewPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(sshCredentialPayload{
		PrivateKeyPEM: string(keyPEM),
		HostPublicKey: string(ssh.MarshalAuthorizedKey(hostPub)),
		User:          "deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

type sshScanFixture struct {
	targets *sqliteManagedTargetStore
	creds   *sqliteOutboundCredentialStore
	target  ManagedTarget
	run     sshTargetScanner
	dialed  int
	cfg     agentinstall.SSHTarget
	audit   *sshRecordingAudit
}

func newSSHScanFixture(t *testing.T, marker string, exec agentinstall.Executor, dialErr error) *sshScanFixture {
	t.Helper()
	f := &sshScanFixture{}
	f.targets, f.creds = winrmTestStores(t)
	if _, err := f.creds.Create(context.Background(), "cred-ssh", "linux", CredentialTypeSSHKey, "", sshCredentialJSONWithMarker(t, marker)); err != nil {
		t.Fatal(err)
	}
	tgt, err := f.targets.Create(context.Background(), ManagedTarget{ID: "t-ssh", Name: "linux", Host: "192.0.2.20",
		DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-ssh"})
	if err != nil {
		t.Fatal(err)
	}
	f.target = tgt
	f.audit = &sshRecordingAudit{}
	f.run = newSSHTargetScanner(f.targets, f.creds, f.audit, func(_ context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		f.dialed++
		f.cfg = cfg
		if dialErr != nil {
			return nil, nil, dialErr
		}
		return exec, func() error { return nil }, nil
	})
	return f
}

func TestSSHScanner_ImportsCertsAndWarnsOnUnreadable(t *testing.T) {
	exec := &sshDiscFakeExec{
		files: map[string][]byte{
			"/etc/ssl/certs/a.crt":          certFilePEM(t, "a.example.com"),
			"/etc/ssl/certs/b.pem":          certFilePEM(t, "b.example.com"),
			"/etc/ssh/ssh_host_ed25519.pub": []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 root@host"),
		},
		findOut: map[string]string{
			"/etc/ssl/certs": "/etc/ssl/certs/a.crt\n/etc/ssl/certs/b.pem\n/etc/ssl/certs/locked/c.crt",
			"/etc/ssh":       "/etc/ssh/ssh_host_ed25519.pub",
		},
	}
	f := newSSHScanFixture(t, "MARKER-1", exec, nil)
	res := f.run(context.Background(), f.target.ID)

	if res.Status != "completed" || res.CertsFound != 2 || res.ErrorCount != 1 || len(res.Endpoints) != 1 {
		t.Fatalf("result: %+v", res)
	}
	ep := res.Endpoints[0]
	if ep.Error != "" || ep.Host != "192.0.2.20" || ep.Port != 22 || ep.Protocol != "ssh" || !ep.Reachable {
		t.Fatalf("endpoint: %+v", ep)
	}
	// W34-10: permission-denied paths fold into one INSUFFICIENT_PRIVILEGE
	// finding carrying the account, the mode, the paths and the fix.
	if len(ep.Findings) != 1 || !strings.HasPrefix(ep.Findings[0], "INSUFFICIENT_PRIVILEGE: ") ||
		!strings.Contains(ep.Findings[0], "user=deploy; mode=none; unreadable=1; paths=/etc/ssl/certs/locked/c.crt") ||
		!strings.Contains(ep.Findings[0], "fix=") || !strings.Contains(ep.Findings[0], "sudo password") {
		t.Fatalf("findings: %v", ep.Findings)
	}
	if ep.HostObs == nil || ep.HostObs.PrivilegeMode != "none" || ep.HostObs.UnreadableCount != 1 {
		t.Fatalf("scan state not carried: %+v", ep.HostObs)
	}
	if len(ep.HostKeyAlgorithms) != 1 || ep.HostKeyAlgorithms[0] != "ssh-ed25519" {
		t.Fatalf("host key algorithms: %v", ep.HostKeyAlgorithms)
	}
	if ep.Certs[0].CommonName != "a.example.com" || ep.Certs[0].SourcePath != "/etc/ssl/certs/a.crt" || ep.Certs[0].Raw == nil {
		t.Fatalf("cert not mapped with raw DER and source path: %+v", ep.Certs[0])
	}
	if f.cfg.User != "deploy" || f.cfg.Port != 22 || f.cfg.HostKeyCallback == nil || len(f.cfg.HostKeyAlgorithms) == 0 {
		t.Fatalf("dial must carry the credential's user, a pinned callback and algorithms: %+v", f.cfg)
	}
}

func TestSSHScanner_NothingReadableIsFailed(t *testing.T) {
	exec := &sshDiscFakeExec{
		findOut: map[string]string{"/etc/ssl/certs": "/etc/ssl/certs/locked.crt"},
	}
	f := newSSHScanFixture(t, "MARKER-2", exec, nil)
	res := f.run(context.Background(), f.target.ID)
	if res.Status != "failed" || res.Endpoints[0].Error == "" || res.CertsFound != 0 {
		t.Fatalf("zero certs plus errors must be a failed endpoint: %+v", res)
	}
}

func TestSSHScanner_RefusesNonSSHTarget(t *testing.T) {
	f := newSSHScanFixture(t, "MARKER-3", &sshDiscFakeExec{}, nil)
	agent, err := f.targets.Create(context.Background(), ManagedTarget{ID: "t-agent", Name: "a", Host: "h", DiscoveryMode: "agent", InstallMode: "agent", RenewalMethod: "manual", CredentialRef: "cred-ssh"})
	if err != nil {
		t.Fatal(err)
	}
	none, err := f.targets.Create(context.Background(), ManagedTarget{ID: "t-none", Name: "n", Host: "h", DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-ssh"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{agent.ID, none.ID, "missing"} {
		res := f.run(context.Background(), id)
		if res.Status != "failed" || res.Endpoints[0].Error == "" {
			t.Fatalf("%s must be refused: %+v", id, res)
		}
	}
	if f.dialed != 0 {
		t.Fatalf("a refused target must never be dialed, dialed %d times", f.dialed)
	}
}

func TestSSHScanner_MissingCredential(t *testing.T) {
	f := newSSHScanFixture(t, "MARKER-4", &sshDiscFakeExec{}, nil)
	noRef, _ := f.targets.Create(context.Background(), ManagedTarget{ID: "t-noref", Name: "n", Host: "h", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual"})
	_, _ = f.creds.Create(context.Background(), "cred-tok", "tok", CredentialTypeAPIToken, "", []byte(`{"token":"t"}`))
	wrongType, _ := f.targets.Create(context.Background(), ManagedTarget{ID: "t-wrong", Name: "w", Host: "h", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-tok"})
	dangling, _ := f.targets.Create(context.Background(), ManagedTarget{ID: "t-dangling", Name: "d", Host: "h", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "nope"})
	for _, id := range []string{noRef.ID, wrongType.ID, dangling.ID} {
		if res := f.run(context.Background(), id); res.Status != "failed" || res.CertsFound != 0 {
			t.Fatalf("%s: %+v", id, res)
		}
	}
	if f.dialed != 0 {
		t.Fatal("no credential, no dial")
	}
}

// A refused dial that is not a host-key mismatch is an ordinary failed dial
// and must still import nothing.
func TestSSHScanner_DialFailureImportsNothing(t *testing.T) {
	f := newSSHScanFixture(t, "MARKER-5", &sshDiscFakeExec{}, errors.New("ssh: handshake failed: host key mismatch"))
	res := f.run(context.Background(), f.target.ID)
	if res.Status != "failed" || res.CertsFound != 0 || !strings.Contains(res.Endpoints[0].Error, "host key mismatch") {
		t.Fatalf("result: %+v", res)
	}
	if len(res.Endpoints[0].Certs) != 0 {
		t.Fatal("a failed handshake must import no certs")
	}
}

func TestSSHScanner_HostKeyMismatchImportsNothing(t *testing.T) {
	mm := &agentinstall.HostKeyMismatchError{Host: "192.0.2.20:22", Pinned: "SHA256:pinnedpinned", Observed: "SHA256:observedobserved"}
	// The dial wraps the mismatch the way ssh.NewClientConn and NewSSHExecutor do.
	exec := &sshDiscFakeExec{
		files:   map[string][]byte{"/etc/ssl/certs/a.crt": certFilePEM(t, "a.example.com")},
		findOut: map[string]string{"/etc/ssl/certs": "/etc/ssl/certs/a.crt"},
	}
	f := newSSHScanFixture(t, "MARKER-MM", exec, fmt.Errorf("ssh executor: handshake: %w", fmt.Errorf("ssh: handshake failed: %w", mm)))
	res := f.run(context.Background(), f.target.ID)
	if res.Status != "failed" || res.CertsFound != 0 || len(res.Endpoints[0].Certs) != 0 {
		t.Fatalf("a host-key mismatch must import nothing: %+v", res)
	}
	if e := res.Endpoints[0].Error; !strings.Contains(e, mm.Pinned) || !strings.Contains(e, mm.Observed) {
		t.Fatalf("error must name both fingerprints: %q", e)
	}
	if len(f.audit.entries) != 1 || f.audit.entries[0].Action != "target.hostkey.mismatch" ||
		f.audit.entries[0].Outcome != AuditOutcomeFailure || f.audit.entries[0].ResourceID != f.target.ID {
		t.Fatalf("audit: %+v", f.audit.entries)
	}
}

// The stored pin on the target, not the credential's embedded key, is what the
// dial is given (W24-09).
func TestSSHScanner_StoredPinOverridesCredentialKey(t *testing.T) {
	f := newSSHScanFixture(t, "MARKER-PIN", &sshDiscFakeExec{findOut: map[string]string{}}, nil)
	pinned := testHostKey(t)
	line := agentinstall.HostKeyLine(pinned)
	if _, err := f.targets.Update(context.Background(), f.target.ID, ManagedTargetUpdate{SSHHostKey: &line}); err != nil {
		t.Fatal(err)
	}
	f.run(context.Background(), f.target.ID)
	if f.dialed != 1 || len(f.cfg.HostKeyAlgorithms) != 1 || f.cfg.HostKeyAlgorithms[0] != pinned.Type() {
		t.Fatalf("dial cfg: %+v", f.cfg)
	}
	// The callback accepts the stored key and refuses any other.
	if err := f.cfg.HostKeyCallback("h:22", nil, pinned); err != nil {
		t.Fatalf("stored pin refused: %v", err)
	}
	var mm *agentinstall.HostKeyMismatchError
	if err := f.cfg.HostKeyCallback("h:22", nil, testHostKey(t)); !errors.As(err, &mm) {
		t.Fatalf("a different key must be a mismatch, got %v", err)
	}
}

func TestSSHScanSourcePathPersistedOnLink(t *testing.T) {
	stubEndpointAudit(t)
	db := setupIntegrationDB(t)
	store := migratedDiscoveryStore(t, db)
	c := testX509(t, "src.example.com")
	dc := scanner.CertToDiscovered(c, "192.0.2.20", true)
	dc.SourcePath = "/etc/ssl/certs/src.crt"
	ep := scanner.DiscoveredEndpoint{Host: "192.0.2.20", Port: 22, Protocol: "ssh", Reachable: true, Certs: []scanner.DiscoveredCert{dc}}
	if _, err := store.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{ep}); err != nil {
		t.Fatal(err)
	}
	// A later network scan carries no path and must not erase it.
	plain := ep
	plain.Certs = []scanner.DiscoveredCert{scanner.CertToDiscovered(c, "192.0.2.20", true)}
	if _, err := store.upsertScanResults(context.Background(), []scanner.DiscoveredEndpoint{plain}); err != nil {
		t.Fatal(err)
	}
	res, err := store.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, e := range res.Endpoints {
		for _, mc := range e.MappedCerts {
			got = mc.SourcePath
		}
	}
	if got != "/etc/ssl/certs/src.crt" {
		t.Fatalf("source_path = %q", got)
	}
}

func TestSSHScanner_CredentialNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	const marker = "KK-UNIQUE-KEY-MARKER-7f3a9c"

	exec := &sshDiscFakeExec{
		files:   map[string][]byte{"/etc/ssl/certs/a.crt": certFilePEM(t, "a.example.com")},
		findOut: map[string]string{"/etc/ssl/certs": "/etc/ssl/certs/a.crt\n/etc/ssl/certs/denied.crt"},
	}
	okF := newSSHScanFixture(t, marker, exec, nil)
	results := []any{okF.run(context.Background(), okF.target.ID)}

	dialF := newSSHScanFixture(t, marker, exec, errors.New("dial tcp: connection refused"))
	results = append(results, dialF.run(context.Background(), dialF.target.ID))

	// A credential whose key is unparseable: the parse error path.
	badF := newSSHScanFixture(t, marker, exec, nil)
	if _, err := badF.creds.Create(context.Background(), "cred-bad", "bad", CredentialTypeSSHKey, "",
		[]byte(`{"private_key_pem":"`+marker+` not a key","host_public_key":"ssh-ed25519 AAAA","user":"u"}`)); err != nil {
		t.Fatal(err)
	}
	bad, _ := badF.targets.Create(context.Background(), ManagedTarget{ID: "t-bad", Name: "b", Host: "h", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-bad"})
	results = append(results, badF.run(context.Background(), bad.ID))

	// Garbage that is not even JSON: the unmarshal error path.
	if _, err := badF.creds.Create(context.Background(), "cred-junk", "junk", CredentialTypeSSHKey, "", []byte(marker+" not json")); err != nil {
		t.Fatal(err)
	}
	junk, _ := badF.targets.Create(context.Background(), ManagedTarget{ID: "t-junk", Name: "j", Host: "h", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-junk"})
	results = append(results, badF.run(context.Background(), junk.ID))

	for i, r := range results {
		blob, _ := json.Marshal(r)
		if strings.Contains(string(blob), marker) || strings.Contains(fmt.Sprintf("%+v", r), marker) {
			t.Fatalf("result %d carries credential bytes", i)
		}
	}
	if strings.Contains(buf.String(), marker) {
		t.Fatalf("credential bytes reached the log:\n%s", buf.String())
	}
	if buf.Len() == 0 {
		t.Fatal("failure paths must log something, otherwise this test proves nothing")
	}
}

// ---- handler ----

type sshRecordingAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (r *sshRecordingAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: []AuditEntry{}, Limit: 25}, nil
}
func (r *sshRecordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	return nil
}

func TestHandlerScanTypeSSH_AcceptsSSHTargetRefusesOthers(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "true")
	targets, _ := winrmTestStores(t)
	mk := func(id, tenant, install string) {
		if _, err := targets.Create(context.Background(), ManagedTarget{ID: id, Name: id, Host: id + ".example.com", DiscoveryMode: "network", InstallMode: install, RenewalMethod: "manual", Tenant: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	mk("t-ssh", "acme", "ssh")
	mk("t-agent", "acme", "agent")
	mk("t-other", "globex", "ssh")

	auth := NewAuthenticatorFromEnv()
	rec := &recordingDiscoveryProvider{}
	audit := &sshRecordingAudit{}
	mux := http.NewServeMux()
	registerDiscoveryHandlersWithTargets(mux, auth, rec, nil, audit, targets)
	_, key, err := auth.CreateAPIKey("tenant-admin", "acme-admin", "pki-admin", nil, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	if w := post(`{"scan_type":"ssh","target":"t-ssh"}`); w.Code != http.StatusCreated {
		t.Fatalf("ssh target: want 201, got %d: %s", w.Code, w.Body.String())
	}
	if got := rec.snapshot(); len(got) != 1 || got[0] != "ssh|t-ssh" {
		t.Fatalf("scan not filed: %v", got)
	}
	for body, want := range map[string]int{
		`{"scan_type":"ssh","target":"t-agent"}`:            http.StatusBadRequest,
		`{"scan_type":"ssh","target":"nope"}`:               http.StatusNotFound,
		`{"scan_type":"ssh","target":"t-other"}`:            http.StatusNotFound,
		`{"scan_type":"ssh","target":"t-ssh","ports":[22]}`: http.StatusBadRequest,
	} {
		if w := post(body); w.Code != want {
			t.Fatalf("%s: want %d, got %d: %s", body, want, w.Code, w.Body.String())
		}
	}
	if got := rec.snapshot(); len(got) != 1 {
		t.Fatalf("a refused request must not file a scan: %v", got)
	}
	if blob, _ := json.Marshal(audit.entries); len(audit.entries) == 0 || strings.Contains(string(blob), "PRIVATE KEY") {
		t.Fatalf("audit entries: %s", blob)
	}
}

// ---- scheduler ----

func TestDiscoverySchedulerAddsOneSSHScanPerSSHTarget(t *testing.T) {
	targets, _ := winrmTestStores(t)
	mk := func(id, disc, install string) {
		if _, err := targets.Create(context.Background(), ManagedTarget{ID: id, Name: id, Host: id + ".example.com", DiscoveryMode: disc, InstallMode: install, RenewalMethod: "manual"}); err != nil {
			t.Fatal(err)
		}
	}
	mk("ssh-1", "network", "ssh")
	mk("ssh-2", "agent", "ssh")
	mk("win-1", "winrm", "iis")
	mk("agent-1", "agent", "agent")
	mk("ssh-off", "none", "ssh")

	rec := &recordingDiscoveryProvider{}
	sched := newDiscoveryScheduler(rec, time.Hour, nil, nil).WithManagedTargets(targets)
	sched.runOnce(context.Background())

	calls := rec.snapshot()
	if countCalls(calls, "ssh|ssh-1") != 1 || countCalls(calls, "ssh|ssh-2") != 1 {
		t.Fatalf("one ssh scan per ssh-mode target: %v", calls)
	}
	if countCalls(calls, "winrm|win-1") != 1 || len(calls) != 3 {
		t.Fatalf("winrm target scheduled once, agent/none targets never: %v", calls)
	}
}

func TestNewAgentlessSSHScannerHasProductionCaller(t *testing.T) {
	out, err := exec.Command("grep", "-rl", "--include=*.go", "NewAgentlessSSHScanner", "../../internal", "../../cmd").Output()
	if err != nil {
		t.Fatalf("grep: %v", err)
	}
	found := false
	for _, f := range strings.Fields(string(out)) {
		if !strings.HasSuffix(f, "_test.go") && !strings.HasSuffix(f, "agentless_ssh.go") {
			found = true
		}
	}
	if !found {
		t.Fatalf("NewAgentlessSSHScanner has no production caller outside agentless_ssh.go: %s", out)
	}
}

// ssListenerExec answers the listener sweep on top of the find fake.
type ssListenerExec struct{ *sshDiscFakeExec }

func (e ssListenerExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "ss" {
		return []byte("LISTEN 0 1 *:8443 *:* users:((\"java\",pid=9,fd=1))\n"), nil
	}
	return e.sshDiscFakeExec.Run(ctx, name, args...)
}

func (e ssListenerExec) ReadFile(p string) ([]byte, error) {
	switch p {
	case "/proc/9/status":
		return []byte("Name:\tjava\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n"), nil
	case "/proc/9/cmdline":
		return []byte("java\x00-Dcatalina.base=/opt/tomcat\x00"), nil
	}
	return e.sshDiscFakeExec.ReadFile(p)
}

func TestSSHScanner_CarriesListenerObservations(t *testing.T) {
	exec := ssListenerExec{&sshDiscFakeExec{findOut: map[string]string{"/etc/ssl": ""}}}
	f := newSSHScanFixture(t, "mk-listen", exec, nil)
	res := f.run(context.Background(), f.target.ID)
	if len(res.Endpoints) != 1 || res.Endpoints[0].HostObs == nil {
		t.Fatalf("scan result lost the host observations: %+v", res)
	}
	obs := res.Endpoints[0].HostObs
	if obs.TargetID != f.target.ID || !obs.ListenersScanned || len(obs.Listeners) != 1 {
		t.Fatalf("%+v", obs)
	}
	if got := obs.Listeners[0]; got.Port != 8443 || got.Evidence.Tech != "tomcat" || got.Evidence.Weight != 100 {
		t.Fatalf("listener evidence = %+v", got)
	}
}

// postureSSHExec scripts a host with a root-owned Tomcat keystore, a
// world-readable key, and a tomcat process running as uid 1001. It records
// every ReadFile so the test can prove key files are never read.
type postureSSHExec struct {
	*sshDiscFakeExec
	reads []string
}

func (e *postureSSHExec) ReadFile(p string) ([]byte, error) {
	e.reads = append(e.reads, p)
	switch p {
	case "/proc/9/status":
		return []byte("Name:\tjava\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n"), nil
	case "/proc/9/cmdline":
		return []byte("java\x00-Dcatalina.base=/opt/tomcat\x00"), nil
	}
	return e.sshDiscFakeExec.ReadFile(p)
}

func (e *postureSSHExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "ss":
		return []byte("LISTEN 0 1 *:8443 *:* users:((\"java\",pid=9,fd=1))\n"), nil
	case "stat":
		return []byte("0 0 600 root root /opt/tomcat/conf/keystore.jks\n0 0 644 root root /opt/tomcat/conf/tls.key\n"), nil
	case "readlink", "id":
		return nil, errors.New("not available")
	}
	return e.sshDiscFakeExec.Run(ctx, name, args...)
}

func TestSSHScanner_PostureFindingsAndRenewalSeverity(t *testing.T) {
	base := &sshDiscFakeExec{
		files:   map[string][]byte{"/opt/tomcat/conf/keystore.jks": []byte("not a keystore")},
		findOut: map[string]string{"/opt/tomcat/conf": "/opt/tomcat/conf/keystore.jks\n/opt/tomcat/conf/tls.key\n"},
	}
	exec := &postureSSHExec{sshDiscFakeExec: base}
	f := newSSHScanFixture(t, "mk-posture", exec, nil)
	res := f.run(context.Background(), f.target.ID)
	if len(res.Endpoints) != 1 || res.Endpoints[0].HostObs == nil || !res.Endpoints[0].HostObs.FilesScanned {
		t.Fatalf("no posture on the scan result: %+v", res)
	}
	files := map[string]scanner.HostFile{}
	for _, hf := range res.Endpoints[0].HostObs.Files {
		files[hf.Path] = hf
	}
	jks, key := files["/opt/tomcat/conf/keystore.jks"], files["/opt/tomcat/conf/tls.key"]
	if jks.Posture != "privileged" || jks.ServiceTech != "tomcat" || jks.ServiceUID != 1001 || jks.Owner != "root" {
		t.Fatalf("jks = %+v", jks)
	}
	if key.Kind != "key" || len(key.Findings) == 0 {
		t.Fatalf("key = %+v", key)
	}
	for _, r := range exec.reads {
		if r == "/opt/tomcat/conf/tls.key" {
			t.Fatal("the key file was read")
		}
	}
	var gotPriv, gotKey bool
	for _, fd := range res.Endpoints[0].Findings {
		switch scanner.FindingCode(fd) {
		case scanner.FindingPrivilegedInstallPath:
			gotPriv = true
			if scanner.IsHighSeverityFinding(fd) {
				t.Fatalf("a target that does not auto-renew must stay medium: %s", fd)
			}
		case scanner.FindingKeyWorldReadable:
			gotKey = true
		}
	}
	if !gotPriv || !gotKey {
		t.Fatalf("endpoint findings = %v", res.Endpoints[0].Findings)
	}
}

func TestMarkRenewalBlockedFindings(t *testing.T) {
	mk := func() *scanner.ScanResult {
		return &scanner.ScanResult{Endpoints: []scanner.DiscoveredEndpoint{{
			Findings: []string{"PRIVILEGED_INSTALL_PATH: path=/a", "KEY_WORLD_READABLE: path=/b"},
			HostObs:  &scanner.HostObservations{Files: []scanner.HostFile{{Findings: []string{"PRIVILEGED_INSTALL_PATH: path=/a"}}}},
		}}}
	}
	for name, c := range map[string]struct {
		autoRenew  bool
		privileged bool
		high       bool
	}{
		"auto-renew, plain credential":      {true, false, true},
		"auto-renew, privileged credential": {true, true, false},
		"manual renewal":                    {false, false, false},
		"manual renewal, privileged":        {false, true, false},
	} {
		r := mk()
		markRenewalBlockedFindings(r, c.autoRenew, c.privileged)
		ep := r.Endpoints[0]
		if got := scanner.IsHighSeverityFinding(ep.Findings[0]); got != c.high {
			t.Errorf("%s: endpoint finding high = %v, want %v (%q)", name, got, c.high, ep.Findings[0])
		}
		if got := scanner.IsHighSeverityFinding(ep.HostObs.Files[0].Findings[0]); got != c.high {
			t.Errorf("%s: file finding high = %v, want %v", name, got, c.high)
		}
	}
}
