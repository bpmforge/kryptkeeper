// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	kkacme "kryptkeeper/internal/acme"
	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/keystore"
)

// W11-04: the ACME connector against the IN-REPO ACME server, in-process —
// order, http-01 solve, finalize, download, inventory landing. Zero live
// network (playbook rule): the server validates http-01 by GETting
// http://<identifier>/..., and identifiers must be DNS names on port 80, so
// the server's http-01 dial seam routes the test name to the connector's
// 127.0.0.1:<solver-port> listener. The seam replaces only the dial; the
// fetch, KeyAuthorization comparison and order state machine are real.

const acmeTestHost = "solver.example.test"

// newTestUpstreamACME starts an in-repo ACME server whose http-01 validation
// resolves acmeTestHost to solverAddr.
func newTestUpstreamACME(t *testing.T, solverAddr string) (baseURL string) {
	return newTestUpstreamACMEWrapped(t, solverAddr, nil)
}

// newTestUpstreamACMEWrapped lets a test put a handler in front of the server
// (same base URL, so directory links stay valid).
func newTestUpstreamACMEWrapped(t *testing.T, solverAddr string, wrap func(http.Handler) http.Handler) (baseURL string) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("Upstream ACME Root", pkix.Name{CommonName: "Upstream ACME Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root CA: %v", err)
	}
	ts := httptest.NewServer(nil)
	srv := kkacme.NewServerWithStore(ts.URL, engine, rootCA.ID, kkacme.NewMemStore(), ca.NewMemRevocationStore())
	srv.SetHTTP01DialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host != acmeTestHost {
			return nil, fmt.Errorf("test dial seam: %q is not routed", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, solverAddr)
	})
	ts.Config.Handler = srv.Handler()
	if wrap != nil {
		ts.Config.Handler = wrap(ts.Config.Handler)
	}
	t.Cleanup(ts.Close)
	return ts.URL
}

// pebbleStyleFinalize makes finalize answer like Pebble: order status
// "processing", no certificate yet and no Location header. The order itself
// is still really issued by the in-repo server and valid on the next GET.
func pebbleStyleFinalize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/acme/finalize/") {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		var order map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &order) != nil {
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		order["status"] = "processing"
		delete(order, "certificate")
		for k, v := range rec.Header() {
			if k != "Location" && k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(order)
	})
}

// freeLocalPort reserves then releases a port — the standard test trick; the
// tiny race is acceptable in-process.
func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func newACMETestConnector(t *testing.T, directoryURL string, solverPort int, inventory CertificateProvider) connectors.IssuerConnector {
	t.Helper()
	cfg, _ := json.Marshal(acmeConnectorConfig{
		DirectoryURL: directoryURL + "/acme/directory",
		Email:        "ops@example.com",
		HTTP01Listen: fmt.Sprintf("127.0.0.1:%d", solverPort),
	})
	conn := NewACMEIssuerConnector(ConnectorRecord{
		ID: "conn-acme-test", Name: "Upstream Test CA", Type: "acme",
		ConfigJSON: string(cfg),
	}, inventory, nil)
	conn.(*acmeIssuerConnector).allowLoopbackForTest = true // upstream is http on loopback
	return conn
}

func TestACMEConnectorIssuesEndToEnd(t *testing.T) {
	solverPort := freeLocalPort(t)
	upstream := newTestUpstreamACME(t, fmt.Sprintf("127.0.0.1:%d", solverPort))
	db := setupIntegrationDB(t)
	inventory, _ := newIntegrationCAProvider(t, db)
	identifier := acmeTestHost

	conn := newACMETestConnector(t, upstream, solverPort, inventory)
	if h := conn.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("upstream directory should probe healthy: %+v", h)
	}

	res, err := conn.Issue(context.Background(), connectors.IssueRequest{
		CSRPEM: generateTestCSRPEM(t, identifier),
		TeamID: "team-acme",
	})
	if err != nil {
		t.Fatalf("acme issue: %v", err)
	}
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") || res.FingerprintSHA256 == "" {
		t.Fatalf("incomplete issue result: fp=%q pemlen=%d", res.FingerprintSHA256, len(res.CertificatePEM))
	}

	// The upstream-issued leaf is OUR inventory now: synced, managed, and
	// wired to renew through this connector.
	item, ok, err := inventory.GetCertificate(context.Background(), res.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("upstream cert not in inventory: ok=%v err=%v", ok, err)
	}
	if item.Origin != "synced" || item.ManagementState != "managed" ||
		item.RenewalMethod != "acme" || item.RenewalConnectorID != "conn-acme-test" {
		t.Fatalf("estate stamp wrong: origin=%q state=%q method=%q conn=%q",
			item.Origin, item.ManagementState, item.RenewalMethod, item.RenewalConnectorID)
	}
	if item.IssuerCN != "Upstream ACME Root CA" {
		t.Fatalf("leaf not issued by the upstream CA: issuer=%q", item.IssuerCN)
	}
}

// W27-38: Pebble answers finalize with "processing" and no Location header;
// x/crypto/acme then fails with `Post ""` unless the connector falls back to
// the order URL it kept from AuthorizeOrder.
func TestACMEConnectorFinalizeWithoutLocationHeader(t *testing.T) {
	solverPort := freeLocalPort(t)
	upstream := newTestUpstreamACMEWrapped(t, fmt.Sprintf("127.0.0.1:%d", solverPort), pebbleStyleFinalize)
	db := setupIntegrationDB(t)
	inventory, _ := newIntegrationCAProvider(t, db)
	conn := newACMETestConnector(t, upstream, solverPort, inventory)
	res, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost), TeamID: "team-acme"})
	if err != nil {
		t.Fatalf("issue without finalize Location: %v", err)
	}
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") || res.FingerprintSHA256 == "" {
		t.Fatalf("incomplete result: %+v", res)
	}
}

// A failed challenge surfaces the CA's problem, never a silent zero result:
// the identifier points at a port nobody serves.
func TestACMEConnectorSurfacesChallengeFailure(t *testing.T) {
	solverPort := freeLocalPort(t)
	deadPort := freeLocalPort(t) // nothing listens here
	// The identifier routes to the dead port, not the connector's solver.
	upstream := newTestUpstreamACME(t, fmt.Sprintf("127.0.0.1:%d", deadPort))

	conn := newACMETestConnector(t, upstream, solverPort, nil)
	_, err := conn.Issue(context.Background(), connectors.IssueRequest{
		CSRPEM: generateTestCSRPEM(t, acmeTestHost),
	})
	if err == nil {
		t.Fatal("expected challenge validation to fail for an unreachable identifier")
	}
	if !strings.Contains(err.Error(), "challenge validation") {
		t.Fatalf("failure should name the phase, got: %v", err)
	}
}

// The renewal executor routes certificates carrying a renewal_connector_id
// THROUGH the registry — the upstream half of acceptance #2. A fake
// connector keeps this test fast; the real ACME path is covered above.
func TestRenewalExecutorRoutesUpstreamConnector(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-upstream",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{
		ManagementState: "managed", RenewalMethod: "acme", RenewalConnectorID: "conn-fake-up",
	}); err != nil {
		t.Fatalf("estate update: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	upstreamPEM := estateTestCertPEM(t)
	registry := connectors.NewRegistry()
	registry.Register(recordingConnector{id: "conn-fake-up", pem: upstreamPEM})
	exec.WithConnectorRegistry(registry)
	// The fake upstream chain differs from the internal CA's; verify against
	// what the installer wrote (same closure shape as the engine tests).
	exec.verifier = func(_ context.Context, _ string) (string, error) {
		return leafFingerprint(fake.files["/etc/nginx/tls/renewed.crt"])
	}

	result, err := exec.ExecuteRenewal(ctx, fp, sshTestTarget(), sshTestProfile())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.Renewed || result.NewFingerprint != "fp-upstream" {
		t.Fatalf("upstream path not taken: %+v", result)
	}
	// The installed bytes are the CONNECTOR's chain, not an internal
	// re-issue — the routing proof.
	installedFP, err := leafFingerprint(fake.files["/etc/nginx/tls/renewed.crt"])
	if err != nil {
		t.Fatalf("installed leaf: %v", err)
	}
	wantFP, err := leafFingerprint([]byte(upstreamPEM))
	if err != nil {
		t.Fatalf("want leaf: %v", err)
	}
	if installedFP != wantFP {
		t.Fatalf("installed %s, want the upstream connector's %s", installedFP, wantFP)
	}
}

type recordingConnector struct {
	id  string
	pem string
}

func (r recordingConnector) ID() string     { return r.id }
func (r recordingConnector) Type() string   { return "acme" }
func (r recordingConnector) Origin() string { return "synced" }
func (r recordingConnector) Health(context.Context) connectors.Health {
	return connectors.Health{Status: "healthy"}
}
func (r recordingConnector) Issue(context.Context, connectors.IssueRequest) (connectors.IssueResult, error) {
	return connectors.IssueResult{FingerprintSHA256: "fp-upstream", CertificatePEM: r.pem}, nil
}

// --- W27-23: fleet http-01 -------------------------------------------------

// fleetFakeExecutor stands in for a target host's filesystem and shell.
type fleetFakeExecutor struct {
	mu    sync.Mutex
	files map[string][]byte
	cmds  []string
}

func newFleetFakeExecutor() *fleetFakeExecutor { return &fleetFakeExecutor{files: map[string][]byte{}} }

func (f *fleetFakeExecutor) Exists(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[path]
	return ok
}
func (f *fleetFakeExecutor) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (f *fleetFakeExecutor) WriteFile(path string, content []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = append([]byte(nil), content...)
	return nil
}
func (f *fleetFakeExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "rm" && len(args) == 3 && args[0] == "-f" && args[1] == "--" {
		delete(f.files, args[2])
	}
	return nil, nil
}
func (f *fleetFakeExecutor) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}
func (f *fleetFakeExecutor) fileCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.files)
}

type fleetFakeTargets struct {
	ManagedTargetStore
	target ManagedTarget
}

func (s fleetFakeTargets) Get(_ context.Context, id string) (ManagedTarget, error) {
	if id != s.target.ID {
		return ManagedTarget{}, fmt.Errorf("target %s not found", id)
	}
	return s.target, nil
}

// fleetWebServer is the target's web server on port 80: it serves whatever
// the fake executor holds under the webroot and records what it served.
type fleetWebServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	served map[string]string // request path -> body at request time
}

func newFleetWebServer(t *testing.T, fake *fleetFakeExecutor, webroot string, serveFiles bool) *fleetWebServer {
	t.Helper()
	w := &fleetWebServer{served: map[string]string{}}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := fake.ReadFile(webroot + r.URL.Path)
		if err != nil || !serveFiles {
			http.NotFound(rw, r)
			return
		}
		w.mu.Lock()
		w.served[r.URL.Path] = string(body)
		w.mu.Unlock()
		_, _ = rw.Write(body)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *fleetWebServer) addr() string { return strings.TrimPrefix(w.srv.URL, "http://") }

func fleetSSHTarget() ManagedTarget {
	return ManagedTarget{ID: "tgt-1", Name: "web-1", Host: "web-1.example.test", InstallMode: "ssh", CredentialRef: "cred-1"}
}

func newFleetACMEConnector(t *testing.T, directoryURL, hubListen, tenant string, hosts []acmeHTTP01Host, target ManagedTarget, fake *fleetFakeExecutor, dialed *[]agentinstall.SSHTarget) *acmeIssuerConnector {
	t.Helper()
	cfg, _ := json.Marshal(acmeConnectorConfig{
		DirectoryURL: directoryURL + "/acme/directory", Email: "ops@example.com",
		HTTP01Listen: hubListen, HTTP01Mode: "fleet", HTTP01Hosts: hosts,
	})
	creds := &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-1", CredentialType: CredentialTypeSSHKey},
		payload: testSSHCredentialJSON(t),
	}
	conn := NewACMEIssuerConnector(ConnectorRecord{
		ID: "conn-acme-fleet", Name: "Fleet", Type: "acme", ConfigJSON: string(cfg), Tenant: tenant,
	}, nil, creds).(*acmeIssuerConnector)
	conn.allowLoopbackForTest = true
	conn.targets = fleetFakeTargets{target: target}
	conn.fleetDial = func(_ context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		if cfg.HostKeyCallback == nil {
			t.Fatal("fleet dial must carry a pinned host key callback")
		}
		if dialed != nil {
			*dialed = append(*dialed, cfg)
		}
		return fake, func() error { return nil }, nil
	}
	return conn
}

func TestACMEConnectorFleetHTTP01ServedFromTargetHostNotHub(t *testing.T) {
	fake := newFleetFakeExecutor()
	web := newFleetWebServer(t, fake, defaultFleetWebroot, true)
	upstream := newTestUpstreamACME(t, web.addr())
	hubPort := freeLocalPort(t)

	var dialed []agentinstall.SSHTarget
	conn := newFleetACMEConnector(t, upstream, fmt.Sprintf("127.0.0.1:%d", hubPort), "",
		[]acmeHTTP01Host{{Domain: acmeTestHost, TargetID: "tgt-1"}}, fleetSSHTarget(), fake, &dialed)

	if _, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)}); err != nil {
		t.Fatalf("fleet issue: %v", err)
	}
	if len(dialed) != 1 || dialed[0].User != "deploy" || dialed[0].Port != 2222 || dialed[0].Host != "web-1.example.test" {
		t.Fatalf("dial config not taken from target/credential: %+v", dialed)
	}
	web.mu.Lock()
	defer web.mu.Unlock()
	if len(web.served) != 1 {
		t.Fatalf("target web server served %d challenge files, want 1: %v", len(web.served), web.served)
	}
	var path, body string
	for path, body = range web.served {
	}
	token := strings.TrimPrefix(path, fleetChallengePrefix)
	if token == path || !strings.HasPrefix(body, token+".") {
		t.Fatalf("served %q for %q, not a key authorization for that token", body, path)
	}
	if fake.fileCount() != 0 {
		t.Fatalf("challenge file left on the target: %v", fake.files)
	}
	cmds := fake.commands()
	wantRm := "rm -f -- " + defaultFleetWebroot + path
	if len(cmds) < 2 || cmds[0] != "mkdir -p -- "+defaultFleetWebroot+"/.well-known/acme-challenge" || cmds[len(cmds)-1] != wantRm {
		t.Fatalf("command log: %v (want mkdir first and %q last)", cmds, wantRm)
	}
	// Fleet mode never opens the hub listener.
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hubPort), time.Second); err == nil {
		c.Close()
		t.Fatal("hub listener was opened in fleet mode")
	}
}

func TestACMEConnectorFleetHTTP01CleansUpAfterFailedValidation(t *testing.T) {
	fake := newFleetFakeExecutor()
	web := newFleetWebServer(t, fake, defaultFleetWebroot, false) // answers 404
	upstream := newTestUpstreamACME(t, web.addr())
	conn := newFleetACMEConnector(t, upstream, "", "",
		[]acmeHTTP01Host{{Domain: acmeTestHost, TargetID: "tgt-1"}}, fleetSSHTarget(), fake, nil)

	_, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)})
	if err == nil || !strings.Contains(err.Error(), "challenge validation") {
		t.Fatalf("want a challenge validation failure, got %v", err)
	}
	if fake.fileCount() != 0 {
		t.Fatalf("challenge file left on the target after a failed validation: %v", fake.files)
	}
	cmds := fake.commands()
	if len(cmds) == 0 || !strings.HasPrefix(cmds[len(cmds)-1], "rm -f -- ") {
		t.Fatalf("no cleanup command: %v", cmds)
	}
}

func TestFleetSolverRefusals(t *testing.T) {
	ctx := context.Background()
	mk := func(tenant string, hosts []acmeHTTP01Host, target ManagedTarget) (*acmeIssuerConnector, *fleetFakeExecutor) {
		fake := newFleetFakeExecutor()
		return newFleetACMEConnector(t, "https://ca.invalid", "", tenant, hosts, target, fake, nil), fake
	}
	okHost := []acmeHTTP01Host{{Domain: "a.example.test", TargetID: "tgt-1"}}
	goodPath := fleetChallengePrefix + "tok_en-1"

	for name, hosts := range map[string][]acmeHTTP01Host{
		"wildcard":          {{Domain: "*.example.test", TargetID: "tgt-1"}},
		"relative webroot":  {{Domain: "a.example.test", TargetID: "tgt-1", Webroot: "var/www"}},
		"dotdot webroot":    {{Domain: "a.example.test", TargetID: "tgt-1", Webroot: "/var/../etc"}},
		"quoted webroot":    {{Domain: "a.example.test", TargetID: "tgt-1", Webroot: "/var/www/\"x\""}},
		"missing target id": {{Domain: "a.example.test"}},
	} {
		conn, _ := mk("", hosts, fleetSSHTarget())
		if _, err := newFleetHTTP01Solver(conn); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	emptyHosts, _ := mk("", nil, fleetSSHTarget())
	if _, err := newFleetHTTP01Solver(emptyHosts); err == nil {
		t.Error("empty http01_hosts accepted")
	}

	conn, fake := mk("", okHost, fleetSSHTarget())
	s, err := newFleetHTTP01Solver(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.put(ctx, "other.example.test", goodPath, "ka"); err == nil || !strings.Contains(err.Error(), "no http01_hosts entry") {
		t.Errorf("unknown identifier: %v", err)
	}
	for _, bad := range []string{fleetChallengePrefix + "../../etc/passwd", "/etc/passwd", fleetChallengePrefix + "a/b", fleetChallengePrefix, fleetChallengePrefix + "tok en"} {
		if err := s.put(ctx, "a.example.test", bad, "ka"); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
	if n := len(fake.commands()); n != 0 || fake.fileCount() != 0 {
		t.Errorf("rejected tokens reached the executor: %d commands", n)
	}

	nonSSH := fleetSSHTarget()
	nonSSH.InstallMode = "push"
	conn, fake = mk("", okHost, nonSSH)
	s, _ = newFleetHTTP01Solver(conn)
	if err := s.put(ctx, "a.example.test", goodPath, "ka"); err == nil || !strings.Contains(err.Error(), "needs an ssh-mode target") {
		t.Errorf("non-ssh target: %v", err)
	}
	foreign := fleetSSHTarget()
	foreign.Tenant = "globex"
	conn, fake2 := mk("acme", okHost, foreign)
	s, _ = newFleetHTTP01Solver(conn)
	if err := s.put(ctx, "a.example.test", goodPath, "ka"); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Errorf("cross-tenant target: %v", err)
	}
	if len(fake.commands())+len(fake2.commands()) != 0 {
		t.Error("refused targets reached the executor")
	}
}

func TestACMEConnectorLogsOrderAndAuthorizationStatus(t *testing.T) {
	var buf bytes.Buffer
	var logMu sync.Mutex
	log.SetOutput(&lockedWriter{mu: &logMu, w: &buf})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// Hub-listener path.
	solverPort := freeLocalPort(t)
	hubUpstream := newTestUpstreamACME(t, fmt.Sprintf("127.0.0.1:%d", solverPort))
	hubConn := newACMETestConnector(t, hubUpstream, solverPort, nil)
	if _, err := hubConn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)}); err != nil {
		t.Fatalf("hub issue: %v", err)
	}

	// Fleet path.
	fake := newFleetFakeExecutor()
	web := newFleetWebServer(t, fake, defaultFleetWebroot, true)
	fleetUpstream := newTestUpstreamACME(t, web.addr())
	fleetConn := newFleetACMEConnector(t, fleetUpstream, "", "",
		[]acmeHTTP01Host{{Domain: acmeTestHost, TargetID: "tgt-1"}}, fleetSSHTarget(), fake, nil)
	if _, err := fleetConn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)}); err != nil {
		t.Fatalf("fleet issue: %v", err)
	}
	logMu.Lock()
	all := buf.String()
	logMu.Unlock()
	t.Logf("acme log lines:\n%s", all)

	for _, id := range []string{"conn-acme-test", "conn-acme-fleet"} {
		for _, want := range []string{
			"acme connector " + id + ": order status=pending identifiers=1",
			"acme connector " + id + ": authorization status=pending identifier=" + acmeTestHost,
			"acme connector " + id + ": challenge accepted type=http-01 identifier=" + acmeTestHost,
			"acme connector " + id + ": authorization status=valid identifier=" + acmeTestHost,
			"acme connector " + id + ": order status=",
			"acme connector " + id + ": certificate issued identifiers=1",
		} {
			if !strings.Contains(all, want) {
				t.Errorf("log lacks %q", want)
			}
		}
	}

	// No key authorization, token, key material or credential payload.
	web.mu.Lock()
	defer web.mu.Unlock()
	forbidden := []string{"PRIVATE KEY", "private_key_pem", "host_public_key"}
	for path, body := range web.served {
		forbidden = append(forbidden, body, strings.TrimPrefix(path, fleetChallengePrefix))
	}
	for _, bad := range forbidden {
		if bad != "" && strings.Contains(all, bad) {
			t.Errorf("log leaks %q", bad)
		}
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
