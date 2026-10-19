// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/agentinstall"
)

// W17-07: coordinated rollout. The property that matters most is that
// ONE renewal reaches EVERY node — renewing per node would give each
// cluster member a different identity, which is the bug this feature
// exists to prevent.

// fakeCluster stands in for N F5 BIG-IP appliances — the canonical
// multi-node case where several LB nodes serve the SAME certificate.
// Each node records the certificate bytes it was handed.
type fakeCluster struct {
	mu       sync.Mutex
	received map[string][]byte // node name -> the PEM the appliance would serve
	// expectFingerprint is what the injected verifier reports back; the
	// pusher compares it against the fingerprint it pushed.
	expectFingerprint string
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{received: map[string][]byte{}}
}

func (c *fakeCluster) handler(node string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := readAllBody(r)
		// iControl file upload carries the raw PEM; that is the material
		// the appliance will serve, so record it per node.
		if strings.HasPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/") &&
			strings.HasSuffix(r.URL.Path, ".crt") {
			c.mu.Lock()
			c.received[node] = append([]byte(nil), raw...)
			// A correctly-installed appliance would serve exactly what it
			// was handed, so report that leaf's fingerprint back.
			if fp, err := leafFingerprint(raw); err == nil {
				c.expectFingerprint = fp
			}
			c.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}
}

func readAllBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}

func rolloutTestMux(t *testing.T, cluster *fakeCluster, nodeNames []string) (*http.ServeMux, CertificateProvider, string, []string) {
	t.Helper()
	return rolloutTestMuxAudit(t, cluster, nodeNames, stubAuditProvider{})
}

func rolloutTestMuxAudit(t *testing.T, cluster *fakeCluster, nodeNames []string, audit AuditProvider) (*http.ServeMux, CertificateProvider, string, []string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	certDB := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, certDB)
	caID := getFirstCAID(t, engine)

	storeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "rollout.db"))
	if err != nil {
		t.Fatalf("open store db: %v", err)
	}
	t.Cleanup(func() { storeDB.Close() })
	targetStore := &sqliteManagedTargetStore{db: storeDB}
	if err := targetStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("target schema: %v", err)
	}
	credStore := &sqliteOutboundCredentialStore{db: storeDB, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := credStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("cred schema: %v", err)
	}

	ctx := context.Background()
	var targetIDs []string
	for _, node := range nodeNames {
		srv := httptest.NewServer(cluster.handler(node))
		t.Cleanup(srv.Close)
		credJSON, _ := json.Marshal(map[string]string{
			"base_url": srv.URL, "username": "admin", "password": "pw",
			"client_ssl_profile": "cluster-clientssl",
		})
		if _, err := credStore.Create(ctx, "cred-"+node, node, CredentialTypeAPIToken, "", credJSON); err != nil {
			t.Fatalf("create credential: %v", err)
		}
		tgt, err := targetStore.Create(ctx, ManagedTarget{
			ID: "tgt-" + node, Name: node, Host: "127.0.0.1",
			DiscoveryMode: "none", InstallMode: "f5", RenewalMethod: "manual",
			CredentialRef: "cred-" + node,
		})
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
		targetIDs = append(targetIDs, tgt.ID)
	}

	// Inject a verifier so the canary gate can PASS without real TLS
	// listeners; it echoes back whatever fingerprint was pushed, which is
	// what a correctly-installed appliance would serve.
	prev := newRolloutExecutor
	newRolloutExecutor = func(certs CertificateProvider, creds OutboundCredentialStore) *RenewalExecutor {
		e := NewRenewalExecutor(certs, creds)
		e.verifier = func(_ context.Context, hostPort string) (string, error) {
			c := cluster
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.expectFingerprint, nil
		}
		return e
	}
	t.Cleanup(func() { newRolloutExecutor = prev })

	mux := http.NewServeMux()
	registerRolloutHandler(mux, auth, provider, targetStore, credStore, audit, nil)
	return mux, provider, caID, targetIDs
}

func postRollout(t *testing.T, mux *http.ServeMux, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/rollout", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// THE headline property: one renewal, identical material on every node.
func TestRolloutPushesOneIdenticalCertToEveryNode(t *testing.T) {
	cluster := newFakeCluster()
	nodes := []string{"node-a", "node-b", "node-c"}
	mux, provider, caID, targetIDs := rolloutTestMux(t, cluster, nodes)

	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "cluster.example.com", "cluster.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-cluster",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	specs := []map[string]any{}
	for i, id := range targetIDs {
		specs = append(specs, map[string]any{"target_id": id, "is_canary": i == 0})
	}
	rec := postRollout(t, mux, map[string]any{
		"fingerprint": issued.CertificateItem.FingerprintSHA256,
		"group":       "edge-cluster",
		"nodes":       specs,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if len(cluster.received) != len(nodes) {
		t.Fatalf("every node must receive the certificate, got %d of %d: %v",
			len(cluster.received), len(nodes), keysOf(cluster.received))
	}
	// All nodes must hold BYTE-IDENTICAL material. This is the invariant
	// that a per-node renewal would silently violate.
	var reference []byte
	for node, got := range cluster.received {
		if reference == nil {
			reference = got
			continue
		}
		if !bytes.Equal(reference, got) {
			t.Fatalf("node %s received DIFFERENT certificate material — the cluster would serve a split identity", node)
		}
	}
	// And it must be a real leaf, not an empty push.
	if block, _ := pem.Decode(reference); block == nil {
		t.Fatalf("nodes received non-PEM material (%d bytes)", len(reference))
	}
	// The response must never carry key material.
	if bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("rollout response leaked key material")
	}
	_ = hex.EncodeToString(sha256.New().Sum(nil))
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Tenant visibility is authorized for EVERY node BEFORE anything is
// installed: an unknown target must abort the whole rollout untouched.
func TestRolloutAuthorizesAllNodesBeforeTouchingAny(t *testing.T) {
	cluster := newFakeCluster()
	mux, provider, caID, targetIDs := rolloutTestMux(t, cluster, []string{"node-a"})

	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "c2.example.com", "c2.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-cluster",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	rec := postRollout(t, mux, map[string]any{
		"fingerprint": issued.CertificateItem.FingerprintSHA256,
		"group":       "mixed",
		"nodes": []map[string]any{
			{"target_id": targetIDs[0], "is_canary": true},
			{"target_id": "tgt-does-not-exist"},
		},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unresolvable node must abort the rollout, got %d", rec.Code)
	}
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if len(cluster.received) != 0 {
		t.Fatalf("NO node may be touched when authorization fails: %v", keysOf(cluster.received))
	}
}

func TestRolloutValidatesBodyAndAuth(t *testing.T) {
	mux, _, _, _ := rolloutTestMux(t, newFakeCluster(), []string{"node-a"})

	rec := postRollout(t, mux, map[string]any{"group": "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing fingerprint/nodes must be refused, got %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/rollout", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// --- W27-15: staged ssh rollout through the handler ---

// stagedFakeExecutor is an in-memory ssh host that emulates the cp/mv/rm
// commands the staged installer issues (renewalFakeExecutor ignores args).
type stagedFakeExecutor struct {
	mu         sync.Mutex
	files      map[string][]byte
	failReload bool
}

func (f *stagedFakeExecutor) Exists(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[p]
	return ok
}

func (f *stagedFakeExecutor) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (f *stagedFakeExecutor) WriteFile(p string, c []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = append([]byte(nil), c...)
	return nil
}

func (f *stagedFakeExecutor) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case name == "systemctl" && len(args) > 0 && args[0] == "reload" && f.failReload:
		return []byte("reload failed"), errors.New("reload failed")
	case name == "cp" && len(args) == 4:
		b, ok := f.files[args[2]]
		if !ok {
			return nil, errors.New("cp: no such file")
		}
		f.files[args[3]] = append([]byte(nil), b...)
	case name == "mv" && len(args) == 4:
		b, ok := f.files[args[2]]
		if !ok {
			return nil, errors.New("mv: no such file")
		}
		f.files[args[3]] = b
		delete(f.files, args[2])
	case name == "rm" && len(args) == 3:
		delete(f.files, args[2])
	}
	return []byte("ok"), nil
}

type stagedRolloutEnv struct {
	mux      *http.ServeMux
	provider CertificateProvider
	caID     string
	targets  []string
	hosts    map[string]*stagedFakeExecutor // by target host
	audit    *recordingAuditProvider
	dials    *int32
}

const stagedCertPath = "/etc/nginx/tls/site.crt"
const stagedKeyPath = "/etc/nginx/tls/site.key"

func stagedRolloutMux(t *testing.T, hostNames []string) *stagedRolloutEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	provider, engine := newIntegrationCAProvider(t, setupIntegrationDB(t))
	storeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "staged.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storeDB.Close() })
	targetStore := &sqliteManagedTargetStore{db: storeDB}
	credStore := &sqliteOutboundCredentialStore{db: storeDB, passphrase: []byte("handler-test-passphrase-32bytes!")}
	ctx := context.Background()
	if err := targetStore.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := credStore.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := credStore.Create(ctx, "cred-ssh", "ssh", CredentialTypeSSHKey, "", testSSHCredentialJSON(t)); err != nil {
		t.Fatal(err)
	}

	env := &stagedRolloutEnv{provider: provider, caID: getFirstCAID(t, engine), hosts: map[string]*stagedFakeExecutor{}, audit: &recordingAuditProvider{}, dials: new(int32)}
	for _, h := range hostNames {
		env.hosts[h] = &stagedFakeExecutor{files: map[string][]byte{
			stagedCertPath: []byte("OLD-CERT-" + h), stagedKeyPath: []byte("OLD-KEY-" + h),
		}}
		tgt, err := targetStore.Create(ctx, ManagedTarget{
			ID: "tgt-" + h, Name: h, Host: h, DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual",
			CredentialRef: "cred-ssh", InstallServerType: "nginx", InstallCertPath: stagedCertPath, InstallKeyPath: stagedKeyPath,
		})
		if err != nil {
			t.Fatal(err)
		}
		env.targets = append(env.targets, tgt.ID)
	}

	prev := newRolloutExecutor
	newRolloutExecutor = func(certs CertificateProvider, creds OutboundCredentialStore) *RenewalExecutor {
		e := NewRenewalExecutor(certs, creds)
		e.dial = func(_ context.Context, cfg agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
			atomic.AddInt32(env.dials, 1)
			return env.hosts[cfg.Host], func() error { return nil }, nil
		}
		// A reloaded host serves whatever sits at the live cert path.
		e.verifier = func(_ context.Context, hostPort string) (string, error) {
			host, _, _ := net.SplitHostPort(hostPort)
			b, err := env.hosts[host].ReadFile(stagedCertPath)
			if err != nil {
				return "", err
			}
			block, _ := pem.Decode(b)
			if block == nil {
				return "OLD-NOT-PEM", nil
			}
			return agentinstall.FingerprintSHA256(block.Bytes), nil
		}
		return e
	}
	t.Cleanup(func() { newRolloutExecutor = prev })

	env.mux = http.NewServeMux()
	registerRolloutHandler(env.mux, auth, provider, targetStore, credStore, env.audit, nil)
	return env
}

func (env *stagedRolloutEnv) issue(t *testing.T, cn string) string {
	t.Helper()
	issued, err := env.provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: env.caID, CSRPEM: generateTestCSRPEM(t, cn, cn), TemplateID: "file-backed-default", TeamID: "team-staged",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return issued.CertificateItem.FingerprintSHA256
}

// stagedFileListing fails if any host still holds a .kk-staged / .kk-prev file.
func (f *stagedFakeExecutor) leftovers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for p := range f.files {
		if strings.HasSuffix(p, ".kk-staged") || strings.HasSuffix(p, ".kk-prev") {
			out = append(out, p)
		}
	}
	return out
}

func TestRolloutSSHStagedHandlerFlipFailureRestoresAll(t *testing.T) {
	hosts := []string{"node1.example.com", "node2.example.com", "node3.example.com"}
	env := stagedRolloutMux(t, hosts)
	env.hosts[hosts[2]].failReload = true
	fp := env.issue(t, "staged.example.com")

	rec := postRollout(t, env.mux, map[string]any{
		"fingerprint": fp, "group": "web",
		"nodes": []map[string]any{
			{"target_id": env.targets[0], "is_canary": true}, {"target_id": env.targets[1]}, {"target_id": env.targets[2]},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("response must be key-free")
	}
	var body struct{ Data RolloutResult }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	res := body.Data
	if res.Mode != "staged" || !res.Halted || res.NewFingerprint == "" {
		t.Fatalf("want staged+halted+new_fingerprint, got %+v", res)
	}
	want := []string{"rolled_back", "rolled_back", "failed"}
	for i, n := range res.NodeResults {
		if n.Outcome != want[i] {
			t.Fatalf("node %d outcome %q, want %q (%+v)", i, n.Outcome, want[i], res)
		}
	}
	for _, h := range hosts {
		if string(env.hosts[h].files[stagedCertPath]) != "OLD-CERT-"+h || string(env.hosts[h].files[stagedKeyPath]) != "OLD-KEY-"+h {
			t.Fatalf("%s must end on the old material", h)
		}
		if l := env.hosts[h].leftovers(); len(l) != 0 {
			t.Fatalf("%s leftovers: %v", h, l)
		}
	}
	rows := 0
	env.audit.mu.Lock()
	for _, e := range env.audit.entries {
		if e.Action == "certificate.renew_rollout" && strings.Contains(e.ChangeSummary, `"node_id"`) {
			rows++
		}
	}
	env.audit.mu.Unlock()
	if rows != 3 {
		t.Fatalf("want one audit row per node, got %d", rows)
	}
}

func TestRolloutSSHStagedHandlerHappyPathCommits(t *testing.T) {
	hosts := []string{"node1.example.com", "node2.example.com"}
	env := stagedRolloutMux(t, hosts)
	fp := env.issue(t, "staged-ok.example.com")
	rec := postRollout(t, env.mux, map[string]any{
		"fingerprint": fp, "group": "web",
		"nodes": []map[string]any{{"target_id": env.targets[0], "is_canary": true}, {"target_id": env.targets[1]}},
	})
	var body struct{ Data RolloutResult }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || body.Data.Halted || body.Data.Mode != "staged" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	for _, h := range hosts {
		blk, _ := pem.Decode(env.hosts[h].files[stagedCertPath])
		if blk == nil || agentinstall.FingerprintSHA256(blk.Bytes) != body.Data.NewFingerprint {
			t.Fatalf("%s does not serve the new leaf", h)
		}
		if l := env.hosts[h].leftovers(); len(l) != 0 {
			t.Fatalf("%s leftovers after commit: %v", h, l)
		}
		for _, b := range env.hosts[h].files {
			if strings.Contains(string(b), "OLD-KEY") {
				t.Fatalf("%s retains the superseded key", h)
			}
		}
	}
}

func TestRolloutOutsideWindowDoesNotRenew(t *testing.T) {
	hosts := []string{"node1.example.com", "node2.example.com"}
	env := stagedRolloutMux(t, hosts)
	fp := env.issue(t, "window.example.com")
	hour := time.Now().UTC().Hour()
	start, end := (hour+2)%24, (hour+4)%24
	before := countCertificates(t, env.provider)
	rec := postRollout(t, env.mux, map[string]any{
		"fingerprint": fp, "group": "web", "window": map[string]int{"start_hour": start, "end_hour": end},
		"nodes": []map[string]any{{"target_id": env.targets[0]}, {"target_id": env.targets[1]}},
	})
	var body struct{ Data RolloutResult }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || !body.Data.Deferred {
		t.Fatalf("want deferred, got %d %s", rec.Code, rec.Body.String())
	}
	if after := countCertificates(t, env.provider); after != before {
		t.Fatalf("out-of-window request issued a certificate (%d -> %d)", before, after)
	}
	if atomic.LoadInt32(env.dials) != 0 {
		t.Fatal("out-of-window request must not dial")
	}
}

func countCertificates(t *testing.T, p CertificateProvider) int {
	t.Helper()
	r, err := p.ListCertificates(context.Background(), CertificateListQuery{Limit: 1})
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	return r.Total
}

// Case C of tests/live/rollout: a halted rollout already minted a successor
// that no node kept. Retrying the rollout of the predecessor must say so
// (409 naming the existing successor) instead of a generic 503, and must not
// mint again or push anything.
func TestRolloutRetryAfterMintedSuccessorIs409NamingSuccessor(t *testing.T) {
	cluster := newFakeCluster()
	audit := &recordingAuditProvider{}
	mux, provider, caID, targetIDs := rolloutTestMuxAudit(t, cluster, []string{"node-a"}, audit)

	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "retry.example.com", "retry.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-cluster",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	oldFP := issued.CertificateItem.FingerprintSHA256
	body := map[string]any{
		"fingerprint": oldFP, "group": "g",
		"nodes": []map[string]any{{"target_id": targetIDs[0], "is_canary": true}},
	}
	if rec := postRollout(t, mux, body); rec.Code != http.StatusOK {
		t.Fatalf("first rollout: %d %s", rec.Code, rec.Body.String())
	}
	detail, ok, err := provider.GetCertificate(context.Background(), oldFP)
	if err != nil || !ok || detail.SuccessorFP == nil || *detail.SuccessorFP == "" {
		t.Fatalf("first rollout must have minted a successor: ok=%v err=%v", ok, err)
	}
	successor := *detail.SuccessorFP

	cluster.mu.Lock()
	cluster.received = map[string][]byte{}
	cluster.mu.Unlock()

	rec := postRollout(t, mux, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("retry must be 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "conflict" || got["successor_fingerprint"] != successor {
		t.Fatalf("409 body must name the successor %s: %v", successor, got)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("409 body leaked key material")
	}
	cluster.mu.Lock()
	pushed := len(cluster.received)
	cluster.mu.Unlock()
	if pushed != 0 {
		t.Fatalf("a conflicting retry must not push to any node, pushed to %d", pushed)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	last := audit.entries[len(audit.entries)-1]
	if last.Action != "certificate.renew_rollout" || last.Outcome != AuditOutcomeFailure {
		t.Fatalf("conflict outcome must be audited, last entry: %+v", last)
	}
}
