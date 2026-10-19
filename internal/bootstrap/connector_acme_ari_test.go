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
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	kkacme "kryptkeeper/internal/acme"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/keystore"
)

// W26-27: ARI-driven renewal timing and the replaces order. The real Let's
// Encrypt staging proof belongs to W20-29; everything here runs in-process.

func ariTestCertPEM(t *testing.T, aki []byte, serial int64) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "ari.example.test"},
		DNSNames: []string{"ari.example.test"}, AuthorityKeyId: aki,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(80 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestARICertIDVector(t *testing.T) {
	aki := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}
	cert, err := parseLeafPEM(ariTestCertPEM(t, aki, 0x0102))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ariCertID(cert)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(aki) + "." + base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02})
	if got != want {
		t.Fatalf("certID = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "=+/") {
		t.Fatalf("certID must be unpadded base64url: %q", got)
	}
	if _, err := ariCertID(&x509.Certificate{SerialNumber: big.NewInt(1)}); err == nil {
		t.Fatal("a cert without AKI must not yield a certID")
	}
}

func TestChooseRenewalTimeStaysInWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := ariWindow{Start: now.Add(24 * time.Hour), End: now.Add(48 * time.Hour)}
	lo, hi := w.End, w.Start
	for range 1000 {
		got := chooseRenewalTime(w, now, func(n int64) int64 { return mrandN(n) })
		if got.Before(w.Start) || got.After(w.End) {
			t.Fatalf("draw %v outside window", got)
		}
		if got.Before(lo) {
			lo = got
		}
		if got.After(hi) {
			hi = got
		}
	}
	if spread := hi.Sub(lo); spread < w.End.Sub(w.Start)/2 {
		t.Fatalf("draws cover only %v of a %v window", spread, w.End.Sub(w.Start))
	}
}

func mrandN(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}

func TestChooseRenewalTimePastWindowIsNow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := ariWindow{Start: now.Add(-3 * time.Hour), End: now.Add(-time.Hour)}
	if got := chooseRenewalTime(w, now, mrandN); !got.Equal(now) {
		t.Fatalf("closed window: got %v, want now", got)
	}
}

func TestChooseRenewalTimeStartPastEndFuture(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := ariWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	for range 200 {
		got := chooseRenewalTime(w, now, mrandN)
		if got.Before(now) || got.After(w.End) {
			t.Fatalf("draw %v outside [now, end]", got)
		}
	}
}

func TestParseRetryAfterAcceptsSecondsAndDates(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("21600", now); got != 6*time.Hour {
		t.Fatalf("delta-seconds: %v", got)
	}
	if got := parseRetryAfter(now.Add(2*time.Hour).Format(time.RFC3339), now); got != 2*time.Hour {
		t.Fatalf("rfc3339: %v", got)
	}
	if got := parseRetryAfter(now.Add(time.Hour).Format(http.TimeFormat), now); got != time.Hour {
		t.Fatalf("http-date: %v", got)
	}
	if got := parseRetryAfter("soon", now); got != 6*time.Hour {
		t.Fatalf("garbage: %v", got)
	}
}

// newARIUpstream is newTestUpstreamACME with a handler wrapper, so a test can
// observe or answer requests ahead of the real server.
func newARIUpstream(t *testing.T, solverAddr string, wrap func(http.Handler) http.Handler) string {
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
		return (&net.Dialer{}).DialContext(ctx, network, solverAddr)
	})
	var h http.Handler = srv.Handler()
	if wrap != nil {
		h = wrap(h)
	}
	ts.Config.Handler = h
	t.Cleanup(ts.Close)
	return ts.URL
}

func issueViaFakeCA(t *testing.T, upstream string, port int, ctx context.Context) (*acmeIssuerConnector, string) {
	t.Helper()
	conn := newACMETestConnector(t, upstream, port, nil).(*acmeIssuerConnector)
	res, err := conn.Issue(ctx, connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return conn, res.CertificatePEM
}

func TestFetchARIAgainstFakeCA(t *testing.T) {
	port := freeLocalPort(t)
	upstream := newARIUpstream(t, fmt.Sprintf("127.0.0.1:%d", port), nil)
	conn, chain := issueViaFakeCA(t, upstream, port, context.Background())

	leaf, err := parseLeafPEM(chain)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ariCertID(leaf)
	if err != nil {
		t.Fatalf("fake-CA leaf has no AKI: %v", err)
	}
	resp, err := http.Get(upstream + "/acme/renewalInfo/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var want kkacme.RenewalInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&want); err != nil {
		t.Fatal(err)
	}

	w, err := conn.fetchARI(context.Background(), chain)
	if err != nil {
		t.Fatalf("fetchARI: %v", err)
	}
	if got := w.Start.UTC().Format(time.RFC3339); got != want.SuggestedWindow.Start {
		t.Fatalf("start %s != %s", got, want.SuggestedWindow.Start)
	}
	if got := w.End.UTC().Format(time.RFC3339); got != want.SuggestedWindow.End {
		t.Fatalf("end %s != %s", got, want.SuggestedWindow.End)
	}
	if w.RetryAfter != 6*time.Hour {
		t.Fatalf("delta-seconds Retry-After not honoured: %v", w.RetryAfter)
	}
}

type ariStubCerts struct {
	CertificateProvider
	pem string
}

func (s ariStubCerts) DownloadCertificate(context.Context, string, string, bool) (CertificateDownloadResult, error) {
	return CertificateDownloadResult{Body: []byte(s.pem)}, nil
}

func resetARIPlans(t *testing.T) {
	t.Helper()
	old := ariPlans
	ariPlans = newARIPlanCache()
	t.Cleanup(func() { ariPlans = old })
}

func TestAriDueWhenWindowEndedInThePast(t *testing.T) {
	resetARIPlans(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dir":
			_ = json.NewEncoder(w).Encode(map[string]string{"renewalInfo": srv.URL + "/ari"})
		case strings.HasPrefix(r.URL.Path, "/ari/"):
			now := time.Now().UTC()
			w.Header().Set("Retry-After", "600")
			_ = json.NewEncoder(w).Encode(map[string]any{"suggestedWindow": map[string]string{
				"start": now.Add(-3 * time.Hour).Format(time.RFC3339), "end": now.Add(-time.Hour).Format(time.RFC3339)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(acmeConnectorConfig{DirectoryURL: srv.URL + "/dir"})
	conn := NewACMEIssuerConnector(ConnectorRecord{ID: "conn-ari", Type: "acme", ConfigJSON: string(cfg)}, nil, nil)
	conn.(*acmeIssuerConnector).allowLoopbackForTest = true
	reg := connectors.NewRegistry()
	reg.Register(conn)

	due := NewARIDueFunc(func(context.Context) (*connectors.Registry, error) { return reg, nil },
		ariStubCerts{pem: ariTestCertPEM(t, []byte{1, 2, 3}, 7)})
	d := due(context.Background(), CertificateItem{FingerprintSHA256: "fp1", RenewalConnectorID: "conn-ari"}, time.Now())
	if !d.Known || !d.Due {
		t.Fatalf("want Known && Due, got %+v", d)
	}
	if !strings.Contains(d.Detail, "replaces=") || !strings.Contains(d.Detail, "ari_window=") {
		t.Fatalf("detail missing fields: %q", d.Detail)
	}

	// An unreachable CA means Known=false, never an error that blocks renewal.
	srv.Close()
	resetARIPlans(t)
	if d := due(context.Background(), CertificateItem{FingerprintSHA256: "fp1", RenewalConnectorID: "conn-ari"}, time.Now()); d.Known {
		t.Fatalf("ARI outage must fall back to threshold rules: %+v", d)
	}
}

type auditRecorder struct {
	mu      sync.Mutex
	actions []string
}

func (a *auditRecorder) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (a *auditRecorder) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, e.Action)
	return nil
}
func (a *auditRecorder) count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, x := range a.actions {
		if x == action {
			n++
		}
	}
	return n
}

type countingConnector struct {
	recordingConnector
	mu    sync.Mutex
	calls int
}

func (c *countingConnector) Issue(ctx context.Context, r connectors.IssueRequest) (connectors.IssueResult, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.recordingConnector.Issue(ctx, r)
}

func runARISweep(t *testing.T, decision ARIDecision, thresholdDays int) (issues int, audit *auditRecorder) {
	t.Helper()
	return runARISweepWith(t, func(context.Context, CertificateItem, time.Time) ARIDecision { return decision }, thresholdDays)
}

func runARISweepWith(t *testing.T, ari func(context.Context, CertificateItem, time.Time) ARIDecision, thresholdDays int) (issues int, audit *auditRecorder) {
	t.Helper()
	t.Setenv("RENEWAL_POLL_MINUTES", "1")
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: getFirstCAID(t, engine), CSRPEM: generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-sweep",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpdateEstate(ctx, issued.CertificateItem.FingerprintSHA256, EstateUpdate{
		ManagementState: "managed", RenewalMethod: "acme", RenewalConnectorID: "conn-fake-up",
	}); err != nil {
		t.Fatal(err)
	}
	targets := newSweepTestTargetStore(t)
	tgt := sweepTarget(true)
	tgt.RenewalThresholdDays = thresholdDays
	if _, err := targets.Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	exec.verifier = func(context.Context, string) (string, error) {
		return leafFingerprint(fake.files["/etc/nginx/tls/sweep.crt"])
	}
	cc := &countingConnector{recordingConnector: recordingConnector{id: "conn-fake-up", pem: estateTestCertPEM(t)}}
	reg := connectors.NewRegistry()
	reg.Register(cc)
	exec.WithConnectorRegistry(reg)

	sched := newSweepScheduler(t, provider, targets, exec)
	audit = &auditRecorder{}
	sched.auditProvider = audit
	sched.WithARIDue(ari)
	sched.runScan() // one tick
	return cc.calls, audit
}

func TestSchedulerRenewsOnPastARIWindowWithinOneTick(t *testing.T) {
	// Far from expiry (threshold 1 day on a ~90 day cert): only ARI can trigger it.
	issues, audit := runARISweep(t, ARIDecision{Known: true, Due: true, Detail: "ari_window=past"}, 1)
	if issues != 1 {
		t.Fatalf("want exactly 1 renewal attempt, got %d", issues)
	}
	if n := audit.count("acme.upstream.renew"); n != 1 {
		t.Fatalf("want 1 acme.upstream.renew audit row, got %d", n)
	}
}

func TestSchedulerARINotDueSuppressesThresholdRenewal(t *testing.T) {
	// Inside the 100-day threshold, but the CA says not yet.
	issues, audit := runARISweep(t, ARIDecision{Known: true, Due: false}, 100)
	if issues != 0 || audit.count("acme.upstream.renew") != 0 {
		t.Fatalf("Known && !Due must not renew: issues=%d", issues)
	}
	// Unknown ARI falls back to the threshold rule.
	issues, _ = runARISweep(t, ARIDecision{}, 100)
	if issues != 1 {
		t.Fatalf("!Known must use threshold rules, got %d attempts", issues)
	}
}

func decodeOrderPayload(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		t.Fatalf("jws: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		t.Fatalf("payload b64: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestRenewalOrderCarriesReplaces(t *testing.T) {
	port := freeLocalPort(t)
	var mu sync.Mutex
	var payloads []map[string]any
	upstream := newARIUpstream(t, fmt.Sprintf("127.0.0.1:%d", port), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/acme/new-order" {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				mu.Lock()
				payloads = append(payloads, decodeOrderPayload(t, body))
				mu.Unlock()
			}
			next.ServeHTTP(w, r)
		})
	})
	conn, firstChain := issueViaFakeCA(t, upstream, port, context.Background())
	old, _ := parseLeafPEM(firstChain)
	wantID, err := ariCertID(old)
	if err != nil {
		t.Fatal(err)
	}

	ctx := WithACMEReplaces(context.Background(), firstChain)
	if _, err := conn.Issue(ctx, connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)}); err != nil {
		t.Fatalf("renewal with replaces must still complete: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 {
		t.Fatalf("want 2 new-order posts, got %d", len(payloads))
	}
	if _, has := payloads[0]["replaces"]; has {
		t.Fatal("first (non-renewal) order must not carry replaces")
	}
	if payloads[1]["replaces"] != wantID {
		t.Fatalf("replaces = %v, want %q", payloads[1]["replaces"], wantID)
	}
}

func TestAlreadyReplacedIsNotAFailure(t *testing.T) {
	port := freeLocalPort(t)
	var mu sync.Mutex
	rejected := 0
	upstream := newARIUpstream(t, fmt.Sprintf("127.0.0.1:%d", port), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/acme/new-order" {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				if _, has := decodeOrderPayload(t, body)["replaces"]; has {
					mu.Lock()
					rejected++
					mu.Unlock()
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:alreadyReplaced","detail":"already replaced"}`))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	conn, chain := issueViaFakeCA(t, upstream, port, context.Background())

	// The inner order surfaces the sentinel...
	client, err := conn.accountClient(context.Background(), acmeCredentialPayload{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.authorizeReplacesOrder(context.Background(), client, nil, chain)
	if !errors.Is(err, errACMEAlreadyReplaced) {
		t.Fatalf("want errACMEAlreadyReplaced, got %v", err)
	}

	// ...and the connector treats it as non-fatal, ordering without replaces.
	ctx := WithACMEReplaces(context.Background(), chain)
	if _, err := conn.Issue(ctx, connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)}); err != nil {
		t.Fatalf("alreadyReplaced must not fail the renewal: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if rejected < 2 {
		t.Fatalf("expected the replaces order to be attempted and rejected, rejected=%d", rejected)
	}
}
