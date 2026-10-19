// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/connectors"
)

// W26-29: mass-revocation detector and monitor. Fake clock via m.now; the
// monitor is driven by calling Tick directly (no sleeps).

var mrT0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

const mrConn = "conn-mr"

type mrCerts struct {
	CertificateProvider
	mu    sync.Mutex
	items []CertificateItem
	pems  map[string]string
	dls   int
}

func (c *mrCerts) ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CertificateListResult{Items: append([]CertificateItem(nil), c.items...), Total: len(c.items)}, nil
}

func (c *mrCerts) DownloadCertificate(_ context.Context, fp, _ string, _ bool) (CertificateDownloadResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dls++
	return CertificateDownloadResult{Body: []byte(c.pems[fp])}, nil
}

func (c *mrCerts) setSuccessor(fp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.items {
		if c.items[i].FingerprintSHA256 == fp {
			s := "successor-" + fp
			c.items[i].SuccessorFP = &s
		}
	}
}

type mrScanner struct {
	mu    sync.Mutex
	scans int
	armed map[string]bool
}

func (s *mrScanner) RequestScan() { s.mu.Lock(); s.scans++; s.mu.Unlock() }
func (s *mrScanner) noTargetCount(_ context.Context, certs []CertificateItem) int {
	n := 0
	for _, c := range certs {
		if !s.armed[c.FingerprintSHA256] {
			n++
		}
	}
	return n
}

type mrAlerts struct {
	mu     sync.Mutex
	events []string
	detail []string
}

// mrWindow is what the stub CA answers for one cert id.
type mrWindow struct {
	end         time.Time
	explanation string
}

type mrARI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	windows map[string]mrWindow // keyed by cert id; missing = end t0+30d
	noARI   bool
	// retryAfter is the Retry-After header value; hits counts renewalInfo requests.
	retryAfter string
	hits       int
}

func newMRARI(t *testing.T) *mrARI {
	t.Helper()
	a := &mrARI{windows: map[string]mrWindow{}, retryAfter: "0"}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case r.URL.Path == "/dir":
			if a.noARI {
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"renewalInfo": a.srv.URL + "/ari"})
		case strings.HasPrefix(r.URL.Path, "/ari/"):
			a.hits++
			win, ok := a.windows[strings.TrimPrefix(r.URL.Path, "/ari/")]
			if !ok {
				win = mrWindow{end: mrT0.Add(30 * 24 * time.Hour)}
			}
			w.Header().Set("Retry-After", a.retryAfter)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"suggestedWindow": map[string]string{"start": win.end.Add(-time.Hour).Format(time.RFC3339), "end": win.end.Format(time.RFC3339)},
				"explanationURL":  win.explanation,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *mrARI) set(id string, w mrWindow) { a.mu.Lock(); a.windows[id] = w; a.mu.Unlock() }

type mrHarness struct {
	t       *testing.T
	ari     *mrARI
	certs   *mrCerts
	audit   *memAuditProvider
	scanner *mrScanner
	mon     *ACMEMassRevokeMonitor
	alerts  *mrAlerts
	clock   time.Time
}

func newMRHarness(t *testing.T) *mrHarness {
	t.Helper()
	resetARIPlans(t)
	oldMin := ariMinRefresh
	ariMinRefresh = 0 // tests tick on a fake clock; production floors the pacing at 1h
	t.Cleanup(func() { ariMinRefresh = oldMin })
	h := &mrHarness{t: t, ari: newMRARI(t), certs: &mrCerts{pems: map[string]string{}}, audit: &memAuditProvider{},
		scanner: &mrScanner{armed: map[string]bool{}}, alerts: &mrAlerts{}, clock: mrT0}
	oldAlert := acmeAlert
	acmeAlert = func(event, id, detail string) {
		h.alerts.mu.Lock()
		h.alerts.events = append(h.alerts.events, event+"|"+id)
		h.alerts.detail = append(h.alerts.detail, detail)
		h.alerts.mu.Unlock()
	}
	t.Cleanup(func() { acmeAlert = oldAlert })

	cfg, _ := json.Marshal(acmeConnectorConfig{DirectoryURL: h.ari.srv.URL + "/dir"})
	conn := NewACMEIssuerConnector(ConnectorRecord{ID: mrConn, Type: "acme", ConfigJSON: string(cfg)}, nil, nil).(*acmeIssuerConnector)
	conn.allowLoopbackForTest = true
	reg := connectors.NewRegistry()
	reg.Register(conn)
	h.mon = newACMEMassRevokeMonitor(func(context.Context) (*connectors.Registry, error) { return reg, nil }, h.certs, h.audit, h.scanner)
	h.mon.now = func() time.Time { return h.clock }
	return h
}

// addCert registers a self-signed leaf with a unique AKI/serial and returns
// its fingerprint and ARI cert id.
func (h *mrHarness) addCert(i int, pemText string) (fp, id string) {
	h.t.Helper()
	if pemText == "" {
		pemText = ariTestCertPEM(h.t, []byte{0xAA, byte(i), 0x01}, int64(1000+i))
	}
	leaf, err := parseLeafPEM(pemText)
	if err != nil {
		h.t.Fatal(err)
	}
	id, err = ariCertID(leaf)
	if err != nil {
		h.t.Fatal(err)
	}
	fp = fmt.Sprintf("fp-%02d", i)
	h.certs.mu.Lock()
	h.certs.items = append(h.certs.items, CertificateItem{FingerprintSHA256: fp, RenewalConnectorID: mrConn})
	h.certs.pems[fp] = pemText
	h.certs.mu.Unlock()
	return fp, id
}

func (h *mrHarness) tick(advance time.Duration) []massRevokeSignal {
	h.clock = h.clock.Add(advance)
	return h.mon.Tick(context.Background())
}

func (h *mrHarness) auditCount() int {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	n := 0
	for _, e := range h.audit.entries {
		if e.Action == "acme.upstream.massrevoke" {
			n++
		}
	}
	return n
}

func (h *mrHarness) alertCount() int {
	h.alerts.mu.Lock()
	defer h.alerts.mu.Unlock()
	return len(h.alerts.events)
}

func TestAriWindowPulledForwardRaisesSignal(t *testing.T) {
	h := newMRHarness(t)
	fp, id := h.addCert(1, "")
	if got := h.tick(0); len(got) != 0 {
		t.Fatalf("normal window must not signal: %+v", got)
	}
	h.ari.set(id, mrWindow{end: mrT0.Add(3 * time.Minute), explanation: "https://ca.example/revoked"})
	got := h.tick(2 * time.Minute)
	if len(got) != 1 || got[0].Source != "ari" || got[0].Fingerprint != fp {
		t.Fatalf("want one ari signal for %s, got %+v", fp, got)
	}
	if h.clock.Sub(mrT0) >= 5*time.Minute || acmeMassRevokeInterval > 5*time.Minute {
		t.Fatalf("alert not within the 5 minute budget: elapsed %v interval %v", h.clock.Sub(mrT0), acmeMassRevokeInterval)
	}
	if h.auditCount() != 1 || h.alertCount() != 1 || h.scanner.scans != 1 {
		t.Fatalf("audit=%d alerts=%d scans=%d", h.auditCount(), h.alertCount(), h.scanner.scans)
	}
	e := h.audit.entries[0]
	if e.ActorType != "system" || e.ActorID != "acme-massrevoke-monitor" || e.ResourceID != fp || e.ResourceType != "certificate" ||
		!strings.HasPrefix(e.ChangeSummary, "source=ari connector="+mrConn) {
		t.Fatalf("audit row wrong: %+v", e)
	}
	if _, ok := ariPlans.forcedDue(mrConn, fp); !ok {
		t.Fatal("affected cert not forced due")
	}
	if d := NewARIDueFunc(nil, nil)(context.Background(), CertificateItem{FingerprintSHA256: fp, RenewalConnectorID: mrConn}, h.clock); !d.Known || !d.Due {
		t.Fatalf("ARI hook must report forced cert due: %+v", d)
	}
}

// pulledForward with the 24h rule alone (no explanationURL).
func TestAriPullForwardWithoutExplanationSignals(t *testing.T) {
	h := newMRHarness(t)
	_, id := h.addCert(1, "")
	h.tick(0)
	h.ari.set(id, mrWindow{end: mrT0.Add(time.Minute)})
	if got := h.tick(time.Minute); len(got) != 1 {
		t.Fatalf("cached window >24h away collapsing to now must signal: %+v", got)
	}
}

type mrPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  string
	leaf   *x509.Certificate
	bundle string
}

func newMRPKI(t *testing.T, ocspURL string) *mrPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MR Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{9, 9, 9},
		NotBefore: mrT0.Add(-time.Hour), NotAfter: mrT0.Add(24 * time.Hour * 365),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "mr.example.test"}, DNSNames: []string{"mr.example.test"},
		NotBefore: mrT0.Add(-time.Hour), NotAfter: mrT0.Add(60 * 24 * time.Hour),
	}
	if ocspURL != "" {
		leafTmpl.OCSPServer = []string{ocspURL}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	enc := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return &mrPKI{ca: ca, caKey: caKey, caPEM: enc(caDER), leaf: leaf, bundle: enc(leafDER) + enc(caDER)}
}

func ocspResponder(t *testing.T, p **mrPKI, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if _, err := goocsp.ParseRequest(raw); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pki := *p
		resp, err := goocsp.CreateResponse(pki.ca, pki.ca, goocsp.Response{
			Status: status, SerialNumber: pki.leaf.SerialNumber, ThisUpdate: mrT0.Add(-time.Minute), NextUpdate: mrT0.Add(time.Hour),
			RevokedAt: mrT0.Add(-30 * time.Second), RevocationReason: goocsp.KeyCompromise,
		}, pki.caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOCSPRevokedRaisesSignal(t *testing.T) {
	h := newMRHarness(t)
	h.ari.noARI = true
	var pki *mrPKI
	srv := ocspResponder(t, &pki, goocsp.Revoked)
	pki = newMRPKI(t, srv.URL)
	h.addCert(1, pki.bundle)
	got := h.tick(2 * time.Minute)
	if len(got) != 1 || got[0].Source != "ocsp" {
		t.Fatalf("want one ocsp signal, got %+v", got)
	}
	if h.auditCount() != 1 || h.alertCount() != 1 || h.scanner.scans != 1 {
		t.Fatalf("audit=%d alerts=%d scans=%d", h.auditCount(), h.alertCount(), h.scanner.scans)
	}
	if !strings.HasPrefix(h.audit.entries[0].ChangeSummary, "source=ocsp connector="+mrConn) {
		t.Fatalf("audit summary: %q", h.audit.entries[0].ChangeSummary)
	}
}

func TestNoSignalForNormalWindowOrMissingOCSP(t *testing.T) {
	h := newMRHarness(t)
	// Natural window nearing its end: cached window was <24h out, no explanationURL.
	_, id1 := h.addCert(1, "")
	h.ari.set(id1, mrWindow{end: mrT0.Add(20 * time.Hour)})
	h.tick(0)
	h.ari.set(id1, mrWindow{end: mrT0.Add(4 * time.Minute)})
	if got := h.tick(2 * time.Minute); len(got) != 0 {
		t.Fatalf("natural window end must not signal: %+v", got)
	}
	// No OCSPServer and no ARI at all: silent skip.
	h2 := newMRHarness(t)
	h2.ari.noARI = true
	h2.addCert(2, "")
	if got := h2.tick(0); len(got) != 0 {
		t.Fatalf("missing OCSP must not signal: %+v", got)
	}
	// OCSP answering "good" does not signal either.
	h3 := newMRHarness(t)
	h3.ari.noARI = true
	var pki *mrPKI
	srv := ocspResponder(t, &pki, goocsp.Good)
	pki = newMRPKI(t, srv.URL)
	h3.addCert(3, pki.bundle)
	if got := h3.tick(0); len(got) != 0 {
		t.Fatalf("good OCSP must not signal: %+v", got)
	}
	if h.auditCount()+h2.auditCount()+h3.auditCount() != 0 || h.alertCount()+h2.alertCount()+h3.alertCount() != 0 {
		t.Fatal("no audit or alert expected")
	}
}

func TestHundredPercentOfAffectedCertsAreHandled(t *testing.T) {
	h := newMRHarness(t)
	var fps, ids []string
	for i := 1; i <= 10; i++ {
		fp, id := h.addCert(i, "")
		fps, ids = append(fps, fp), append(ids, id)
	}
	h.tick(0)
	// Flip 6 certs; 4 of those have an armed target.
	for i := 0; i < 6; i++ {
		h.ari.set(ids[i], mrWindow{end: mrT0.Add(2 * time.Minute), explanation: "https://ca.example/why"})
	}
	for _, i := range []int{0, 1, 2, 3} {
		h.scanner.armed[fps[i]] = true
	}
	got := h.tick(2 * time.Minute)
	if len(got) != 6 || h.auditCount() != 6 {
		t.Fatalf("affected=%d audited=%d, want 6/6", len(got), h.auditCount())
	}
	for i, fp := range fps {
		_, forced := ariPlans.forcedDue(mrConn, fp)
		if forced != (i < 6) {
			t.Fatalf("cert %d forced=%v", i, forced)
		}
	}
	if h.alertCount() != 1 || h.alerts.detail[0] != "6 certificate(s) affected, no_target=2" {
		t.Fatalf("alerts: %v %v", h.alerts.events, h.alerts.detail)
	}
	if h.scanner.scans != 1 {
		t.Fatalf("scans=%d", h.scanner.scans)
	}
}

// The forced certs are renewed by the real scheduler sweep, not just flagged.
func TestForcedCertIsRenewedBySchedulerSweep(t *testing.T) {
	resetARIPlans(t)
	hook := NewARIDueFunc(nil, nil)
	issues, audit := runARISweepWith(t, func(ctx context.Context, c CertificateItem, now time.Time) ARIDecision {
		ariPlans.forceDue(c.RenewalConnectorID, c.FingerprintSHA256, "mass_revocation:ari") // what Tick does
		return hook(ctx, c, now)
	}, 1)
	if issues != 1 || audit.count("acme.upstream.renew") != 1 {
		t.Fatalf("forced cert must start renewal: issues=%d renew audits=%d", issues, audit.count("acme.upstream.renew"))
	}
}

func TestLatchPreventsRepeatAlerts(t *testing.T) {
	h := newMRHarness(t)
	fp, id := h.addCert(1, "")
	h.tick(0)
	h.ari.set(id, mrWindow{end: mrT0.Add(2 * time.Minute), explanation: "https://ca.example/why"})
	if got := h.tick(2 * time.Minute); len(got) != 1 {
		t.Fatalf("first tick: %+v", got)
	}
	if got := h.tick(2 * time.Minute); len(got) != 0 {
		t.Fatalf("latched cert re-signalled: %+v", got)
	}
	if h.auditCount() != 1 || h.alertCount() != 1 || h.scanner.scans != 1 {
		t.Fatalf("repeat tick leaked: audit=%d alerts=%d scans=%d", h.auditCount(), h.alertCount(), h.scanner.scans)
	}
	h.certs.setSuccessor(fp)
	h.tick(2 * time.Minute)
	if len(h.mon.latch) != 0 {
		t.Fatalf("latch not cleared on successor: %v", h.mon.latch)
	}
	if _, ok := ariPlans.forcedDue(mrConn, fp); ok {
		t.Fatal("forced flag not cleared on successor")
	}
}

func TestRequestScanIsNonBlockingAndNilSafe(t *testing.T) {
	var nilSched *RenewalScheduler
	nilSched.RequestScan()
	s := &RenewalScheduler{scanNow: make(chan struct{}, 1)}
	s.RequestScan()
	s.RequestScan() // buffer full: must not block
	if len(s.scanNow) != 1 {
		t.Fatalf("want exactly one pending scan, got %d", len(s.scanNow))
	}
}

// A cert whose CA-advised Retry-After is in the future costs the CA nothing:
// no renewalInfo request and no certificate download across idle ticks.
func TestFutureRetryAfterMakesNoCARequests(t *testing.T) {
	h := newMRHarness(t)
	ariMinRefresh = time.Hour // real pacing floor
	h.ari.retryAfter = "21600"
	_, id := h.addCert(1, "")
	h.tick(0)
	h.ari.mu.Lock()
	hits0 := h.ari.hits
	h.ari.mu.Unlock()
	if hits0 != 1 || h.certs.dls != 1 {
		t.Fatalf("first tick: ari hits=%d downloads=%d, want 1/1", hits0, h.certs.dls)
	}
	for range 5 { // 10 fake minutes, well inside the 6h Retry-After
		h.tick(2 * time.Minute)
	}
	h.ari.mu.Lock()
	hits := h.ari.hits
	h.ari.mu.Unlock()
	if hits != hits0 || h.certs.dls != 1 {
		t.Fatalf("idle ticks hit the CA: ari hits=%d downloads=%d", hits, h.certs.dls)
	}
	// Once Retry-After elapses the signal is still caught.
	h.ari.set(id, mrWindow{end: h.clock.Add(6 * time.Hour).Add(time.Minute), explanation: "https://ca.example/why"})
	if got := h.tick(6 * time.Hour); len(got) != 1 {
		t.Fatalf("due check after Retry-After must catch the pull-forward: %+v", got)
	}
}
