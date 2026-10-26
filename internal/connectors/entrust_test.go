// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W36-10: Entrust ECS connector against a TLS fixture that demands a client
// certificate and Basic auth, pinning OUR request shapes. Reuses ejbcaMakePKI
// for in-test keys (leaf serial 0xABCDEF01, issued by a throwaway CA).

const (
	entrustTestUser   = "api-user"
	entrustTestSecret = "TOPSECRET-ENTRUST-KEY"
)

type entrustFixture struct {
	pki      ejbcaPKI
	srv      *httptest.Server
	issue    func(w http.ResponseWriter, body map[string]any)
	poll     func(w http.ResponseWriter, n int)
	polls    int
	lastBody map[string]any
	listBody string
	revPath  string
	revBody  map[string]any
	revCode  int
	clients  int
	listQ    string
}

func (f *entrustFixture) certJSON(withCert bool) map[string]any {
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.leafDER}))
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.caDER}))
	m := map[string]any{"trackingId": 4242, "status": "ACTIVE"}
	if withCert {
		m["endEntityCert"] = leaf
		m["chainCerts"] = []string{leaf, ca}
		m["serialNumber"] = "ABCDEF01"
	}
	return m
}

func newEntrustFixture(t *testing.T) *entrustFixture {
	t.Helper()
	f := &entrustFixture{pki: ejbcaMakePKI(t), revCode: 200, clients: 200,
		listBody: `{"summary":{"total":1},"certificates":[{"trackingId":4242,"status":"ACTIVE"}]}`}
	f.issue = func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(f.certJSON(true))
	}
	f.poll = func(w http.ResponseWriter, _ int) { _ = json.NewEncoder(w).Encode(f.certJSON(true)) }
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "kk-client" {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != entrustTestUser || p != entrustTestSecret {
			http.Error(w, "bad basic auth", http.StatusUnauthorized)
			return
		}
		const base = "/enterprise/v2"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base+"/clients":
			w.WriteHeader(f.clients)
			_, _ = w.Write([]byte(`{"clients":[{"clientId":1}]}`))
		case r.Method == http.MethodPost && r.URL.Path == base+"/certificates":
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.lastBody = body
			f.issue(w, body)
		case r.Method == http.MethodGet && r.URL.Path == base+"/certificates":
			f.listQ = r.URL.RawQuery
			_, _ = w.Write([]byte(f.listBody))
		case r.Method == http.MethodGet && r.URL.Path == base+"/certificates/4242":
			f.polls++
			f.poll(w, f.polls)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revocations"):
			f.revPath = r.URL.Path
			f.revBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&f.revBody)
			w.WriteHeader(f.revCode)
			if f.revCode >= 400 {
				_, _ = w.Write([]byte(`{"status":400,"errors":[{"message":"cannot revoke"}]}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	f.srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *entrustFixture) connector() *EntrustConnector {
	srvCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return NewEntrustConnector("en-1", EntrustConfig{
		BaseURL: f.srv.URL + "/enterprise/v2", Username: entrustTestUser, APIKey: entrustTestSecret,
		ClientCertPEM: f.pki.clientCert, ClientKeyPEM: f.pki.clientK, CACertPEM: string(srvCert),
		ClientID: 7, RequesterName: "Ops", RequesterEmail: "ops@example.com",
		PollAttempts: 4, PollInterval: time.Millisecond,
	}, testClient(f.pki.clientCert, f.pki.clientK, string(srvCert)))
}

func TestEntrustIssueShapeAndChain(t *testing.T) {
	f := newEntrustFixture(t)
	res, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	for k, want := range map[string]any{
		"csr": f.pki.csrPEM, "certType": "STANDARD_SSL", "signingAlg": "SHA-2",
		"eku": "SERVER_AUTH", "clientId": float64(7),
	} {
		if f.lastBody[k] != want {
			t.Errorf("body[%s] = %v, want %v", k, f.lastBody[k], want)
		}
	}
	want := time.Now().UTC().AddDate(0, 0, 90).Format("2006-01-02")
	if f.lastBody["certExpiryDate"] != want {
		t.Errorf("certExpiryDate = %v, want %s", f.lastBody["certExpiryDate"], want)
	}
	if _, bad := f.lastBody["certLifetime"]; bad {
		t.Error("certLifetime must be absent unless configured")
	}
	tr, _ := f.lastBody["tracking"].(map[string]any)
	if tr["requesterName"] != "Ops" || tr["requesterEmail"] != "ops@example.com" || tr["requesterPhone"] != nil {
		t.Errorf("tracking = %v", tr)
	}
	if strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("want leaf+CA (echoed leaf deduped): %d blocks", strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE"))
	}
	first, _ := pem.Decode([]byte(res.CertificatePEM))
	if string(first.Bytes) != string(f.pki.leafDER) || len(res.FingerprintSHA256) != 64 {
		t.Fatal("leaf must come first with a sha256 fingerprint")
	}
}

func TestEntrustCertLifetimeOverridesExpiry(t *testing.T) {
	f := newEntrustFixture(t)
	c := f.connector()
	c.cfg.CertLifetime = "P1Y"
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err != nil {
		t.Fatal(err)
	}
	if f.lastBody["certLifetime"] != "P1Y" {
		t.Errorf("certLifetime = %v", f.lastBody["certLifetime"])
	}
	if _, bad := f.lastBody["certExpiryDate"]; bad {
		t.Error("certExpiryDate must be absent when certLifetime is set")
	}
}

func TestEntrustPendingThenIssued(t *testing.T) {
	f := newEntrustFixture(t)
	f.issue = func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"trackingId":4242}`))
	}
	f.poll = func(w http.ResponseWriter, n int) {
		if n < 3 {
			_, _ = w.Write([]byte(`{"trackingId":4242,"status":"PENDING"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(f.certJSON(true))
	}
	res, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err != nil || f.polls != 3 || res.CertificatePEM == "" {
		t.Fatalf("err=%v polls=%d", err, f.polls)
	}
}

func TestEntrustPollDeclinedAndTimeout(t *testing.T) {
	f := newEntrustFixture(t)
	f.issue = func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"trackingId":4242}`))
	}
	f.poll = func(w http.ResponseWriter, _ int) {
		_, _ = w.Write([]byte(`{"status":"DECLINED","declineReason":"policy"}`))
	}
	c := f.connector()
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("err = %v", err)
	}
	f.polls = 0
	f.poll = func(w http.ResponseWriter, _ int) { _, _ = w.Write([]byte(`{"status":"PENDING"}`)) }
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil || f.polls != 4 {
		t.Fatalf("err=%v polls=%d", err, f.polls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Issue(ctx, IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("cancelled context must fail")
	}
}

func TestEntrustIssueRefusesGarbage(t *testing.T) {
	f := newEntrustFixture(t)
	c := f.connector()
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: "nope"}); err == nil {
		t.Fatal("bad CSR must be refused")
	}
	f.issue = func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"trackingId":1,"endEntityCert":"-----BEGIN CERTIFICATE-----\nbm90\n-----END CERTIFICATE-----"}`))
	}
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("unparseable certificate must be refused")
	}
	f.issue = func(w http.ResponseWriter, _ map[string]any) { _, _ = w.Write([]byte(`{}`)) }
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("missing trackingId must be refused")
	}
}

func TestEntrust4xxDoesNotLeakSecret(t *testing.T) {
	f := newEntrustFixture(t)
	f.issue = func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":400,"errors":[{"message":"bad key size","field":"csr"}]}`))
	}
	c := f.connector()
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "bad key size") {
		t.Fatalf("err = %v", err)
	}
	h := c.Health(context.Background())
	if h.Status != "degraded" || !strings.Contains(h.Detail, "last issue error") {
		t.Fatalf("health = %+v", h)
	}
	for _, s := range []string{entrustTestSecret, f.pki.clientK, "PRIVATE KEY"} {
		if strings.Contains(err.Error(), s) || strings.Contains(h.Detail, s) {
			t.Fatal("secret leaked")
		}
	}
}

func TestEntrust429CarriesRetryAfter(t *testing.T) {
	f := newEntrustFixture(t)
	f.issue = func(w http.ResponseWriter, _ map[string]any) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	_, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 2*time.Second || rl.Reason != "upstream_429" {
		t.Fatalf("err = %v", err)
	}
}

func TestEntrustRevokeShape(t *testing.T) {
	f := newEntrustFixture(t)
	c := f.connector()
	// Odd-length serial is left-padded to whole bytes and upper-cased.
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "0xabcdef1", Reason: 4}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.listQ != "serialNumber=0ABCDEF1" {
		t.Errorf("list query = %q", f.listQ)
	}
	if f.revPath != "/enterprise/v2/certificates/4242/revocations" {
		t.Errorf("path = %s", f.revPath)
	}
	if f.revBody["crlReason"] != "superseded" || f.revBody["revocationComment"] == "" {
		t.Errorf("body = %v", f.revBody)
	}
	// Unknown code omits crlReason; serial falls back to the certificate.
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.leafDER}))
	if err := c.Revoke(context.Background(), RevokeRequest{CertificatePEM: leaf, Reason: 99}); err != nil {
		t.Fatal(err)
	}
	if _, has := f.revBody["crlReason"]; has || f.listQ != "serialNumber=ABCDEF01" {
		t.Errorf("body=%v query=%q", f.revBody, f.listQ)
	}
}

func TestEntrustRevokeRefusesAmbiguity(t *testing.T) {
	f := newEntrustFixture(t)
	c := f.connector()
	for _, body := range []string{
		`{"certificates":[]}`,
		`{"certificates":[{"trackingId":1},{"trackingId":2}]}`,
	} {
		f.listBody, f.revPath = body, ""
		err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "01"})
		if err == nil || !strings.Contains(err.Error(), "refusing to revoke") || f.revPath != "" {
			t.Fatalf("body %s: err=%v revPath=%q", body, err, f.revPath)
		}
	}
	if err := c.Revoke(context.Background(), RevokeRequest{}); err == nil {
		t.Fatal("no serial must refuse")
	}
}

func TestEntrustRevokeError(t *testing.T) {
	f := newEntrustFixture(t)
	f.revCode = http.StatusBadRequest
	err := f.connector().Revoke(context.Background(), RevokeRequest{SerialHex: "ab"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || strings.Contains(err.Error(), entrustTestSecret) {
		t.Fatalf("err = %v", err)
	}
}

func TestEntrustHealth(t *testing.T) {
	f := newEntrustFixture(t)
	c := f.connector()
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health = %+v", h)
	}
	f.clients = http.StatusServiceUnavailable
	if h := c.Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("health = %+v", h)
	}
}

func TestEntrustBadClientPEMDegradesWithoutLeak(t *testing.T) {
	f := newEntrustFixture(t)
	c := NewEntrustConnector("en-2", EntrustConfig{BaseURL: f.srv.URL, ClientCertPEM: f.pki.clientCert, ClientKeyPEM: "garbage-" + entrustTestSecret}, testClient("", "", ""))
	h := c.Health(context.Background())
	if h.Status != "degraded" || strings.Contains(h.Detail, entrustTestSecret) {
		t.Fatalf("health = %+v", h)
	}
	if c.Type() != "entrust" || c.Origin() != "synced" || c.ID() != "en-2" {
		t.Fatal("identity accessors")
	}
	if c.cfg.BaseURL != f.srv.URL || c.cfg.ClientID != 1 || c.cfg.CertType != "STANDARD_SSL" {
		t.Fatal("defaults not applied")
	}
}

func TestEntrustRequiresBasicAuthAndClientCert(t *testing.T) {
	f := newEntrustFixture(t)
	c := f.connector()
	c.cfg.APIKey = "wrong"
	if h := c.Health(context.Background()); h.Status != "degraded" || strings.Contains(h.Detail, "wrong") {
		t.Fatalf("health = %+v", h)
	}
}
