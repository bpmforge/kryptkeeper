// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W5-04: k8s TLS-secret push — GET→PUT renewal, GET-404→POST first
// install, bearer auth everywhere, verify-after-push with restore.

type k8sFixture struct {
	srv      *httptest.Server
	requests []string
	// secret is the currently-stored manifest ("" = absent).
	secret string
}

type k8sSecretManifest struct {
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
	Meta map[string]string `json:"metadata"`
}

func newK8sFixture(t *testing.T, preexisting string) *k8sFixture {
	t.Helper()
	f := &k8sFixture{secret: preexisting}
	const namedPath = "/api/v1/namespaces/edge/secrets/shop-tls"
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer sekrit-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body) // fixture: short in-memory bodies
		body := string(raw)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == namedPath:
			if f.secret == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(f.secret))
		case r.Method == http.MethodPut && r.URL.Path == namedPath:
			f.secret = body
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/edge/secrets":
			f.secret = body
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == namedPath:
			f.secret = ""
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *k8sFixture) storedSecret(t *testing.T) k8sSecretManifest {
	t.Helper()
	var m k8sSecretManifest
	if err := json.Unmarshal([]byte(f.secret), &m); err != nil {
		t.Fatalf("stored secret unparsable: %v: %s", err, f.secret)
	}
	return m
}

func k8sPusherFor(f *k8sFixture) *K8sPusher {
	p, err := NewK8sPusher(K8sConfig{
		BaseURL: f.srv.URL, BearerToken: "sekrit-token",
		Namespace: "edge", SecretName: "shop-tls",
	}, f.srv.Client())
	if err != nil {
		panic(err) // test helper: f.srv.Client() is always non-nil, so no CA bundle is ever parsed here
	}
	return p
}

func k8sReq() PushRequest {
	return PushRequest{Name: "shop-tls", CertPEM: []byte("CERTPEM"), KeyPEM: []byte("KEYPEM")}
}

const priorSecretJSON = `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"shop-tls","namespace":"edge"},"type":"kubernetes.io/tls","data":{"tls.crt":"T0xE","tls.key":"T0xESw=="}}`

func TestK8sRenewalReplacesSecret(t *testing.T) {
	f := newK8sFixture(t, priorSecretJSON)
	p := k8sPusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "abcd", nil })

	req := k8sReq()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "AB:CD"
	res, err := p.Push(context.Background(), req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified || !res.Verified {
		t.Fatalf("expected verified: %+v", res)
	}
	want := []string{
		"GET /api/v1/namespaces/edge/secrets/shop-tls",
		"PUT /api/v1/namespaces/edge/secrets/shop-tls",
	}
	if len(f.requests) != 2 || f.requests[0] != want[0] || f.requests[1] != want[1] {
		t.Fatalf("sequence %v, want %v", f.requests, want)
	}
	m := f.storedSecret(t)
	if m.Type != "kubernetes.io/tls" {
		t.Fatalf("secret type %q", m.Type)
	}
	if crt, _ := base64.StdEncoding.DecodeString(m.Data["tls.crt"]); string(crt) != "CERTPEM" {
		t.Fatalf("tls.crt content wrong: %v", m.Data)
	}
	if key, _ := base64.StdEncoding.DecodeString(m.Data["tls.key"]); string(key) != "KEYPEM" {
		t.Fatalf("tls.key content wrong: %v", m.Data)
	}
}

func TestK8sFirstInstallCreates(t *testing.T) {
	f := newK8sFixture(t, "")
	p := k8sPusherFor(f)

	if _, err := p.Push(context.Background(), k8sReq()); err != nil {
		t.Fatalf("push: %v", err)
	}
	want := []string{
		"GET /api/v1/namespaces/edge/secrets/shop-tls",
		"POST /api/v1/namespaces/edge/secrets",
	}
	if len(f.requests) != 2 || f.requests[0] != want[0] || f.requests[1] != want[1] {
		t.Fatalf("sequence %v, want %v", f.requests, want)
	}
}

func TestK8sVerifyMismatchRestoresPriorSecret(t *testing.T) {
	f := newK8sFixture(t, priorSecretJSON)
	p := k8sPusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil })
	p.retryAttempts, p.retryDelay = 2, time.Millisecond // permanent mismatch: don't pay the full ~135s window

	req := k8sReq()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "abcd"
	res, err := p.Push(context.Background(), req)
	if err == nil {
		t.Fatal("mismatch must error")
	}
	if res.Outcome != OutcomeVerifyFailed || !res.RolledBack {
		t.Fatalf("expected verify_failed + rollback: %+v", res)
	}
	// The stored manifest is the captured prior one, byte-for-byte.
	if f.secret != priorSecretJSON {
		t.Fatalf("prior secret not restored: %s", f.secret)
	}
}

func TestK8sVerifyMismatchOnFirstInstallDeletes(t *testing.T) {
	f := newK8sFixture(t, "")
	p := k8sPusherFor(f).WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil })
	p.retryAttempts, p.retryDelay = 2, time.Millisecond // permanent mismatch: don't pay the full ~135s window

	req := k8sReq()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "abcd"
	if _, err := p.Push(context.Background(), req); err == nil {
		t.Fatal("mismatch must error")
	}
	if f.secret != "" {
		t.Fatalf("first-install secret must be deleted on verify failure: %s", f.secret)
	}
	last := f.requests[len(f.requests)-1]
	if last != "DELETE /api/v1/namespaces/edge/secrets/shop-tls" {
		t.Fatalf("expected trailing DELETE, got %v", f.requests)
	}
}

// W19-03 live UAT (kind): a kubelet propagates an updated Secret into a
// Pod's mounted volume on its own sync cadence, so a workload dialed
// immediately after a successful push can still serve the pre-push leaf
// for tens of seconds -- observed live, not a fingerprint mismatch that
// should roll back. Push must retry verify until it matches (or the
// bounded window is exhausted), the same shape as installer.go's
// verifyUntilMatchOrExhausted for the nginx/apache reload race.
func TestK8sVerifyRetriesUntilMatch(t *testing.T) {
	f := newK8sFixture(t, priorSecretJSON)
	calls := 0
	p := k8sPusherFor(f).WithVerifier(func(context.Context, string) (string, error) {
		calls++
		if calls < 3 {
			return "stale", nil // simulates the kubelet not having propagated yet
		}
		return "abcd", nil
	})
	p.retryAttempts, p.retryDelay = 5, time.Millisecond

	req := k8sReq()
	req.VerifyHostPort = "shop.example.com:443"
	req.ExpectedFingerprint = "AB:CD"
	res, err := p.Push(context.Background(), req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Outcome != OutcomeInstalledVerified || !res.Verified {
		t.Fatalf("expected verified once the fingerprint catches up: %+v", res)
	}
	if calls != 3 {
		t.Fatalf("expected exactly 3 verify calls (retry until match), got %d", calls)
	}
}

// W19-03 live UAT (kind): a rollback restore PUTs the pre-push manifest
// verbatim, but the write that just failed verification already advanced
// the Secret's resourceVersion -- Kubernetes' optimistic concurrency then
// rejects the restore with 409 Conflict on every real rollback, not just a
// race. The restore must re-GET the current object and carry its
// resourceVersion, never the stale one captured before the write.
func TestK8sRollbackReGetsResourceVersionToAvoidConflict(t *testing.T) {
	const namedPath = "/api/v1/namespaces/edge/secrets/shop-tls"
	rv := 100
	var putBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == namedPath:
			_, _ = w.Write([]byte(`{"metadata":{"name":"shop-tls","namespace":"edge","resourceVersion":"` + itoa(rv) + `"},"type":"kubernetes.io/tls","data":{"tls.crt":"b2xk"}}`))
		case r.Method == http.MethodPut && r.URL.Path == namedPath:
			raw, _ := io.ReadAll(r.Body)
			putBodies = append(putBodies, string(raw))
			var body struct {
				Metadata struct {
					ResourceVersion string `json:"resourceVersion"`
				} `json:"metadata"`
			}
			_ = json.Unmarshal(raw, &body)
			// Real API-server semantics: a PUT with no resourceVersion is
			// an unconditional replace (the install path); a PUT that DOES
			// carry one is rejected with 409 unless it matches the
			// object's CURRENT version (the restore path, after the
			// resourceVersion has since advanced).
			if body.Metadata.ResourceVersion != "" && body.Metadata.ResourceVersion != itoa(rv) {
				w.WriteHeader(http.StatusConflict)
				return
			}
			rv++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)

	p, err := NewK8sPusher(K8sConfig{BaseURL: srv.URL, Namespace: "edge", SecretName: "shop-tls"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	p = p.WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil }) // permanent mismatch
	p.retryAttempts, p.retryDelay = 2, time.Millisecond

	req := PushRequest{Name: "shop-tls", CertPEM: []byte("CERTPEM"), KeyPEM: []byte("KEYPEM"),
		VerifyHostPort: "shop.example.com:443", ExpectedFingerprint: "abcd"}
	res, err := p.Push(context.Background(), req)
	if err == nil {
		t.Fatal("verify mismatch must error")
	}
	if !res.RolledBack {
		t.Fatalf("restore must succeed once it carries the CURRENT resourceVersion: %+v", res)
	}
	if len(putBodies) != 2 {
		t.Fatalf("expected install PUT + restore PUT, got %d: %v", len(putBodies), putBodies)
	}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func TestK8sAuthFailureSurfaces(t *testing.T) {
	f := newK8sFixture(t, "")
	p, err := NewK8sPusher(K8sConfig{BaseURL: f.srv.URL, BearerToken: "wrong", Namespace: "edge", SecretName: "shop-tls"}, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Push(context.Background(), k8sReq()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("auth failure must surface the status, got %v", err)
	}
}

// Review fix (security challenger #1): install succeeds, verify fails,
// and the restore PUT fails — the secret is left on the unverified
// cert, so RolledBack must be FALSE with the detail naming the risk.
func TestK8sRollbackFailureReportedHonestly(t *testing.T) {
	putCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"data":{"tls.crt":"b2xk"}}`)) // existed=true, prior manifest
		case http.MethodPut:
			putCount++
			if putCount == 1 {
				w.WriteHeader(http.StatusOK) // install replace succeeds
			} else {
				w.WriteHeader(http.StatusInternalServerError) // restore fails
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	p, err := NewK8sPusher(K8sConfig{BaseURL: srv.URL, Namespace: "edge", SecretName: "shop-tls"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	p = p.WithVerifier(func(context.Context, string) (string, error) { return "ffff", nil })
	p.retryAttempts, p.retryDelay = 2, time.Millisecond // permanent mismatch: don't pay the full ~135s window
	req := PushRequest{Name: "shop-tls", CertPEM: []byte("CERTPEM"), KeyPEM: []byte("KEYPEM"),
		VerifyHostPort: "shop.example.com:443", ExpectedFingerprint: "abcd"}
	res, err := p.Push(context.Background(), req)
	if err == nil {
		t.Fatal("verify+rollback failure must error")
	}
	if res.RolledBack {
		t.Fatalf("a failed restore must report RolledBack=false: %+v", res)
	}
	if !strings.Contains(res.Detail, "ROLLBACK FAILED") {
		t.Fatalf("detail must name the rollback failure: %q", res.Detail)
	}
}

// W19-17: a k8s push target's own cluster CA (self-signed, e.g. kind) must
// verify without a kubectl proxy in front of it, and with no skip-verify
// escape hatch. Uses a real TLS listener (httptest.NewTLSServer) so the
// handshake itself is exercised, not just the HTTP semantics the plain
// k8sFixture covers.
func newK8sTLSFixture(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound) // no pre-existing secret
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func selfSignedCAPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestK8sPusherTrustsConfiguredCACert(t *testing.T) {
	prev := pushAllowLoopback
	pushAllowLoopback = true
	t.Cleanup(func() { pushAllowLoopback = prev })
	srv := newK8sTLSFixture(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	p, err := NewK8sPusher(K8sConfig{
		BaseURL: srv.URL, BearerToken: "tok", Namespace: "edge", SecretName: "shop-tls",
		CACertPEM: caPEM,
	}, nil) // nil: exercise the constructor's own TLS-client construction
	if err != nil {
		t.Fatalf("trusted CA bundle must construct cleanly: %v", err)
	}
	if _, err := p.Push(context.Background(), k8sReq()); err != nil {
		t.Fatalf("push against a trusted CA bundle must succeed, got: %v", err)
	}
}

func TestK8sPusherUntrustedCACertFailsVerification(t *testing.T) {
	prev := pushAllowLoopback
	pushAllowLoopback = true
	t.Cleanup(func() { pushAllowLoopback = prev })
	srv := newK8sTLSFixture(t)
	wrongCAPEM := selfSignedCAPEM(t, "not-the-real-cluster-ca")

	p, err := NewK8sPusher(K8sConfig{
		BaseURL: srv.URL, BearerToken: "tok", Namespace: "edge", SecretName: "shop-tls",
		CACertPEM: wrongCAPEM,
	}, nil)
	if err != nil {
		t.Fatalf("a well-formed (if wrong) CA bundle must construct: %v", err)
	}
	_, err = p.Push(context.Background(), k8sReq())
	if err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("an untrusted CA bundle must fail TLS verification clearly, got: %v", err)
	}
}

func TestK8sPusherMalformedCACertRefusedAtConstruction(t *testing.T) {
	if _, err := NewK8sPusher(K8sConfig{BaseURL: "https://k8s.invalid", CACertPEM: []byte("not a pem bundle")}, nil); err == nil {
		t.Fatal("a malformed CA bundle must be refused at construction, not deferred to the first push")
	}
}

func TestK8sPushRejectsNonDNS1123Names(t *testing.T) {
	for _, cfg := range []K8sConfig{
		{BaseURL: "https://k.invalid", Namespace: "../kube-system", SecretName: "x"},
		{BaseURL: "https://k.invalid", Namespace: "edge", SecretName: "a/b"},
		{BaseURL: "https://k.invalid", Namespace: "Edge", SecretName: "x"},
	} {
		p, err := NewK8sPusher(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Push(context.Background(), PushRequest{}); err == nil || !strings.Contains(err.Error(), "DNS-1123") {
			t.Errorf("%+v: want DNS-1123 refusal, got %v", cfg, err)
		}
	}
}
