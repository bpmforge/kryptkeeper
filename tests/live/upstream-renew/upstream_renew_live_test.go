// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package upstreamrenew_test

// W27-10 connector-level live proof: each upstream client obtains a
// certificate from an INDEPENDENT server (not Kryptkeeper's own
// internal/scep|est|wstep), and a TLS server presenting that certificate shows
// the same SHA-256 fingerprint the client reported.
//
// Gated by KK_LIVE_UPSTREAM=1 plus per-leg variables; a leg with missing
// variables is skipped with "NOT RUN: <var> unset", never faked. Secrets are
// read from files, never logged: every line this file logs goes through
// logf, which checks it against the secrets read, so a leak fails the test.
//
//	KK_UP_SCEP_URL            e.g. http://127.0.0.1:12016/scep
//	KK_UP_SCEP_CA_FILE        (optional) PEM of the SCEP CA; chain is checked when set
//	KK_UP_EST_URL             e.g. https://localhost:18085
//	KK_UP_EST_CA_FILE         PEM the EST server certificate chains to (also the issuing CA)
//	KK_UP_EST_USER, KK_UP_EST_PASSWORD_FILE
//	KK_UP_WSTEP_URL, KK_UP_WSTEP_USER, KK_UP_WSTEP_PASSWORD_FILE, KK_UP_WSTEP_TEMPLATE
//	KK_UP_DIGICERT_KEY_FILE, KK_UP_DIGICERT_ORG_ID, KK_UP_DIGICERT_BASE_URL (optional)

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/connectors"
)

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("KK_LIVE_UPSTREAM") != "1" {
		t.Skip("NOT RUN: KK_LIVE_UPSTREAM=1 not set; see tests/live/upstream-renew/README.md")
	}
}

func needEnv(t *testing.T, names ...string) map[string]string {
	t.Helper()
	requireLive(t)
	out := map[string]string{}
	for _, n := range names {
		v := strings.TrimSpace(os.Getenv(n))
		if v == "" {
			t.Skipf("NOT RUN: %s unset", n)
		}
		out[n] = v
	}
	return out
}

// secretFile reads a secret from a file; the value never reaches argv or logs.
func secretFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// leakGuard fails the test if a logged line contains a secret read from a file.
type leakGuard struct {
	t       *testing.T
	secrets []string
}

func (g *leakGuard) logf(format string, args ...any) {
	g.t.Helper()
	line := strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " ")
	for _, s := range g.secrets {
		if s != "" && strings.Contains(line, s) {
			g.t.Fatalf("a secret appears in harness output (line withheld)")
		}
	}
	g.t.Log(line)
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func normFP(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(s))
}

func newCSR(t *testing.T, key crypto.Signer, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func loadPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CA file: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		t.Fatalf("CA file %s holds no certificate", path)
	}
	return pool
}

// renewAndServe is the shared proof: issue through conn, check the reported
// fingerprint against the returned leaf, serve that leaf over TLS and compare
// what a client dials against new_fingerprint, and (when roots is non-nil)
// require the leaf to chain to the server's published CA.
func renewAndServe(t *testing.T, g *leakGuard, conn connectors.IssuerConnector, key crypto.Signer, cn string, withRSAHandles bool, roots *x509.CertPool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	req := connectors.IssueRequest{CSRPEM: newCSR(t, key, cn)}
	if withRSAHandles {
		req.Signer = key
		dec, ok := key.(crypto.Decrypter)
		if !ok {
			t.Fatal("RSA key is not a crypto.Decrypter")
		}
		req.Decrypter = dec
	}
	start := time.Now()
	res, err := conn.Issue(ctx, req)
	if err != nil {
		t.Fatalf("%s Issue: %v", conn.Type(), err)
	}
	elapsed := time.Since(start)

	var blocks []*x509.Certificate
	rest := []byte(res.CertificatePEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, perr := x509.ParseCertificate(b.Bytes)
		if perr != nil {
			t.Fatalf("returned certificate unparseable: %v", perr)
		}
		blocks = append(blocks, c)
	}
	if len(blocks) == 0 {
		t.Fatal("no certificate in the response")
	}
	leaf := blocks[0]
	newFP := normFP(res.FingerprintSHA256)
	if got := fingerprint(leaf.Raw); got != newFP {
		t.Fatalf("reported fingerprint %s != SHA-256 of the returned leaf %s", newFP, got)
	}
	if leaf.PublicKey == nil || !samePublicKey(leaf.PublicKey, key.Public()) {
		t.Fatal("issued leaf does not carry the requested public key")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // reads the peer certificate only; the chain is verified separately below
	c, err := tls.Dial("tcp", srv.Listener.Addr().String(), conf)
	if err != nil {
		t.Fatalf("dial the TLS server presenting the issued certificate: %v", err)
	}
	served := fingerprint(c.ConnectionState().PeerCertificates[0].Raw)
	_ = c.Close()
	if served != newFP {
		t.Fatalf("served fingerprint %s != new_fingerprint %s", served, newFP)
	}

	chain := "not checked (no CA file)"
	if roots != nil {
		inter := x509.NewCertPool()
		for _, b := range blocks[1:] {
			inter.AddCert(b)
		}
		if _, verr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); verr != nil {
			t.Fatalf("issued leaf does not chain to the server's published CA: %v", verr)
		}
		chain = "verified to the server's CA"
	}
	g.logf("PASS %s: CN=%s issuer=%q new_fingerprint=%s served_fingerprint=%s match=yes elapsed=%s chain=%s",
		conn.Type(), cn, leaf.Issuer.CommonName, newFP, served, elapsed.Round(time.Millisecond), chain)
}

func samePublicKey(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}

func TestLiveSCEPRenewal(t *testing.T) {
	env := needEnv(t, "KK_UP_SCEP_URL")
	g := &leakGuard{t: t}
	var roots *x509.CertPool
	if f := strings.TrimSpace(os.Getenv("KK_UP_SCEP_CA_FILE")); f != "" {
		roots = loadPool(t, f)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048) // classic SCEP key transport is RSA only
	if err != nil {
		t.Fatal(err)
	}
	conn := connectors.NewSCEPClient("live-scep", connectors.SCEPClientConfig{EndpointURL: env["KK_UP_SCEP_URL"]}, &http.Client{Timeout: 60 * time.Second})
	if h := conn.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("SCEP health: %s %s", h.Status, h.Detail)
	}
	renewAndServe(t, g, conn, key, "scep-live.uat.example", true, roots)
}

func TestLiveESTRenewal(t *testing.T) {
	env := needEnv(t, "KK_UP_EST_URL", "KK_UP_EST_CA_FILE", "KK_UP_EST_USER", "KK_UP_EST_PASSWORD_FILE")
	pw := secretFile(t, env["KK_UP_EST_PASSWORD_FILE"])
	g := &leakGuard{t: t, secrets: []string{pw}}
	roots := loadPool(t, env["KK_UP_EST_CA_FILE"])
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	conn := connectors.NewESTClient("live-est", connectors.ESTClientConfig{BaseURL: env["KK_UP_EST_URL"], Username: env["KK_UP_EST_USER"], Password: pw}, client)
	if h := conn.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("EST health: %s %s", h.Status, h.Detail)
	}
	renewAndServe(t, g, conn, key, "est-live.uat.example", false, roots)
}

func TestLiveWSTEPRenewal(t *testing.T) {
	env := needEnv(t, "KK_UP_WSTEP_URL", "KK_UP_WSTEP_USER", "KK_UP_WSTEP_PASSWORD_FILE", "KK_UP_WSTEP_TEMPLATE")
	pw := secretFile(t, env["KK_UP_WSTEP_PASSWORD_FILE"])
	g := &leakGuard{t: t, secrets: []string{pw}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn := connectors.NewWSTEPClient("live-wstep", connectors.WSTEPClientConfig{
		EndpointURL: env["KK_UP_WSTEP_URL"], Username: env["KK_UP_WSTEP_USER"], Password: pw, TemplateName: env["KK_UP_WSTEP_TEMPLATE"],
	}, &http.Client{Timeout: 60 * time.Second})
	renewAndServe(t, g, conn, key, "wstep-live.uat.example", false, nil)
}

func TestLiveDigiCertRenewal(t *testing.T) {
	env := needEnv(t, "KK_UP_DIGICERT_KEY_FILE", "KK_UP_DIGICERT_ORG_ID")
	apiKey := secretFile(t, env["KK_UP_DIGICERT_KEY_FILE"])
	g := &leakGuard{t: t, secrets: []string{apiKey}}
	org, err := strconv.Atoi(env["KK_UP_DIGICERT_ORG_ID"])
	if err != nil {
		t.Fatalf("KK_UP_DIGICERT_ORG_ID: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit poll pacing: approval-gated orders poll for up to 60 attempts x 5 s.
	conn := connectors.NewDigiCertConnector("live-digicert", connectors.DigiCertConfig{
		BaseURL: os.Getenv("KK_UP_DIGICERT_BASE_URL"), APIKey: apiKey, OrganizationID: org, PollAttempts: 60, PollInterval: 5 * time.Second,
	}, &http.Client{Timeout: 60 * time.Second})
	renewAndServe(t, g, conn, key, "digicert-live.uat.example", false, nil)
}

// TestLiveDigiCertRateLimit needs no account: a local stub answers every order
// with HTTP 429. It must surface as the typed rate-limit error (not the
// generic "HTTP 4xx:" form), carry Retry-After, and, through the Registry the
// hub uses, put the connector into backoff so a second call never reaches the
// upstream. A real 429 cannot be forced on demand against a live account.
func TestLiveDigiCertRateLimit(t *testing.T) {
	var hits atomic.Int32
	stub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "120")
		http.Error(w, `{"errors":[{"code":"too_many_requests"}]}`, http.StatusTooManyRequests)
	}))
	defer stub.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn := connectors.NewDigiCertConnector("rl-digicert", connectors.DigiCertConfig{
		BaseURL: stub.URL, APIKey: "stub-key-not-a-secret", OrganizationID: 1, PollAttempts: 1, PollInterval: time.Millisecond,
	}, stub.Client())
	req := connectors.IssueRequest{CSRPEM: newCSR(t, key, "rl.uat.example")}

	_, err = conn.Issue(context.Background(), req)
	if err == nil {
		t.Fatal("429 must be an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rate limited") || !strings.Contains(msg, "429") {
		t.Fatalf("error does not read as a rate limit: %q", msg)
	}
	if strings.Contains(msg, "HTTP 4") && !strings.Contains(msg, "rate limited") {
		t.Fatalf("429 surfaced as a generic HTTP 4xx failure: %q", msg)
	}
	var rl *connectors.RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "upstream_429" || rl.RetryAfter != 120*time.Second {
		t.Fatalf("want *RateLimitError{upstream_429, Retry-After 120s}, got %T %+v", err, rl)
	}

	reg := connectors.NewRegistry().WithThrottle(connectors.NewThrottle(connectors.Limits{}, nil))
	reg.Register(conn)
	before := hits.Load()
	if _, err = reg.Issue(context.Background(), "rl-digicert", req); !errors.As(err, &rl) || rl.Reason != "upstream_429" {
		t.Fatalf("registry first call: want upstream_429, got %v", err)
	}
	mid := hits.Load()
	if _, err = reg.Issue(context.Background(), "rl-digicert", req); !errors.As(err, &rl) || rl.Reason != "backoff" {
		t.Fatalf("registry second call: want backoff, got %v", err)
	}
	if hits.Load() != mid || mid != before+1 {
		t.Fatalf("backoff must not reach the upstream: hits before=%d after first=%d after second=%d", before, mid, hits.Load())
	}
	t.Logf("PASS digicert 429: typed RateLimitError (upstream_429, Retry-After 120s); registry backoff blocked the second call (upstream hit once)")
}
