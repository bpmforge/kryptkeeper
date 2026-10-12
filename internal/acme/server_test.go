// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/crl"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/ocsp"

	_ "modernc.org/sqlite"
)

// challengeRoutes maps a DNS name used as an ACME identifier in tests to the
// loopback listener that really serves it. The http-01 dial seam
// (SetHTTP01DialContext) consults it, so a test proves real end-to-end
// http-01 validation without the CA ever being allowed to dial 127.0.0.1
// directly. The port in the dialled address is ignored.
var challengeRoutes sync.Map // host -> "127.0.0.1:<port>"

var challengeSeq atomic.Int64

// testHTTP01Dial routes known test names to their listener and sends
// everything else (redirect targets such as 127.0.0.1 or 169.254.169.254)
// through the production dial guard, so tests keep exercising it.
func testHTTP01Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		if target, ok := challengeRoutes.Load(host); ok {
			return (&net.Dialer{}).DialContext(ctx, network, target.(string))
		}
	}
	return (&net.Dialer{Control: http01DialControl()}).DialContext(ctx, network, addr)
}

func registerChallengeRoute(t *testing.T, target string) string {
	t.Helper()
	name := fmt.Sprintf("ch%d.example.test", challengeSeq.Add(1))
	challengeRoutes.Store(name, target)
	t.Cleanup(func() { challengeRoutes.Delete(name) })
	return name
}

// startChallengeHost serves h on a loopback listener and returns the DNS name
// that the test dial seam routes to it.
func startChallengeHost(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return registerChallengeRoute(t, strings.TrimPrefix(srv.URL, "http://"))
}

// deadChallengeHost returns a name routed to a port nothing listens on.
func deadChallengeHost(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return registerChallengeRoute(t, addr)
}

func newTestACMEServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv, ts, _, _ := newTestACMEServerWithRevStore(t)
	return srv, ts
}

// newTestACMEServerWithRevStore builds an ACME test server the same way
// newTestACMEServer does, but wires a real ca.RevocationStore into
// construction (via NewServerWithStore, W1-14/G-91) and returns it alongside
// the CA engine -- so revoke-cert tests can assert directly on
// ca.RevocationStore.IsRevoked, and so every other test in this file
// (through the newTestACMEServer wrapper above) exercises the revStore
// codepath rather than the nil one.
func newTestACMEServerWithRevStore(t *testing.T) (srv *Server, ts *httptest.Server, engine ca.Service, revStore ca.RevocationStore) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine = ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("ACME Test Root", pkix.Name{
		CommonName: "ACME Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	revStore = ca.NewMemRevocationStore()
	ts = httptest.NewServer(nil)
	srv = NewServerWithStore(ts.URL, engine, rootCA.ID, NewMemStore(), revStore)
	srv.SetHTTP01DialContext(testHTTP01Dial)
	ts.Config.Handler = srv.Handler()
	return srv, ts, engine, revStore
}

// newTestACMEServerWithDBRevStore is like newTestACMEServerWithRevStore but
// wires a real SQL-backed ca.DBRevocationStore (sqlite, schema built by the
// production migration runner, internal/db.RunMigrations) instead of
// ca.MemRevocationStore, and a matching ca.DBStore for CAs sharing the same
// *sql.DB -- exactly how cmd/kryptkeeper/main.go wires APP_CERTIFICATE_PROVIDER=ca
// with a configured core DB (both caStore and revStore there share coreDB).
// W1-14's tests only ever exercised MemRevocationStore, which has no
// pre-existing-row requirement and so could not have caught G-92: an
// ACME-issued certificate is never inserted into the certificates table at
// issuance, so DBRevocationStore.Revoke's UPDATE silently matched zero rows.
func newTestACMEServerWithDBRevStore(t *testing.T) (srv *Server, ts *httptest.Server, engine ca.Service, revStore *ca.DBRevocationStore, keys keystore.Store, rootCA *ca.CA) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "acme-revocation-test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	keys, err = keystore.NewSoftwareStore(t.TempDir(), []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine = ca.NewEngine(keys, ca.NewDBStore(db, false))
	rootCA, err = engine.CreateRootCA("ACME DB Test Root", pkix.Name{
		CommonName: "ACME DB Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	revStore = ca.NewDBRevocationStore(db, false)
	ts = httptest.NewServer(nil)
	srv = NewServerWithStore(ts.URL, engine, rootCA.ID, NewMemStore(), revStore)
	srv.SetHTTP01DialContext(testHTTP01Dial)
	ts.Config.Handler = srv.Handler()
	return srv, ts, engine, revStore, keys, rootCA
}

// --- JWS test client helpers -----------------------------------------------
//
// acmeTestClient signs outer ACME JWS envelopes (RFC 8555 §6.2) with an
// ES256 (ECDSA P-256) key, mirroring what a real ACME client does. Every
// mutating-endpoint test below goes through this rather than posting a bare
// JSON body, now that the transport requires it (W1-08).

type acmeTestClient struct {
	priv *ecdsa.PrivateKey
	jwk  *JSONWebKey
	kid  string // set by newACMEAccount once the account exists
}

func newACMETestClient(t *testing.T) *acmeTestClient {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	return &acmeTestClient{priv: priv, jwk: jwkFromECDSAPublicKey(&priv.PublicKey)}
}

func jwkFromECDSAPublicKey(pub *ecdsa.PublicKey) *JSONWebKey {
	size := (pub.Curve.Params().BitSize + 7) / 8
	xPad := make([]byte, size)
	yPad := make([]byte, size)
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(xPad[size-len(xBytes):], xBytes)
	copy(yPad[size-len(yBytes):], yBytes)
	return &JSONWebKey{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xPad),
		Y:   base64.RawURLEncoding.EncodeToString(yPad),
	}
}

// accountID returns the account ID portion of the client's kid URL (set
// only after newACMEAccount).
func (c *acmeTestClient) accountID() string {
	return c.kid[strings.LastIndex(c.kid, "/")+1:]
}

func (c *acmeTestClient) thumbprint(t *testing.T) string {
	t.Helper()
	tp, err := jwkThumbprint(c.jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// sign builds a signed outer JWS for url with the given payload (nil/empty
// for a POST-as-GET-style empty payload). Uses jwk if the client has no kid
// yet (new-account), kid otherwise.
func (c *acmeTestClient) sign(t *testing.T, url, nonce string, payload []byte) *JWS {
	t.Helper()
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: nonce, URL: url}
	if c.kid == "" {
		hdr.JWK = c.jwk
	} else {
		hdr.KID = c.kid
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payloadB64 := ""
	if len(payload) > 0 {
		payloadB64 = base64.RawURLEncoding.EncodeToString(payload)
	}
	signingInput := []byte(protectedB64 + "." + payloadB64)
	sum := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, c.priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	return &JWS{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func fetchNonce(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, ts.URL+"/acme/new-nonce", nil)
	if err != nil {
		t.Fatalf("build nonce request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch nonce: %v", err)
	}
	defer resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatal("expected Replay-Nonce header")
	}
	return nonce
}

func postJWS(t *testing.T, url string, jws *JWS) *http.Response {
	t.Helper()
	body, err := json.Marshal(jws)
	if err != nil {
		t.Fatalf("marshal jws envelope: %v", err)
	}
	resp, err := http.Post(url, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// postJWS signs payload for url with c's key and posts it.
func (c *acmeTestClient) postJWS(t *testing.T, ts *httptest.Server, url string, payload []byte) *http.Response {
	t.Helper()
	nonce := fetchNonce(t, ts)
	jws := c.sign(t, url, nonce, payload)
	return postJWS(t, url, jws)
}

// newACMEAccount creates a real account via a fully-signed new-account
// request and returns a client whose kid is now set, ready to sign
// subsequent kid-authenticated requests.
func newACMEAccount(t *testing.T, ts *httptest.Server) *acmeTestClient {
	t.Helper()
	c := newACMETestClient(t)
	payload, err := json.Marshal(map[string]any{
		"contact":              []string{"mailto:test@example.com"},
		"termsOfServiceAgreed": true,
	})
	if err != nil {
		t.Fatalf("marshal new-account payload: %v", err)
	}
	resp := c.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create account: expected 201, got %d: %s", resp.StatusCode, b)
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		t.Fatal("expected Location header on account creation")
	}
	return c
}

// issueTestCertificate runs a full order -> http-01 challenge -> finalize
// flow for client and returns the issued certificate, its PEM encoding, and
// the CSR key used (needed by cert-key-authorized revoke-cert tests). This
// is the same flow TestACMEFullOrderFlow exercises step by step; factored
// out here since the revoke-cert tests below all need a real issued
// certificate to work with.
func issueTestCertificate(t *testing.T, ts *httptest.Server, client *acmeTestClient) (cert *x509.Certificate, certPEM []byte, csrKey *ecdsa.PrivateKey) {
	t.Helper()

	host := startChallengeHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		token := parts[len(parts)-1]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(token + "." + client.thumbprint(t)))
	}))

	orderPayload, err := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: host}},
	})
	if err != nil {
		t.Fatalf("marshal order payload: %v", err)
	}
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	if err := json.NewDecoder(orderResp.Body).Decode(&order); err != nil {
		t.Fatalf("decode order: %v", err)
	}
	orderResp.Body.Close()
	if len(order.Authorizations) == 0 {
		t.Fatal("expected at least 1 authorization")
	}

	authzResp, err := http.Get(order.Authorizations[0])
	if err != nil {
		t.Fatalf("get authz: %v", err)
	}
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	var httpChallenge Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			httpChallenge = ch
		}
	}
	if httpChallenge.URL == "" {
		t.Fatal("no http-01 challenge found")
	}
	chResp := client.postJWS(t, ts, httpChallenge.URL, []byte("{}"))
	chResp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	var readyAuthz Authorization
	for time.Now().Before(deadline) {
		pollResp, _ := http.Get(order.Authorizations[0])
		json.NewDecoder(pollResp.Body).Decode(&readyAuthz)
		pollResp.Body.Close()
		if readyAuthz.Status == "valid" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if readyAuthz.Status != "valid" {
		t.Fatalf("expected valid authz after polling, got %s", readyAuthz.Status)
	}

	orderURL := orderResp.Header.Get("Location")
	readyResp, err := http.Get(orderURL)
	if err != nil {
		t.Fatalf("get order: %v", err)
	}
	var readyOrder Order
	json.NewDecoder(readyResp.Body).Decode(&readyOrder)
	readyResp.Body.Close()
	if readyOrder.Status != "ready" {
		t.Fatalf("expected ready order, got %s", readyOrder.Status)
	}

	csrKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: host},
		DNSNames: []string{host},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	finalizePayload, err := json.Marshal(map[string]any{"csr": base64.RawURLEncoding.EncodeToString(csrDER)})
	if err != nil {
		t.Fatalf("marshal finalize payload: %v", err)
	}
	finalizeResp := client.postJWS(t, ts, readyOrder.Finalize, finalizePayload)
	var finalOrder Order
	json.NewDecoder(finalizeResp.Body).Decode(&finalOrder)
	finalizeResp.Body.Close()
	if finalOrder.Status != "valid" || finalOrder.Certificate == "" {
		t.Fatalf("expected valid finalized order with certificate, got status=%s cert=%s", finalOrder.Status, finalOrder.Certificate)
	}

	certResp, err := http.Get(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	certPEM, err = io.ReadAll(certResp.Body)
	certResp.Body.Close()
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}

	der, err := decodePEM(certPEM)
	if err != nil || der == nil {
		t.Fatalf("decode issued cert PEM: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	return cert, certPEM, csrKey
}

// signRaw builds a signed Flattened JSON Serialization JWS from an
// explicit protected header, rather than acmeTestClient.sign's outer-JWS
// shape (jwk-if-no-kid, always-present nonce). Used for the key-change
// inner JWS, whose header rules differ: jwk is always present regardless
// of kid state, and a nonce must not be sent at all.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, hdr jwsProtectedHeader, payload []byte) *JWS {
	t.Helper()
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payloadB64 := ""
	if len(payload) > 0 {
		payloadB64 = base64.RawURLEncoding.EncodeToString(payload)
	}
	signingInput := []byte(protectedB64 + "." + payloadB64)
	sum := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	return &JWS{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func TestACMEDirectory(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/acme/directory")
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Error("expected Replay-Nonce header")
	}

	var dir Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	if !strings.HasSuffix(dir.NewNonce, "/acme/new-nonce") {
		t.Errorf("unexpected newNonce URL: %s", dir.NewNonce)
	}
	if !strings.HasSuffix(dir.NewOrder, "/acme/new-order") {
		t.Errorf("unexpected newOrder URL: %s", dir.NewOrder)
	}
}

func TestACMENewNonce(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	// HEAD returns 200 with nonce.
	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/acme/new-nonce", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD new-nonce: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for HEAD, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Error("expected Replay-Nonce on HEAD")
	}

	// GET returns 204 with nonce.
	resp2, _ := http.Get(ts.URL + "/acme/new-nonce")
	if resp2.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 for GET, got %d", resp2.StatusCode)
	}
}

func TestACMENewAccount(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMETestClient(t)
	payload, _ := json.Marshal(map[string]any{
		"contact":              []string{"mailto:test@example.com"},
		"termsOfServiceAgreed": true,
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-account", payload)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Location") == "" {
		t.Error("expected Location header")
	}

	var acct Account
	json.NewDecoder(resp.Body).Decode(&acct)
	if acct.Status != "valid" {
		t.Errorf("expected valid status, got %s", acct.Status)
	}
	wantThumbprint := client.thumbprint(t)
	if acct.KeyThumbprint != wantThumbprint {
		t.Errorf("expected account key thumbprint %q captured at creation, got %q", wantThumbprint, acct.KeyThumbprint)
	}
}

// TestACMENewAccountBadSignatureRejected proves acceptance criterion 1's
// negative: a request with a tampered (invalid) signature must be rejected,
// not merely one with a missing envelope.
func TestACMENewAccountBadSignatureRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMETestClient(t)
	payload, _ := json.Marshal(map[string]any{
		"contact":              []string{"mailto:a@example.com"},
		"termsOfServiceAgreed": true,
	})
	nonce := fetchNonce(t, ts)
	jws := client.sign(t, ts.URL+"/acme/new-account", nonce, payload)

	sigBytes, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sigBytes[0] ^= 0xFF
	jws.Signature = base64.RawURLEncoding.EncodeToString(sigBytes)

	resp := postJWS(t, ts.URL+"/acme/new-account", jws)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for tampered signature, got %d", resp.StatusCode)
	}
}

// TestACMENewAccountMissingJWSRejected proves acceptance criterion 1's other
// negative: the pre-W1-08 wire format (a bare JSON body, no outer JWS
// envelope) must now be rejected rather than accepted.
func TestACMENewAccountMissingJWSRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	body := `{"contact":["mailto:test@example.com"],"termsOfServiceAgreed":true}`
	resp, err := http.Post(ts.URL+"/acme/new-account", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST new-account: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing JWS envelope, got %d", resp.StatusCode)
	}
}

// runACMEFullOrderFlow drives account creation through HTTP-01 validation,
// finalize and certificate download against an already-running ACME test
// server, and returns the finalized order plus the downloaded cert PEM and
// parsed certificate. Factored out of TestACMEFullOrderFlow (W18-16) so the
// issuance-recording tests below can reuse the same real end-to-end path
// instead of hand-rolling a shorter, less representative one.
func runACMEFullOrderFlow(t *testing.T, ts *httptest.Server) (finalOrder Order, certPEM []byte, cert *x509.Certificate) {
	t.Helper()

	// 1. Create account.
	client := newACMEAccount(t, ts)

	// Stand up a local HTTP server that serves the expected KeyAuthorization
	// for any ACME challenge token (RFC 8555 §8.3: token+"."+thumbprint),
	// now that HTTP-01 validation checks the full value, not just a prefix.
	challengeHost := startChallengeHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		token := parts[len(parts)-1]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(token + "." + client.thumbprint(t)))
	}))

	// 2. Create order using the local challenge server address as the identifier.
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: challengeHost}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	defer orderResp.Body.Close()

	if orderResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(orderResp.Body)
		t.Fatalf("expected 201, got %d: %s", orderResp.StatusCode, body)
	}

	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	if order.Status != "pending" {
		t.Fatalf("expected pending, got %s", order.Status)
	}
	if len(order.Authorizations) != 1 {
		t.Fatalf("expected 1 authz, got %d", len(order.Authorizations))
	}

	// 3. Get authorization.
	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	if authz.Status != "pending" {
		t.Fatalf("expected pending authz, got %s", authz.Status)
	}
	if len(authz.Challenges) < 1 {
		t.Fatal("expected at least 1 challenge")
	}

	// 4. Find and trigger http-01 challenge.
	var httpChallenge Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			httpChallenge = ch
			break
		}
	}
	if httpChallenge.URL == "" {
		t.Fatal("no http-01 challenge found")
	}

	challengeResp := client.postJWS(t, ts, httpChallenge.URL, []byte("{}"))
	challengeResp.Body.Close()

	// 5. Poll authz until valid (async HTTP-01 validation), timeout after 5s.
	authzURL := order.Authorizations[0]
	deadline := time.Now().Add(5 * time.Second)
	var readyAuthz Authorization
	for time.Now().Before(deadline) {
		pollResp, _ := http.Get(authzURL)
		json.NewDecoder(pollResp.Body).Decode(&readyAuthz)
		pollResp.Body.Close()
		if readyAuthz.Status == "valid" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if readyAuthz.Status != "valid" {
		t.Fatalf("expected valid authz after polling, got %s", readyAuthz.Status)
	}

	// 6. Check order is now ready.
	orderURL := orderResp.Header.Get("Location")
	readyResp, _ := http.Get(orderURL)
	var readyOrder Order
	json.NewDecoder(readyResp.Body).Decode(&readyOrder)
	readyResp.Body.Close()

	if readyOrder.Status != "ready" {
		t.Fatalf("expected ready order, got %s", readyOrder.Status)
	}

	// 7. Finalize with CSR.
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: challengeHost},
		DNSNames: []string{challengeHost},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)

	finalizePayload, _ := json.Marshal(map[string]any{"csr": csrB64})
	finalizeResp := client.postJWS(t, ts, readyOrder.Finalize, finalizePayload)
	json.NewDecoder(finalizeResp.Body).Decode(&finalOrder)
	finalizeStatus := finalizeResp.StatusCode
	finalizeResp.Body.Close()

	if finalizeStatus != http.StatusOK {
		t.Fatalf("expected 200 from finalize, got %d", finalizeStatus)
	}
	if finalOrder.Status != "valid" {
		t.Fatalf("expected valid order after finalize, got %s", finalOrder.Status)
	}
	if finalOrder.Certificate == "" {
		t.Fatal("expected certificate URL")
	}

	// 8. Download certificate.
	certResp, _ := http.Get(finalOrder.Certificate)
	certPEM, _ = io.ReadAll(certResp.Body)
	certResp.Body.Close()

	if certResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for cert download, got %d", certResp.StatusCode)
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Error("expected PEM certificate in response")
	}

	// Parse and verify the certificate.
	block, _ := decodePEM(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	var err error
	cert, err = x509.ParseCertificate(block)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != challengeHost {
		t.Errorf("expected CN=%s, got %s", challengeHost, cert.Subject.CommonName)
	}
	return finalOrder, certPEM, cert
}

func TestACMEFullOrderFlow(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	runACMEFullOrderFlow(t, ts)
}

// TestACMEChallengeResponseHasUpLinkHeader is W19-01: certbot's ClientV2
// (RFC 8555's reference implementation shape) reads resp.links["up"] off the
// response to POSTing a challenge answer and hard-fails with
// `ClientError('"up" Link header missing')` if it isn't there. Every
// existing test drove this endpoint with plain http.Post/postJWS and only
// ever inspected the JSON body, so the header's absence was invisible until
// a real client hit it live. Covers all three response paths in
// handleChallenge: the normal processing branch, the already-valid branch,
// and the unknown-challenge-type branch.
func TestACMEChallengeResponseHasUpLinkHeader(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	authz := &Authorization{
		ID:        "authz-link-test",
		AccountID: client.accountID(),
		Identifier: Identifier{
			Type: "dns", Value: "test.example.com",
		},
		Status: "pending",
		Challenges: []Challenge{
			{Type: "http-01", URL: ts.URL + "/acme/challenge/authz-link-test/http-01", Token: "tok", Status: "pending"},
		},
	}
	srv.store.SaveAuthz(authz)

	wantLink := `<` + ts.URL + `/acme/authz/authz-link-test>;rel="up"`

	resp := client.postJWS(t, ts, authz.Challenges[0].URL, []byte("{}"))
	resp.Body.Close()
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("processing branch: Link header = %q, want %q", got, wantLink)
	}

	// Already-valid branch (a distinct early-return code path in
	// handleChallenge -- constructed directly with Status: "valid" rather
	// than driven there via real HTTP-01 validation, same as
	// TestACMEChallengeAlreadyValid does).
	validAuthz := &Authorization{
		ID:        "authz-link-valid",
		AccountID: client.accountID(),
		Identifier: Identifier{
			Type: "dns", Value: "valid.example.com",
		},
		Status: "valid",
		Challenges: []Challenge{
			{Type: "http-01", URL: ts.URL + "/acme/challenge/authz-link-valid/http-01", Token: "tok", Status: "valid"},
		},
	}
	srv.store.SaveAuthz(validAuthz)
	wantValidLink := `<` + ts.URL + `/acme/authz/authz-link-valid>;rel="up"`
	validResp := client.postJWS(t, ts, validAuthz.Challenges[0].URL, []byte("{}"))
	defer validResp.Body.Close()
	if got := validResp.Header.Get("Link"); got != wantValidLink {
		t.Errorf("already-valid branch: Link header = %q, want %q", got, wantValidLink)
	}

	// Unknown-challenge-type branch.
	unknownAuthz := &Authorization{
		ID:        "authz-link-unknown",
		AccountID: client.accountID(),
		Identifier: Identifier{
			Type: "dns", Value: "test2.example.com",
		},
		Status: "pending",
		Challenges: []Challenge{
			{Type: "made-up-01", URL: ts.URL + "/acme/challenge/authz-link-unknown/made-up-01", Token: "tok", Status: "pending"},
		},
	}
	srv.store.SaveAuthz(unknownAuthz)
	wantUnknownLink := `<` + ts.URL + `/acme/authz/authz-link-unknown>;rel="up"`
	unknownResp := client.postJWS(t, ts, unknownAuthz.Challenges[0].URL, []byte("{}"))
	defer unknownResp.Body.Close()
	if got := unknownResp.Header.Get("Link"); got != wantUnknownLink {
		t.Errorf("unknown-type branch: Link header = %q, want %q", got, wantUnknownLink)
	}
}

// TestACMECertificateDownloadHasReplayNonce is W19-01: handleCertificate
// wrote the PEM body but never set Replay-Nonce, so a real client (certbot)
// hit acme.errors.MissingNonce trying to download the certificate it had
// just been issued -- every existing test used a plain http.Get and only
// checked the body, never the header a real client needs for its next POST.
func TestACMECertificateDownloadHasReplayNonce(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	finalOrder, _, _ := runACMEFullOrderFlow(t, ts)

	resp, err := http.Get(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("cert download: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Replay-Nonce"); got == "" {
		t.Error("expected non-empty Replay-Nonce on certificate download response")
	}
}

// TestACMECertificateDownloadIncludesIssuerChain is W19-01: handleFinalize
// stored only the leaf certificate's own PEM, so /acme/cert/{id} served a
// single-block response. RFC 8555 SS7.4.2 doesn't strictly mandate a chain,
// but real clients do: certbot hard-fails parsing it with "less than 2
// certificates in chain". Proves the download now contains both the leaf
// and the issuing CA's certificate, in that order.
func TestACMECertificateDownloadIncludesIssuerChain(t *testing.T) {
	srv, ts, engine, _ := newTestACMEServerWithRevStore(t)
	defer ts.Close()

	finalOrder, _, leaf := runACMEFullOrderFlow(t, ts)

	resp, err := http.Get(finalOrder.Certificate)
	if err != nil {
		t.Fatalf("cert download: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var blocks [][]byte
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block.Bytes)
	}
	if len(blocks) < 2 {
		t.Fatalf("expected at least 2 PEM blocks (leaf + issuer), got %d: %s", len(blocks), body)
	}

	firstCert, err := x509.ParseCertificate(blocks[0])
	if err != nil {
		t.Fatalf("first block did not parse as a certificate: %v", err)
	}
	if certFingerprint(firstCert) != certFingerprint(leaf) {
		t.Error("expected first PEM block to be the leaf certificate the client requested")
	}

	issuerCA, err := engine.GetCA(srv.caID)
	if err != nil {
		t.Fatalf("get issuer CA: %v", err)
	}
	secondCert, err := x509.ParseCertificate(blocks[1])
	if err != nil {
		t.Fatalf("second block did not parse as a certificate: %v", err)
	}
	if certFingerprint(secondCert) != certFingerprint(issuerCA.Certificate) {
		t.Error("expected second PEM block to be the issuing CA's certificate")
	}
}

// fakeIssuedRecorder is a test double for IssuedCertificateRecorder that
// records how it was called and can be made to fail on demand, to verify
// W18-16's "a recorder failure never fails the ACME order" contract.
type fakeIssuedRecorder struct {
	mu       sync.Mutex
	calls    int
	caID     string
	cert     *x509.Certificate
	chainPEM []byte
	err      error
}

func (f *fakeIssuedRecorder) RecordIssuedCertificate(_ context.Context, caID string, cert *x509.Certificate, chainPEM []byte, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.caID = caID
	f.cert = cert
	f.chainPEM = append([]byte(nil), chainPEM...)
	return f.err
}

// TestACMEFinalizeRecordsIssuedCertificate is W18-16: ACME finalize used to
// leave every issued certificate out of the recorder entirely (only
// revocation created an on-demand row). This asserts the recorder is called
// exactly once, with the fingerprint of the certificate the client actually
// downloaded and a non-empty chain.
func TestACMEFinalizeRecordsIssuedCertificate(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("ACME Test Root", pkix.Name{
		CommonName: "ACME Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	recorder := &fakeIssuedRecorder{}
	ts := httptest.NewServer(nil)
	defer ts.Close()
	srv := NewServerWithStore(ts.URL, engine, rootCA.ID, NewMemStore(), ca.NewMemRevocationStore()).
		WithIssuedRecorder(recorder)
	srv.SetHTTP01DialContext(testHTTP01Dial)
	ts.Config.Handler = srv.Handler()

	_, _, cert := runACMEFullOrderFlow(t, ts)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Fatalf("expected recorder called once, got %d", recorder.calls)
	}
	if recorder.caID != rootCA.ID {
		t.Errorf("expected caID=%s, got %s", rootCA.ID, recorder.caID)
	}
	if recorder.cert == nil || certFingerprint(recorder.cert) != certFingerprint(cert) {
		t.Errorf("expected recorder to see the issued certificate, fingerprint mismatch")
	}
	if len(recorder.chainPEM) == 0 {
		t.Error("expected non-empty chain PEM passed to recorder")
	}
	if !strings.Contains(string(recorder.chainPEM), "BEGIN CERTIFICATE") {
		t.Error("expected chain PEM to contain a PEM certificate")
	}
}

// TestACMEFinalizeRecorderErrorDoesNotFailOrder is W18-16's other half: the
// client already has its certificate once finalize responds, so a recorder
// failure must be logged, never surfaced as a failed order.
func TestACMEFinalizeRecorderErrorDoesNotFailOrder(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("ACME Test Root", pkix.Name{
		CommonName: "ACME Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	recorder := &fakeIssuedRecorder{err: errors.New("simulated recorder failure")}
	ts := httptest.NewServer(nil)
	defer ts.Close()
	srv := NewServerWithStore(ts.URL, engine, rootCA.ID, NewMemStore(), ca.NewMemRevocationStore()).
		WithIssuedRecorder(recorder)
	srv.SetHTTP01DialContext(testHTTP01Dial)
	ts.Config.Handler = srv.Handler()

	// runACMEFullOrderFlow itself asserts finalize returns 200 and a valid
	// order with a downloadable certificate -- reaching the end of it proves
	// the recorder's error never changed the HTTP outcome.
	runACMEFullOrderFlow(t, ts)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Fatalf("expected recorder still called once despite its own error, got %d", recorder.calls)
	}
}

func TestACMEFinalizeBeforeReady(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)

	// Create order but don't complete challenges.
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: "test.example.com"}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	// Try to finalize.
	finalizePayload, _ := json.Marshal(map[string]any{"csr": "dGVzdA"})
	finalizeResp := client.postJWS(t, ts, order.Finalize, finalizePayload)
	if finalizeResp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for premature finalize, got %d", finalizeResp.StatusCode)
	}
	finalizeResp.Body.Close()
}

func TestACMEDNS01ChallengeReturnsInvalid(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)

	// Create order.
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: "example.com"}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	// Get authz.
	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	// Find dns-01 challenge.
	var dns01URL string
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dns01URL = ch.URL
			break
		}
	}
	if dns01URL == "" {
		t.Fatal("no dns-01 challenge in authz")
	}

	// Trigger dns-01 — server starts async DNS validation and returns "processing".
	resp := client.postJWS(t, ts, dns01URL, []byte("{}"))
	var ch Challenge
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()

	if ch.Status != "processing" {
		t.Errorf("expected dns-01 status=processing after trigger, got %s", ch.Status)
	}

	// Wait for the async DNS lookup to complete (will fail since "example.com"
	// has no _acme-challenge TXT with the expected digest).
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		pollResp, _ := http.Get(order.Authorizations[0])
		var polledAuthz Authorization
		json.NewDecoder(pollResp.Body).Decode(&polledAuthz)
		pollResp.Body.Close()
		if polledAuthz.Status == "invalid" {
			return // expected outcome
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Error("authz did not become invalid within timeout after dns-01 validation failure")
}

func TestACMEHTTP01ValidationFails(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)

	// Use an unreachable identifier so HTTP-01 fetch fails.
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: deadChallengeHost(t)}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	var http01URL string
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			http01URL = ch.URL
			break
		}
	}

	// Trigger challenge — the name routes to a port nobody listens on.
	resp := client.postJWS(t, ts, http01URL, []byte("{}"))
	resp.Body.Close()

	// Poll until the async validation completes and marks authz invalid.
	deadline := time.Now().Add(15 * time.Second)
	var result Authorization
	for time.Now().Before(deadline) {
		pollResp, _ := http.Get(order.Authorizations[0])
		json.NewDecoder(pollResp.Body).Decode(&result)
		pollResp.Body.Close()
		if result.Status != "pending" && result.Status != "processing" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if result.Status != "invalid" {
		t.Errorf("expected authz invalid after unreachable host, got %s", result.Status)
	}
}

// TestACMEHTTP01TokenOnlyResponseNowRejected proves the closed half of
// acceptance criterion 2 directly: serving just the bare token (the
// pre-W1-08 behavior — token-prefix matching only, no account key bound)
// must now fail, because validateHTTP01 requires the full KeyAuthorization
// (token+"."+account JWK thumbprint).
func TestACMEHTTP01TokenOnlyResponseNowRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)

	// Serves the bare token only — satisfies the old prefix-match check but
	// not the new exact KeyAuthorization match.
	challengeHost := startChallengeHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		token := parts[len(parts)-1]
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(token))
	}))

	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: challengeHost}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	var http01URL string
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			http01URL = ch.URL
			break
		}
	}

	resp := client.postJWS(t, ts, http01URL, []byte("{}"))
	resp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	var result Authorization
	for time.Now().Before(deadline) {
		pollResp, _ := http.Get(order.Authorizations[0])
		json.NewDecoder(pollResp.Body).Decode(&result)
		pollResp.Body.Close()
		if result.Status != "pending" && result.Status != "processing" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if result.Status != "invalid" {
		t.Errorf("expected authz invalid for token-only (non-KeyAuthorization) response, got %s", result.Status)
	}
}

func TestACMENonceService(t *testing.T) {
	ns := NewNonceService(100)

	n1, _ := ns.New()
	n2, _ := ns.New()

	if n1 == n2 {
		t.Error("nonces should be unique")
	}

	if !ns.Consume(n1) {
		t.Error("valid nonce should be consumed")
	}
	if ns.Consume(n1) {
		t.Error("consumed nonce should not be valid again")
	}
	if !ns.Consume(n2) {
		t.Error("n2 should still be valid")
	}
	if ns.Consume("bogus-nonce") {
		t.Error("unknown nonce should not be valid")
	}
}

func TestACMEDirectoryMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/acme/directory", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMENewNonceMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/acme/new-nonce", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMENewAccountMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/acme/new-account")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMENewAccountInvalidBody(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/acme/new-account", "application/json", strings.NewReader("not-json"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestACMENewOrderMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/acme/new-order")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMENewOrderInvalidBody(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/acme/new-order", "application/json", strings.NewReader("bad"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestACMENewOrderEmptyIdentifiers(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	payload, _ := json.Marshal(map[string]any{"identifiers": []Identifier{}})
	resp := client.postJWS(t, ts, ts.URL+"/acme/new-order", payload)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestACMEOrderNotFound(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/acme/order/nonexistent-order")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestACMEAuthzNotFound(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/acme/authz/nonexistent-authz")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestACMEChallengeMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)

	// Create an order to get a real authz and challenge URL.
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: "test.example.com"}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	resp, _ := http.Get(authz.Challenges[0].URL)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMEChallengeAuthzNotFound(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	resp := client.postJWS(t, ts, ts.URL+"/acme/challenge/nonexistent/http-01", []byte("{}"))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestACMEChallengeTypeNotFound(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: "test.example.com"}},
	})
	orderResp := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	resp := client.postJWS(t, ts, ts.URL+"/acme/challenge/"+authz.ID+"/nonexistent-type", []byte("{}"))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown challenge type, got %d", resp.StatusCode)
	}
}

func TestACMEChallengeUnknownTypeReturnsInvalid(t *testing.T) {
	// We need to inject an authz that has an unsupported challenge type,
	// owned by a real account since handleChallenge now checks ownership.
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	authz := &Authorization{
		ID:         "authz-unknown",
		AccountID:  client.accountID(),
		Identifier: Identifier{Type: "dns", Value: "test.example.com"},
		Status:     "pending",
		Challenges: []Challenge{
			{Type: "tls-alpn-01", URL: ts.URL + "/acme/challenge/authz-unknown/tls-alpn-01", Token: "tok", Status: "pending"},
		},
	}
	srv.store.SaveAuthz(authz)

	resp := client.postJWS(t, ts, ts.URL+"/acme/challenge/authz-unknown/tls-alpn-01", []byte("{}"))
	var ch Challenge
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()

	if ch.Status != "invalid" {
		t.Errorf("expected invalid status for unsupported challenge type, got %s", ch.Status)
	}
}

func TestACMEChallengeAlreadyValid(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	authz := &Authorization{
		ID:         "authz-valid",
		AccountID:  client.accountID(),
		Identifier: Identifier{Type: "dns", Value: "test.example.com"},
		Status:     "valid",
		Challenges: []Challenge{
			{Type: "http-01", URL: ts.URL + "/acme/challenge/authz-valid/http-01", Token: "tok", Status: "valid"},
		},
	}
	srv.store.SaveAuthz(authz)

	resp := client.postJWS(t, ts, ts.URL+"/acme/challenge/authz-valid/http-01", []byte("{}"))
	var ch Challenge
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for already-valid challenge, got %d", resp.StatusCode)
	}
	if ch.Status != "valid" {
		t.Errorf("expected valid status, got %s", ch.Status)
	}
}

// TestACMEChallengeCrossAccountRejected proves a real security fix that
// falls out of the JWS rewrite: before W1-08 there was no cryptographic
// account identity at all, so any caller could trigger validation for any
// authorization by ID. Now the kid-authenticated caller must match the
// authorization's owning account.
func TestACMEChallengeCrossAccountRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	owner := newACMEAccount(t, ts)
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: "test.example.com"}},
	})
	orderResp := owner.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	var order Order
	json.NewDecoder(orderResp.Body).Decode(&order)
	orderResp.Body.Close()

	authzResp, _ := http.Get(order.Authorizations[0])
	var authz Authorization
	json.NewDecoder(authzResp.Body).Decode(&authz)
	authzResp.Body.Close()

	attacker := newACMEAccount(t, ts)
	resp := attacker.postJWS(t, ts, authz.Challenges[0].URL, []byte("{}"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a different account triggering someone else's challenge, got %d", resp.StatusCode)
	}
}

// TestACMEChallengeAlreadyValidRaceFree reproduces the G-74 race in the
// already-valid branch of handleChallenge: only Status=="valid" gates
// re-spawning a validation goroutine, not "processing", so a genuine
// concurrent validator can still be writing to the same *Challenge while a
// separate poll hits the already-valid branch. Run with -race.
func TestACMEChallengeAlreadyValidRaceFree(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	authz := &Authorization{
		ID:         "authz-race",
		AccountID:  client.accountID(),
		Identifier: Identifier{Type: "dns", Value: "test.example.com"},
		Status:     "valid",
		Challenges: []Challenge{
			{Type: "http-01", URL: ts.URL + "/acme/challenge/authz-race/http-01", Token: "tok", Status: "valid"},
		},
	}
	srv.store.SaveAuthz(authz)
	ch := &authz.Challenges[0]

	ts2 := ts

	var wg sync.WaitGroup
	wg.Add(2)
	stop := make(chan struct{})

	// Simulates a genuine concurrent validation goroutine still writing to
	// this exact *Challenge (the scenario a double-POST while
	// pending/processing can produce). Runs continuously for the reader's
	// entire duration below -- a fixed small iteration count here finishes
	// (a tight lock/write/unlock loop) long before a single real HTTP
	// round-trip completes, which would never overlap with the reader and
	// so would never actually exercise the race regardless of the fix.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			srv.mu.Lock()
			now := time.Now().UTC()
			ch.Status = "valid"
			ch.Validated = &now
			srv.mu.Unlock()
		}
	}()

	// Repeatedly hits the already-valid branch. Each POST needs a fresh
	// single-use nonce and a fresh signature (the outer JWS is now
	// mandatory), so this can't just reuse http.Post directly like the other
	// goroutine's raw store mutation above.
	challengeURL := ts2.URL + "/acme/challenge/authz-race/http-01"
	go func() {
		defer func() {
			close(stop)
			wg.Done()
		}()
		for i := 0; i < 200; i++ {
			nonceReq, _ := http.NewRequest(http.MethodHead, ts2.URL+"/acme/new-nonce", nil)
			nonceResp, err := http.DefaultClient.Do(nonceReq)
			if err != nil {
				t.Errorf("fetch nonce: %v", err)
				return
			}
			nonce := nonceResp.Header.Get("Replay-Nonce")
			nonceResp.Body.Close()

			jws := client.sign(t, challengeURL, nonce, []byte("{}"))
			jwsBody, _ := json.Marshal(jws)
			resp, err := http.Post(challengeURL, "application/jose+json", bytes.NewReader(jwsBody))
			if err != nil {
				t.Errorf("POST challenge: %v", err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	wg.Wait()
}

func TestACMEFinalizeMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/acme/finalize/some-order")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMEFinalizeOrderNotFound(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	payload, _ := json.Marshal(map[string]any{"csr": "dGVzdA"})
	resp := client.postJWS(t, ts, ts.URL+"/acme/finalize/nonexistent", payload)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestACMEFinalizeBadCSREncoding(t *testing.T) {
	// Create an order and mark it ready by manually injecting a ready order,
	// owned by a real account since finalize now checks ownership.
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	finalizeURL := ts.URL + "/acme/finalize/order-ready"
	order := &Order{
		ID:             "order-ready",
		AccountID:      client.accountID(),
		Status:         "ready",
		Identifiers:    []Identifier{{Type: "dns", Value: "test.example.com"}},
		Authorizations: []string{},
		Finalize:       finalizeURL,
	}
	srv.store.SaveOrder(order)

	// Send invalid base64url.
	payload, _ := json.Marshal(map[string]any{"csr": "!!!invalid-base64!!!"})
	resp := client.postJWS(t, ts, finalizeURL, payload)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid CSR encoding, got %d", resp.StatusCode)
	}
}

func TestACMEFinalizeInvalidCSR(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	finalizeURL := ts.URL + "/acme/finalize/order-ready2"
	order := &Order{
		ID:             "order-ready2",
		AccountID:      client.accountID(),
		Status:         "ready",
		Identifiers:    []Identifier{{Type: "dns", Value: "test.example.com"}},
		Authorizations: []string{},
		Finalize:       finalizeURL,
	}
	srv.store.SaveOrder(order)

	// Valid base64url but not a valid ASN.1 CSR.
	badCSR := base64.RawURLEncoding.EncodeToString([]byte("not-a-csr"))
	payload, _ := json.Marshal(map[string]any{"csr": badCSR})
	resp := client.postJWS(t, ts, finalizeURL, payload)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid CSR, got %d", resp.StatusCode)
	}
}

// TestACMEFinalizeCrossAccountRejected is handleFinalize's counterpart to
// TestACMEChallengeCrossAccountRejected: a kid-authenticated caller must
// match the order's owning account, not just any valid account.
func TestACMEFinalizeCrossAccountRejected(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	owner := newACMEAccount(t, ts)
	finalizeURL := ts.URL + "/acme/finalize/order-owned"
	order := &Order{
		ID:             "order-owned",
		AccountID:      owner.accountID(),
		Status:         "ready",
		Identifiers:    []Identifier{{Type: "dns", Value: "test.example.com"}},
		Authorizations: []string{},
		Finalize:       finalizeURL,
	}
	srv.store.SaveOrder(order)

	attacker := newACMEAccount(t, ts)
	payload, _ := json.Marshal(map[string]any{"csr": "dGVzdA"})
	resp := attacker.postJWS(t, ts, finalizeURL, payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a different account finalizing someone else's order, got %d", resp.StatusCode)
	}
}

func TestACMECertificateNotFound(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/acme/cert/nonexistent-cert-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// --- revoke-cert (RFC 8555 §7.6, W1-09) ------------------------------------

func TestACMERevokeCertMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/acme/revoke-cert")
	if err != nil {
		t.Fatalf("GET revoke-cert: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMERevokeCertAccountKeyAuthorized(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestACMERevokeCertCertKeyAuthorized(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, csrKey := issueTestCertificate(t, ts, client)

	// Authorized by the certificate's own key, not the account -- signs the
	// outer JWS with an inline jwk (no kid) built from the CSR key.
	certKeyClient := &acmeTestClient{priv: csrKey, jwk: jwkFromECDSAPublicKey(&csrKey.PublicKey)}
	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := certKeyClient.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for cert-key authorized revoke, got %d: %s", resp.StatusCode, body)
	}
}

// TestACMERevokeCertUnknownCertificateRejected proves that RFC 8555 §7.6's
// "a server should not allow revocation of certificates it did not issue"
// actually gates: a self-signed certificate presented together with the key
// that signed it would otherwise satisfy the cert-key-authorized check on
// its own (the signature is genuine), but this server has no order/cert
// record of it and must still reject the request -- and must not record
// any revocation state for it either.
func TestACMERevokeCertUnknownCertificateRejected(t *testing.T) {
	srv, ts := newTestACMEServer(t)
	defer ts.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-issued-by-this-server.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("self-sign certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse self-signed certificate: %v", err)
	}

	unrelated := &acmeTestClient{priv: priv, jwk: jwkFromECDSAPublicKey(&priv.PublicKey)}
	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := unrelated.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a certificate this server never issued, got %d", resp.StatusCode)
	}
	if len(srv.revoked) != 0 {
		t.Errorf("expected no revocation state recorded for an unknown certificate, got %d entries", len(srv.revoked))
	}
}

// TestACMERevokeCertWrongCertKeyRejected proves the cert-key-authorized
// path's negative: an unrelated key signing via an inline jwk (no kid, so
// not account-key authorized either) must be rejected, even though the
// outer JWS signature itself verifies fine -- it just isn't the
// certificate's own key.
func TestACMERevokeCertWrongCertKeyRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	unrelated := newACMETestClient(t) // valid key, but not the cert's key and not an account
	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := unrelated.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 when jwk does not match the certificate's key, got %d", resp.StatusCode)
	}
}

// TestACMERevokeCertCrossAccountRejected proves the account-key-authorized
// path's negative: an account that does not own the certificate's order
// (and does not hold the certificate's key) must be rejected.
func TestACMERevokeCertCrossAccountRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	owner := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, owner)

	attacker := newACMEAccount(t, ts)
	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := attacker.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a different account revoking someone else's cert, got %d", resp.StatusCode)
	}
}

// TestACMERevokeCertAlreadyRevokedRejected proves the idempotency negative:
// a second revocation of the same certificate must be rejected, not treated
// as a repeat success.
func TestACMERevokeCertAlreadyRevokedRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)
	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})

	first := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("expected first revoke to succeed, got %d", first.StatusCode)
	}

	second := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for already-revoked cert, got %d", second.StatusCode)
	}
	var prob Problem
	json.NewDecoder(second.Body).Decode(&prob)
	if prob.Type != "urn:ietf:params:acme:error:alreadyRevoked" {
		t.Errorf("expected alreadyRevoked problem type, got %q", prob.Type)
	}
}

func TestACMERevokeCertBadReasonRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
		"reason":      7, // unassigned CRLReason value
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for bad revocation reason, got %d", resp.StatusCode)
	}
	var prob Problem
	json.NewDecoder(resp.Body).Decode(&prob)
	if prob.Type != "urn:ietf:params:acme:error:badRevocationReason" {
		t.Errorf("expected badRevocationReason problem type, got %q", prob.Type)
	}
}

// TestACMERevokeCertReachesCARevocationStore proves W1-14/G-91's core
// requirement: a certificate revoked via POST /acme/revoke-cert must be
// reflected in ca.RevocationStore.IsRevoked -- the store OCSP and CRL
// actually query -- not just acme.Server's own s.revoked map. Prior to this
// ticket, revoke-cert never touched revStore at all.
func TestACMERevokeCertReachesCARevocationStore(t *testing.T) {
	srv, ts, _, revStore := newTestACMEServerWithRevStore(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	revoked, _, _, err := revStore.IsRevoked(cert.SerialNumber, srv.caID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected the certificate to be revoked in ca.RevocationStore, not just acme.Server's local map")
	}
}

// TestACMERevokeCertReachesDBBackedRevocationStore proves W1-15/G-92
// acceptance #1: with a real SQL-backed ca.DBRevocationStore (not the
// in-memory store TestACMERevokeCertReachesCARevocationStore above and every
// other W1-14 test used), a certificate issued via ACME finalize and then
// revoked via POST /acme/revoke-cert is reflected in
// ca.RevocationStore.IsRevoked. Before this fix, DBRevocationStore.Revoke's
// UPDATE matched zero rows for an ACME-issued certificate -- never inserted
// into certificates at issuance, unlike bootstrap.caCertificateProvider's
// dashboard/API path -- and silently returned a nil error, so IsRevoked kept
// reporting not-revoked forever.
func TestACMERevokeCertReachesDBBackedRevocationStore(t *testing.T) {
	srv, ts, _, revStore, _, _ := newTestACMEServerWithDBRevStore(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	revoked, _, _, err := revStore.IsRevoked(cert.SerialNumber, srv.caID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected the ACME-issued certificate to be revoked in the DB-backed ca.RevocationStore")
	}
}

// TestACMERevokeCertDBBackedOCSPAndCRLReportRevoked proves W1-15/G-92
// acceptance #2: in that same DB-backed configuration, OCSP's CertStatusFunc
// and CRL's RevokedCert lookup -- both keyed off ca.RevocationStore, wired
// here the same shape cmd/kryptkeeper/main.go wires them -- report the
// ACME-issued, ACME-revoked certificate as revoked. Exercised through a real
// ocsp.Responder (full request/response round trip) and crl.Generator
// (parsed generated CRL), not just RevocationStore.IsRevoked in isolation.
func TestACMERevokeCertDBBackedOCSPAndCRLReportRevoked(t *testing.T) {
	_, ts, _, revStore, keys, rootCA := newTestACMEServerWithDBRevStore(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	rootSigner, err := keys.Signer(rootCA.KeyID)
	if err != nil {
		t.Fatalf("root CA signer: %v", err)
	}

	// --- OCSP, wired the same shape as cmd/kryptkeeper/main.go's ocspResponder ---
	ocspResponder := ocsp.NewResponder(
		func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
			return revStore.IsRevoked(serial, rootCA.ID)
		},
		func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
			return rootCA.Certificate, rootSigner, nil
		},
		24*time.Hour, 100,
	)
	ocspServer := httptest.NewServer(ocspResponder.Handler())
	defer ocspServer.Close()

	ocspReqDER, err := goocsp.CreateRequest(cert, rootCA.Certificate, nil)
	if err != nil {
		t.Fatalf("create OCSP request: %v", err)
	}
	ocspHTTPResp, err := http.Post(ocspServer.URL, "application/ocsp-request", bytes.NewReader(ocspReqDER))
	if err != nil {
		t.Fatalf("OCSP POST: %v", err)
	}
	defer ocspHTTPResp.Body.Close()
	ocspRespDER, err := io.ReadAll(ocspHTTPResp.Body)
	if err != nil {
		t.Fatalf("read OCSP response: %v", err)
	}
	parsedOCSP, err := goocsp.ParseResponse(ocspRespDER, rootCA.Certificate)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if parsedOCSP.Status != goocsp.Revoked {
		t.Errorf("OCSP status = %d, want Revoked (%d)", parsedOCSP.Status, goocsp.Revoked)
	}

	// --- CRL, wired the same shape as cmd/kryptkeeper/main.go's crlGen ---
	crlGen := crl.NewGenerator(
		func(caID string) ([]crl.RevokedCert, error) {
			entries, err := revStore.ListRevoked(caID)
			if err != nil {
				return nil, err
			}
			result := make([]crl.RevokedCert, len(entries))
			for i, e := range entries {
				result[i] = crl.RevokedCert{SerialNumber: e.Serial, RevokedAt: e.RevokedAt, ReasonCode: e.ReasonCode}
			}
			return result, nil
		},
		func(caID string) (*x509.Certificate, crypto.Signer, error) {
			return rootCA.Certificate, rootSigner, nil
		},
		24*time.Hour,
	)
	generated, err := crlGen.Generate(rootCA.ID)
	if err != nil {
		t.Fatalf("generate CRL: %v", err)
	}
	parsedCRL, err := x509.ParseRevocationList(generated.DER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	found := false
	for _, entry := range parsedCRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected the revoked ACME-issued certificate's serial number in the generated CRL")
	}
}

// TestACMERevokeCertInvalidatesOCSPCache is W19-01: found live against real
// certbot and lego, each of which polled OCSP for its certificate BEFORE
// revoking it (a normal client flow, e.g. checking the status of what it's
// about to replace) and then again after revoking -- and the hub kept
// answering "good" for the rest of ocspResponder's 24h cache validity
// window, because nothing had ever wired WithOCSPCacheInvalidator to a live
// responder. TestACMERevokeCertDBBackedOCSPAndCRLReportRevoked above never
// caught this: its ocsp.Responder is fresh and its FIRST query happens after
// revocation, so there's no stale cache entry to hit. This test queries
// OCSP once before revoking (populating the cache with "good"), revokes
// with WithOCSPCacheInvalidator wired to that same responder, and requires
// the next query -- against the identical cached responder -- to report
// Revoked.
func TestACMERevokeCertInvalidatesOCSPCache(t *testing.T) {
	srv, ts, _, revStore, keys, rootCA := newTestACMEServerWithDBRevStore(t)
	defer ts.Close()

	rootSigner, err := keys.Signer(rootCA.KeyID)
	if err != nil {
		t.Fatalf("root CA signer: %v", err)
	}
	ocspResponder := ocsp.NewResponder(
		func(serial *big.Int, issuer *x509.Certificate) (bool, time.Time, int, error) {
			return revStore.IsRevoked(serial, rootCA.ID)
		},
		func(keyHash []byte) (*x509.Certificate, crypto.Signer, error) {
			return rootCA.Certificate, rootSigner, nil
		},
		24*time.Hour, 100,
	)
	srv.WithOCSPCacheInvalidator(ocspResponder)
	ocspServer := httptest.NewServer(ocspResponder.Handler())
	defer ocspServer.Close()

	client := newACMEAccount(t, ts)
	cert, _, _ := issueTestCertificate(t, ts, client)

	queryOCSP := func() int {
		t.Helper()
		reqDER, err := goocsp.CreateRequest(cert, rootCA.Certificate, nil)
		if err != nil {
			t.Fatalf("create OCSP request: %v", err)
		}
		httpResp, err := http.Post(ocspServer.URL, "application/ocsp-request", bytes.NewReader(reqDER))
		if err != nil {
			t.Fatalf("OCSP POST: %v", err)
		}
		defer httpResp.Body.Close()
		respDER, err := io.ReadAll(httpResp.Body)
		if err != nil {
			t.Fatalf("read OCSP response: %v", err)
		}
		parsed, err := goocsp.ParseResponse(respDER, rootCA.Certificate)
		if err != nil {
			t.Fatalf("parse OCSP response: %v", err)
		}
		return parsed.Status
	}

	if status := queryOCSP(); status != goocsp.Good {
		t.Fatalf("pre-revocation OCSP status = %d, want Good", status)
	}

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	if status := queryOCSP(); status != goocsp.Revoked {
		t.Fatalf("post-revocation OCSP status = %d, want Revoked -- OCSP cache was not invalidated on revoke", status)
	}
}

// TestACMERevokeCertResolvesIssuingCA proves W1-14/G-91 acceptance #3: the
// downstream ca.RevocationStore.Revoke call must be recorded against the CA
// that actually issued the certificate, not hardcoded to srv.caID (the
// server's default CA) -- a server backed by ca.Service could in principle
// issue against more than one CA id. Issues directly against a second CA
// (bypassing handleFinalize, which always uses srv.caID) and wires the
// result into an order this account owns, exactly the shape handleFinalize
// itself would have produced.
func TestACMERevokeCertResolvesIssuingCA(t *testing.T) {
	srv, ts, engine, revStore := newTestACMEServerWithRevStore(t)
	defer ts.Close()

	secondCA, err := engine.CreateRootCA("ACME Test Second CA", pkix.Name{
		CommonName: "ACME Test Second Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create second CA: %v", err)
	}
	if secondCA.ID == srv.caID {
		t.Fatal("test setup: second CA must differ from the server's default CA")
	}

	client := newACMEAccount(t, ts)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "second-ca.example.com"},
	}, csrKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	issued, err := engine.IssueCertificate(secondCA.ID, ca.IssuanceRequest{
		CSR:      csr,
		Validity: 90 * 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		t.Fatalf("issue from second CA: %v", err)
	}

	certID := "second-ca-cert"
	order := &Order{
		ID:          "order-second-ca",
		AccountID:   client.accountID(),
		Status:      "valid",
		Certificate: ts.URL + "/acme/cert/" + certID,
	}
	srv.store.SaveOrder(order)
	srv.store.SaveCert(certID, issued.CertPEM)

	payload, _ := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(issued.Certificate.Raw),
	})
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	revokedUnderIssuer, _, _, err := revStore.IsRevoked(issued.SerialNumber, secondCA.ID)
	if err != nil {
		t.Fatalf("IsRevoked(secondCA): %v", err)
	}
	if !revokedUnderIssuer {
		t.Fatal("expected revocation recorded against the CA that actually issued the certificate")
	}

	revokedUnderDefault, _, _, err := revStore.IsRevoked(issued.SerialNumber, srv.caID)
	if err != nil {
		t.Fatalf("IsRevoked(defaultCAID): %v", err)
	}
	if revokedUnderDefault {
		t.Fatal("revocation must not be recorded against the server's default CA when the certificate came from another")
	}
}

// TestACMEResolveIssuingCARefusesToGuess proves resolveIssuingCAID never
// falls back to the server's default CA: a certificate whose AuthorityKeyId
// matches no CA, or that carries none and verifies under no CA, is an error,
// so handleRevokeCert cannot record the revocation against a CA that never
// issued it (W1-14/G-91 acceptance #3, SEMGREP-014).
func TestACMEResolveIssuingCARefusesToGuess(t *testing.T) {
	srv, ts, _, _ := newTestACMEServerWithRevStore(t)
	defer ts.Close()

	cert := &x509.Certificate{AuthorityKeyId: []byte("not-a-known-ca-subject-key-id")}
	if caID, err := srv.resolveIssuingCAID(cert); err == nil {
		t.Fatalf("expected an error for an AuthorityKeyId matching no known CA, got caID=%q", caID)
	}
	if caID, err := srv.resolveIssuingCAID(&x509.Certificate{}); err == nil {
		t.Fatalf("a certificate with no AuthorityKeyId and no matching signature resolved to %q", caID)
	}
}

type failingListCAsService struct{ ca.Service }

func (failingListCAsService) ListCAs() ([]*ca.CA, error) {
	return nil, errors.New("ca store unavailable")
}

// TestACMERevokeCertLookupFailureIsServerError proves SEMGREP-014: when the
// CA list cannot be read the revocation is not recorded against the default
// CA (so the issuing CA's CRL/OCSP would never show it) -- the client gets a
// server error, the certificate is not marked revoked, and a retry once the
// store recovers succeeds.
func TestACMERevokeCertLookupFailureIsServerError(t *testing.T) {
	srv, ts, engine, revStore := newTestACMEServerWithRevStore(t)
	defer ts.Close()

	secondCA, err := engine.CreateRootCA("ACME Lookup Second CA", pkix.Name{CommonName: "ACME Lookup Second Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create second CA: %v", err)
	}
	client := newACMEAccount(t, ts)
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lookup-fail.example.com"}}, csrKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	issued, err := engine.IssueCertificate(secondCA.ID, ca.IssuanceRequest{CSR: csr, Validity: 90 * 24 * time.Hour, KeyUsage: x509.KeyUsageDigitalSignature})
	if err != nil {
		t.Fatalf("issue from second CA: %v", err)
	}
	certID := "lookup-fail-cert"
	srv.store.SaveOrder(&Order{ID: "order-lookup-fail", AccountID: client.accountID(), Status: "valid", Certificate: ts.URL + "/acme/cert/" + certID})
	srv.store.SaveCert(certID, issued.CertPEM)
	payload, _ := json.Marshal(map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(issued.Certificate.Raw)})

	healthy := srv.caEngine
	srv.caEngine = failingListCAsService{healthy}
	resp := client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("CA list unreadable: status %d, want 500", resp.StatusCode)
	}
	for _, id := range []string{srv.caID, secondCA.ID} {
		if revoked, _, _, _ := revStore.IsRevoked(issued.SerialNumber, id); revoked {
			t.Fatalf("revocation was recorded against CA %s despite the lookup failure", id)
		}
	}

	srv.caEngine = healthy
	resp = client.postJWS(t, ts, ts.URL+"/acme/revoke-cert", payload)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry after the store recovered: status %d, want 200 (not alreadyRevoked)", resp.StatusCode)
	}
	if revoked, _, _, _ := revStore.IsRevoked(issued.SerialNumber, secondCA.ID); !revoked {
		t.Fatal("retry did not record the revocation against the issuing CA")
	}
}

// --- key-change (RFC 8555 §7.3.5, W1-09) ------------------------------------

func TestACMEKeyChangeMethodNotAllowed(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/acme/key-change")
	if err != nil {
		t.Fatalf("GET key-change: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestACMEKeyChangeRotatesAccountKey(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{
		"account": client.kid,
		"oldKey":  client.jwk,
	})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/key-change", JWK: newClient.jwk}
	innerJWS := signRaw(t, newClient.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	// The old key must no longer authenticate this account.
	orderPayload, _ := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: "dns", Value: "example.com"}},
	})
	stale := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	defer stale.Body.Close()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected old key to be rejected after rollover, got %d", stale.StatusCode)
	}

	// The new key must now authenticate as this same account (same kid).
	client.priv = newClient.priv
	client.jwk = newClient.jwk
	fresh := client.postJWS(t, ts, ts.URL+"/acme/new-order", orderPayload)
	defer fresh.Body.Close()
	if fresh.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(fresh.Body)
		t.Errorf("expected new key to authenticate after rollover, got %d: %s", fresh.StatusCode, body)
	}
}

// TestACMEKeyChangeBadInnerSignatureRejected proves step 4's negative: the
// inner JWS must actually verify against the key its own header declares,
// not just carry a jwk that matches the payload's expectations.
func TestACMEKeyChangeBadInnerSignatureRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)
	impostor := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{"account": client.kid, "oldKey": client.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/key-change", JWK: newClient.jwk}
	// Signed with a different key than the header declares.
	innerJWS := signRaw(t, impostor.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for inner jws signature not matching its declared jwk, got %d", resp.StatusCode)
	}
}

func TestACMEKeyChangeInnerMissingJWKRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{"account": client.kid, "oldKey": client.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/key-change"} // no jwk
	innerJWS := signRaw(t, newClient.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when inner jws lacks jwk, got %d", resp.StatusCode)
	}
}

func TestACMEKeyChangeInnerNonceRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{"account": client.kid, "oldKey": client.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", Nonce: "should-not-be-here", URL: ts.URL + "/acme/key-change", JWK: newClient.jwk}
	innerJWS := signRaw(t, newClient.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when inner jws carries a nonce, got %d", resp.StatusCode)
	}
}

func TestACMEKeyChangeInnerURLMismatchRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{"account": client.kid, "oldKey": client.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/new-order", JWK: newClient.jwk} // wrong url
	innerJWS := signRaw(t, newClient.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when inner jws url does not match outer, got %d", resp.StatusCode)
	}
}

func TestACMEKeyChangeWrongOldKeyRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)
	unrelated := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{"account": client.kid, "oldKey": unrelated.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/key-change", JWK: newClient.jwk}
	innerJWS := signRaw(t, newClient.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for mismatched oldKey, got %d", resp.StatusCode)
	}
}

// TestACMEKeyChangeAccountFieldMismatchRejected proves step 7's negative.
// The account actually mutated is always the outer JWS's kid (never the
// inner payload's "account" field), so this isn't a privilege-escalation
// vector either way -- but RFC 8555 requires the integrity check regardless,
// and omitting it is a real interop/conformance gap against strict clients.
func TestACMEKeyChangeAccountFieldMismatchRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	victim := newACMEAccount(t, ts)
	attacker := newACMEAccount(t, ts)
	newClient := newACMETestClient(t)

	innerPayload, _ := json.Marshal(map[string]any{"account": victim.kid, "oldKey": attacker.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/key-change", JWK: newClient.jwk}
	innerJWS := signRaw(t, newClient.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := attacker.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when inner account field names a different account than the outer kid, got %d", resp.StatusCode)
	}
}

// TestACMEKeyChangeConflictingKeyRejected proves step 9's negative: rolling
// over to a key another account already uses must be rejected with a 409
// and a Location header pointing at the conflicting account.
func TestACMEKeyChangeConflictingKeyRejected(t *testing.T) {
	_, ts := newTestACMEServer(t)
	defer ts.Close()

	client := newACMEAccount(t, ts)
	other := newACMEAccount(t, ts)

	innerPayload, _ := json.Marshal(map[string]any{"account": client.kid, "oldKey": client.jwk})
	innerHdr := jwsProtectedHeader{Alg: "ES256", URL: ts.URL + "/acme/key-change", JWK: other.jwk}
	innerJWS := signRaw(t, other.priv, innerHdr, innerPayload)
	innerJWSJSON, _ := json.Marshal(innerJWS)

	resp := client.postJWS(t, ts, ts.URL+"/acme/key-change", innerJWSJSON)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 when new key already belongs to another account, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") == "" {
		t.Error("expected Location header referencing the conflicting account")
	}
}

func TestACMEMemStoreLoadAndListAccounts(t *testing.T) {
	store := NewMemStore()

	// LoadAccount on empty store.
	_, ok := store.LoadAccount("missing")
	if ok {
		t.Error("expected false for missing account")
	}

	// ListAccounts on empty store.
	if got := store.ListAccounts(); len(got) != 0 {
		t.Errorf("expected empty list, got %d", len(got))
	}

	// SaveAccount and retrieve.
	acct := &Account{ID: "acct-1", Status: "valid"}
	store.SaveAccount(acct)

	got, ok := store.LoadAccount("acct-1")
	if !ok {
		t.Fatal("expected account to be found")
	}
	if got.ID != "acct-1" {
		t.Errorf("unexpected ID %q", got.ID)
	}

	list := store.ListAccounts()
	if len(list) != 1 {
		t.Errorf("expected 1 account, got %d", len(list))
	}
}

func decodePEM(data []byte) ([]byte, error) {
	// Simple PEM decoder for test.
	s := string(data)
	start := strings.Index(s, "-----BEGIN CERTIFICATE-----")
	if start < 0 {
		return nil, nil
	}
	end := strings.Index(s, "-----END CERTIFICATE-----")
	if end < 0 {
		return nil, nil
	}
	b64 := strings.TrimSpace(s[start+len("-----BEGIN CERTIFICATE-----") : end])
	b64 = strings.ReplaceAll(b64, "\n", "")
	return base64.StdEncoding.DecodeString(b64)
}
