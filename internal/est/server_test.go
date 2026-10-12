// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// decodePKCS7CertsOnly mirrors what a real RFC 7030 client (e.g.
// github.com/globalsign/est) does with a cacerts/enroll/reenroll response:
// base64-decode, then parse as a degenerate PKCS#7 SignedData.
func decodePKCS7CertsOnly(t *testing.T, body []byte) []*x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("base64-decode response: %v", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("parse PKCS#7: %v", err)
	}
	return p7.Certificates
}

func newTestESTServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("est-test-passphrase-32chars-ok!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("EST Test Root", pkix.Name{
		CommonName: "EST Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	srv := NewServer(engine, rootCA.ID)
	if err := srv.WithBasicUsers(testUsers(t)); err != nil {
		t.Fatal(err)
	}
	return httptest.NewTLSServer(srv.Handler())
}

func generateCSRBase64(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return base64.StdEncoding.EncodeToString(csrDER)
}

func TestESTCACerts(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatalf("GET cacerts: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/pkcs7-mime") {
		t.Errorf("expected pkcs7-mime content type, got %s", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected non-empty CA certs response")
	}

	// Must be a real degenerate PKCS#7 SignedData, not bare base64 DER
	// (W19-14/UAT W19-05) -- decode it the way a real EST client does.
	certs := decodePKCS7CertsOnly(t, body)
	if len(certs) != 1 {
		t.Fatalf("expected 1 CA cert in PKCS#7, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "EST Test Root CA" {
		t.Errorf("unexpected CA cert CN %q", certs[0].Subject.CommonName)
	}
}

func TestESTSimpleEnroll(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	csrB64 := generateCSRBase64(t, "est-client.example.com")

	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrB64))
	if err != nil {
		t.Fatalf("POST simpleenroll: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	certs := decodePKCS7CertsOnly(t, body)
	if len(certs) != 1 {
		t.Fatalf("expected 1 issued cert in PKCS#7, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "est-client.example.com" {
		t.Errorf("expected CN=est-client.example.com, got %s", certs[0].Subject.CommonName)
	}
}

// Re-enrollment needs a certificate this CA issued (W20-14); Basic alone is
// not enough. The success path is in auth_test.go.
func TestESTSimpleReenrollNeedsHubCertificate(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	csrB64 := generateCSRBase64(t, "est-renew.example.com")

	resp, err := basicPost(ts, "/.well-known/est/simplereenroll", "application/pkcs10", strings.NewReader(csrB64))
	if err != nil {
		t.Fatalf("POST simplereenroll: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestESTCSRAttrs(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/.well-known/est/csrattrs")
	if err != nil {
		t.Fatalf("GET csrattrs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
}

func TestESTMethodNotAllowed(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	// POST to cacerts should fail.
	resp, _ := basicPost(ts, "/.well-known/est/cacerts", "text/plain", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}

	// GET to simpleenroll should fail.
	resp2, _ := ts.Client().Get(ts.URL + "/.well-known/est/simpleenroll")
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp2.StatusCode)
	}

	// POST to csrattrs should fail.
	resp3, _ := basicPost(ts, "/.well-known/est/csrattrs", "text/plain", nil)
	if resp3.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /csrattrs, got %d", resp3.StatusCode)
	}
}

func TestESTSimpleEnrollWithPEM(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	// Send the CSR as a PEM block (alternative to base64 DER).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pem-client.example.com"},
	}, key)

	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\n" +
		base64.StdEncoding.EncodeToString(csrDER) +
		"\n-----END CERTIFICATE REQUEST-----"

	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST simpleenroll (PEM): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	certs := decodePKCS7CertsOnly(t, body)
	if len(certs) != 1 {
		t.Fatalf("expected 1 issued cert in PKCS#7, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "pem-client.example.com" {
		t.Errorf("unexpected CN %q", certs[0].Subject.CommonName)
	}
}

func TestESTSimpleEnrollInvalidCSR(t *testing.T) {
	ts := newTestESTServer(t)
	defer ts.Close()

	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10",
		strings.NewReader("not-a-valid-csr"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid CSR, got %d", resp.StatusCode)
	}
}

// fakeIssuedRecorder is a test double for ca.IssuedCertificateRecorder that
// records how it was called and can be made to fail on demand, to verify
// W18-18's "a recorder failure never fails the EST response" contract.
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

// newTestESTServerWithRecorder builds the same fixture as newTestESTServer
// but returns the CA id and server too, so tests can assert on what the
// recorder saw.
func newTestESTServerWithRecorder(t *testing.T, recorder ca.IssuedCertificateRecorder) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("est-test-passphrase-32chars-ok!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("EST Test Root", pkix.Name{
		CommonName: "EST Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	srv := NewServer(engine, rootCA.ID).WithIssuedRecorder(recorder)
	if err := srv.WithBasicUsers(testUsers(t)); err != nil {
		t.Fatal(err)
	}
	return httptest.NewTLSServer(srv.Handler()), rootCA.ID
}

// TestESTSimpleEnrollRecordsIssuedCertificate is W18-18: EST simpleenroll
// used to leave every issued certificate out of the inventory entirely.
// This asserts the recorder is called exactly once with the certificate the
// client actually downloaded and the CA id EST issued from.
func TestESTSimpleEnrollRecordsIssuedCertificate(t *testing.T) {
	recorder := &fakeIssuedRecorder{}
	ts, caID := newTestESTServerWithRecorder(t, recorder)
	defer ts.Close()

	csrB64 := generateCSRBase64(t, "est-recorded.example.com")
	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrB64))
	if err != nil {
		t.Fatalf("POST simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	certs := decodePKCS7CertsOnly(t, body)
	if len(certs) != 1 {
		t.Fatalf("expected 1 issued cert in PKCS#7, got %d", len(certs))
	}
	cert := certs[0]

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Fatalf("expected recorder called once, got %d", recorder.calls)
	}
	if recorder.caID != caID {
		t.Errorf("expected caID=%s, got %s", caID, recorder.caID)
	}
	if recorder.cert == nil || recorder.cert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("expected recorder to see the issued certificate, serial mismatch")
	}
	if len(recorder.chainPEM) == 0 || !strings.Contains(string(recorder.chainPEM), "BEGIN CERTIFICATE") {
		t.Error("expected non-empty PEM chain passed to recorder")
	}
}

// TestESTSimpleEnrollRecorderErrorDoesNotFailResponse is W18-18's other
// half: the client already has its certificate once simpleenroll responds,
// so a recorder failure must be logged, never surfaced as a failed request.
func TestESTSimpleEnrollRecorderErrorDoesNotFailResponse(t *testing.T) {
	recorder := &fakeIssuedRecorder{err: errors.New("simulated recorder failure")}
	ts, _ := newTestESTServerWithRecorder(t, recorder)
	defer ts.Close()

	csrB64 := generateCSRBase64(t, "est-recorder-error.example.com")
	resp, err := basicPost(ts, "/.well-known/est/simpleenroll", "application/pkcs10", strings.NewReader(csrB64))
	if err != nil {
		t.Fatalf("POST simpleenroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 despite recorder error, got %d: %s", resp.StatusCode, body)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Errorf("expected recorder still called once despite its own error, got %d", recorder.calls)
	}
}

const testUser, testPassword = "est-test", "est-test-password"

// testUsers is a Basic user allowed names under .example.com. The bcrypt
// hash is computed in-test at the minimum cost; nothing secret is committed.
func testUsers(t *testing.T) []User {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return []User{{Username: testUser, BcryptHash: string(h), AllowedDNSSuffixes: []string{".example.com"}}}
}

// basicPost posts as testUser over the test server's TLS client.
func basicPost(ts *httptest.Server, path, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.SetBasicAuth(testUser, testPassword)
	return ts.Client().Do(req)
}
