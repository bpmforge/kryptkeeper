// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/tsa"
)

func tsaTestCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	root, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tsa test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &root.PublicKey, root)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tsa test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, &key.PublicKey, root)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert, der
}

func newTestTSA(t *testing.T) *tsa.Authority {
	t.Helper()
	key, cert, _ := tsaTestCert(t)
	a, err := tsa.New(tsa.Config{Signer: key, Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type tsaAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type tsaImprint struct {
	Alg  tsaAlgID
	Hash []byte
}
type tsaReq struct {
	Version int
	Imprint tsaImprint
	Nonce   *big.Int `asn1:"optional"`
	CertReq bool     `asn1:"optional"`
}

func tsaQuery(t *testing.T, oid asn1.ObjectIdentifier, digest []byte, nonce int64) []byte {
	t.Helper()
	der, err := asn1.Marshal(tsaReq{Version: 1,
		Imprint: tsaImprint{Alg: tsaAlgID{Algorithm: oid, Parameters: asn1.NullRawValue}, Hash: digest},
		Nonce:   big.NewInt(nonce), CertReq: true})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
var oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

func pkiStatus(t *testing.T, reply []byte) int {
	t.Helper()
	var resp struct {
		Status struct {
			Status int
			Rest   asn1.RawValue `asn1:"optional"`
		}
		Token asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(reply, &resp); err != nil {
		t.Fatalf("reply is not a TimeStampResp: %v", err)
	}
	return resp.Status.Status
}

func tsaPost(h http.Handler, ct string, body []byte, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tsa", bytes.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newTSAMux(t *testing.T, a *tsa.Authority, anon bool) (*http.ServeMux, *recordingAuditProvider) {
	t.Helper()
	aud := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerTSAHandler(mux, a, newReportsTestAuth(t), aud, anon)
	return mux, aud
}

func TestTSA_GrantedReplyIsAuditedWithDigest(t *testing.T) {
	mux, aud := newTSAMux(t, newTestTSA(t), false)
	sum := sha256.Sum256([]byte("artifact"))
	rec := tsaPost(mux, "application/timestamp-query", tsaQuery(t, oidSHA256, sum[:], 42), "reports-test-token")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/timestamp-reply" {
		t.Fatalf("status %d ct %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if pkiStatus(t, rec.Body.Bytes()) != 0 {
		t.Fatalf("not granted")
	}
	if len(aud.entries) != 1 {
		t.Fatalf("want exactly one audit row, got %d", len(aud.entries))
	}
	e := aud.entries[0]
	if e.Action != "codesign.timestamp" || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("entry %+v", e)
	}
	for _, want := range []string{"digest=" + hex.EncodeToString(sum[:]), "alg=sha256", "nonce=present", "serial="} {
		if !strings.Contains(e.ChangeSummary, want) {
			t.Errorf("audit detail lacks %q: %s", want, e.ChangeSummary)
		}
	}
}

func TestTSA_WrongContentTypeAndMethod(t *testing.T) {
	mux, aud := newTSAMux(t, newTestTSA(t), false)
	if rec := tsaPost(mux, "application/json", []byte("{}"), "reports-test-token"); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("content type: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tsa", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("method: %d", rec.Code)
	}
	if len(aud.entries) != 2 {
		t.Fatalf("each call must be audited exactly once: %d rows", len(aud.entries))
	}
}

func TestTSA_SHA1RequestIsRejectedInBandAndAudited(t *testing.T) {
	mux, aud := newTSAMux(t, newTestTSA(t), false)
	sum := sha1.Sum([]byte("artifact"))
	rec := tsaPost(mux, "application/timestamp-query", tsaQuery(t, oidSHA1, sum[:], 1), "reports-test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("a rejection is still a 200 reply, got %d", rec.Code)
	}
	if pkiStatus(t, rec.Body.Bytes()) != 2 {
		t.Fatalf("PKIStatus must be rejection(2)")
	}
	if len(aud.entries) != 1 || aud.entries[0].Outcome != AuditOutcomeDenied || !strings.Contains(aud.entries[0].ChangeSummary, "reason=") {
		t.Fatalf("audit: %+v", aud.entries)
	}
}

func TestTSA_AnonymousOffByDefault(t *testing.T) {
	mux, aud := newTSAMux(t, newTestTSA(t), false)
	sum := sha256.Sum256([]byte("x"))
	q := tsaQuery(t, oidSHA256, sum[:], 1)
	if rec := tsaPost(mux, "application/timestamp-query", q, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous must be refused: %d", rec.Code)
	}
	if len(aud.entries) != 1 || aud.entries[0].Outcome != AuditOutcomeDenied {
		t.Fatalf("audit: %+v", aud.entries)
	}
	if strings.Contains(aud.entries[0].ChangeSummary, hex.EncodeToString(sum[:])) {
		t.Fatal("a refused anonymous call must not record a digest")
	}
	mux2, aud2 := newTSAMux(t, newTestTSA(t), true)
	rec := tsaPost(mux2, "application/timestamp-query", q, "")
	if rec.Code != http.StatusOK || pkiStatus(t, rec.Body.Bytes()) != 0 {
		t.Fatalf("anonymous-on: %d", rec.Code)
	}
	if len(aud2.entries) != 1 || aud2.entries[0].ActorID != "anonymous" {
		t.Fatalf("audit: %+v", aud2.entries)
	}
}

func TestTSA_UnconfiguredAnswers503Audited(t *testing.T) {
	mux, aud := newTSAMux(t, nil, false)
	sum := sha256.Sum256([]byte("x"))
	if rec := tsaPost(mux, "application/timestamp-query", tsaQuery(t, oidSHA256, sum[:], 1), "reports-test-token"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
	if len(aud.entries) != 1 {
		t.Fatalf("audit rows: %d", len(aud.entries))
	}
}

func TestTSAFromEnv(t *testing.T) {
	t.Setenv("KRYPTKEEPER_TSA_CERT_FILE", "")
	if a, err := tsaFromEnv(); a != nil || err != nil {
		t.Fatalf("unset must disable the TSA: %v %v", a, err)
	}
	key, _, certDER := tsaTestCert(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tsa.pem"), filepath.Join(dir, "tsa.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o644)
	t.Setenv("KRYPTKEEPER_TSA_CERT_FILE", certPath)
	t.Setenv("KRYPTKEEPER_TSA_KEY_FILE", keyPath)
	if _, err := tsaFromEnv(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a world-readable key must be refused: %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := tsaFromEnv()
	if err != nil || a == nil {
		t.Fatalf("valid files refused: %v", err)
	}
	t.Setenv("KRYPTKEEPER_TSA_POLICY_OID", "1.2.3.4")
	if _, err := tsaFromEnv(); err != nil {
		t.Fatalf("policy oid: %v", err)
	}
	t.Setenv("KRYPTKEEPER_TSA_POLICY_OID", "not-an-oid")
	if _, err := tsaFromEnv(); err == nil {
		t.Fatal("bad oid accepted")
	}
	_ = crypto.SHA256
}
