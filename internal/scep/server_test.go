// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/smallstep/pkcs7"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// --- fixtures ---

// scepFixture is a full RSA-issuing SCEP server plus the pieces a test
// needs to build a real PKCS#7 PKIOperation against it (RFC 8894's envelope
// requires an RSA recipient key, so the CA here -- unlike the pre-W19-15
// ECDSA fixture -- must be RSA).
type scepFixture struct {
	srv        *Server
	ts         *httptest.Server
	caObj      *ca.CA
	engine     ca.Service
	challenges *DBChallengeStore
	audited    []AuditEvent
}

// mint creates a one-time challenge for cn (and dnsNames) on the fixture's
// CA, valid for an hour, and returns its secret.
func (f *scepFixture) mint(t *testing.T, cn string, dnsNames ...string) string {
	t.Helper()
	now := time.Now().UTC()
	_, secret, err := f.challenges.Create(context.Background(), Challenge{
		CAID: f.caObj.ID, CommonName: cn, DNSNames: dnsNames, CreatedBy: "test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint challenge: %v", err)
	}
	return secret
}

func newSCEPFixture(t *testing.T) *scepFixture {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("scep-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("SCEP Test Root", pkix.Name{
		CommonName: "SCEP Test Root CA",
	}, keystore.RSA2048, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	caObj, err := engine.GetCA(rootCA.ID)
	if err != nil {
		t.Fatalf("get root CA: %v", err)
	}

	f := &scepFixture{caObj: caObj, engine: engine, challenges: newTestChallengeStore(t)}
	srv := NewServer(engine, rootCA.ID, f.challenges).WithDecrypter(func() (crypto.Decrypter, error) {
		signer, err := keys.Signer(rootCA.KeyID)
		if err != nil {
			return nil, err
		}
		dec, ok := signer.(crypto.Decrypter)
		if !ok {
			return nil, errors.New("test CA key does not implement crypto.Decrypter")
		}
		return dec, nil
	})
	srv.WithAuditFunc(func(_ context.Context, ev AuditEvent) { f.audited = append(f.audited, ev) })
	f.srv, f.ts = srv, httptest.NewServer(srv.Handler())
	return f
}

func (f *scepFixture) Close() { f.ts.Close() }

// --- request construction helpers ---
//
// A real SCEP client generates one RSA keypair, self-signs it into a
// throwaway identity certificate (used to sign the outer pkiMessage and,
// reciprocally, as the CertRep's encryption recipient), and requests a
// certificate for that same key via an inner PKCS#10 CSR carrying the
// enrollment challenge. These helpers build exactly that, using only
// verified stdlib/pkcs7 APIs -- no bare-CSR shortcut.

// asn1CertificateRequestOuter mirrors RFC 2986's outer CertificationRequest
// SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature } --
// used instead of crypto/x509's private equivalent (unexported) or its
// CertificateRequest.RawSignatureAlgorithm convenience field (Go 1.27+,
// newer than this module's go.mod floor of 1.26).
type asn1CertificateRequestOuter struct {
	TBSCSR             asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

func selfSignedRSACert(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse self-signed cert: %v", err)
	}
	return cert
}

// buildCSRWithChallenge builds a PKCS#10 CSR carrying a PKCS#9
// challengePassword attribute (RFC 2985 §5.4.1). x509.CreateCertificateRequest
// has no support for that attribute shape (its Attributes field marshals as
// AttributeTypeAndValueSET, one level of SEQUENCE too many for
// challengePassword's plain "SET OF AttributeValue") -- confirmed by reading
// crypto/x509's own parseRawAttributes, which explicitly drops
// challengePassword/unstructuredName for the same reason on the parse side.
// So this builds a plain CSR first, then splices a raw attribute into its
// TBS and re-signs -- the same technique x509.CreateCertificateRequest uses
// internally for the requestedExtensions attribute.
func buildCSRWithChallenge(t *testing.T, key *rsa.PrivateKey, cn, challenge string) []byte {
	t.Helper()
	plainDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	// Parsed with our own outer struct rather than x509.CertificateRequest's
	// RawSignatureAlgorithm (added in Go 1.27; this module targets go 1.26)
	// -- both approaches read the same bytes, this just avoids depending on
	// a stdlib field the declared go.mod version doesn't have yet.
	var plainOuter asn1CertificateRequestOuter
	if _, err := asn1.Unmarshal(plainDER, &plainOuter); err != nil {
		t.Fatalf("unmarshal CSR outer: %v", err)
	}

	var tbs tbsCertificateRequestAttrs
	if _, err := asn1.Unmarshal(plainOuter.TBSCSR.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	tbs.Raw = nil // force re-serialization instead of asn1.Marshal reusing the stale raw bytes

	attrBytes, err := asn1.Marshal(pkcs10Attribute{
		Type:   oidChallengePassword,
		Values: []asn1.RawValue{{Class: 0, Tag: 19, Bytes: []byte(challenge)}}, // PrintableString
	})
	if err != nil {
		t.Fatalf("marshal challengePassword attribute: %v", err)
	}
	tbs.RawAttributes = append(tbs.RawAttributes, asn1.RawValue{FullBytes: attrBytes})

	newTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("re-marshal TBS: %v", err)
	}

	hash := sha256.Sum256(newTBS)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign TBS: %v", err)
	}

	outer := asn1CertificateRequestOuter{
		TBSCSR:             asn1.RawValue{FullBytes: newTBS},
		SignatureAlgorithm: plainOuter.SignatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	finalDER, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("marshal final CSR: %v", err)
	}

	// Prove it round-trips before handing it to the server under test.
	final, err := x509.ParseCertificateRequest(finalDER)
	if err != nil {
		t.Fatalf("parse final CSR: %v", err)
	}
	if err := final.CheckSignature(); err != nil {
		t.Fatalf("final CSR self-check: %v", err)
	}
	return finalDER
}

// buildPKIOperation wraps csrDER in a CMS EnvelopedData (recipient: the CA)
// inside a CMS SignedData (signer: the client's self-signed identity cert),
// exactly as RFC 8894 §3.2 requires. txID/nonce are returned so the caller
// can check the CertRep echoes them.
func buildPKIOperation(t *testing.T, caCert *x509.Certificate, clientKey *rsa.PrivateKey, clientCert *x509.Certificate, csrDER []byte) (msgDER []byte, txID string, nonce []byte) {
	t.Helper()
	envelopeDER, err := pkcs7.Encrypt(csrDER, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("encrypt CSR to CA: %v", err)
	}

	sd, err := pkcs7.NewSignedData(envelopeDER)
	if err != nil {
		t.Fatalf("new signed data: %v", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	txID = "test-txn-" + clientCert.SerialNumber.String()
	nonce = make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}

	extra := []pkcs7.Attribute{
		{Type: oidMessageType, Value: asn1.RawValue{Tag: 19, Bytes: []byte(msgTypePKCSReq)}},
		{Type: oidTransactionID, Value: asn1.RawValue{Tag: 19, Bytes: []byte(txID)}},
		{Type: oidSenderNonce, Value: asn1.RawValue{Tag: 4, Bytes: nonce}},
	}
	if err := sd.AddSigner(clientCert, clientKey, pkcs7.SignerInfoConfig{ExtraSignedAttributes: extra}); err != nil {
		t.Fatalf("sign pkiMessage: %v", err)
	}
	msgDER, err = sd.Finish()
	if err != nil {
		t.Fatalf("finish pkiMessage: %v", err)
	}
	return msgDER, txID, nonce
}

func postPKIOperation(t *testing.T, ts *httptest.Server, msgDER []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(ts.URL+"?operation=PKIOperation", "application/x-pki-message", strings.NewReader(string(msgDER)))
	if err != nil {
		t.Fatalf("POST PKIOperation: %v", err)
	}
	return resp
}

// parseCertRep parses a response body as a PKCS#7 CertRep and extracts its
// SCEP attributes, without assuming success -- callers check pkiStatus.
type certRepResult struct {
	p7             *pkcs7.PKCS7
	pkiStatus      string
	failInfo       string
	transactionID  string
	recipientNonce []byte
}

func parseCertRep(t *testing.T, body []byte) certRepResult {
	t.Helper()
	p7, err := pkcs7.Parse(body)
	if err != nil {
		t.Fatalf("parse CertRep as PKCS#7: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("CertRep signature verification failed: %v", err)
	}

	var status, failInfoVal, tx asn1.RawValue
	var nonce asn1.RawValue
	if err := p7.UnmarshalSignedAttribute(oidPKIStatus, &status); err != nil {
		t.Fatalf("missing pkiStatus: %v", err)
	}
	if err := p7.UnmarshalSignedAttribute(oidTransactionID, &tx); err != nil {
		t.Fatalf("missing transactionID: %v", err)
	}
	if err := p7.UnmarshalSignedAttribute(oidRecipientNonce, &nonce); err != nil {
		t.Fatalf("missing recipientNonce: %v", err)
	}
	_ = p7.UnmarshalSignedAttribute(oidFailInfo, &failInfoVal) // absent on SUCCESS

	return certRepResult{
		p7:             p7,
		pkiStatus:      string(status.Bytes),
		failInfo:       string(failInfoVal.Bytes),
		transactionID:  string(tx.Bytes),
		recipientNonce: nonce.Bytes,
	}
}

// --- tests ---

func TestSCEPGetCACert(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	resp, err := http.Get(f.ts.URL + "?operation=GetCACert")
	if err != nil {
		t.Fatalf("GET GetCACert: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Errorf("expected x509-ca-cert content type, got %s", resp.Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(resp.Body)
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if cert.Subject.CommonName != "SCEP Test Root CA" {
		t.Errorf("expected CN=SCEP Test Root CA, got %s", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("expected RSA CA public key, got %T", cert.PublicKey)
	}
}

func TestSCEPGetCACaps(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	resp, err := http.Get(f.ts.URL + "?operation=GetCACaps")
	if err != nil {
		t.Fatalf("GET GetCACaps: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	caps := string(body)
	for _, want := range []string{"SHA-256", "POSTPKIOperation", "AES", "SCEPStandard"} {
		if !strings.Contains(caps, want) {
			t.Errorf("expected %s in capabilities, got %q", want, caps)
		}
	}
	if strings.Contains(caps, "Renewal") {
		t.Error("Renewal is not implemented and must not be advertised")
	}
}

// TestSCEPPKIOperationEnroll proves the real PKCS#7 exchange end to end:
// a genuine client-built PKIOperation (RSA self-signed identity + encrypted
// CSR) is unwrapped, issued, and the CertRep decrypts to a certificate that
// chains to the CA.
func TestSCEPPKIOperationEnroll(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientCert := selfSignedRSACert(t, clientKey, "scep-device.example.com")
	csrDER := buildCSRWithChallenge(t, clientKey, "scep-device.example.com", f.mint(t, "scep-device.example.com"))
	msgDER, txID, nonce := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)

	resp := postPKIOperation(t, f.ts, msgDER)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	rep := parseCertRep(t, body)
	if rep.pkiStatus != pkiStatusSuccess {
		t.Fatalf("expected pkiStatus SUCCESS, got %q (failInfo=%q)", rep.pkiStatus, rep.failInfo)
	}
	if rep.transactionID != txID {
		t.Errorf("expected transactionID %q echoed, got %q", txID, rep.transactionID)
	}
	if string(rep.recipientNonce) != string(nonce) {
		t.Error("expected recipientNonce to echo the request's senderNonce")
	}

	envelope, err := pkcs7.Parse(rep.p7.Content)
	if err != nil {
		t.Fatalf("CertRep content is not a PKCS#7 envelope: %v", err)
	}
	degenerate, err := envelope.Decrypt(clientCert, clientKey)
	if err != nil {
		t.Fatalf("client failed to decrypt CertRep: %v", err)
	}
	certsOnly, err := pkcs7.Parse(degenerate)
	if err != nil {
		t.Fatalf("decrypted content is not a degenerate certs-only PKCS#7: %v", err)
	}
	if len(certsOnly.Certificates) != 1 {
		t.Fatalf("expected exactly one issued certificate, got %d", len(certsOnly.Certificates))
	}
	issued := certsOnly.Certificates[0]
	if issued.Subject.CommonName != "scep-device.example.com" {
		t.Errorf("expected CN=scep-device.example.com, got %s", issued.Subject.CommonName)
	}

	roots := x509.NewCertPool()
	roots.AddCert(f.caObj.Certificate)
	if _, err := issued.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued certificate does not chain to the CA: %v", err)
	}
}

func TestSCEPPKIOperationWrongChallenge(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientCert := selfSignedRSACert(t, clientKey, "scep-wrong-challenge.example.com")
	csrDER := buildCSRWithChallenge(t, clientKey, "scep-wrong-challenge.example.com", "totally-wrong")
	msgDER, txID, nonce := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)

	resp := postPKIOperation(t, f.ts, msgDER)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wrong challenge must still be a protocol-level FAILURE (HTTP 200), got %d: %s", resp.StatusCode, body)
	}

	rep := parseCertRep(t, body)
	if rep.pkiStatus != pkiStatusFailure {
		t.Fatalf("expected pkiStatus FAILURE, got %q", rep.pkiStatus)
	}
	if rep.failInfo != failInfoBadRequest {
		t.Errorf("expected failInfo badRequest, got %q", rep.failInfo)
	}
	if rep.transactionID != txID {
		t.Errorf("expected transactionID %q echoed even on failure, got %q", txID, rep.transactionID)
	}
	if string(rep.recipientNonce) != string(nonce) {
		t.Error("expected recipientNonce to echo the request's senderNonce even on failure")
	}
}

func TestSCEPPKIOperationMalformedMessage(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	resp := postPKIOperation(t, f.ts, []byte("not a pkcs7 message at all"))
	defer resp.Body.Close()
	// A message that doesn't even parse carries no transactionID to
	// attribute a CertRep to -- HTTP 400, not a signed FAILURE.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unparseable pkiMessage, got %d", resp.StatusCode)
	}
}

// fakeIssuedRecorder is a test double for ca.IssuedCertificateRecorder that
// records how it was called and can be made to fail on demand, to verify
// W18-18's "a recorder failure never fails the SCEP response" contract.
type fakeIssuedRecorder struct {
	mu       sync.Mutex
	calls    int
	caID     string
	source   string
	cert     *x509.Certificate
	chainPEM []byte
	err      error
}

func (f *fakeIssuedRecorder) RecordIssuedCertificate(_ context.Context, caID string, cert *x509.Certificate, chainPEM []byte, source string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.caID = caID
	f.source = source
	f.cert = cert
	f.chainPEM = append([]byte(nil), chainPEM...)
	return f.err
}

func TestSCEPPKIOperationRecordsIssuedCertificate(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()
	recorder := &fakeIssuedRecorder{}
	f.srv.WithIssuedRecorder(recorder)

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientCert := selfSignedRSACert(t, clientKey, "scep-recorded.example.com")
	csrDER := buildCSRWithChallenge(t, clientKey, "scep-recorded.example.com", f.mint(t, "scep-recorded.example.com"))
	msgDER, _, _ := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)

	resp := postPKIOperation(t, f.ts, msgDER)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	rep := parseCertRep(t, body)
	if rep.pkiStatus != pkiStatusSuccess {
		t.Fatalf("expected SUCCESS, got %q", rep.pkiStatus)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Fatalf("expected recorder called once, got %d", recorder.calls)
	}
	if recorder.caID != f.caObj.ID {
		t.Errorf("expected caID=%s, got %s", f.caObj.ID, recorder.caID)
	}
	if recorder.source != "scep" {
		t.Errorf("expected source=scep, got %s", recorder.source)
	}
	if recorder.cert == nil || recorder.cert.Subject.CommonName != "scep-recorded.example.com" {
		t.Error("expected recorder to see the issued certificate")
	}
	if len(recorder.chainPEM) == 0 || !strings.Contains(string(recorder.chainPEM), "BEGIN CERTIFICATE") {
		t.Error("expected non-empty PEM chain passed to recorder")
	}
}

func TestSCEPPKIOperationRecorderErrorDoesNotFailResponse(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()
	recorder := &fakeIssuedRecorder{err: errors.New("simulated recorder failure")}
	f.srv.WithIssuedRecorder(recorder)

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientCert := selfSignedRSACert(t, clientKey, "scep-recorder-error.example.com")
	csrDER := buildCSRWithChallenge(t, clientKey, "scep-recorder-error.example.com", f.mint(t, "scep-recorder-error.example.com"))
	msgDER, _, _ := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)

	resp := postPKIOperation(t, f.ts, msgDER)
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

// TestSCEPPKIOperationEnroll_SlowReaderNotTruncated is the regression test
// for W19-05's UAT finding: handlePKIOperation used to read the POST body
// with a single r.Body.Read(buf) call, silently truncating whenever the
// underlying connection delivered the body across more than one read, as a
// real binary PKCS#7 blob from sscep/micromdm-scep does.
// iotest.OneByteReader forces the worst case: one byte per Read call.
func TestSCEPPKIOperationEnroll_SlowReaderNotTruncated(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientCert := selfSignedRSACert(t, clientKey, "scep-slow-reader.example.com")
	csrDER := buildCSRWithChallenge(t, clientKey, "scep-slow-reader.example.com", f.mint(t, "scep-slow-reader.example.com"))
	msgDER, _, _ := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)

	req := httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", nil)
	req.Body = io.NopCloser(iotest.OneByteReader(strings.NewReader(string(msgDER))))
	rr := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rep := parseCertRep(t, rr.Body.Bytes())
	if rep.pkiStatus != pkiStatusSuccess {
		t.Fatalf("expected SUCCESS (body likely truncated otherwise), got %q", rep.pkiStatus)
	}
}

func TestSCEPPKIOperationViaGET(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientCert := selfSignedRSACert(t, clientKey, "scep-get.example.com")
	csrDER := buildCSRWithChallenge(t, clientKey, "scep-get.example.com", f.mint(t, "scep-get.example.com"))
	msgDER, _, _ := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, csrDER)
	msgB64 := base64.StdEncoding.EncodeToString(msgDER)

	resp, err := http.Get(f.ts.URL + "?operation=PKIOperation&message=" + url.QueryEscape(msgB64))
	if err != nil {
		t.Fatalf("GET PKIOperation: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for GET PKIOperation, got %d: %s", resp.StatusCode, body)
	}
	rep := parseCertRep(t, body)
	if rep.pkiStatus != pkiStatusSuccess {
		t.Fatalf("expected SUCCESS, got %q", rep.pkiStatus)
	}
}

func TestSCEPUnknownOperation(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	resp, _ := http.Get(f.ts.URL + "?operation=InvalidOp")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSCEPMethodNotAllowed(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	resp, _ := http.Post(f.ts.URL+"?operation=GetCACert", "text/plain", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST GetCACert: expected 405, got %d", resp.StatusCode)
	}

	resp2, _ := http.Post(f.ts.URL+"?operation=GetCACaps", "text/plain", nil)
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST GetCACaps: expected 405, got %d", resp2.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodDelete, f.ts.URL+"?operation=PKIOperation", nil)
	resp3, _ := http.DefaultClient.Do(req)
	if resp3.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE PKIOperation: expected 405, got %d", resp3.StatusCode)
	}
}

func TestSCEPPKIOperationMissingMessage(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()

	resp, _ := http.Get(f.ts.URL + "?operation=PKIOperation")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing message, got %d", resp.StatusCode)
	}
}

// enrollWith runs one PKIOperation for a CSR naming csrCN and carrying
// secret, and returns the CertRep and, on success, the issued certificate.
func (f *scepFixture) enrollWith(t *testing.T, csrCN, secret string) (certRepResult, *x509.Certificate) {
	t.Helper()
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := selfSignedRSACert(t, clientKey, csrCN)
	msgDER, _, _ := buildPKIOperation(t, f.caObj.Certificate, clientKey, clientCert, buildCSRWithChallenge(t, clientKey, csrCN, secret))
	resp := postPKIOperation(t, f.ts, msgDER)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	rep := parseCertRep(t, body)
	if rep.pkiStatus != pkiStatusSuccess {
		return rep, nil
	}
	envelope, err := pkcs7.Parse(rep.p7.Content)
	if err != nil {
		t.Fatal(err)
	}
	degenerate, err := envelope.Decrypt(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	certsOnly, err := pkcs7.Parse(degenerate)
	if err != nil || len(certsOnly.Certificates) != 1 {
		t.Fatalf("certs-only: %v", err)
	}
	return rep, certsOnly.Certificates[0]
}

// W20-16: the certificate carries the names the challenge was minted for,
// never the CSR's; and a challenge works exactly once.
func TestSCEPChallengeBindsNamesAndIsOneTime(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()
	secret := f.mint(t, "printer-7.example.com", "printer-7.example.com", "printer-7.lan.example.com")

	rep, issued := f.enrollWith(t, "Administrator", secret)
	if issued == nil {
		t.Fatalf("enroll with a fresh challenge failed: %+v", rep)
	}
	if issued.Subject.String() != "CN=printer-7.example.com" {
		t.Errorf("subject %q: the CSR's name must not reach the certificate", issued.Subject)
	}
	if strings.Join(issued.DNSNames, ",") != "printer-7.example.com,printer-7.lan.example.com" {
		t.Errorf("DNS names %v, want the challenge's", issued.DNSNames)
	}

	if rep, again := f.enrollWith(t, "printer-7.example.com", secret); again != nil || rep.pkiStatus != pkiStatusFailure {
		t.Fatalf("a used challenge enrolled again: %+v", rep)
	}

	if len(f.audited) != 2 {
		t.Fatalf("audit rows %+v, want success then denied", f.audited)
	}
	if ok := f.audited[0]; ok.Outcome != "success" || ok.Actor != "printer-7.example.com" || !strings.Contains(ok.Detail, "serial=") {
		t.Errorf("success row %+v", ok)
	}
	if denied := f.audited[1]; denied.Outcome != "denied" || !strings.Contains(denied.Detail, "already used") {
		t.Errorf("reuse row %+v", denied)
	}
	for _, ev := range f.audited {
		if strings.Contains(ev.Detail, secret) {
			t.Fatal("the challenge secret must never reach the audit log")
		}
	}
}

func TestSCEPChallengeExpiredOrForAnotherCARefused(t *testing.T) {
	f := newSCEPFixture(t)
	defer f.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	_, expired, err := f.challenges.Create(ctx, Challenge{CAID: f.caObj.ID, CommonName: "late.example.com", CreatedBy: "test",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	_, otherCA, err := f.challenges.Create(ctx, Challenge{CAID: "some-other-ca", CommonName: "elsewhere.example.com", CreatedBy: "test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{"expired": expired, "other CA": otherCA, "unknown": "0123456789abcdef"} {
		if rep, issued := f.enrollWith(t, "x.example.com", secret); issued != nil || rep.pkiStatus != pkiStatusFailure {
			t.Errorf("%s challenge enrolled: %+v", name, rep)
		}
	}
	for _, ev := range f.audited {
		if ev.Outcome != "denied" {
			t.Errorf("unexpected audit row %+v", ev)
		}
	}
}
