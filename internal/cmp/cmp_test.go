// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// --- test fixtures: a real CRMF+POPO+PBM PKIMessage, built the way a
// standards-conformant client (openssl cmp included) builds one, so these
// tests exercise the exact wire shape UAT W19-05 found broken rather than a
// synthetic shortcut. ---

const testSecret = "kk-uat-secret"
const testReference = "kk-uat"

// oidECDSAWithSHA256 matches signatureOIDs in crmf.go.
var oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

func newCMPTestEngine(t *testing.T) (caService ca.Service, caID string) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-cmp-passphrase-32chars-min!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("CMP Test Root CA", pkix.Name{
		CommonName:   "CMP Test Root CA",
		Organization: []string{"Test"},
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	return engine, rootCA.ID
}

// retagContext re-tags a DER-encoded universal value as IMPLICIT
// [class-context, tag] — the inverse of asUniversalSequence, used here to
// build request messages the way a real client's ASN.1 encoder would.
func retagContext(tag int, der []byte, compound bool) asn1.RawValue {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		panic(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: compound, Bytes: raw.Bytes}
}

// explicitContext wraps a complete DER-encoded TLV as EXPLICIT
// [class-context, tag] — i.e. the outer tag's content IS der verbatim,
// tag+length included, unlike retagContext's IMPLICIT re-tag.
func explicitContext(tag int, der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: der}
}

// buildCRMFIRBody builds a CertReqMessages body (used for IR/CR/KUR alike)
// containing one CertReqMsg: certReqId=0, CertTemplate{subject, publicKey},
// and a POPOSigningKey signature over the CertRequest DER — RFC 4211 §4.1's
// default (poposkInput absent) POPO, exactly what openssl's `-popo 1` sends.
func buildCRMFIRBody(t *testing.T, priv *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	return buildCRMFBody(t, &priv.PublicKey, oidECDSAWithSHA256, func(h []byte) ([]byte, error) {
		return ecdsa.SignASN1(rand.Reader, priv, h)
	}, cn)
}

// buildCRMFBody is buildCRMFIRBody generalised over key type so a test can
// send an RSA request; sign receives the SHA-256 of the CertRequest DER.
func buildCRMFBody(t *testing.T, pub crypto.PublicKey, algOID asn1.ObjectIdentifier, sign func(digest []byte) ([]byte, error), cn string) []byte {
	t.Helper()
	return buildCRMFBodySANs(t, pub, algOID, sign, cn, nil)
}

// buildCRMFBodySANs is buildCRMFBody with dNSName SANs in the CertTemplate's
// extensions, the way a client asks for names (SUP-A04-2).
func buildCRMFBodySANs(t *testing.T, pub crypto.PublicKey, algOID asn1.ObjectIdentifier, sign func(digest []byte) ([]byte, error), cn string, dnsNames []string) []byte {
	t.Helper()

	subjectDER, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}
	// subject [5] Name: Name is a CHOICE (rdnSequence RDNSequence), and
	// X.680 always tags a CHOICE-typed field EXPLICITLY regardless of
	// CRMF's module default -- the outer tag wraps the complete
	// RDNSequence encoding rather than replacing its own SEQUENCE tag.
	subjectField, err := asn1.Marshal(explicitContext(5, subjectDER))
	if err != nil {
		t.Fatalf("marshal subject field: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubField, err := asn1.Marshal(retagContext(6, pubDER, true))
	if err != nil {
		t.Fatalf("marshal publicKey field: %v", err)
	}

	templateFields := append(append([]byte{}, subjectField...), pubField...)
	if len(dnsNames) > 0 {
		var gn []byte
		for _, d := range dnsNames {
			b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(d)})
			if err != nil {
				t.Fatalf("marshal dNSName: %v", err)
			}
			gn = append(gn, b...)
		}
		names, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: gn})
		if err != nil {
			t.Fatalf("marshal GeneralNames: %v", err)
		}
		extsDER, err := asn1.Marshal([]pkix.Extension{{Id: oidSubjectAltName, Value: names}})
		if err != nil {
			t.Fatalf("marshal Extensions: %v", err)
		}
		extField, err := asn1.Marshal(retagContext(9, extsDER, true))
		if err != nil {
			t.Fatalf("marshal extensions field: %v", err)
		}
		templateFields = append(templateFields, extField...)
	}
	certTemplate, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: templateFields,
	})
	if err != nil {
		t.Fatalf("marshal CertTemplate: %v", err)
	}

	reqIDBytes, err := asn1.Marshal(0)
	if err != nil {
		t.Fatalf("marshal certReqId: %v", err)
	}
	certReq, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte{}, reqIDBytes...), certTemplate...),
	})
	if err != nil {
		t.Fatalf("marshal CertRequest: %v", err)
	}

	// POPOSigningKey: sign the DER of CertRequest itself (poposkInput absent).
	h := sha256.Sum256(certReq)
	sig, err := sign(h[:])
	if err != nil {
		t.Fatalf("sign POPO: %v", err)
	}
	psk := popoSigningKeyV2{
		AlgID:     pkix.AlgorithmIdentifier{Algorithm: algOID},
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	pskDER, err := asn1.Marshal(psk)
	if err != nil {
		t.Fatalf("marshal POPOSigningKey: %v", err)
	}
	popoField, err := asn1.Marshal(retagContext(1, pskDER, true))
	if err != nil {
		t.Fatalf("marshal popo field: %v", err)
	}

	certReqMsg, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte{}, certReq...), popoField...),
	})
	if err != nil {
		t.Fatalf("marshal CertReqMsg: %v", err)
	}

	// CertReqMessages ::= SEQUENCE OF CertReqMsg (one element here). PKIBody's
	// ir/cr/kur alternatives are EXPLICIT (RFC 4210's PKIXCMP module
	// default), so the PKIBody wrapper built in buildProtectedPKIMessage
	// wraps this COMPLETE CertReqMessages encoding -- own SEQUENCE tag+
	// length included -- not bare content.
	certReqMessages, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: certReqMsg,
	})
	if err != nil {
		t.Fatalf("marshal CertReqMessages: %v", err)
	}
	return certReqMessages
}

// pbmOptions lets a test deliberately break protection (wrong secret, no
// protection at all) while reusing the rest of the message assembly.
type pbmOptions struct {
	skip         bool
	secretForMAC string // if empty, defaults to testSecret
	kid          string // senderKID; if empty, defaults to testReference
	txnID        string // if empty, a fixed default
	nonce        string // senderNonce; if empty, fresh random per message
}

// buildProtectedPKIMessage assembles a full PKIMessage: header (pvno,
// placeholder sender/recipient, protectionAlg, senderKID, transactionID,
// senderNonce) + body + PBM protection, mirroring the production response
// builder's shape in pkimessage.go / protection.go so tests exercise the
// exact same DER structure as the server verifies.
func buildProtectedPKIMessage(t *testing.T, bodyType int, bodyContent []byte, opts pbmOptions) []byte {
	t.Helper()

	emptyDN, err := generalNameEmptyDirectoryName()
	if err != nil {
		t.Fatalf("build sender/recipient: %v", err)
	}
	pvno, err := asn1.Marshal(2)
	if err != nil {
		t.Fatalf("marshal pvno: %v", err)
	}

	var headerContent []byte
	headerContent = append(headerContent, pvno...)
	headerContent = append(headerContent, emptyDN...) // sender
	headerContent = append(headerContent, emptyDN...) // recipient

	salt := []byte("test-salt-16byte")
	param := pbmParameter{
		Salt:           salt,
		Owf:            pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		IterationCount: 100,
		Mac:            pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256},
	}
	protAlg := pkix.AlgorithmIdentifier{Algorithm: oidPasswordBasedMac}
	if !opts.skip {
		paramDER, err := asn1.Marshal(param)
		if err != nil {
			t.Fatalf("marshal PBMParameter: %v", err)
		}
		protAlg.Parameters = asn1.RawValue{FullBytes: paramDER}
		// RFC 4210's PKIXCMP module is EXPLICIT TAGS, so every optional
		// header field below wraps a complete inner TLV rather than
		// replacing its tag.
		protAlgDER, err := asn1.MarshalWithParams(protAlg, "explicit,tag:1")
		if err != nil {
			t.Fatalf("marshal protectionAlg: %v", err)
		}
		headerContent = append(headerContent, protAlgDER...)

		kidValue := opts.kid
		if kidValue == "" {
			kidValue = testReference
		}
		kid, err := asn1.MarshalWithParams([]byte(kidValue), "explicit,tag:2")
		if err != nil {
			t.Fatalf("marshal senderKID: %v", err)
		}
		headerContent = append(headerContent, kid...)
	}

	txnID := []byte("test-transaction-id-0001")
	if opts.txnID != "" {
		txnID = []byte(opts.txnID)
	}
	txn, err := asn1.MarshalWithParams(txnID, "explicit,tag:4")
	if err != nil {
		t.Fatalf("marshal transactionID: %v", err)
	}
	headerContent = append(headerContent, txn...)

	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		t.Fatalf("senderNonce: %v", err)
	}
	if opts.nonce != "" {
		senderNonce = []byte(opts.nonce)
	}
	sn, err := asn1.MarshalWithParams(senderNonce, "explicit,tag:5")
	if err != nil {
		t.Fatalf("marshal senderNonce: %v", err)
	}
	headerContent = append(headerContent, sn...)

	header, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: headerContent,
	})
	if err != nil {
		t.Fatalf("marshal PKIHeader: %v", err)
	}

	body, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: bodyType, IsCompound: true,
		Bytes: bodyContent,
	})
	if err != nil {
		t.Fatalf("marshal PKIBody: %v", err)
	}

	msgContent := append(append([]byte{}, header...), body...)

	if !opts.skip {
		protectedPart, err := protectedPartDER(header, body)
		if err != nil {
			t.Fatalf("build ProtectedPart: %v", err)
		}
		secret := opts.secretForMAC
		if secret == "" {
			secret = testSecret
		}
		mac, _, err := computePBM([]byte(secret), param, protectedPart)
		if err != nil {
			t.Fatalf("compute PBM: %v", err)
		}
		bitStringDER, err := asn1.Marshal(asn1.BitString{Bytes: mac, BitLength: len(mac) * 8})
		if err != nil {
			t.Fatalf("marshal protection BIT STRING: %v", err)
		}
		protField, err := asn1.Marshal(explicitContext(0, bitStringDER))
		if err != nil {
			t.Fatalf("marshal protection field: %v", err)
		}
		msgContent = append(msgContent, protField...)
	}

	pkiMsg, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: msgContent,
	})
	if err != nil {
		t.Fatalf("marshal PKIMessage: %v", err)
	}
	return pkiMsg
}

func newServerForTest(engine ca.Service, caID string) *Server {
	return NewServer(engine, caID, testSecret, testReference)
}

func postCMP(h http.Handler, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/cmp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/pkixcmp")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func decodeResponse(t *testing.T, der []byte) pkiMessageRaw {
	t.Helper()
	var msg pkiMessageRaw
	if _, err := asn1.Unmarshal(der, &msg); err != nil {
		t.Fatalf("response is not a valid PKIMessage: %v", err)
	}
	return msg
}

// --- IR: the happy path UAT W19-05 found broken. ---

func TestCMPHandlerIR_ValidRequest_IssuesAndProtects(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	srv := newServerForTest(engine, caID)
	h := srv.Handler()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	body := buildCRMFIRBody(t, priv, "cmp-ir-test")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyIP {
		t.Fatalf("response body tag = %d, want PKIBodyIP (%d)", msg.Body.Tag, PKIBodyIP)
	}
	if len(msg.Protection.FullBytes) == 0 {
		t.Fatal("response carries no protection — openssl cmp verifies response protection by default")
	}

	// The response must itself verify against the same shared secret.
	hdr, err := parseHeader(msg.Header)
	if err != nil {
		t.Fatalf("parse response header: %v", err)
	}
	if err := verifyPBMProtection(&hdr, msg.Protection, msg.Body.FullBytes, []byte(testSecret)); err != nil {
		t.Fatalf("response protection does not verify against the shared secret: %v", err)
	}
}

func TestCMPHandlerIR_WrongSecret_Rejected(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	srv := newServerForTest(engine, caID)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-wrong-secret")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{secretForMAC: "not-the-real-secret"})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (protocol-level rejection), got %d", rr.Code)
	}
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyError {
		t.Fatalf("body tag = %d, want PKIBodyError (%d) for a wrong secret", msg.Body.Tag, PKIBodyError)
	}
}

func TestCMPHandlerIR_MissingProtection_Rejected(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	srv := newServerForTest(engine, caID)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-no-protection")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{skip: true})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (protocol-level rejection), got %d", rr.Code)
	}
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyError {
		t.Fatalf("body tag = %d, want PKIBodyError (%d) for an unprotected request", msg.Body.Tag, PKIBodyError)
	}
}

func TestCMPHandlerIR_BadPOP_Rejected(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	srv := newServerForTest(engine, caID)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-bad-pop")
	// Corrupt a byte inside the CertReqMessages body (well past the header)
	// so the POPO signature no longer verifies against the (unchanged)
	// CertRequest bytes it's supposed to cover.
	corrupted := append([]byte{}, body...)
	corrupted[len(corrupted)-1] ^= 0xFF
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, corrupted, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (protocol-level rejection), got %d", rr.Code)
	}
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyError {
		t.Fatalf("body tag = %d, want PKIBodyError (%d) for a tampered POPO", msg.Body.Tag, PKIBodyError)
	}
}

// --- KUR: same protected-CRMF path, different body/response tag. ---

func TestCMPHandlerKUR_ReturnsKUPBodyType(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	srv := newServerForTest(engine, caID)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-kur-test")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyKUR, body, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("KUR: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyKUP {
		t.Fatalf("KUR response body tag = %d, want PKIBodyKUP (%d)", msg.Body.Tag, PKIBodyKUP)
	}
}

// --- certConf / pkiconf ---

func TestCMPHandlerCertConf_RespondsPKIConf(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	srv := newServerForTest(engine, caID)
	h := srv.Handler()

	// CertConfirmContent ::= SEQUENCE OF CertStatus — an empty sequence is
	// enough to exercise the pkiconf response path.
	confBody, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true})
	if err != nil {
		t.Fatalf("marshal CertConfirmContent: %v", err)
	}
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyCertConf, confBody, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("certConf: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyPKIConf {
		t.Fatalf("certConf response body tag = %d, want PKIBodyPKIConf (%d)", msg.Body.Tag, PKIBodyPKIConf)
	}
}

// --- transport-level basics ---

func TestCMPHandler_MethodNotAllowed(t *testing.T) {
	srv := &Server{}
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/cmp", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCMPHandler_InvalidBody(t *testing.T) {
	srv := &Server{}
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodPost, "/cmp", strings.NewReader("not cmp"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestBodyTypeConstants(t *testing.T) {
	if PKIBodyIR != 0 || PKIBodyIP != 1 || PKIBodyCR != 2 || PKIBodyCP != 3 {
		t.Errorf("RFC 4210 body type constants mismatch")
	}
}

// --- W18-18 inventory recorder wiring, now exercised through a real
// protected IR/KUR rather than a bare CSR. ---

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

func TestCMPHandlerIRRecordsIssuedCertificate(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	recorder := &fakeIssuedRecorder{}
	srv := newServerForTest(engine, caID).WithIssuedRecorder(recorder)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-ir-recorded")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Fatalf("expected recorder called once, got %d", recorder.calls)
	}
	if recorder.caID != caID {
		t.Errorf("expected caID=%s, got %s", caID, recorder.caID)
	}
	if recorder.cert == nil || recorder.cert.Subject.CommonName != "cmp-ir-recorded" {
		t.Errorf("expected recorder to see the issued certificate")
	}
	if len(recorder.chainPEM) == 0 || !strings.Contains(string(recorder.chainPEM), "BEGIN CERTIFICATE") {
		t.Error("expected non-empty PEM chain passed to recorder")
	}
}

func TestCMPHandlerKeyUpdateRecordsIssuedCertificate(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	recorder := &fakeIssuedRecorder{}
	srv := newServerForTest(engine, caID).WithIssuedRecorder(recorder)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-kur-recorded")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyKUR, body, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("KUR: expected 200, got %d", rr.Code)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Fatalf("expected recorder called once for KUR, got %d", recorder.calls)
	}
	if recorder.caID != caID {
		t.Errorf("expected caID=%s, got %s", caID, recorder.caID)
	}
}

func TestCMPHandlerRecorderErrorDoesNotFailResponse(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	recorder := &fakeIssuedRecorder{err: errors.New("simulated recorder failure")}
	srv := newServerForTest(engine, caID).WithIssuedRecorder(recorder)
	h := srv.Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := buildCRMFIRBody(t, priv, "cmp-recorder-error")
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{})

	rr := postCMP(h, pkiMsg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 despite recorder error, got %d: %s", rr.Code, rr.Body.String())
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 1 {
		t.Errorf("expected recorder still called once despite its own error, got %d", recorder.calls)
	}
}

// oidSHA256WithRSA matches signatureOIDs in crmf.go.
var oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

func rsaCMPIR(t *testing.T, bits int, cn string) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	body := buildCRMFBody(t, &priv.PublicKey, oidSHA256WithRSA, func(h []byte) ([]byte, error) {
		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h)
	}, cn)
	return buildProtectedPKIMessage(t, PKIBodyIR, body, pbmOptions{})
}

// FG-1 (OWASP-A04-002): CMP must not certify weak keys, and must keep
// accepting RSA-2048.
func TestCMPHandlerIR_RSA1024_Rejected(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	h := newServerForTest(engine, caID).Handler()
	rr := postCMP(h, rsaCMPIR(t, 1024, "cmp-rsa1024"))
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyError {
		t.Fatalf("body tag = %d, want PKIBodyError for an RSA-1024 key", msg.Body.Tag)
	}
}

func TestCMPHandlerIR_RSA2048_Accepted(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	h := newServerForTest(engine, caID).Handler()
	rr := postCMP(h, rsaCMPIR(t, 2048, "cmp-rsa2048"))
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyIP {
		t.Fatalf("body tag = %d, want PKIBodyIP for an RSA-2048 key", msg.Body.Tag)
	}
}

// W23-35: an IR through a revoked CA is answered with an error PKIMessage and
// records nothing.
func TestCMPHandlerIR_RefusedWhenCARevoked(t *testing.T) {
	engine, caID := newCMPTestEngine(t)
	recorder := &fakeIssuedRecorder{}
	h := newServerForTest(engine, caID).WithIssuedRecorder(recorder).Handler()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkiMsg := buildProtectedPKIMessage(t, PKIBodyIR, buildCRMFIRBody(t, priv, "cmp-revoked"), pbmOptions{})

	if err := engine.UpdateCAStatus(caID, "revoked"); err != nil {
		t.Fatal(err)
	}
	rr := postCMP(h, pkiMsg)
	msg := decodeResponse(t, rr.Body.Bytes())
	if msg.Body.Tag != PKIBodyError {
		t.Fatalf("body tag = %d, want PKIBodyError (%d)", msg.Body.Tag, PKIBodyError)
	}
	if !strings.Contains(rr.Body.String(), "issuing CA revoked") {
		t.Error("error body does not say the issuing CA is revoked")
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.calls != 0 {
		t.Fatalf("a certificate was recorded through a revoked CA: %d", recorder.calls)
	}
}
