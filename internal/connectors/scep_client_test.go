// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/scep"
)

// oidPKCS9ChallengePassword is RFC 2985 §5.4.1's challengePassword OID --
// duplicated from internal/scep (unexported there) so this test can build a
// CSR carrying it without reaching into another package's internals.
var oidPKCS9ChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// asn1CertificateRequestOuter mirrors RFC 2986's outer CertificationRequest
// SEQUENCE, matching internal/scep/server_test.go's identical helper (both
// need it for the same reason: splicing a raw PKCS#9 attribute into a CSR's
// TBS that x509.CreateCertificateRequest cannot express).
type asn1CertificateRequestOuter struct {
	TBSCSR             asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

// tbsCSRAttrs mirrors RFC 2986's CertificationRequestInfo just far enough to
// reach the raw attributes SET.
type tbsCSRAttrs struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

// pkcs10Attribute is RFC 2986 §4.1's Attribute: { type OID, values SET OF AttributeValue }.
type pkcs10Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// W13-03/W19-28: SCEP + EST clients proven against a real CA engine. Both
// now prove against our own servers: EST against internal/est.Server, and
// SCEP (since W19-15 made internal/scep.Server a real RFC 8894 endpoint and
// W19-28 made SCEPClient speak the matching real PKIOperation) against
// internal/scep.Server. There is no fixture double left standing in for the
// SCEP protocol -- see newSCEPUpstream below.

func upstreamCAEngine(t *testing.T) (ca.Service, string) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-legacy-client-passphrase!!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Legacy Root", pkix.Name{CommonName: "Legacy Root"},
		keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	return engine, root.ID
}

// scepUpstream is a real internal/scep.Server behind an httptest server,
// backed by an RSA root CA -- W19-28's client (like the real RFC 8894
// exchange it speaks) requires an RSA CA for the envelopedData key-transport
// step (github.com/smallstep/pkcs7 only supports RSA recipients).
type scepUpstream struct {
	ts  *httptest.Server
	key crypto.Signer // RSA client key + decrypter for this test's IssueRequest
}

// oneChallenge is a scep.ChallengeStore holding a single one-time challenge
// bound to cn. The client tests exercise the RFC 8894 exchange; the store's
// own rules are tested in internal/scep.
type oneChallenge struct {
	mu         sync.Mutex
	secret, cn string
	caID       string
	used       bool
}

func (o *oneChallenge) Create(context.Context, scep.Challenge) (scep.Challenge, string, error) {
	return scep.Challenge{}, "", errors.New("not supported")
}
func (o *oneChallenge) Consume(_ context.Context, secret string, _ time.Time) (scep.Challenge, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case secret != o.secret:
		return scep.Challenge{}, scep.ErrChallengeUnknown
	case o.used:
		return scep.Challenge{}, scep.ErrChallengeUsed
	}
	o.used = true
	return scep.Challenge{ID: "test", CAID: o.caID, CommonName: o.cn}, nil
}
func (o *oneChallenge) List(context.Context) ([]scep.Challenge, error) { return nil, nil }
func (o *oneChallenge) Delete(context.Context, string) error           { return nil }

// newSCEPUpstream serves a SCEP CA whose one challenge is bound to cn.
func newSCEPUpstream(t *testing.T, challenge, cn string) *scepUpstream {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("scep-client-test-passphrase-32c!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("SCEP Upstream Root", pkix.Name{CommonName: "SCEP Upstream Root CA"},
		keystore.RSA2048, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	srv := scep.NewServer(engine, rootCA.ID, &oneChallenge{secret: challenge, cn: cn, caID: rootCA.ID}).WithDecrypter(func() (crypto.Decrypter, error) {
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
	ts := httptest.NewServer(srv.Handler())

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	return &scepUpstream{ts: ts, key: clientKey}
}

func (u *scepUpstream) Close() { u.ts.Close() }

// scepCSRWithChallenge builds a PKCS#10 CSR carrying the PKCS#9
// challengePassword attribute internal/scep.Server requires --
// x509.CreateCertificateRequest has no support for that attribute shape, so
// this splices a raw attribute into the TBS and re-signs, mirroring
// internal/scep/server_test.go's buildCSRWithChallenge (that helper is
// unexported and lives in a different package, so it can't be reused
// directly; the two independently agreeing on the wire shape is the point).
func scepCSRWithChallenge(t *testing.T, key *rsa.PrivateKey, cn, challenge string) string {
	t.Helper()
	plainDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	var plainOuter asn1CertificateRequestOuter
	if _, err := asn1.Unmarshal(plainDER, &plainOuter); err != nil {
		t.Fatalf("unmarshal CSR outer: %v", err)
	}

	var tbs tbsCSRAttrs
	if _, err := asn1.Unmarshal(plainOuter.TBSCSR.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	tbs.Raw = nil

	attrBytes, err := asn1.Marshal(pkcs10Attribute{
		Type:   oidPKCS9ChallengePassword,
		Values: []asn1.RawValue{{Class: 0, Tag: 19, Bytes: []byte(challenge)}},
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

	final := asn1CertificateRequestOuter{
		TBSCSR:             asn1.RawValue{FullBytes: newTBS},
		SignatureAlgorithm: plainOuter.SignatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	finalDER, err := asn1.Marshal(final)
	if err != nil {
		t.Fatalf("marshal final CSR: %v", err)
	}

	parsed, err := x509.ParseCertificateRequest(finalDER)
	if err != nil {
		t.Fatalf("parse final CSR: %v", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("final CSR self-check: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: finalDER}))
}

func TestSCEPClientEnrollsAgainstRealServer(t *testing.T) {
	u := newSCEPUpstream(t, "test-challenge", "legacy-scep.example.com")
	defer u.Close()

	c := NewSCEPClient("scep-1", SCEPClientConfig{EndpointURL: u.ts.URL}, u.ts.Client())
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health: %+v", h)
	}

	rsaKey := u.key.(*rsa.PrivateKey)
	csrPEM := scepCSRWithChallenge(t, rsaKey, "legacy-scep.example.com", "test-challenge")
	res, err := c.Issue(context.Background(), IssueRequest{
		CSRPEM:    csrPEM,
		Signer:    rsaKey,
		Decrypter: rsaKey,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	block, _ := pem.Decode([]byte(res.CertificatePEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.Subject.CommonName != "legacy-scep.example.com" {
		t.Fatalf("issued cert: %v %v", cert, err)
	}
}

func TestSCEPClientRejectsWrongChallenge(t *testing.T) {
	u := newSCEPUpstream(t, "test-challenge", "legacy-scep.example.com")
	defer u.Close()

	c := NewSCEPClient("scep-1", SCEPClientConfig{EndpointURL: u.ts.URL}, u.ts.Client())
	rsaKey := u.key.(*rsa.PrivateKey)
	csrPEM := scepCSRWithChallenge(t, rsaKey, "scep-wrong.example.com", "totally-wrong")
	_, err := c.Issue(context.Background(), IssueRequest{
		CSRPEM:    csrPEM,
		Signer:    rsaKey,
		Decrypter: rsaKey,
	})
	if err == nil {
		t.Fatal("expected FAILURE from wrong challenge password, got nil error")
	}
}

func TestSCEPClientRequiresSignerAndDecrypter(t *testing.T) {
	u := newSCEPUpstream(t, "test-challenge", "legacy-scep.example.com")
	defer u.Close()
	c := NewSCEPClient("scep-1", SCEPClientConfig{EndpointURL: u.ts.URL}, u.ts.Client())
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "no-signer.example.com")})
	if err == nil {
		t.Fatal("expected an error when Signer/Decrypter are missing")
	}
}

func TestLegacyClientsHealthDegradedWhenDown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	client := srv.Client()
	srv.Close()
	if h := NewESTClient("e", ESTClientConfig{BaseURL: url}, client).Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("est health: %+v", h)
	}
	if h := NewSCEPClient("s", SCEPClientConfig{EndpointURL: url}, client).Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("scep health: %+v", h)
	}
}

// Review fix (crypto challenger #2): a certs-only response whose base64
// body is line-wrapped (as real EST/SCEP servers emit) must parse, not
// be misdiagnosed as a PKCS#7 envelope. Exercises parseCertsOnlyResponse,
// still used by the EST client.
func TestParseCertsOnlyToleratesWrappedBase64(t *testing.T) {
	der := certDERForWrap(t, "wrapped.example.com")
	b64 := base64.StdEncoding.EncodeToString(der)
	var wrapped strings.Builder
	for len(b64) > 64 {
		wrapped.WriteString(b64[:64])
		wrapped.WriteString("\r\n")
		b64 = b64[64:]
	}
	wrapped.WriteString(b64)
	res, err := parseCertsOnlyResponse("c", "est", []byte(wrapped.String()))
	if err != nil {
		t.Fatalf("wrapped base64 must parse: %v", err)
	}
	if len(res.FingerprintSHA256) != 64 {
		t.Fatalf("expected a parsed cert, got %+v", res)
	}
}

func certDERForWrap(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der
}
