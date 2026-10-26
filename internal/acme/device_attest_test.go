// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"kryptkeeper/internal/ca"
)

// --- fake attestation PKI --------------------------------------------------
//
// Everything below is generated in the test: the "Apple" and "TPM" roots are
// throwaway keys configured as the trusted roots, so no real vendor root or
// device is involved. Real-device proof is a ROADMAP row.

type fakeCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newFakeCA(t *testing.T, cn string, parent *fakeCA) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &fakeCA{cert: cert, key: key, der: der}
}

func (c *fakeCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// appleLeaf issues an Apple-shaped attestation leaf for pub.
func (c *fakeCA) appleLeaf(t *testing.T, pub *ecdsa.PublicKey, serial, udid string, nonce []byte) []byte {
	t.Helper()
	exts := []pkix.Extension{{Id: oidAppleFreshness, Value: nonce}}
	if serial != "" {
		exts = append(exts, pkix.Extension{Id: oidAppleSerialNumber, Value: []byte(serial)})
	}
	if udid != "" {
		exts = append(exts, pkix.Extension{Id: oidAppleUDID, Value: []byte(udid)})
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "fake Apple attestation leaf"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func marshalCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func appleAttObj(t *testing.T, x5c ...[]byte) []byte {
	return marshalCBOR(t, map[string]any{"fmt": "apple", "attStmt": map[string]any{"x5c": x5c}})
}

func tokenHash(token string) []byte { h := sha256.Sum256([]byte(token)); return h[:] }

// --- TPM structure encoders (test side) -------------------------------------

func be16(v int) []byte       { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
func tpm2b(b []byte) []byte   { return append(be16(len(b)), b...) }
func pad32(b *big.Int) []byte { out := make([]byte, 32); b.FillBytes(out); return out }
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func tpmPubAreaECC(pub *ecdsa.PublicKey, nameAlg int) []byte {
	return cat(be16(0x0023), be16(nameAlg), []byte{0, 6, 4, 114}, tpm2b(nil),
		be16(0x0010), // symmetric: TPM_ALG_NULL
		be16(0x0010), // scheme: TPM_ALG_NULL
		be16(0x0003), // curveID: NIST P-256
		be16(0x0010), // kdf: TPM_ALG_NULL
		tpm2b(pad32(pub.X)), tpm2b(pad32(pub.Y)))
}

func tpmCertInfoBytes(extra, name []byte) []byte {
	return cat(binary.BigEndian.AppendUint32(nil, tpmGeneratedValue), be16(tpmSTAttestCertify),
		tpm2b(nil), tpm2b(extra), make([]byte, 17), make([]byte, 8), tpm2b(name), tpm2b(nil))
}

// aikCert issues an AIK certificate per WebAuthn 8.3.1 whose SAN is critical
// (as in the spec's own test vector) and carries the TPM manufacturer
// directoryName and, when serial is set, a PermanentIdentifier otherName.
func (c *fakeCA) aikCert(t *testing.T, pub *ecdsa.PublicKey, serial string, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	dir, _ := asn1.Marshal(pkix.RDNSequence{{{Type: oidTCGManufacturer, Value: "id:49465800"}}})
	names := []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dir}}
	if serial != "" {
		pi, _ := asn1.Marshal(permanentIDForTest{IdentifierValue: serial})
		oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3})
		expl, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: pi})
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oid, expl...)})
	}
	san, _ := asn1.Marshal(names)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKpAIKCertificate},
		ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltNameExt, Critical: true, Value: san}},
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type permanentIDForTest struct {
	IdentifierValue string `asn1:"utf8"`
}

type tpmOpts struct {
	extraData []byte // default: SHA-256(keyAuth)
	nameAlg   int    // default SHA-256
}

// tpmAttObj builds a WebAuthn tpm attestation object for credKey, signed by
// aikKey, with x5c as given.
func tpmAttObj(t *testing.T, credKey *ecdsa.PublicKey, aikKey *ecdsa.PrivateKey, keyAuth string, x5c [][]byte, o tpmOpts) []byte {
	t.Helper()
	if o.nameAlg == 0 {
		o.nameAlg = tpmAlgSHA256
	}
	if o.extraData == nil {
		h := sha256.Sum256([]byte(keyAuth))
		o.extraData = h[:]
	}
	pubArea := tpmPubAreaECC(credKey, o.nameAlg)
	nd := sha256.Sum256(pubArea)
	certInfo := tpmCertInfoBytes(o.extraData, cat(be16(o.nameAlg), nd[:]))
	d := sha256.Sum256(certInfo)
	r, s, err := ecdsa.Sign(rand.Reader, aikKey, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := cat(be16(tpmAlgECDSA), be16(tpmAlgSHA256), tpm2b(pad32(r)), tpm2b(pad32(s)))
	return marshalCBOR(t, map[string]any{"fmt": "tpm", "attStmt": map[string]any{
		"ver": "2.0", "alg": -7, "x5c": x5c, "sig": sig, "certInfo": certInfo, "pubArea": pubArea,
	}})
}

// --- server harness ---------------------------------------------------------

type deviceEnv struct {
	srv     *Server
	ts      *httptest.Server
	apple   *fakeCA
	tpmRoot *fakeCA

	mu      sync.Mutex
	events  []AuditEvent
	allowed map[string]bool
	tplOK   bool
}

func newDeviceEnv(t *testing.T, mod func(*DeviceAttestationConfig)) *deviceEnv {
	t.Helper()
	srv, ts := newTestACMEServer(t)
	t.Cleanup(ts.Close)
	e := &deviceEnv{srv: srv, ts: ts, apple: newFakeCA(t, "fake Apple Enterprise Attestation Root", nil),
		tpmRoot: newFakeCA(t, "fake TPM manufacturer root", nil), allowed: map[string]bool{}, tplOK: true}
	srv.WithAuditFunc(func(_ context.Context, ev AuditEvent) {
		e.mu.Lock()
		e.events = append(e.events, ev)
		e.mu.Unlock()
	})
	cfg := DeviceAttestationConfig{
		AppleRoots: e.apple.pool(), TPMRoots: e.tpmRoot.pool(), DefaultTemplateID: "tpl-device",
		DeviceAllowed: func(_ context.Context, _, id string) (bool, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.allowed[id], nil
		},
		TemplateAllows: func(_ context.Context, id string) (bool, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return id == "tpl-device" && e.tplOK, nil
		},
	}
	if mod != nil {
		mod(&cfg)
	}
	srv.WithDeviceAttestation(cfg)
	return e
}

func (e *deviceEnv) allow(ids ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, id := range ids {
		e.allowed[id] = true
	}
}

func (e *deviceEnv) audited(action string) []AuditEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []AuditEvent
	for _, ev := range e.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

func (e *deviceEnv) newOrder(t *testing.T, c *acmeTestClient, ident string) (int, Order, Problem) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"identifiers": []Identifier{{Type: identifierTypePermanent, Value: ident}}})
	resp := c.postJWS(t, e.ts, e.ts.URL+"/acme/new-order", payload)
	defer resp.Body.Close()
	var o Order
	var p Problem
	if resp.StatusCode == http.StatusCreated {
		_ = json.NewDecoder(resp.Body).Decode(&o)
	} else {
		_ = json.NewDecoder(resp.Body).Decode(&p)
	}
	return resp.StatusCode, o, p
}

func (e *deviceEnv) challenge(t *testing.T, o Order) Challenge {
	t.Helper()
	resp, err := http.Get(o.Authorizations[0])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var a Authorization
	_ = json.NewDecoder(resp.Body).Decode(&a)
	if len(a.Challenges) != 1 || a.Challenges[0].Type != challengeDeviceAttest {
		t.Fatalf("want a single device-attest-01 challenge, got %+v", a.Challenges)
	}
	return a.Challenges[0]
}

func (e *deviceEnv) respond(t *testing.T, c *acmeTestClient, ch Challenge, attObj []byte) (int, Problem) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"attObj": base64.RawURLEncoding.EncodeToString(attObj)})
	resp := c.postJWS(t, e.ts, ch.URL, payload)
	defer resp.Body.Close()
	var p Problem
	if resp.StatusCode != http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&p)
	}
	return resp.StatusCode, p
}

func (e *deviceEnv) orderStatus(t *testing.T, o Order) string {
	t.Helper()
	resp, err := http.Get(e.ts.URL + "/acme/order/" + o.Finalize[strings.LastIndex(o.Finalize, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Order
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return got.Status
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newDeviceKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func problemIs(p Problem, typ string) bool { return p.Type == typ }

// --- the tests --------------------------------------------------------------

func TestDeviceAttestAppleSuccess(t *testing.T) {
	e := newDeviceEnv(t, nil)
	e.allow("C02TESTSERIAL")
	client := newACMEAccount(t, e.ts)
	dev := newDeviceKey(t)

	status, order, p := e.newOrder(t, client, "C02TESTSERIAL")
	if status != http.StatusCreated {
		t.Fatalf("new-order: %d %+v", status, p)
	}
	ch := e.challenge(t, order)
	leaf := e.apple.appleLeaf(t, &dev.PublicKey, "C02TESTSERIAL", "UDID-0001", tokenHash(ch.Token))
	if code, p := e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der)); code != http.StatusOK {
		t.Fatalf("challenge: %d %+v", code, p)
	}
	if got := e.orderStatus(t, order); got != "ready" {
		t.Fatalf("order status %q, want ready", got)
	}

	code, prob, final := finalizeWith(t, e.ts, client, order, csrFor(t, dev, &x509.CertificateRequest{}))
	if code != http.StatusOK {
		t.Fatalf("finalize: %d %+v", code, prob)
	}
	cert := fetchCert(t, final)
	ids, foreign, err := ca.SANPermanentIdentifiers(cert.Extensions)
	if err != nil || len(ids) != 1 || ids[0].Value != "C02TESTSERIAL" || foreign != 0 {
		t.Fatalf("certificate SAN: ids=%v foreign=%d err=%v", ids, foreign, err)
	}
	if len(cert.DNSNames) != 0 || cert.Subject.CommonName != "C02TESTSERIAL" {
		t.Fatalf("unexpected names: dns=%v cn=%q", cert.DNSNames, cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("device certificate must be client-auth only, got %v", cert.ExtKeyUsage)
	}
	if want, _ := publicKeyThumbprint(&dev.PublicKey); mustThumb(t, cert.PublicKey) != want {
		t.Fatal("certificate key is not the attested key")
	}
	if len(e.audited("acme.device_attest.accept")) != 1 || len(e.audited("acme.device_attest.issue")) != 1 {
		t.Fatalf("expected accept and issue audit rows, got %+v", e.events)
	}
	for _, ev := range e.events {
		if strings.Contains(ev.Detail, "UDID-0001") || strings.Contains(ev.Detail, base64.RawURLEncoding.EncodeToString(leaf[:16])) {
			t.Fatalf("audit detail leaked attestation content: %q", ev.Detail)
		}
	}
}

func TestDeviceAttestAppleMatchesUDID(t *testing.T) {
	e := newDeviceEnv(t, nil)
	e.allow("UDID-0001")
	client := newACMEAccount(t, e.ts)
	dev := newDeviceKey(t)
	_, order, _ := e.newOrder(t, client, "UDID-0001")
	ch := e.challenge(t, order)
	leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SERIAL", "UDID-0001", tokenHash(ch.Token))
	if code, p := e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der)); code != http.StatusOK {
		t.Fatalf("UDID must satisfy the identifier: %d %+v", code, p)
	}
}

func TestDeviceAttestTPMSuccess(t *testing.T) {
	e := newDeviceEnv(t, nil)
	e.allow("TPMSERIAL42")
	client := newACMEAccount(t, e.ts)
	dev := newDeviceKey(t)
	aik := newDeviceKey(t)

	_, order, _ := e.newOrder(t, client, "TPMSERIAL42")
	ch := e.challenge(t, order)
	aikDER := e.tpmRoot.aikCert(t, &aik.PublicKey, "TPMSERIAL42", nil)
	obj := tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+client.thumbprint(t), [][]byte{aikDER}, tpmOpts{})
	if code, p := e.respond(t, client, ch, obj); code != http.StatusOK {
		t.Fatalf("challenge: %d %+v", code, p)
	}

	code, prob, final := finalizeWith(t, e.ts, client, order, csrFor(t, dev, &x509.CertificateRequest{}))
	if code != http.StatusOK {
		t.Fatalf("finalize: %d %+v", code, prob)
	}
	cert := fetchCert(t, final)
	if ids, _, _ := ca.SANPermanentIdentifiers(cert.Extensions); len(ids) != 1 || ids[0].Value != "TPMSERIAL42" {
		t.Fatalf("SAN ids = %v", ids)
	}
}

func TestDeviceAttestRefusals(t *testing.T) {
	type tc struct {
		name    string
		apple   bool
		order   string
		reason  string // substring of the audit reason
		mut     func(t *testing.T, e *deviceEnv, ch Challenge, client *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte
		noAllow bool
	}
	otherApple := func(t *testing.T) *fakeCA { return newFakeCA(t, "attacker root", nil) }
	cases := []tc{
		{name: "apple wrong nonce", apple: true, order: "SER1", reason: "freshness code",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, _ *acmeTestClient, dev, _ *ecdsa.PrivateKey) []byte {
				leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash("some other token"))
				return appleAttObj(t, leaf, e.apple.der)
			}},
		{name: "apple keyauth is not accepted as the nonce", apple: true, order: "SER1", reason: "freshness code",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, _ *ecdsa.PrivateKey) []byte {
				leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token+"."+c.thumbprint(t)))
				return appleAttObj(t, leaf, e.apple.der)
			}},
		{name: "apple identifier mismatch", apple: true, order: "SER1", reason: "differs from the order",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, _ *acmeTestClient, dev, _ *ecdsa.PrivateKey) []byte {
				leaf := e.apple.appleLeaf(t, &dev.PublicKey, "NOT-SER1", "OTHER-UDID", tokenHash(ch.Token))
				return appleAttObj(t, leaf, e.apple.der)
			}},
		{name: "apple untrusted root", apple: true, order: "SER1", reason: "trusted root",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, _ *acmeTestClient, dev, _ *ecdsa.PrivateKey) []byte {
				rogue := otherApple(t)
				leaf := rogue.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token))
				return appleAttObj(t, leaf, rogue.der)
			}},
		{name: "apple unknown device", apple: true, order: "SER1", reason: "not in allow-list", noAllow: true,
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, _ *acmeTestClient, dev, _ *ecdsa.PrivateKey) []byte {
				leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token))
				return appleAttObj(t, leaf, e.apple.der)
			}},
		{name: "tpm wrong nonce", order: "SER1", reason: "extraData",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				h := sha256.Sum256([]byte("a different key authorization"))
				return tpmAttObj(t, &dev.PublicKey, aik, "", [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{extraData: h[:]})
			}},
		{name: "tpm token alone is not the key authorization", order: "SER1", reason: "extraData",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token, [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{})
			}},
		{name: "tpm identifier mismatch", order: "SER1", reason: "differs from the order",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "OTHER", nil)}, tpmOpts{})
			}},
		{name: "tpm AIK without a permanent identifier", order: "SER1", reason: "permanent identifier",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "", nil)}, tpmOpts{})
			}},
		{name: "tpm untrusted root", order: "SER1", reason: "trusted root",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				rogue := otherApple(t)
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{rogue.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{})
			}},
		{name: "tpm unknown device", order: "SER1", reason: "not in allow-list", noAllow: true,
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{})
			}},
		{name: "tpm AIK signed certInfo by another key", order: "SER1", reason: "signature",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				other := newDeviceKey(t)
				return tpmAttObj(t, &dev.PublicKey, other, ch.Token+"."+c.thumbprint(t), [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{})
			}},
		{name: "tpm AIK that is a CA", order: "SER1", reason: "must not be a CA",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				der := e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", func(x *x509.Certificate) { x.IsCA, x.BasicConstraintsValid = true, true })
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{der}, tpmOpts{})
			}},
		{name: "tpm AIK with a subject", order: "SER1", reason: "subject must be empty",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				der := e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", func(x *x509.Certificate) { x.Subject = pkix.Name{CommonName: "x"} })
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{der}, tpmOpts{})
			}},
		{name: "tpm AIK without the AIK EKU", order: "SER1", reason: "extended key usage",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				der := e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", func(x *x509.Certificate) { x.UnknownExtKeyUsage = nil })
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{der}, tpmOpts{})
			}},
		{name: "tpm SHA-1 name algorithm", order: "SER1", reason: "nameAlg",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+c.thumbprint(t), [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{nameAlg: tpmAlgSHA1})
			}},
		{name: "garbage attObj", order: "SER1", reason: "well-formed",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return []byte{0xff, 0x00, 0x01}
			}},
		{name: "unknown format", order: "SER1", reason: "not supported",
			mut: func(t *testing.T, e *deviceEnv, ch Challenge, c *acmeTestClient, dev, aik *ecdsa.PrivateKey) []byte {
				return marshalCBOR(t, map[string]any{"fmt": "packed", "attStmt": map[string]any{}})
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDeviceEnv(t, nil)
			if !c.noAllow {
				e.allow("SER1")
			}
			client := newACMEAccount(t, e.ts)
			dev, aik := newDeviceKey(t), newDeviceKey(t)
			status, order, p := e.newOrder(t, client, c.order)
			if status != http.StatusCreated {
				t.Fatalf("new-order: %d %+v", status, p)
			}
			ch := e.challenge(t, order)
			code, prob := e.respond(t, client, ch, c.mut(t, e, ch, client, dev, aik))
			if code != http.StatusBadRequest || !problemIs(prob, errBadAttestationStatement) {
				t.Fatalf("want 400 badAttestationStatement, got %d %+v", code, prob)
			}
			rej := e.audited("acme.device_attest.reject")
			if len(rej) != 1 || !strings.Contains(strings.ToLower(rej[0].Detail), strings.ToLower(c.reason)) {
				t.Fatalf("want one reject audit row mentioning %q, got %+v", c.reason, rej)
			}
			if len(e.audited("acme.device_attest.accept")) != 0 {
				t.Fatal("a refused attestation must not be audited as accepted")
			}
			if got := e.orderStatus(t, order); got == "ready" || got == "valid" {
				t.Fatalf("order must not become ready, is %q", got)
			}
			// The challenge is spent: a retry is refused rather than re-verified.
			if code, _ := e.respond(t, client, ch, []byte{0}); code != http.StatusBadRequest {
				t.Fatalf("a second response to an invalid challenge must be refused, got %d", code)
			}
		})
	}
}

func TestDeviceAttestWrongKeyAtFinalize(t *testing.T) {
	e := newDeviceEnv(t, nil)
	e.allow("SER1")
	client := newACMEAccount(t, e.ts)
	dev, other := newDeviceKey(t), newDeviceKey(t)
	_, order, _ := e.newOrder(t, client, "SER1")
	ch := e.challenge(t, order)
	leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token))
	if code, p := e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der)); code != http.StatusOK {
		t.Fatalf("challenge: %d %+v", code, p)
	}
	code, prob, _ := finalizeWith(t, e.ts, client, order, csrFor(t, other, &x509.CertificateRequest{}))
	if code != http.StatusBadRequest || prob.Type != "urn:ietf:params:acme:error:badCSR" {
		t.Fatalf("a CSR for a different key must be badCSR, got %d %+v", code, prob)
	}
	rej := e.audited("acme.device_attest.reject")
	if len(rej) != 1 || !strings.Contains(rej[0].Detail, "CSR key differs") {
		t.Fatalf("expected an audited key-mismatch refusal, got %+v", rej)
	}
	if got := e.orderStatus(t, order); got != "invalid" {
		t.Fatalf("order status %q, want invalid", got)
	}
}

func TestDeviceAttestFinalizeCSRRules(t *testing.T) {
	for name, tmpl := range map[string]*x509.CertificateRequest{
		"dns name":    {DNSNames: []string{"evil.example.test"}},
		"email":       {EmailAddresses: []string{"a@example.test"}},
		"other ident": {ExtraExtensions: []pkix.Extension{permanentIDSAN(t, "SOMEONE-ELSE")}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newDeviceEnv(t, nil)
			e.allow("SER1")
			client := newACMEAccount(t, e.ts)
			dev := newDeviceKey(t)
			_, order, _ := e.newOrder(t, client, "SER1")
			ch := e.challenge(t, order)
			leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token))
			e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der))
			code, prob, _ := finalizeWith(t, e.ts, client, order, csrFor(t, dev, tmpl))
			if code != http.StatusBadRequest || prob.Type != "urn:ietf:params:acme:error:badCSR" {
				t.Fatalf("want badCSR, got %d %+v", code, prob)
			}
		})
	}
	t.Run("matching identifier in the CSR is accepted", func(t *testing.T) {
		e := newDeviceEnv(t, nil)
		e.allow("SER1")
		client := newACMEAccount(t, e.ts)
		dev := newDeviceKey(t)
		_, order, _ := e.newOrder(t, client, "SER1")
		ch := e.challenge(t, order)
		leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token))
		e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der))
		code, prob, _ := finalizeWith(t, e.ts, client, order, csrFor(t, dev, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{permanentIDSAN(t, "SER1")}}))
		if code != http.StatusOK {
			t.Fatalf("finalize: %d %+v", code, prob)
		}
	})
}

func permanentIDSAN(t *testing.T, v string) pkix.Extension {
	t.Helper()
	pi, _ := asn1.Marshal(permanentIDForTest{IdentifierValue: v})
	oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3})
	expl, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: pi})
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oid, expl...)}})
	return pkix.Extension{Id: oidSubjectAltNameExt, Value: san}
}

func mustThumb(t *testing.T, pub any) string {
	t.Helper()
	s, err := publicKeyThumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDeviceAttestNotOffered(t *testing.T) {
	post := func(t *testing.T, e *deviceEnv) (int, Problem) {
		client := newACMEAccount(t, e.ts)
		code, _, p := e.newOrder(t, client, "SER1")
		return code, p
	}
	t.Run("no roots configured", func(t *testing.T) {
		srv, ts := newTestACMEServer(t)
		defer ts.Close()
		srv.WithDeviceAttestation(DeviceAttestationConfig{TemplateAllows: func(context.Context, string) (bool, error) { return true, nil }, DefaultTemplateID: "tpl-device"})
		if srv.device != nil {
			t.Fatal("device attestation must stay off without roots")
		}
		e := &deviceEnv{srv: srv, ts: ts}
		code, p := post(t, e)
		if code != http.StatusBadRequest || p.Type != "urn:ietf:params:acme:error:unsupportedIdentifier" {
			t.Fatalf("got %d %+v", code, p)
		}
	})
	t.Run("template lacks the flag", func(t *testing.T) {
		e := newDeviceEnv(t, nil)
		e.tplOK = false
		code, p := post(t, e)
		if code != http.StatusBadRequest || p.Type != "urn:ietf:params:acme:error:unsupportedIdentifier" {
			t.Fatalf("got %d %+v", code, p)
		}
		if rej := e.audited("acme.device_attest.reject"); len(rej) != 1 || !strings.Contains(rej[0].Detail, "template does not allow") {
			t.Fatalf("refusal must be audited with its reason: %+v", rej)
		}
	})
	t.Run("no template at all", func(t *testing.T) {
		e := newDeviceEnv(t, func(c *DeviceAttestationConfig) { c.DefaultTemplateID = "" })
		if code, _ := post(t, e); code != http.StatusBadRequest {
			t.Fatalf("got %d", code)
		}
	})
	t.Run("only the other format is configured", func(t *testing.T) {
		e := newDeviceEnv(t, func(c *DeviceAttestationConfig) { c.TPMRoots = nil })
		e.allow("SER1")
		client := newACMEAccount(t, e.ts)
		dev, aik := newDeviceKey(t), newDeviceKey(t)
		_, order, _ := e.newOrder(t, client, "SER1")
		ch := e.challenge(t, order)
		obj := tpmAttObj(t, &dev.PublicKey, aik, ch.Token+"."+client.thumbprint(t), [][]byte{e.tpmRoot.aikCert(t, &aik.PublicKey, "SER1", nil)}, tpmOpts{})
		if code, p := e.respond(t, client, ch, obj); code != http.StatusBadRequest || !strings.Contains(p.Detail, "not enabled") {
			t.Fatalf("got %d %+v", code, p)
		}
	})
	t.Run("dns orders are unaffected", func(t *testing.T) {
		e := newDeviceEnv(t, nil)
		client := newACMEAccount(t, e.ts)
		payload, _ := json.Marshal(map[string]any{"identifiers": []Identifier{{Type: "dns", Value: "host.example.test"}}})
		resp := client.postJWS(t, e.ts, e.ts.URL+"/acme/new-order", payload)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("dns order: %d", resp.StatusCode)
		}
	})
}

func TestDeviceAttestOrderValidation(t *testing.T) {
	e := newDeviceEnv(t, nil)
	client := newACMEAccount(t, e.ts)
	for _, bad := range []string{"", "/1.2.3", "a/b/c", "SER/1.2.x", "SER/3.1", "SER/01.2", "bad\x01serial", strings.Repeat("x", 65), "SER/1.40"} {
		if code, _, p := e.newOrder(t, client, bad); code != http.StatusBadRequest || p.Type != "urn:ietf:params:acme:error:malformed" {
			t.Errorf("identifier %q: got %d %+v", bad, code, p)
		}
	}
	for _, good := range []string{"C02ABC", "abc-DEF_1", "SER/1.2.3.4", "SER/2.999.1"} {
		if code, _, p := e.newOrder(t, client, good); code != http.StatusCreated {
			t.Errorf("identifier %q: got %d %+v", good, code, p)
		}
	}
	// Mixed and multiple identifiers are refused.
	payload, _ := json.Marshal(map[string]any{"identifiers": []Identifier{{Type: identifierTypePermanent, Value: "A"}, {Type: "dns", Value: "a.example.test"}}})
	resp := client.postJWS(t, e.ts, e.ts.URL+"/acme/new-order", payload)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mixed order: %d", resp.StatusCode)
	}
}

func TestDeviceAttestIdentifierIsOctetExact(t *testing.T) {
	e := newDeviceEnv(t, nil)
	e.allow("c02abc")
	client := newACMEAccount(t, e.ts)
	dev := newDeviceKey(t)
	_, order, _ := e.newOrder(t, client, "c02abc") // lower-case order, upper-case device
	ch := e.challenge(t, order)
	leaf := e.apple.appleLeaf(t, &dev.PublicKey, "C02ABC", "", tokenHash(ch.Token))
	if code, _ := e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der)); code != http.StatusBadRequest {
		t.Fatalf("identifiers are case sensitive, got %d", code)
	}
}

func TestDeviceAttestRemovedFromInventoryBeforeFinalize(t *testing.T) {
	e := newDeviceEnv(t, nil)
	e.allow("SER1")
	client := newACMEAccount(t, e.ts)
	dev := newDeviceKey(t)
	_, order, _ := e.newOrder(t, client, "SER1")
	ch := e.challenge(t, order)
	leaf := e.apple.appleLeaf(t, &dev.PublicKey, "SER1", "", tokenHash(ch.Token))
	e.respond(t, client, ch, appleAttObj(t, leaf, e.apple.der))
	e.mu.Lock()
	delete(e.allowed, "SER1")
	e.mu.Unlock()
	code, prob, _ := finalizeWith(t, e.ts, client, order, csrFor(t, dev, &x509.CertificateRequest{}))
	if code != http.StatusForbidden || prob.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %d %+v", code, prob)
	}
}

func TestParsePermanentIdentifier(t *testing.T) {
	pi, err := parsePermanentIdentifier("SER1/1.2.3")
	if err != nil || pi.Value != "SER1" || !pi.Assigner.Equal(asn1.ObjectIdentifier{1, 2, 3}) {
		t.Fatalf("%+v %v", pi, err)
	}
	if !sameIdentifier(pi, ca.PermanentIdentifier{Value: "SER1", Assigner: asn1.ObjectIdentifier{1, 2, 3}}) ||
		sameIdentifier(pi, ca.PermanentIdentifier{Value: "SER1"}) {
		t.Fatal("assigner is part of identifier equality")
	}
}

// TestTPMGoldenWebAuthnVector decodes the WebAuthn level 3 section 16.13 TPM
// attestation (a real encoder's output, not ours) so a symmetric mistake
// between this file's encoders and the parsers cannot go unnoticed. Its
// extraData is SHA-256(authData || clientDataHash), not an ACME key
// authorization, so the statement is checked below the ACME layer.
func TestTPMGoldenWebAuthnVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/webauthn_tpm_es256.txt")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string][]byte{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			fields[k], _ = hex.DecodeString(v)
		}
	}
	var ao struct {
		Fmt      string `cbor:"fmt"`
		AuthData []byte `cbor:"authData"`
		AttStmt  struct {
			Alg      int64    `cbor:"alg"`
			X5C      [][]byte `cbor:"x5c"`
			Sig      []byte   `cbor:"sig"`
			CertInfo []byte   `cbor:"certInfo"`
			PubArea  []byte   `cbor:"pubArea"`
		} `cbor:"attStmt"`
	}
	if err := cbor.Unmarshal(fields["attestationObject"], &ao); err != nil {
		t.Fatal(err)
	}
	aik, err := x509.ParseCertificate(ao.AttStmt.X5C[0])
	if err != nil {
		t.Fatal(err)
	}
	cdh := sha256.Sum256(fields["clientDataJSON"])
	extra := sha256.Sum256(append(append([]byte(nil), ao.AuthData...), cdh[:]...))
	key, err := verifyTPMStatement(aik.PublicKey, ao.AttStmt.Alg, ao.AttStmt.CertInfo, ao.AttStmt.PubArea, ao.AttStmt.Sig, extra[:])
	if err != nil {
		t.Fatalf("the spec's own vector must verify: %v", err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || hex.EncodeToString(pad32(pub.X)) != "41202698c9d9753fb4bb3f27cd09fe6b8afdb76438ee2ae54d7c9dade10d864b" {
		t.Fatalf("attested key is not the credential key in authData: %v", key)
	}
	// Flipping one bit of extraData, certInfo or the signature must fail.
	bad := append([]byte(nil), extra[:]...)
	bad[0] ^= 1
	if _, err := verifyTPMStatement(aik.PublicKey, ao.AttStmt.Alg, ao.AttStmt.CertInfo, ao.AttStmt.PubArea, ao.AttStmt.Sig, bad); err == nil {
		t.Fatal("wrong extraData verified")
	}
	ci := append([]byte(nil), ao.AttStmt.CertInfo...)
	ci[len(ci)-5] ^= 1
	if _, err := verifyTPMStatement(aik.PublicKey, ao.AttStmt.Alg, ci, ao.AttStmt.PubArea, ao.AttStmt.Sig, extra[:]); err == nil {
		t.Fatal("tampered certInfo verified")
	}
	// The vector's AIK certificate meets 8.3.1 except that it names no device.
	if _, err := checkAIKCertificate(aik); err == nil || !strings.Contains(err.Error(), "permanent identifier") {
		t.Fatalf("golden AIK certificate: %v", err)
	}
}

func TestAuthzAttestationPersists(t *testing.T) {
	s := newTestSQLiteStore(t)
	a := &Authorization{ID: "authz-1", AccountID: "acct", Identifier: Identifier{Type: identifierTypePermanent, Value: "SER1"},
		Status: "valid", Expires: time.Now().UTC().Add(time.Hour), AttestedKeyThumbprint: "thumb", AttestationFormat: "apple"}
	if err := s.SaveAuthz(a); err != nil {
		t.Fatal(err)
	}
	got, ok := s.LoadAuthz("authz-1")
	if !ok || got.AttestedKeyThumbprint != "thumb" || got.AttestationFormat != "apple" {
		t.Fatalf("round trip lost attestation state: %+v", got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "thumb") {
		t.Fatalf("attestation state must not be serialized to clients: %s", b)
	}
	// A second EnsureSchema over an existing table is a no-op (upgrade path).
	if err := s.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
}
