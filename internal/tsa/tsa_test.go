// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // needed to build an unsupported-hash request
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

var fixedNow = time.Date(2026, 10, 16, 12, 30, 45, 123456789, time.UTC)

// openssl verifies against the wall clock unless told otherwise; the fixture
// certificates are valid around fixedNow only, so every ts -verify pins
// -attime to it (otherwise the suite fails from 2026-10-17 12:30Z onward).
var fixedNowUnix = strconv.FormatInt(fixedNow.Unix(), 10)

type testPKI struct {
	root    *x509.Certificate
	rootPEM []byte
	tsaCert *x509.Certificate
	tsaKey  *ecdsa.PrivateKey
}

func ekuExt(t *testing.T, critical bool, oids ...asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(oids)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: critical, Value: der}
}

var (
	oidTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidCodeSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
)

func newCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTSACert(t *testing.T, p *testPKI, rootKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey, mut func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(42),
		Subject:         pkix.Name{CommonName: "Test TSA"},
		NotBefore:       fixedNow.Add(-time.Hour),
		NotAfter:        fixedNow.Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{ekuExt(t, true, oidTimeStamping)},
	}
	if mut != nil {
		mut(tmpl)
	}
	return newCert(t, tmpl, p.root, &key.PublicKey, rootKey)
}

func newPKI(t *testing.T) (*testPKI, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             fixedNow.Add(-24 * time.Hour),
		NotAfter:              fixedNow.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	root := newCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	p := &testPKI{root: root, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})}
	p.tsaKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.tsaCert = newTSACert(t, p, rootKey, p.tsaKey, nil)
	return p, rootKey
}

func (p *testPKI) authority(t *testing.T, mut func(*Config)) *Authority {
	t.Helper()
	cfg := Config{Signer: p.tsaKey, Cert: p.tsaCert, Chain: []*x509.Certificate{p.root}, Now: func() time.Time { return fixedNow }}
	if mut != nil {
		mut(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func requireOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("KRYPTKEEPER_REQUIRE_OPENSSL") == "1" {
			t.Fatal("openssl required (KRYPTKEEPER_REQUIRE_OPENSSL=1) but not on PATH")
		}
		t.Skip("openssl not on PATH")
	}
	return path
}

func runOpenSSL(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(requireOpenSSL(t), args...).CombinedOutput() //nolint:gosec // test-controlled args
	return string(out), err
}

func goRequest(t *testing.T, oid asn1.ObjectIdentifier, digest []byte, mut func(*timeStampReq)) []byte {
	t.Helper()
	r := timeStampReq{Version: 1, MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}, HashedMessage: digest}}
	if mut != nil {
		mut(&r)
	}
	der, err := asn1.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func sha256Req(t *testing.T, data string, mut func(*timeStampReq)) []byte {
	d := sha256.Sum256([]byte(data))
	return goRequest(t, oidSHA256, d[:], mut)
}

func decodeResp(t *testing.T, der []byte) timeStampResp {
	t.Helper()
	var r timeStampResp
	if rest, err := asn1.Unmarshal(der, &r); err != nil || len(rest) != 0 {
		t.Fatalf("decode resp: %v", err)
	}
	return r
}

func failBit(r timeStampResp, bit int) bool {
	return r.Status.FailInfo.At(bit) == 1
}

func tstFromToken(t *testing.T, token []byte) tstInfo {
	t.Helper()
	p7, err := pkcs7.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	var info tstInfo
	if _, err := asn1.Unmarshal(p7.Content, &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestRespond_GrantedVerifiesWithOpenSSL(t *testing.T) {
	requireOpenSSL(t)
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	dir := t.TempDir()
	data := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(data, []byte("hello timestamp"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(dir, "q.tsq")
	if out, err := runOpenSSL(t, "ts", "-query", "-data", data, "-sha256", "-cert", "-out", q); err != nil {
		t.Fatalf("ts -query: %v %s", err, out)
	}
	reqDER, _ := os.ReadFile(q)
	respDER, g, err := a.Respond(reqDER)
	if err != nil || g == nil {
		t.Fatalf("Respond: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "r.tsr"), respDER, 0o600)
	os.WriteFile(filepath.Join(dir, "root.pem"), p.rootPEM, 0o600)
	// chain embedded because the query set certReq
	if out, err := runOpenSSL(t, "ts", "-verify", "-attime", fixedNowUnix, "-data", data, "-in", filepath.Join(dir, "r.tsr"), "-CAfile", filepath.Join(dir, "root.pem")); err != nil {
		t.Fatalf("ts -verify: %v %s", err, out)
	}
	if out, err := runOpenSSL(t, "ts", "-reply", "-in", filepath.Join(dir, "r.tsr"), "-text"); err != nil || !strings.Contains(out, "Status: Granted") {
		t.Fatalf("reply text: %v %s", err, out)
	}
}

func TestRespond_TokenOnlyVerifies(t *testing.T) {
	requireOpenSSL(t)
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	dir := t.TempDir()
	data := filepath.Join(dir, "f.bin")
	os.WriteFile(data, []byte("token only"), 0o600)
	d := sha256.Sum256([]byte("token only"))
	respDER, _, err := a.Respond(goRequest(t, oidSHA256, d[:], func(r *timeStampReq) { r.CertReq = true }))
	if err != nil {
		t.Fatal(err)
	}
	tok := decodeResp(t, respDER).TimeStampToken.FullBytes
	os.WriteFile(filepath.Join(dir, "t.tst"), tok, 0o600)
	os.WriteFile(filepath.Join(dir, "root.pem"), p.rootPEM, 0o600)
	if out, err := runOpenSSL(t, "ts", "-verify", "-attime", fixedNowUnix, "-data", data, "-in", filepath.Join(dir, "t.tst"), "-token_in", "-CAfile", filepath.Join(dir, "root.pem")); err != nil {
		t.Fatalf("ts -verify -token_in: %v %s", err, out)
	}
}

func TestRespond_TamperedFileFailsOpenSSL(t *testing.T) {
	requireOpenSSL(t)
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	dir := t.TempDir()
	d := sha256.Sum256([]byte("original"))
	respDER, _, err := a.Respond(goRequest(t, oidSHA256, d[:], func(r *timeStampReq) { r.CertReq = true }))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.bin")
	os.WriteFile(other, []byte("tampered"), 0o600)
	os.WriteFile(filepath.Join(dir, "r.tsr"), respDER, 0o600)
	os.WriteFile(filepath.Join(dir, "root.pem"), p.rootPEM, 0o600)
	if out, err := runOpenSSL(t, "ts", "-verify", "-attime", fixedNowUnix, "-data", other, "-in", filepath.Join(dir, "r.tsr"), "-CAfile", filepath.Join(dir, "root.pem")); err == nil {
		t.Fatalf("verify of a different file must fail: %s", out)
	}
}

func TestRespond_CertReqEmbedsChain(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	certCount := func(certReq bool) int {
		der, _, err := a.Respond(sha256Req(t, "x", func(r *timeStampReq) { r.CertReq = certReq }))
		if err != nil {
			t.Fatal(err)
		}
		p7, err := pkcs7.Parse(decodeResp(t, der).TimeStampToken.FullBytes)
		if err != nil {
			t.Fatal(err)
		}
		return len(p7.Certificates)
	}
	if n := certCount(true); n != 2 {
		t.Fatalf("certReq: want TSA cert + root, got %d", n)
	}
	if n := certCount(false); n != 1 {
		t.Fatalf("no certReq: want TSA cert only, got %d", n)
	}
}

func TestRespond_NonceEchoed(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	nonce := new(big.Int).Lsh(big.NewInt(0xdeadbeef), 70)
	der, g, err := a.Respond(sha256Req(t, "n", func(r *timeStampReq) { r.Nonce = nonce }))
	if err != nil {
		t.Fatal(err)
	}
	info := tstFromToken(t, decodeResp(t, der).TimeStampToken.FullBytes)
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 || g.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce not echoed: %v", info.Nonce)
	}
	der, _, err = a.Respond(sha256Req(t, "n", nil))
	if err != nil {
		t.Fatal(err)
	}
	if info := tstFromToken(t, decodeResp(t, der).TimeStampToken.FullBytes); info.Nonce != nil {
		t.Fatalf("nonce must be absent, got %v", info.Nonce)
	}
}

func TestRespond_InjectedClock(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	der, g, err := a.Respond(sha256Req(t, "c", nil))
	if err != nil {
		t.Fatal(err)
	}
	want := fixedNow.Truncate(time.Second)
	info := tstFromToken(t, decodeResp(t, der).TimeStampToken.FullBytes)
	if !info.GenTime.Equal(want) || !g.GenTime.Equal(want) {
		t.Fatalf("genTime %v / %v, want %v", info.GenTime, g.GenTime, want)
	}
}

func TestRespond_SerialsUnique(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	req := sha256Req(t, "s", nil)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		_, g, err := a.Respond(req)
		if err != nil {
			t.Fatal(err)
		}
		if g.Serial.Sign() <= 0 || seen[g.Serial.String()] {
			t.Fatalf("serial %v not positive/unique at %d", g.Serial, i)
		}
		seen[g.Serial.String()] = true
	}
}

func TestRespond_UnsupportedHashRefused(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	d := sha1.Sum([]byte("x")) //nolint:gosec // deliberately unsupported
	der, g, err := a.Respond(goRequest(t, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, d[:], nil))
	var re *RejectError
	if !errors.Is(err, ErrUnsupportedHash) || !errors.As(err, &re) || g != nil {
		t.Fatalf("err = %v", err)
	}
	r := decodeResp(t, der)
	if r.Status.Status != 2 || !failBit(r, FailBadAlg) || len(r.TimeStampToken.FullBytes) != 0 {
		t.Fatalf("resp = %+v", r)
	}
}

func TestRespond_BadDigestLength(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	der, _, err := a.Respond(goRequest(t, oidSHA256, make([]byte, 20), nil))
	var re *RejectError
	if !errors.As(err, &re) || re.FailInfo != FailBadDataFormat {
		t.Fatalf("err = %v", err)
	}
	if r := decodeResp(t, der); r.Status.Status != 2 || !failBit(r, FailBadDataFormat) {
		t.Fatalf("resp = %+v", r)
	}
}

func TestRespond_GarbageDER(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, nil)
	for _, in := range [][]byte{nil, []byte("not der"), {0x30, 0x03, 0x02, 0x01, 0x01}} {
		der, g, err := a.Respond(in)
		var re *RejectError
		if !errors.As(err, &re) || re.FailInfo != FailBadDataFormat || g != nil {
			t.Fatalf("input %x: err = %v", in, err)
		}
		if r := decodeResp(t, der); r.Status.Status != 2 || !failBit(r, FailBadDataFormat) {
			t.Fatalf("resp = %+v", r)
		}
	}
}

func TestRespond_BadVersionPolicyAndCriticalExt(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, func(c *Config) { c.PolicyOID = asn1.ObjectIdentifier{1, 2, 3, 4} })
	cases := []struct {
		name string
		mut  func(*timeStampReq)
		bit  int
	}{
		{"version2", func(r *timeStampReq) { r.Version = 2 }, FailBadDataFormat},
		{"policy", func(r *timeStampReq) { r.ReqPolicy = asn1.ObjectIdentifier{1, 2, 3, 5} }, FailBadRequest},
		{"critical ext", func(r *timeStampReq) {
			r.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 9}, Critical: true, Value: []byte{5, 0}}}
		}, FailBadRequest},
	}
	for _, c := range cases {
		der, _, err := a.Respond(sha256Req(t, "x", c.mut))
		var re *RejectError
		if !errors.As(err, &re) || re.FailInfo != c.bit {
			t.Fatalf("%s: err = %v", c.name, err)
		}
		if r := decodeResp(t, der); !failBit(r, c.bit) {
			t.Fatalf("%s: failInfo bit missing", c.name)
		}
	}
	// matching policy is granted
	if _, _, err := a.Respond(sha256Req(t, "x", func(r *timeStampReq) { r.ReqPolicy = asn1.ObjectIdentifier{1, 2, 3, 4} })); err != nil {
		t.Fatal(err)
	}
}

func TestRespond_SignerFailureIsSystemFailure(t *testing.T) {
	p, _ := newPKI(t)
	a := p.authority(t, func(c *Config) { c.Serial = func() (*big.Int, error) { return nil, errors.New("boom") } })
	der, g, err := a.Respond(sha256Req(t, "x", nil))
	var re *RejectError
	if err == nil || errors.As(err, &re) || g != nil {
		t.Fatalf("err = %v", err)
	}
	if r := decodeResp(t, der); r.Status.Status != 2 || !failBit(r, FailSystemFailure) {
		t.Fatalf("resp = %+v", r)
	}
}

func TestNew_RejectsBadCert(t *testing.T) {
	p, rootKey := newPKI(t)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := []struct {
		name   string
		cert   *x509.Certificate
		signer crypto.Signer
	}{
		{"non-critical EKU", newTSACert(t, p, rootKey, p.tsaKey, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{ekuExt(t, false, oidTimeStamping)}
		}), p.tsaKey},
		{"also codeSigning", newTSACert(t, p, rootKey, p.tsaKey, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{ekuExt(t, true, oidTimeStamping, oidCodeSigning)}
		}), p.tsaKey},
		{"no EKU", newTSACert(t, p, rootKey, p.tsaKey, func(c *x509.Certificate) { c.ExtraExtensions = nil }), p.tsaKey},
		{"expired", newTSACert(t, p, rootKey, p.tsaKey, func(c *x509.Certificate) { c.NotAfter = fixedNow.Add(-time.Minute) }), p.tsaKey},
		{"key mismatch", p.tsaCert, otherKey},
	}
	for _, c := range cases {
		if _, err := New(Config{Signer: c.signer, Cert: c.cert, Now: func() time.Time { return fixedNow }}); err == nil {
			t.Errorf("%s: New accepted a bad cert", c.name)
		}
	}
	if _, err := New(Config{}); err == nil {
		t.Error("empty config accepted")
	}
}
