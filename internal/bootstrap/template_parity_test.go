// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"golang.org/x/crypto/bcrypt"

	kkacme "kryptkeeper/internal/acme"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/cmp"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/est"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/scep"
	"kryptkeeper/internal/wstep"
)

// W26-25 (UC-B10, FR-P8): the same CSR, submitted through all six issuance
// paths, must get the same accept/deny verdict. Every cell of the matrix is
// driven over the path's own wire format against ONE shared CA, ONE
// issuance-policy table and ONE template, so a difference between two
// columns is a real difference in what the path enforces, not in fixtures.
//
// Where the code does not (yet) agree, the divergence is recorded in
// parityKnownDivergence with the failing path and the missing control, and
// the test insists the divergence is still real: when a path starts agreeing
// the entry must be deleted. compliant and weak_key may never diverge.

// --- shapes -----------------------------------------------------------------

type parityVerdict struct {
	Accepted bool
	Detail   string // status / fault text; logged and sanity-checked only
}

type parityCSR struct {
	Name string
	DER  []byte        // plain PKCS#10, signed by Key
	Key  crypto.Signer // the key under test (distinct from any transport key)
	DNS  string
	EKU  bool // the CSR asks for codeSigning in its extensionRequest
}

type parityPath struct {
	Name  string
	Issue func(t *testing.T, c parityCSR) parityVerdict
}

type parityCase struct {
	Name string
	DNS  string
	RSA  bool
	EKU  bool
	Want bool // expected verdict: true = accept
}

const (
	parityGoodDNS = "ok.corp.example"
	parityBadDNS  = "evil.other.example"
	parityTplID   = "parity-tpl"
)

var parityCases = []parityCase{
	{Name: "compliant", DNS: parityGoodDNS, Want: true},
	{Name: "weak_key", DNS: parityGoodDNS, RSA: true, Want: false},
	{Name: "wrong_eku", DNS: parityGoodDNS, EKU: true, Want: false},
	{Name: "bad_san", DNS: parityBadDNS, Want: false},
}

var parityPathNames = []string{"api", "acme", "est", "scep", "cmp", "wstep"}

// parityKnownDivergence: case -> path -> "why / follow-up". An entry says the
// path's verdict differs from the case's Want TODAY. Never for compliant or
// weak_key (those are bugs to fix, not to document).
//
// wrong_eku: no path reads the EKU a CSR asks for. The certificate's EKU is
// fixed by the path (API: the template's list; EST/SCEP/CMP/WSTEP: clientAuth;
// ACME: serverAuth), so a CSR asking for codeSigning is not refused anywhere,
// but it never gets codeSigning either. TestTemplatePolicyParity asserts that
// invariant on every accepted certificate. Whether to also REFUSE such a CSR
// is a product decision (W26-F1).
//
// bad_san: API and WSTEP refuse through the template name policy; ACME
// (provisioner allow_names), EST (user suffixes) and CMP (server suffixes)
// refuse through their own, separately configured, suffix list. SCEP takes its
// names from the admin-minted challenge and has no suffix control at all, so a
// minted challenge for an out-of-policy name is honoured (W26-F2). None of the
// four protocol bindings reads the template's name_policy, they merely have to
// be configured to match it.
var parityKnownDivergence = map[string]map[string]string{
	"wrong_eku": {
		"api":   "api: CSR extensionRequest EKU is ignored, the template EKU list is stamped instead; no refusal. follow-up W26-F1",
		"acme":  "acme: CSR extensionRequest EKU is ignored, serverAuth is stamped; no template EKU hook. follow-up W26-F1",
		"est":   "est: CSR extensionRequest EKU is ignored, clientAuth is stamped; no template EKU hook. follow-up W26-F1",
		"scep":  "scep: CSR extensionRequest EKU is ignored, clientAuth is stamped; no template EKU hook. follow-up W26-F1",
		"cmp":   "cmp: CertTemplate EKU is ignored, clientAuth is stamped; no template EKU hook. follow-up W26-F1",
		"wstep": "wstep: CSR extensionRequest EKU is ignored, clientAuth is stamped (checked against the template list). follow-up W26-F1",
	},
	"bad_san": {
		"scep": "scep: names come from the admin-minted challenge, not the CSR; no template name policy or suffix list at enrol. follow-up W26-F2",
	},
}

// --- shared environment -----------------------------------------------------

type parityEnv struct {
	db       *sql.DB
	engine   *ca.Engine
	caID     string
	provider CertificateProvider
	caObj    *ca.CA
	keys     keystore.Store
	tpl      TemplateItem
	strict   bool
}

func parityTemplate() TemplateItem {
	return TemplateItem{
		ID:                parityTplID,
		Name:              parityTplID,
		Active:            true,
		AllowedAlgorithms: []string{"ECDSA-P256", "RSA-3072"},
		MinKeySize:        3072,
		// Both: the API stamps this list; WSTEP issues clientAuth and EST,
		// SCEP and CMP likewise, so a serverAuth-only template would refuse
		// even the compliant WSTEP request (see the report on W26-25).
		ExtendedKeyUsage: []string{"serverAuth", "clientAuth"},
		NamePolicy:       &ca.NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}},
		ValidityPeriod:   "720h",
	}
}

func newParityEnv(t *testing.T, strict bool) *parityEnv {
	t.Helper()
	db := setupIntegrationDB(t)
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("parity-passphrase-32bytes-long!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, false))
	// SCEP's PKIOperation envelope needs an RSA recipient key, so the one CA
	// is RSA; every other path is indifferent to the CA key type.
	root, err := engine.CreateRootCA("Parity Root", pkix.Name{CommonName: "Parity Root CA"}, keystore.RSA2048, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root CA: %v", err)
	}
	caObj, err := engine.GetCA(root.ID)
	if err != nil {
		t.Fatalf("get CA: %v", err)
	}
	env := &parityEnv{db: db, engine: engine, caID: root.ID, caObj: caObj, keys: keys, strict: strict, tpl: parityTemplate()}
	if strict {
		pe, err := ca.NewPolicyEngine(db, false)
		if err != nil {
			t.Fatalf("policy engine: %v", err)
		}
		if _, err := pe.UpsertPolicy(ca.IssuancePolicy{
			ID: "parity-engine-policy", Name: "parity-engine-policy", Enabled: true,
			Rules: ca.PolicyRules{AllowedAlgorithms: []string{"ECDSA-P256", "RSA-3072"}, MinRSABits: 3072},
		}); err != nil {
			t.Fatalf("upsert policy: %v", err)
		}
		engine.SetPolicyEngine(pe)
	}
	provider := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, false), db, false)
	if strict {
		provider = WithTemplateProvider(provider, &integrationMemTemplateProvider{templates: map[string]TemplateItem{parityTplID: env.tpl}})
	}
	env.provider = provider
	return env
}

// --- CSR construction -------------------------------------------------------

var parityOIDExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
var parityOIDCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}

func parityKey(t *testing.T, useRSA bool) crypto.Signer {
	t.Helper()
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	return k
}

func parityCSRTemplate(t *testing.T, dns string, eku bool) *x509.CertificateRequest {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}}
	if eku {
		val, err := asn1.Marshal([]asn1.ObjectIdentifier{parityOIDCodeSigning})
		if err != nil {
			t.Fatalf("marshal EKU: %v", err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: parityOIDExtKeyUsage, Value: val}}
	}
	return tmpl
}

func (c parityCase) build(t *testing.T) parityCSR {
	t.Helper()
	key := parityKey(t, c.RSA)
	der, err := x509.CreateCertificateRequest(rand.Reader, parityCSRTemplate(t, c.DNS, c.EKU), key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return parityCSR{Name: c.Name, DER: der, Key: key, DNS: c.DNS, EKU: c.EKU}
}

func (c parityCSR) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: c.DER}))
}

// --- verdict sanity: no accepted certificate may carry the wrong EKU ---------

func parityNoCodeSigning(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	if cert == nil {
		return
	}
	for _, e := range cert.ExtKeyUsage {
		if e == x509.ExtKeyUsageCodeSigning {
			t.Errorf("%s issued a certificate carrying codeSigning EKU", path)
		}
	}
}

// --- drivers ----------------------------------------------------------------

func (e *parityEnv) paths(t *testing.T) []parityPath {
	t.Helper()
	return []parityPath{
		{"api", e.issueAPI},
		{"acme", e.newACMEDriver(t)},
		{"est", e.newESTDriver(t)},
		{"scep", e.newSCEPDriver(t)},
		{"cmp", e.newCMPDriver(t)},
		{"wstep", e.newWSTEPDriver(t)},
	}
}

// API: caCertificateProvider.IssueCertificate with the template named, which
// is what POST /api/v1/certificates calls; an error is a deny (4xx), a
// returned item is the 201.
func (e *parityEnv) issueAPI(t *testing.T, c parityCSR) parityVerdict {
	t.Helper()
	req := CertificateIssueRequest{CAID: e.caID, CSRPEM: c.pem(), TeamID: "team-parity"}
	if e.strict {
		req.TemplateID = parityTplID
	}
	res, err := e.provider.IssueCertificate(context.Background(), req)
	if err != nil {
		return parityVerdict{Detail: err.Error()}
	}
	item, ok, err := e.provider.GetCertificate(context.Background(), res.CertificateItem.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("api: issued certificate not readable back: ok=%v err=%v", ok, err)
	}
	for _, eku := range item.ExtendedKeyUsage {
		if strings.Contains(strings.ToLower(eku), "codesign") {
			t.Errorf("api issued a certificate carrying the %q EKU", eku)
		}
	}
	return parityVerdict{Accepted: true, Detail: "201"}
}

// ACME: the connector (an RFC 8555 client) drives the in-repo ACME server's
// directory, order, http-01, finalize and download. The server's http-01
// dial seam routes EVERY test host to the connector's solver, so identifier
// proof succeeds for any name and the only thing left to refuse a CSR is the
// server's own finalize policy.
func (e *parityEnv) newACMEDriver(t *testing.T) func(*testing.T, parityCSR) parityVerdict {
	solverPort := freeLocalPort(t)
	solverAddr := fmt.Sprintf("127.0.0.1:%d", solverPort)
	ts := httptest.NewServer(nil)
	srv := kkacme.NewServerWithStore(ts.URL, e.engine, e.caID, kkacme.NewMemStore(), ca.NewMemRevocationStore())
	// W26-02: the provisioner is ACME's own name control. It is bound to the
	// same suffix and template as every other path (the enrollment gate stays
	// unset, role gating is not this test's concern).
	provisioners := kkacme.NewMemProvisionerStore()
	if err := provisioners.Create(context.Background(), kkacme.Provisioner{
		Name: "parity", CAID: e.caID, TemplateID: parityTplID,
		AllowNames: []string{"*.corp.example"}, Challenges: []string{"http-01"},
	}); err != nil {
		t.Fatalf("create provisioner: %v", err)
	}
	srv.WithProvisioners(provisioners, nil)
	srv.SetHTTP01DialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || !strings.HasSuffix(host, ".example") {
			return nil, fmt.Errorf("parity dial seam: %q is not routed", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, solverAddr)
	})
	ts.Config.Handler = srv.Handler()
	t.Cleanup(ts.Close)
	return func(t *testing.T, c parityCSR) parityVerdict {
		t.Helper()
		cfg, _ := json.Marshal(acmeConnectorConfig{
			DirectoryURL: ts.URL + "/acme/parity/directory",
			Email:        "ops@example.com",
			HTTP01Listen: solverAddr,
		})
		conn := NewACMEIssuerConnector(ConnectorRecord{ID: "conn-parity", Name: "Parity", Type: "acme", ConfigJSON: string(cfg)}, nil, nil)
		conn.(*acmeIssuerConnector).allowLoopbackForTest = true
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		res, err := conn.Issue(ctx, connectors.IssueRequest{CSRPEM: c.pem()})
		if err != nil {
			return parityVerdict{Detail: err.Error()}
		}
		if block, _ := pem.Decode([]byte(res.CertificatePEM)); block != nil {
			if cert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				parityNoCodeSigning(t, "acme", cert)
			}
		}
		return parityVerdict{Accepted: true, Detail: "finalize ok"}
	}
}

// EST: simpleenroll over TLS with an HTTP Basic user bound to the template's
// suffix.
func (e *parityEnv) newESTDriver(t *testing.T) func(*testing.T, parityCSR) parityVerdict {
	hash, err := bcrypt.GenerateFromPassword([]byte("parity-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv := est.NewServer(e.engine, e.caID)
	if err := srv.WithBasicUsers([]est.User{{Username: "parity", BcryptHash: string(hash), AllowedDNSSuffixes: []string{".corp.example"}}}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	return func(t *testing.T, c parityCSR) parityVerdict {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/est/simpleenroll", strings.NewReader(base64.StdEncoding.EncodeToString(c.DER)))
		req.Header.Set("Content-Type", "application/pkcs10")
		req.SetBasicAuth("parity", "parity-pass")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("est post: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return parityVerdict{Detail: fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(body)))}
		}
		if der, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body))); derr == nil {
			if p7, perr := pkcs7.Parse(der); perr == nil && len(p7.Certificates) == 1 {
				parityNoCodeSigning(t, "est", p7.Certificates[0])
			}
		}
		return parityVerdict{Accepted: true, Detail: "200"}
	}
}

// SCEP: PKIOperation (PKCSReq) signed by a throwaway RSA transport identity;
// the CSR key under test is separate. The challenge is minted for the CSR's
// name, as an administrator approving that name would.
func (e *parityEnv) newSCEPDriver(t *testing.T) func(*testing.T, parityCSR) parityVerdict {
	challenges := scep.NewDBChallengeStore(e.db, false)
	srv := scep.NewServer(e.engine, e.caID, challenges).WithDecrypter(func() (crypto.Decrypter, error) {
		signer, err := e.keys.Signer(e.caObj.KeyID)
		if err != nil {
			return nil, err
		}
		dec, ok := signer.(crypto.Decrypter)
		if !ok {
			return nil, fmt.Errorf("CA key is not a crypto.Decrypter")
		}
		return dec, nil
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return func(t *testing.T, c parityCSR) parityVerdict {
		t.Helper()
		now := time.Now().UTC()
		_, secret, err := challenges.Create(context.Background(), scep.Challenge{
			CAID: e.caID, CommonName: c.DNS, DNSNames: []string{c.DNS}, CreatedBy: "parity",
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("mint challenge: %v", err)
		}
		transport, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		transportCert := paritySelfSigned(t, transport, c.DNS)
		csrDER := parityCSRWithChallenge(t, c, secret)
		msg := parityPKIOperation(t, e.caObj.Certificate, transport, transportCert, csrDER)
		resp, err := http.Post(ts.URL+"?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(msg))
		if err != nil {
			t.Fatalf("scep post: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return parityVerdict{Detail: fmt.Sprintf("http %d", resp.StatusCode)}
		}
		p7, err := pkcs7.Parse(body)
		if err != nil {
			t.Fatalf("parse CertRep: %v", err)
		}
		if err := p7.Verify(); err != nil {
			t.Fatalf("CertRep signature: %v", err)
		}
		var status asn1.RawValue
		if err := p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}, &status); err != nil {
			t.Fatalf("missing pkiStatus: %v", err)
		}
		if string(status.Bytes) != "0" { // pkiStatus SUCCESS = 0
			var fail asn1.RawValue
			_ = p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}, &fail)
			return parityVerdict{Detail: fmt.Sprintf("pkiStatus=%s failInfo=%s", status.Bytes, fail.Bytes)}
		}
		if envelope, err := pkcs7.Parse(p7.Content); err == nil {
			if degenerate, err := envelope.Decrypt(transportCert, transport); err == nil {
				if certsOnly, err := pkcs7.Parse(degenerate); err == nil && len(certsOnly.Certificates) == 1 {
					parityNoCodeSigning(t, "scep", certsOnly.Certificates[0])
				}
			}
		}
		return parityVerdict{Accepted: true, Detail: "CertRep SUCCESS"}
	}
}

func paritySelfSigned(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// SCEP wire OIDs (RFC 8894 / Verisign pkiMessage attributes), copied because
// the scep package keeps them unexported.
var (
	parityOIDChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	parityOIDMessageType       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	parityOIDTransactionID     = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	parityOIDSenderNonce       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
)

type parityCSROuter struct {
	TBSCSR             asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type parityTBSAttrs struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type parityPKCS10Attr struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// parityCSRWithChallenge splices a PKCS#9 challengePassword into the case's
// CSR and re-signs it with the key under test (see scep/server_test.go
// buildCSRWithChallenge for why x509 cannot do this itself).
func parityCSRWithChallenge(t *testing.T, c parityCSR, challenge string) []byte {
	t.Helper()
	var outer parityCSROuter
	if _, err := asn1.Unmarshal(c.DER, &outer); err != nil {
		t.Fatalf("unmarshal CSR: %v", err)
	}
	var tbs parityTBSAttrs
	if _, err := asn1.Unmarshal(outer.TBSCSR.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshal TBS: %v", err)
	}
	tbs.Raw = nil
	attr, err := asn1.Marshal(parityPKCS10Attr{
		Type:   parityOIDChallengePassword,
		Values: []asn1.RawValue{{Class: 0, Tag: 19, Bytes: []byte(challenge)}},
	})
	if err != nil {
		t.Fatalf("marshal attribute: %v", err)
	}
	tbs.RawAttributes = append(tbs.RawAttributes, asn1.RawValue{FullBytes: attr})
	newTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal TBS: %v", err)
	}
	digest := sha256.Sum256(newTBS)
	sig, err := c.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign TBS: %v", err)
	}
	final, err := asn1.Marshal(parityCSROuter{
		TBSCSR:             asn1.RawValue{FullBytes: newTBS},
		SignatureAlgorithm: outer.SignatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("marshal CSR: %v", err)
	}
	parsed, err := x509.ParseCertificateRequest(final)
	if err != nil {
		t.Fatalf("parse spliced CSR: %v", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("spliced CSR signature: %v", err)
	}
	return final
}

func parityPKIOperation(t *testing.T, caCert *x509.Certificate, key *rsa.PrivateKey, cert *x509.Certificate, csrDER []byte) []byte {
	t.Helper()
	envelope, err := pkcs7.Encrypt(csrDER, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("encrypt CSR: %v", err)
	}
	sd, err := pkcs7.NewSignedData(envelope)
	if err != nil {
		t.Fatalf("signed data: %v", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	extra := []pkcs7.Attribute{
		{Type: parityOIDMessageType, Value: asn1.RawValue{Tag: 19, Bytes: []byte("19")}}, // PKCSReq
		{Type: parityOIDTransactionID, Value: asn1.RawValue{Tag: 19, Bytes: []byte("parity-txn-" + cert.SerialNumber.String())}},
		{Type: parityOIDSenderNonce, Value: asn1.RawValue{Tag: 4, Bytes: nonce}},
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: extra}); err != nil {
		t.Fatalf("sign pkiMessage: %v", err)
	}
	msg, err := sd.Finish()
	if err != nil {
		t.Fatalf("finish pkiMessage: %v", err)
	}
	return msg
}

// CMP: ir over PBM-protected CRMF with a POPO signed by the key under test.
// The server is bound to the template's suffix, as KRYPTKEEPER_CMP_* does.
func (e *parityEnv) newCMPDriver(t *testing.T) func(*testing.T, parityCSR) parityVerdict {
	srv := cmp.NewServer(e.engine, e.caID, "parity-secret", "parity-ref").WithAllowedDNSSuffixes([]string{".corp.example"})
	h := srv.Handler()
	return func(t *testing.T, c parityCSR) parityVerdict {
		t.Helper()
		pub := c.Key.Public()
		var algOID asn1.ObjectIdentifier
		var sign func([]byte) ([]byte, error)
		switch k := c.Key.(type) {
		case *ecdsa.PrivateKey:
			algOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
			sign = func(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, k, d) }
		case *rsa.PrivateKey:
			algOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
			sign = func(d []byte) ([]byte, error) { return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d) }
		default:
			t.Fatalf("unsupported key %T", c.Key)
		}
		body := parityCRMFBody(t, pub, algOID, sign, c.DNS, c.EKU)
		msg := parityProtectedPKIMessage(t, 0 /* ir */, body)
		req := httptest.NewRequest(http.MethodPost, "/cmp", bytes.NewReader(msg))
		req.Header.Set("Content-Type", "application/pkixcmp")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		var resp struct {
			Header asn1.RawValue
			Body   asn1.RawValue
		}
		if _, err := asn1.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			return parityVerdict{Detail: fmt.Sprintf("http %d, unparseable PKIMessage: %v", rr.Code, err)}
		}
		switch resp.Body.Tag {
		case 1: // ip
			return parityVerdict{Accepted: true, Detail: "ip"}
		case 23: // error
			return parityVerdict{Detail: "PKIBody error"}
		}
		t.Fatalf("cmp answered body tag %d, want ip(1) or error(23)", resp.Body.Tag)
		return parityVerdict{}
	}
}

var (
	parityOIDPBM      = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	parityOIDSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	parityOIDHMACSHA2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	parityOIDSAN      = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type parityPBMParameter struct {
	Salt           []byte
	Owf            pkix.AlgorithmIdentifier
	IterationCount int
	Mac            pkix.AlgorithmIdentifier
}

type parityPOPOSigningKey struct {
	PoposkInput asn1.RawValue `asn1:"optional,tag:0"`
	AlgID       pkix.AlgorithmIdentifier
	Signature   asn1.BitString
}

func parityRetag(t *testing.T, tag int, der []byte, compound bool) asn1.RawValue {
	t.Helper()
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		t.Fatalf("retag: %v", err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: compound, Bytes: raw.Bytes}
}

func parityMust(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1 marshal: %v", err)
	}
	return b
}

func parityConstructed(t *testing.T, content []byte) []byte {
	t.Helper()
	return parityMust(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

// parityCRMFBody builds CertReqMessages (one CertReqMsg: subject, publicKey,
// dNSName SAN and, when eku is set, an extendedKeyUsage codeSigning request)
// with a POPOSigningKey over the CertRequest, per cmp/cmp_test.go
// buildCRMFBodySANs.
func parityCRMFBody(t *testing.T, pub crypto.PublicKey, algOID asn1.ObjectIdentifier, sign func([]byte) ([]byte, error), dns string, eku bool) []byte {
	t.Helper()
	subjectDER := parityMust(t, pkix.Name{CommonName: dns}.ToRDNSequence())
	subjectField := parityMust(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 5, IsCompound: true, Bytes: subjectDER})
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubField := parityMust(t, parityRetag(t, 6, pubDER, true))

	gn := parityMust(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(dns)})
	names := parityConstructed(t, gn)
	exts := []pkix.Extension{{Id: parityOIDSAN, Value: names}}
	if eku {
		exts = append(exts, pkix.Extension{Id: parityOIDExtKeyUsage, Value: parityMust(t, []asn1.ObjectIdentifier{parityOIDCodeSigning})})
	}
	extField := parityMust(t, parityRetag(t, 9, parityMust(t, exts), true))

	fields := append(append(append([]byte{}, subjectField...), pubField...), extField...)
	certTemplate := parityConstructed(t, fields)
	certReq := parityConstructed(t, append(parityMust(t, 0), certTemplate...))

	digest := sha256.Sum256(certReq)
	sig, err := sign(digest[:])
	if err != nil {
		t.Fatalf("sign POPO: %v", err)
	}
	pskDER := parityMust(t, parityPOPOSigningKey{
		AlgID:     pkix.AlgorithmIdentifier{Algorithm: algOID},
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	popoField := parityMust(t, parityRetag(t, 1, pskDER, true))
	certReqMsg := parityConstructed(t, append(append([]byte{}, certReq...), popoField...))
	return parityConstructed(t, certReqMsg)
}

func parityProtectedPKIMessage(t *testing.T, bodyType int, bodyContent []byte) []byte {
	t.Helper()
	emptySeq := parityMust(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true})
	emptyDN := parityMust(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: emptySeq})

	var hdr []byte
	hdr = append(hdr, parityMust(t, 2)...) // pvno
	hdr = append(hdr, emptyDN...)          // sender
	hdr = append(hdr, emptyDN...)          // recipient

	param := parityPBMParameter{
		Salt:           []byte("parity-salt-16by"),
		Owf:            pkix.AlgorithmIdentifier{Algorithm: parityOIDSHA256},
		IterationCount: 100,
		Mac:            pkix.AlgorithmIdentifier{Algorithm: parityOIDHMACSHA2},
	}
	paramDER := parityMust(t, param)
	protAlg := pkix.AlgorithmIdentifier{Algorithm: parityOIDPBM, Parameters: asn1.RawValue{FullBytes: paramDER}}
	protAlgDER, err := asn1.MarshalWithParams(protAlg, "explicit,tag:1")
	if err != nil {
		t.Fatalf("protectionAlg: %v", err)
	}
	hdr = append(hdr, protAlgDER...)
	kid, _ := asn1.MarshalWithParams([]byte("parity-ref"), "explicit,tag:2")
	hdr = append(hdr, kid...)
	txnBytes := make([]byte, 16)
	nonce := make([]byte, 16)
	_, _ = rand.Read(txnBytes)
	_, _ = rand.Read(nonce)
	txn, _ := asn1.MarshalWithParams(txnBytes, "explicit,tag:4")
	hdr = append(hdr, txn...)
	sn, _ := asn1.MarshalWithParams(nonce, "explicit,tag:5")
	hdr = append(hdr, sn...)
	header := parityConstructed(t, hdr)
	body := parityMust(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: bodyType, IsCompound: true, Bytes: bodyContent})

	protectedPart := parityConstructed(t, append(append([]byte{}, header...), body...))
	key := append([]byte("parity-secret"), param.Salt...)
	for i := 0; i < param.IterationCount; i++ {
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(protectedPart)
	macBytes := mac.Sum(nil)
	bits := parityMust(t, asn1.BitString{Bytes: macBytes, BitLength: len(macBytes) * 8})
	protField := parityMust(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: bits})

	return parityConstructed(t, append(append(append([]byte{}, header...), body...), protField...))
}

// WSTEP: an RST carrying the CSR, with the template named in TokenType. The
// names come from the authenticated machine identity (the CSR only proves the
// key), so the identity is the one Kerberos would yield for this host.
func (e *parityEnv) newWSTEPDriver(t *testing.T) func(*testing.T, parityCSR) parityVerdict {
	lookup := func(tokenType string) (wstep.TemplateRef, bool) {
		if !e.strict || tokenType != parityTplID {
			return wstep.TemplateRef{}, false
		}
		policy := TemplatePolicy(e.tpl)
		return wstep.TemplateRef{Name: e.tpl.Name, Enrollee: wstep.EnrolleeMachine, Policy: &policy}, true
	}
	return func(t *testing.T, c parityCSR) parityVerdict {
		t.Helper()
		id := wstep.Identity{Method: "kerberos", Principal: "host$@CORP.EXAMPLE", Subject: pkix.Name{CommonName: c.DNS}, DNSNames: []string{c.DNS}}
		auth := func(inner http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(w, r.WithContext(wstep.WithIdentity(r.Context(), id)))
			})
		}
		h := wstep.NewServer(e.engine, e.caID).WithAuthenticator(auth).WithTemplateLookup(lookup).Handler()
		tokenType := "urn:parity:none"
		if e.strict {
			tokenType = parityTplID
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(parityRST(c.DER, tokenType))))
		if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "Fault") {
			return parityVerdict{Accepted: true, Detail: "200"}
		}
		return parityVerdict{Detail: fmt.Sprintf("%d %s", rec.Code, parityFaultText(rec.Body.String()))}
	}
}

func parityFaultText(body string) string {
	if i := strings.Index(body, "<s:Text"); i >= 0 {
		if j := strings.Index(body[i:], ">"); j >= 0 {
			rest := body[i+j+1:]
			if k := strings.Index(rest, "<"); k >= 0 {
				return rest[:k]
			}
		}
	}
	if len(body) > 160 {
		return body[:160]
	}
	return body
}

func parityRST(csrDER []byte, tokenType string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>%s</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wst:BinarySecurityToken>%s</wst:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`, tokenType, base64.StdEncoding.EncodeToString(csrDER))
}

// --- tests ------------------------------------------------------------------

func TestTemplatePolicyParity(t *testing.T) {
	env := newParityEnv(t, true)
	paths := env.paths(t)
	if len(paths) != len(parityPathNames) {
		t.Fatalf("driver count %d, want %d", len(paths), len(parityPathNames))
	}

	// Every known divergence must name a real cell, and never compliant/weak_key.
	for caseName, byPath := range parityKnownDivergence {
		if caseName == "compliant" || caseName == "weak_key" {
			t.Fatalf("%s may not have a known divergence: fix the path instead", caseName)
		}
		for pathName := range byPath {
			found := false
			for _, p := range parityPathNames {
				found = found || p == pathName
			}
			if !found {
				t.Fatalf("known divergence names unknown path %q", pathName)
			}
		}
	}

	for _, cs := range parityCases {
		for _, p := range paths {
			t.Run(cs.Name+"/"+p.Name, func(t *testing.T) {
				v := p.Issue(t, cs.build(t))
				t.Logf("matrix %-9s %-6s accepted=%-5v want=%-5v detail=%q", cs.Name, p.Name, v.Accepted, cs.Want, v.Detail)

				why, known := parityKnownDivergence[cs.Name][p.Name]
				switch {
				case v.Accepted != cs.Want && !known:
					t.Errorf("%s/%s: verdict accepted=%v, want %v (detail %q); fix the path or record it in parityKnownDivergence",
						cs.Name, p.Name, v.Accepted, cs.Want, v.Detail)
				case v.Accepted == cs.Want && known:
					t.Errorf("%s/%s: stale known divergence, remove it (%s)", cs.Name, p.Name, why)
				case v.Accepted != cs.Want && known:
					t.Logf("known divergence: %s", why)
				}
			})
		}
	}
}

// The drivers can answer both ways: with no policy and no template an API
// issuance of the weak-key CSR is accepted, and the same CSR is refused by the
// strict environment (the matrix's weak_key/api cell).
func TestParityHarnessSelfCheck(t *testing.T) {
	cs := parityCase{Name: "weak_key", DNS: parityGoodDNS, RSA: true}

	permissive := newParityEnv(t, false)
	if v := permissive.issueAPI(t, cs.build(t)); !v.Accepted {
		t.Fatalf("permissive engine refused the weak key: %q", v.Detail)
	}
	strict := newParityEnv(t, true)
	if v := strict.issueAPI(t, cs.build(t)); v.Accepted {
		t.Fatal("strict engine accepted the weak key")
	}
}
