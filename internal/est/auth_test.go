// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/bcrypt"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

type estFixture struct {
	engine ca.Service
	caID   string
	srv    *Server
	audit  []AuditEvent
}

func newFixture(t *testing.T) *estFixture {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("est-auth-test-passphrase-32bytes"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "EST Auth Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := &estFixture{engine: engine, caID: root.ID}
	f.srv = NewServer(engine, root.ID).WithAuditFunc(func(_ context.Context, ev AuditEvent) { f.audit = append(f.audit, ev) })
	return f
}

func (f *estFixture) withBasic(t *testing.T, suffixes ...string) *estFixture {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.WithBasicUsers([]User{{Username: "enroller", BcryptHash: string(h), AllowedDNSSuffixes: suffixes}}); err != nil {
		t.Fatal(err)
	}
	return f
}

// tlsServer serves f over TLS, asking for (not verifying) client
// certificates like the hub listener with KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT.
func (f *estFixture) tlsServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(f.srv.Handler())
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func csrB64(t *testing.T, tmpl *x509.CertificateRequest) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// hostile asks for someone else's name and extra SANs.
func hostile(t *testing.T) string {
	return csrB64(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Administrator", Organization: []string{"Domain Admins"}}})
}

type call struct {
	user, pass string
	cert       *tls.Certificate
}

func post(t *testing.T, ts *httptest.Server, path, body string, c call) *http.Response {
	t.Helper()
	client := ts.Client()
	if c.cert != nil {
		tr := client.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{*c.cert}
		client = &http.Client{Transport: tr}
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/pkcs10")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func issuedCert(t *testing.T, resp *http.Response) *x509.Certificate {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil || len(p7.Certificates) != 1 {
		t.Fatalf("response: %v", err)
	}
	return p7.Certificates[0]
}

func TestEnrollmentRefusedWithoutConfiguredCredentials(t *testing.T) {
	f := newFixture(t)
	ts := f.tlsServer(t)
	for _, path := range []string{"/.well-known/est/simpleenroll", "/.well-known/est/simplereenroll"} {
		resp := post(t, ts, path, hostile(t), call{})
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: got %d", path, resp.StatusCode)
		}
		if path == "/.well-known/est/simpleenroll" && !strings.Contains(string(body), "no authentication is configured") {
			t.Fatalf("%s: %q", path, body)
		}
	}
	resp, err := ts.Client().Get(ts.URL + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cacerts: %d", resp.StatusCode)
	}
}

// RFC 7030 3.2.3: no credential over plaintext, and no challenge inviting one.
func TestPlaintextNeverAuthenticates(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	ts := httptest.NewServer(f.srv.Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(csrB64(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.devices.example.com"}})))
	req.SetBasicAuth("enroller", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("plaintext with valid credentials: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if len(f.audit) != 0 {
		t.Fatalf("plaintext request audited as an authentication: %+v", f.audit)
	}
}

func TestBasicChallengeAndRejection(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	ts := f.tlsServer(t)
	good := csrB64(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.devices.example.com"}})

	resp := post(t, ts, "/.well-known/est/simpleenroll", good, call{})
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") || len(f.audit) != 0 {
		t.Fatalf("bare request: %d %q audit=%v", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), f.audit)
	}
	// "nobody" with the dummy hash's own password: the source is public,
	// so an unknown user must be refused for being unknown, not only for a
	// wrong password.
	for _, c := range []call{{user: "enroller", pass: "wrong"}, {user: "nobody", pass: "pw"}, {user: "nobody", pass: "kryptkeeper-est-dummy"}} {
		if resp := post(t, ts, "/.well-known/est/simpleenroll", good, c); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s/%s: got %d", c.user, c.pass, resp.StatusCode)
		}
	}
	if len(f.audit) != 3 || f.audit[0].Outcome != "denied" || f.audit[1].Actor != "nobody" {
		t.Fatalf("rejected credentials must be audited: %+v", f.audit)
	}
}

func TestBasicBindsNamesToTheUser(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	ts := f.tlsServer(t)
	cred := call{user: "enroller", pass: "pw"}

	cert := issuedCert(t, post(t, ts, "/.well-known/est/simpleenroll", csrB64(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Sensor-1.Devices.Example.com", Organization: []string{"Domain Admins"}},
		DNSNames: []string{"sensor-1.devices.example.com", "alias.devices.example.com"},
	}), cred))
	if cert.Subject.String() != "CN=sensor-1.devices.example.com" {
		t.Fatalf("subject %q: only the normalised CN may survive", cert.Subject)
	}
	if !slices.Equal(cert.DNSNames, []string{"sensor-1.devices.example.com", "alias.devices.example.com"}) {
		t.Fatalf("SANs %v", cert.DNSNames)
	}
	last := f.audit[len(f.audit)-1]
	if last.Action != "est.enroll" || last.Outcome != "success" || last.Actor != "enroller" {
		t.Fatalf("audit %+v", last)
	}

	for name, tmpl := range map[string]*x509.CertificateRequest{
		"foreign CN":     {Subject: pkix.Name{CommonName: "Administrator"}},
		"foreign SAN":    {Subject: pkix.Name{CommonName: "a.devices.example.com"}, DNSNames: []string{"dc01.corp.example.com"}},
		"IP SAN":         {Subject: pkix.Name{CommonName: "a.devices.example.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
		"email SAN":      {Subject: pkix.Name{CommonName: "a.devices.example.com"}, EmailAddresses: []string{"x@devices.example.com"}},
		"URI SAN":        {Subject: pkix.Name{CommonName: "a.devices.example.com"}, URIs: []*url.URL{{Scheme: "spiffe", Host: "td"}}},
		"wildcard":       {Subject: pkix.Name{CommonName: "*.devices.example.com"}},
		"names nothing":  {},
		"suffix apex":    {Subject: pkix.Name{CommonName: "devices.example.com"}},
		"suffix lookbad": {Subject: pkix.Name{CommonName: "evildevices.example.com"}},
	} {
		if resp := post(t, ts, "/.well-known/est/simpleenroll", csrB64(t, tmpl), cred); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, resp.StatusCode)
		}
	}
}

func TestNameAllowed(t *testing.T) {
	sfx := []string{".devices.corp"}
	for name, want := range map[string]bool{
		"a.devices.corp":    true,
		"a.b.devices.corp":  true,
		"devices.corp":      false,
		"evildevices.corp":  false,
		".devices.corp":     false,
		"a..devices.corp":   false,
		"..devices.corp":    false,
		"*.devices.corp":    false,
		"a.devices.corp.":   false,
		"a b.devices.corp":  false,
		"a.devices.corp.io": false,
	} {
		if got := nameAllowed(name, sfx); got != want {
			t.Errorf("%q: got %v", name, got)
		}
	}
	if nameAllowed("a.devices.corp", nil) {
		t.Error("an empty suffix list must allow nothing")
	}
}

func TestWithBasicUsersValidates(t *testing.T) {
	h, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	for name, u := range map[string][]User{
		"no suffixes":    {{Username: "u", BcryptHash: string(h)}},
		"suffix no dot":  {{Username: "u", BcryptHash: string(h), AllowedDNSSuffixes: []string{"corp"}}},
		"wildcard":       {{Username: "u", BcryptHash: string(h), AllowedDNSSuffixes: []string{".*.corp"}}},
		"plain password": {{Username: "u", BcryptHash: "hunter2", AllowedDNSSuffixes: []string{".corp"}}},
		"empty username": {{BcryptHash: string(h), AllowedDNSSuffixes: []string{".corp"}}},
		"duplicate":      {{Username: "u", BcryptHash: string(h), AllowedDNSSuffixes: []string{".corp"}}, {Username: "u", BcryptHash: string(h), AllowedDNSSuffixes: []string{".corp"}}},
	} {
		if err := NewServer(nil, "").WithBasicUsers(u); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// selfCA makes an external trust anchor (e.g. a device manufacturer CA) and
// a client certificate it issued.
func selfCA(t *testing.T, cn string, leafDNS ...string) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn + " CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: leafDNS,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &k.PublicKey, caKey)
	return caCert, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: k}
}

func TestClientCertificateEnrollment(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	anchor, device := selfCA(t, "sensor-9.devices.example.com", "sensor-9.devices.example.com")
	_, foreign := selfCA(t, "laptop.corp.example.com")
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	f.srv.WithClientCertAnchors(roots)
	ts := f.tlsServer(t)

	// The device certificate is the identity; the CSR's names are ignored.
	cert := issuedCert(t, post(t, ts, "/.well-known/est/simpleenroll", hostile(t), call{cert: &device}))
	if cert.Subject.CommonName != "sensor-9.devices.example.com" || len(cert.Subject.Organization) != 0 ||
		!slices.Equal(cert.DNSNames, []string{"sensor-9.devices.example.com"}) {
		t.Fatalf("subject %q SANs %v", cert.Subject, cert.DNSNames)
	}
	if last := f.audit[len(f.audit)-1]; last.Outcome != "success" || !strings.Contains(last.Detail, "method=certificate") {
		t.Fatalf("audit %+v", last)
	}

	// A device certificate without SANs: the CSR's SANs must not fill the gap.
	anchor2, bare := selfCA(t, "sensor-10.devices.example.com")
	roots.AddCert(anchor2)
	plain := issuedCert(t, post(t, ts, "/.well-known/est/simpleenroll", csrB64(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"dc01.corp.example.com"},
	}), call{cert: &bare}))
	if plain.Subject.CommonName != "sensor-10.devices.example.com" || len(plain.DNSNames) != 0 {
		t.Fatalf("SAN-less identity got CSR names: %q %v", plain.Subject, plain.DNSNames)
	}

	// A certificate from an unknown issuer is not a credential: Basic is
	// asked for instead.
	if resp := post(t, ts, "/.well-known/est/simpleenroll", hostile(t), call{cert: &foreign}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("foreign client certificate: got %d, want the Basic challenge", resp.StatusCode)
	}
}

func TestReenrollment(t *testing.T) {
	f := newFixture(t)
	revs := ca.NewMemRevocationStore()
	roots := x509.NewCertPool()
	f.srv.WithClientCertAnchors(roots).WithReenrollment(revs)
	ts := f.tlsServer(t)

	// A certificate this hub issued earlier.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	subject := pkix.Name{CommonName: "sensor-1.devices.example.com"}
	old, err := f.engine.IssueCertificate(f.caID, ca.IssuanceRequest{CSR: csr, Subject: &subject,
		DNSNames: []string{"sensor-1.devices.example.com"}, CallerNamesOnly: true, Validity: time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	held := tls.Certificate{Certificate: [][]byte{old.Certificate.Raw}, PrivateKey: k}

	renewed := issuedCert(t, post(t, ts, "/.well-known/est/simplereenroll", hostile(t), call{cert: &held}))
	if renewed.Subject.CommonName != "sensor-1.devices.example.com" || !slices.Equal(renewed.DNSNames, []string{"sensor-1.devices.example.com"}) ||
		renewed.SerialNumber.Cmp(old.Certificate.SerialNumber) == 0 {
		t.Fatalf("renewed %q %v", renewed.Subject, renewed.DNSNames)
	}
	if last := f.audit[len(f.audit)-1]; last.Action != "est.reenroll" || last.Outcome != "success" {
		t.Fatalf("audit %+v", last)
	}

	// A certificate from another issuer, or none, may not re-enroll.
	_, foreign := selfCA(t, "sensor-1.devices.example.com")
	for name, c := range map[string]call{"foreign": {cert: &foreign}, "none": {}} {
		if resp := post(t, ts, "/.well-known/est/simplereenroll", hostile(t), c); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: got %d", name, resp.StatusCode)
		}
	}

	// Revoked: refused and audited.
	if err := revs.Revoke(old.Certificate.SerialNumber, f.caID, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if resp := post(t, ts, "/.well-known/est/simplereenroll", hostile(t), call{cert: &held}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked: got %d", resp.StatusCode)
	}
	if last := f.audit[len(f.audit)-1]; last.Action != "est.reenroll" || last.Outcome != "denied" || last.Detail != "certificate is revoked" {
		t.Fatalf("audit %+v", last)
	}
}
