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
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

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
	for name, c := range map[string]struct {
		c    call
		code int
	}{"foreign": {call{cert: &foreign}, http.StatusForbidden}, "none": {call{}, http.StatusUnauthorized}} {
		if resp := post(t, ts, "/.well-known/est/simplereenroll", hostile(t), c.c); resp.StatusCode != c.code {
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

// W26-07: API-managed users, the users-file precedence, and the failure alert.

type fakeSource struct {
	users map[string]User
	err   error
}

func (f fakeSource) LookupUser(_ context.Context, name string) (User, bool, error) {
	if f.err != nil {
		return User{}, false, f.err
	}
	u, ok := f.users[name]
	return u, ok && !u.Disabled, nil
}

func minCostHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func goodCSR(t *testing.T) string {
	return csrB64(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.devices.example.com"}})
}

func TestDBUserAuthenticatesWithAllowedSuffix(t *testing.T) {
	f := newFixture(t)
	store := newTestUserStore(t)
	if _, err := store.Create(context.Background(), StoredUser{Username: "api-user", BcryptHash: minCostHash(t, "s3cret"), AllowedDNSSuffixes: []string{".devices.example.com"}, CreatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	f.srv.WithUserSource(store)
	ts := f.tlsServer(t)

	cert := issuedCert(t, post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "api-user", pass: "s3cret"}))
	if cert.Subject.CommonName != "a.devices.example.com" {
		t.Fatalf("subject %q", cert.Subject)
	}
	if resp := post(t, ts, "/.well-known/est/simpleenroll", csrB64(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x.other.example.com"}}), call{user: "api-user", pass: "s3cret"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("name outside the suffix: %d", resp.StatusCode)
	}
}

func TestWrongPasswordIs401AndAuditedAsEnrollFailure(t *testing.T) {
	f := newFixture(t)
	f.srv.WithUserSource(fakeSource{users: map[string]User{"u": {Username: "u", BcryptHash: minCostHash(t, "right"), AllowedDNSSuffixes: []string{".devices.example.com"}}}})
	ts := f.tlsServer(t)
	resp := post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "u", pass: "wrong"})
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if len(f.audit) != 1 || f.audit[0].Action != "est.enroll.failure" || f.audit[0].Outcome != "denied" || f.audit[0].Actor != "u" {
		t.Fatalf("audit %+v", f.audit)
	}
}

func TestNameBindingRefusalIsAuditedAsEnrollFailure(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	ts := f.tlsServer(t)
	post(t, ts, "/.well-known/est/simpleenroll", hostile(t), call{user: "enroller", pass: "pw"})
	if len(f.audit) != 1 || f.audit[0].Action != "est.enroll.failure" || f.audit[0].Outcome != "denied" {
		t.Fatalf("audit %+v", f.audit)
	}
}

func TestFileUserWinsOnNameClash(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com") // "enroller" / "pw"
	f.srv.WithUserSource(fakeSource{users: map[string]User{"enroller": {Username: "enroller", BcryptHash: minCostHash(t, "db-pw"), AllowedDNSSuffixes: []string{".devices.example.com"}}}})
	ts := f.tlsServer(t)
	if !f.srv.HasFileUser("enroller") || f.srv.HasFileUser("db-only") {
		t.Fatal("HasFileUser")
	}
	if resp := post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "enroller", pass: "db-pw"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the source's password must not work for a file user: %d", resp.StatusCode)
	}
	issuedCert(t, post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "enroller", pass: "pw"}))
}

func TestDisabledUserIndistinguishableFrom401Unknown(t *testing.T) {
	f := newFixture(t)
	f.srv.WithUserSource(fakeSource{users: map[string]User{"off": {Username: "off", BcryptHash: minCostHash(t, "pw"), AllowedDNSSuffixes: []string{".devices.example.com"}, Disabled: true}}})
	ts := f.tlsServer(t)
	snap := func(c call) (int, string, string) {
		resp := post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), c)
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(body)
	}
	c1, h1, b1 := snap(call{user: "off", pass: "pw"}) // the correct password
	c2, h2, b2 := snap(call{user: "ghost", pass: "pw"})
	if c1 != c2 || h1 != h2 || b1 != b2 || c1 != http.StatusUnauthorized {
		t.Fatalf("disabled %d %q %q vs unknown %d %q %q", c1, h1, b1, c2, h2, b2)
	}
	if len(f.audit) != 2 || f.audit[0].Detail != "user disabled" || f.audit[1].Detail != "invalid credentials" {
		t.Fatalf("audit %+v", f.audit)
	}
}

func TestUserSourceErrorFailsClosed503(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	f.srv.WithUserSource(fakeSource{err: errors.New("db down")})
	ts := f.tlsServer(t)
	resp := post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "someone", pass: "pw"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %d", resp.StatusCode)
	}
	// A file user does not need the source and still works.
	issuedCert(t, post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "enroller", pass: "pw"}))
}

func TestUserSourceCountsAsConfigured(t *testing.T) {
	s := NewServer(nil, "ca")
	if s.EnrollmentConfigured() {
		t.Fatal("configured with nothing")
	}
	s.WithUserSource(fakeSource{})
	if !s.EnrollmentConfigured() {
		t.Fatal("a user source is a credential type")
	}
}

func TestAlertAfterTenFailuresPerMinute(t *testing.T) {
	var w failureWindow
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 10; i++ {
		if _, fire := w.record("a", t0.Add(time.Duration(i)*time.Second)); fire {
			t.Fatalf("attempt %d alerted", i)
		}
	}
	if n, fire := w.record("a", t0.Add(11*time.Second)); !fire || n != 11 {
		t.Fatalf("11th: n=%d fire=%v", n, fire)
	}
	if _, fire := w.record("a", t0.Add(12*time.Second)); fire {
		t.Fatal("alerted twice in one window")
	}
	if _, fire := w.record("b", t0.Add(12*time.Second)); fire {
		t.Fatal("users are counted independently")
	}
	// Next minute re-arms.
	later := t0.Add(2 * time.Minute)
	for i := 0; i < 10; i++ {
		if _, fire := w.record("a", later); fire {
			t.Fatal("new window alerted early")
		}
	}
	if _, fire := w.record("a", later); !fire {
		t.Fatal("new window did not re-arm")
	}
	// The key table is bounded; the oldest key is the one evicted.
	small := failureWindow{max: 3}
	for _, k := range []string{"k1", "k2", "k3", "k4", "k5"} {
		small.record(k, t0)
	}
	if small.order.Len() != 3 || len(small.byKey) != 3 || small.byKey["k1"] != nil || small.byKey["k5"] == nil {
		t.Fatalf("cap not enforced: %d keys", len(small.byKey))
	}
	long := strings.Repeat("x", 500)
	w.record(long, t0)
	if w.byKey[long] != nil || w.byKey[long[:failureKeyMax]] == nil {
		t.Fatal("key not truncated")
	}
}

func TestAlertFiresThroughServerOnEleventhBadPassword(t *testing.T) {
	f := newFixture(t).withBasic(t, ".devices.example.com")
	var alerts []map[string]string
	f.srv.WithAlertFunc(func(_ context.Context, kind string, d map[string]string) {
		if kind != "est.basic.failures" {
			t.Errorf("kind %q", kind)
		}
		alerts = append(alerts, d)
	})
	ts := f.tlsServer(t)
	for i := 0; i < 12; i++ {
		post(t, ts, "/.well-known/est/simpleenroll", goodCSR(t), call{user: "enroller", pass: "bad"})
	}
	if len(alerts) != 1 || alerts[0]["user"] != "enroller" || alerts[0]["count"] != "11" || alerts[0]["source_ip"] == "" {
		t.Fatalf("alerts %v", alerts)
	}
}

func TestValidateSuffixes(t *testing.T) {
	got, err := ValidateSuffixes([]string{" .Devices.Example.com "})
	if err != nil || !slices.Equal(got, []string{".devices.example.com"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{nil, {}, {"devices.example.com"}, {"."}, {"*.example.com"}, {".ok.example.com", "bad"}} {
		if _, err := ValidateSuffixes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewUserPasswordIs24CharactersAndHashes(t *testing.T) {
	pw, hash, err := NewUserPassword()
	if err != nil || len(pw) != 24 || strings.ContainsAny(pw, "+/=") {
		t.Fatalf("%q %v", pw, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) != nil {
		t.Fatal("hash does not match")
	}
}

func TestDBUserStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestUserStore(t)
	u := StoredUser{Username: "u1", BcryptHash: minCostHash(t, "a"), AllowedDNSSuffixes: []string{".a.example.com"}, CreatedBy: "admin"}
	if _, err := st.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(ctx, u); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate: %v", err)
	}
	off := true
	if _, err := st.Update(ctx, "u1", &off, []string{".b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.LookupUser(ctx, "u1"); ok {
		t.Fatal("disabled user looked up as ok")
	}
	if err := st.SetPassword(ctx, "u1", minCostHash(t, "b")); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "u1")
	if err != nil || !got.Disabled || got.PasswordRotatedAt == nil || !slices.Equal(got.AllowedDNSSuffixes, []string{".b.example.com"}) {
		t.Fatalf("%+v %v", got, err)
	}
	if list, _ := st.List(ctx); len(list) != 1 {
		t.Fatalf("list %v", list)
	}
	if err := st.Delete(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "u1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := st.Update(ctx, "u1", &off, nil); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func newTestUserStore(t *testing.T) *DBUserStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "est.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := NewDBUserStore(db, false)
	if err := st.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}
