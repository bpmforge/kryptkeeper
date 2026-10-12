// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

var aliceID = IdentityForPrincipal("alice", "CORP.EXAMPLE")

// asIdentity stands in for a completed Kerberos exchange.
func asIdentity(id Identity) AuthWrapper {
	return func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

// fakeKerberos behaves like gokrb5's SPNEGO wrapper at the HTTP level: no
// Authorization header gets the bare challenge, "Negotiate good" is a valid
// ticket for id, anything else is a rejected token.
func fakeKerberos(id Identity) AuthWrapper {
	return func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Header.Get("Authorization") {
			case "":
				w.Header().Set("WWW-Authenticate", "Negotiate")
				http.Error(w, "Unauthorised.", http.StatusUnauthorized)
			case "Negotiate good":
				inner.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
			default:
				w.Header().Set("WWW-Authenticate", "Negotiate oRQwEqADCgECoQsGCSqGSIb3EgECAg==")
				http.Error(w, "Unauthorised.", http.StatusUnauthorized)
			}
		})
	}
}

type auditLog struct{ events []AuditEvent }

func (a *auditLog) fn(_ context.Context, ev AuditEvent) { a.events = append(a.events, ev) }

func csrFor(t *testing.T, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func post(h http.Handler, body, authz string, peer *x509.Certificate) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/soap+xml")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	if peer != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func issuedFrom(t *testing.T, w *httptest.ResponseRecorder) *x509.Certificate {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	return parseRSTR(t, w.Body.Bytes()).leaf(t)
}

// rstr mirrors the MS-WSTEP 4.1.1.2 response fields a Windows client reads.
type rstr struct {
	Header struct {
		Action    string `xml:"Action"`
		RelatesTo string `xml:"RelatesTo"`
	} `xml:"Header"`
	Body struct {
		Resp struct {
			TokenType   string `xml:"TokenType"`
			Disposition string `xml:"DispositionMessage"`
			PKCS7       string `xml:"BinarySecurityToken"`
			Leaf        string `xml:"RequestedSecurityToken>BinarySecurityToken"`
			RequestID   string `xml:"RequestID"`
		} `xml:"RequestSecurityTokenResponseCollection>RequestSecurityTokenResponse"`
	} `xml:"Body"`
}

func parseRSTR(t *testing.T, body []byte) rstr {
	t.Helper()
	var r rstr
	if err := xml.Unmarshal(body, &r); err != nil {
		t.Fatalf("response is not XML: %v\n%s", err, body)
	}
	return r
}

func (r rstr) leaf(t *testing.T) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Body.Resp.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// hostileCSR names someone else and asks for foreign SANs; only its key may
// reach the certificate.
func hostileCSR(t *testing.T) []byte {
	return csrFor(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "Administrator", Organization: []string{"Domain Admins"}},
		DNSNames:    []string{"dc01.corp.example", "evil.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	})
}

func TestIdentityForPrincipal(t *testing.T) {
	m := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	if m.Subject.CommonName != "ws01.corp.example" || !slices.Equal(m.DNSNames, []string{"ws01.corp.example"}) || m.Principal != "WS01$@CORP.EXAMPLE" {
		t.Fatalf("machine identity %+v", m)
	}
	u := IdentityForPrincipal("alice", "CORP.EXAMPLE")
	if u.Subject.CommonName != "alice" || len(u.DNSNames) != 0 || u.Method != "kerberos" {
		t.Fatalf("user identity %+v", u)
	}
}

func TestAnonymousPostGetsNegotiateChallengeOnly(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	rec, audit := &fakeRecorder{}, &auditLog{}
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(aliceID)).
		WithIssuedRecorder(rec).WithAuditFunc(audit.fn).Handler()

	w := post(h, buildWSTEPRequest(hostileCSR(t)), "", nil)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Negotiate" {
		t.Fatalf("got %d %q, want 401 Negotiate", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if len(rec.got) != 0 {
		t.Fatalf("anonymous request issued %d certificates", len(rec.got))
	}
	if len(audit.events) != 0 {
		t.Fatalf("the bare challenge must not be audited, got %+v", audit.events)
	}
}

func TestNoAuthenticatorRefusesEnrollment(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	rec := &fakeRecorder{}
	w := post(NewServer(engine, caID).WithIssuedRecorder(rec).Handler(), buildWSTEPRequest(hostileCSR(t)), "", nil)
	if w.Code != http.StatusUnauthorized || len(rec.got) != 0 {
		t.Fatalf("got %d with %d issued; an unconfigured server must not issue", w.Code, len(rec.got))
	}
}

func TestRejectedKerberosTokenIsAudited(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	audit := &auditLog{}
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(aliceID)).WithAuditFunc(audit.fn).Handler()

	w := post(h, buildWSTEPRequest(hostileCSR(t)), "Negotiate TlRMTVNTUAABAAAA", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
	if len(audit.events) != 1 || audit.events[0].Action != "wstep.enroll" || audit.events[0].Outcome != "denied" {
		t.Fatalf("want one denied wstep.enroll row, got %+v", audit.events)
	}
}

func TestEnrollmentBindsSubjectToKerberosMachine(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	rec, audit := &fakeRecorder{}, &auditLog{}
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).
		WithIssuedRecorder(rec).WithAuditFunc(audit.fn).Handler()

	cert := issuedFrom(t, post(h, buildWSTEPRequest(hostileCSR(t)), "Negotiate good", nil))
	if cert.Subject.CommonName != "ws01.corp.example" || len(cert.Subject.Organization) != 0 {
		t.Fatalf("subject %q came from the CSR, not the principal", cert.Subject)
	}
	if !slices.Equal(cert.DNSNames, []string{"ws01.corp.example"}) || len(cert.IPAddresses) != 0 {
		t.Fatalf("SANs dns=%v ip=%v; CSR SANs must be ignored", cert.DNSNames, cert.IPAddresses)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("EKU %v, want client-auth only", cert.ExtKeyUsage)
	}
	if len(rec.got) != 1 || rec.got[0].source != "wstep" {
		t.Fatalf("inventory %+v", rec.got)
	}
	if len(audit.events) != 1 || audit.events[0].Action != "wstep.enroll" || audit.events[0].Outcome != "success" || audit.events[0].Actor != "WS01$@CORP.EXAMPLE" {
		t.Fatalf("audit %+v", audit.events)
	}
}

func TestEnrollmentForUserCarriesNoSANs(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(aliceID)).Handler()
	cert := issuedFrom(t, post(h, buildWSTEPRequest(hostileCSR(t)), "Negotiate good", nil))
	if cert.Subject.CommonName != "alice" || len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 {
		t.Fatalf("user cert subject=%q dns=%v ip=%v", cert.Subject, cert.DNSNames, cert.IPAddresses)
	}
}

// renewalFixture is a hub with renewal on and a client certificate the hub
// itself issued.
type renewalFixture struct {
	srv   *Server
	revs  *ca.MemRevocationStore
	audit *auditLog
	leaf  *x509.Certificate
}

func newRenewalFixture(t *testing.T, eku []x509.ExtKeyUsage) renewalFixture {
	t.Helper()
	engine, caID := newTestCAEngine(t)
	csr, err := x509.ParseCertificateRequest(csrFor(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}))
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: "ws01.corp.example"}
	issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{
		CSR: csr, Subject: &subject, DNSNames: []string{"ws01.corp.example"}, CallerNamesOnly: true,
		Validity: 24 * time.Hour, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := renewalFixture{revs: ca.NewMemRevocationStore(), audit: &auditLog{}, leaf: issued.Certificate}
	f.srv = NewServer(engine, caID).WithAuthenticator(fakeKerberos(aliceID)).
		WithRenewal(f.revs).WithAuditFunc(f.audit.fn)
	return f
}

func TestRenewalWithHubCertificateKeepsItsIdentity(t *testing.T) {
	f := newRenewalFixture(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	cert := issuedFrom(t, post(f.srv.Handler(), buildWSTEPRequest(hostileCSR(t)), "", f.leaf))
	if cert.Subject.CommonName != "ws01.corp.example" || !slices.Equal(cert.DNSNames, []string{"ws01.corp.example"}) || len(cert.IPAddresses) != 0 {
		t.Fatalf("renewed subject=%q dns=%v ip=%v", cert.Subject, cert.DNSNames, cert.IPAddresses)
	}
	if cert.SerialNumber.Cmp(f.leaf.SerialNumber) == 0 {
		t.Fatal("renewal returned the old certificate")
	}
	if len(f.audit.events) != 1 || f.audit.events[0].Action != "wstep.renew" || f.audit.events[0].Outcome != "success" {
		t.Fatalf("audit %+v", f.audit.events)
	}
}

func TestRenewalRefusesUnusableHubCertificate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		eku   []x509.ExtKeyUsage
		setup func(f renewalFixture)
	}{
		{"expired", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, func(f renewalFixture) {
			f.srv.now = func() time.Time { return f.leaf.NotAfter.Add(time.Second) }
		}},
		{"not yet valid", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, func(f renewalFixture) {
			f.srv.now = func() time.Time { return f.leaf.NotBefore.Add(-time.Second) }
		}},
		{"revoked", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, func(f renewalFixture) {
			if err := f.revs.Revoke(f.leaf.SerialNumber, f.srv.caID, 1, time.Now()); err != nil {
				panic(err)
			}
		}},
		{"no client-auth EKU", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, func(renewalFixture) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenewalFixture(t, tc.eku)
			tc.setup(f)
			// A valid Kerberos ticket alongside must not rescue a bad
			// renewal credential: the certificate was the claim made.
			w := post(f.srv.Handler(), buildWSTEPRequest(hostileCSR(t)), "Negotiate good", f.leaf)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
			}
			if len(f.audit.events) != 1 || f.audit.events[0].Action != "wstep.renew" || f.audit.events[0].Outcome != "denied" || f.audit.events[0].Actor == "" {
				t.Fatalf("want one denied wstep.renew row with an actor, got %+v", f.audit.events)
			}
		})
	}
}

func TestRenewalFailsClosedWhenRevocationUnknown(t *testing.T) {
	f := newRenewalFixture(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	f.srv.revocation = brokenRevocations{}
	if w := post(f.srv.Handler(), buildWSTEPRequest(hostileCSR(t)), "", f.leaf); w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
}

type brokenRevocations struct{}

func (brokenRevocations) IsRevoked(*big.Int, string) (bool, time.Time, int, error) {
	return false, time.Time{}, 0, context.DeadlineExceeded
}

// Windows may present a certificate from another CA on its own; that is not
// a renewal credential, so the request goes through Kerberos instead.
func TestForeignClientCertificateFallsThroughToKerberos(t *testing.T) {
	f := newRenewalFixture(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	foreign := selfSigned(t, "ws01.corp.example")

	if w := post(f.srv.Handler(), buildWSTEPRequest(hostileCSR(t)), "", foreign); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Negotiate" {
		t.Fatalf("got %d %q, want the Negotiate challenge", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	cert := issuedFrom(t, post(f.srv.Handler(), buildWSTEPRequest(hostileCSR(t)), "Negotiate good", foreign))
	if cert.Subject.CommonName != "alice" {
		t.Fatalf("subject %q, want the Kerberos principal's", cert.Subject)
	}
}

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
