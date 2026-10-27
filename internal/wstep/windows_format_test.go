// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"

	"kryptkeeper/internal/ca"
)

// rstAs builds the RST a Windows client sends (MS-WSTEP 4.1.1.1): token
// base64 wrapped at 64 columns, a MessageID, and the PKCS7 ValueType even
// for a bare PKCS#10.
func rstAs(token []byte, messageID string) string {
	b64 := base64.StdEncoding.EncodeToString(token)
	var wrapped strings.Builder
	for len(b64) > 64 {
		wrapped.WriteString(b64[:64] + "\r\n")
		b64 = b64[64:]
	}
	wrapped.WriteString(b64)
	return fmt.Sprintf(`<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header>
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
<a:MessageID>%s</a:MessageID>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<RequestSecurityToken xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
<RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
<BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">%s</BinarySecurityToken>
<RequestID xsi:nil="true" xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>
</RequestSecurityToken>
</s:Body>
</s:Envelope>`, messageID, wrapped.String())
}

func TestWindowsShapedEnrollmentGetsSpecResponse(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).Handler()

	w := post(h, rstAs(hostileCSR(t), "urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919"), "Negotiate good", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	r := parseRSTR(t, w.Body.Bytes())
	leaf := r.leaf(t)
	if leaf.Subject.CommonName != "ws01.corp.example" {
		t.Fatalf("subject %q", leaf.Subject)
	}
	if r.Header.Action != "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep" {
		t.Fatalf("action %q", r.Header.Action)
	}
	if r.Header.RelatesTo != "urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919" {
		t.Fatalf("RelatesTo %q must echo the MessageID", r.Header.RelatesTo)
	}
	if r.Body.Resp.Disposition != "Issued" || r.Body.Resp.RequestID != leaf.SerialNumber.Text(16) {
		t.Fatalf("disposition %q request ID %q", r.Body.Resp.Disposition, r.Body.Resp.RequestID)
	}

	// The PKCS#7 token carries the leaf and its issuer so Windows can
	// build the chain.
	der, err := base64.StdEncoding.DecodeString(r.Body.Resp.PKCS7)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("PKCS#7 token: %v", err)
	}
	issuer, err := engine.GetCA(caID)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Certificates) != 2 || !p7.Certificates[0].Equal(leaf) || !p7.Certificates[1].Equal(issuer.Certificate) {
		t.Fatalf("PKCS#7 holds %d certificates, want leaf then issuer", len(p7.Certificates))
	}
	if err := leaf.CheckSignatureFrom(p7.Certificates[1]); err != nil {
		t.Fatalf("chain in PKCS#7 does not verify: %v", err)
	}
}

// A renewal wraps the new PKCS#10 in SignedData signed by the old key
// (MS-WSTEP 4.1.5.1). Identity still comes from Kerberos.
func TestPKCS7WrappedRenewalRequestIsAccepted(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).Handler()

	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "old"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	oldDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &oldKey.PublicKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, _ := x509.ParseCertificate(oldDER)
	sd, err := pkcs7.NewSignedData(hostileCSR(t))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(oldCert, oldKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	wrapped, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}

	cert := issuedFrom(t, post(h, rstAs(wrapped, "urn:uuid:1"), "Negotiate good", nil))
	if cert.Subject.CommonName != "ws01.corp.example" {
		t.Fatalf("subject %q, want the Kerberos machine", cert.Subject)
	}
}

func TestRequestCSRRejectsJunk(t *testing.T) {
	for name, token := range map[string]string{
		"empty":         " \r\n ",
		"not base64":    "!!!",
		"not a request": base64.StdEncoding.EncodeToString([]byte("junk")),
	} {
		if _, _, err := requestCSR(token); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// cmcPKIDataFor builds RFC 5272 PKIData around csrs, the way CertEnroll
// does for a CES request.
func cmcPKIDataFor(t testing.TB, csrs ...[]byte) []byte {
	t.Helper()
	empty, _ := asn1.Marshal([]asn1.RawValue{})
	reqs := make([]asn1.RawValue, 0, len(csrs))
	for i, c := range csrs {
		inner, err := asn1.Marshal(cmcTaggedCertificationRequest{BodyPartID: int64(i + 1), CertificationRequest: asn1.RawValue{FullBytes: c}})
		if err != nil {
			t.Fatal(err)
		}
		// TaggedRequest's tcr arm is [0] IMPLICIT: same contents, new tag.
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(inner, &seq); err != nil {
			t.Fatal(err)
		}
		reqs = append(reqs, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: seq.Bytes})
	}
	der, err := asn1.Marshal(cmcPKIData{
		ControlSequence: asn1.RawValue{FullBytes: empty},
		ReqSequence:     reqs,
		CMSSequence:     asn1.RawValue{FullBytes: empty},
		OtherMsgSeq:     asn1.RawValue{FullBytes: empty},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func signedDataAround(t testing.TB, content []byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	out, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCMCWrappedEnrollmentIsAccepted(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).Handler()

	csr := hostileCSR(t)
	cert := issuedFrom(t, post(h, rstAs(signedDataAround(t, cmcPKIDataFor(t, csr)), "urn:uuid:2"), "Negotiate good", nil))
	if cert.Subject.CommonName != "ws01.corp.example" {
		t.Fatalf("subject %q", cert.Subject)
	}
	parsed, _ := x509.ParseCertificateRequest(csr)
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(cert.PublicKey) {
		t.Fatal("issued key is not the CMC request's key")
	}
}

func TestCMCWithTwoRequestsIsRefused(t *testing.T) {
	if _, err := cmcCertificationRequest(cmcPKIDataFor(t, hostileCSR(t), hostileCSR(t))); err == nil {
		t.Fatal("two requests in one PKIData must be refused")
	}
	if _, err := cmcCertificationRequest(cmcPKIDataFor(t)); err == nil {
		t.Fatal("no request must be refused")
	}
}

func csrForTemplate(t *testing.T, oid asn1.ObjectIdentifier, major int64) []byte {
	t.Helper()
	value, err := asn1.Marshal(certificateTemplateExt{TemplateID: oid, Major: major, Minor: 0})
	if err != nil {
		t.Fatal(err)
	}
	return csrFor(t, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "Administrator"},
		ExtraExtensions: []pkix.Extension{{Id: oidCertificateTemplate, Value: value}},
	})
}

func TestTemplateExtensionStampedWithHubRevision(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	offered := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 8, 4150237, 1, 1}
	resolve := func(oid string) (TemplateRef, bool) {
		if oid == offered.String() {
			return TemplateRef{OID: oid, MajorVersion: 3}, true
		}
		return TemplateRef{}, false
	}
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).WithTemplateResolver(resolve).Handler()

	// The client claims revision 99; the certificate carries the hub's 3.
	cert := issuedFrom(t, post(h, rstAs(csrForTemplate(t, offered, 99), "urn:uuid:3"), "Negotiate good", nil))
	var got certificateTemplateExt
	var found bool
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidCertificateTemplate) {
			found = true
			if _, err := asn1.Unmarshal(e.Value, &got); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || !got.TemplateID.Equal(offered) || got.Major != 3 {
		t.Fatalf("template extension found=%v %+v, want %v major 3", found, got, offered)
	}

	// No template requested: no extension, as before.
	plain := issuedFrom(t, post(h, rstAs(hostileCSR(t), "urn:uuid:4"), "Negotiate good", nil))
	for _, e := range plain.Extensions {
		if e.Id.Equal(oidCertificateTemplate) {
			t.Fatal("template extension added although none was requested")
		}
	}

	// A template the hub does not offer is refused, not issued untemplated.
	w := post(h, rstAs(csrForTemplate(t, asn1.ObjectIdentifier{1, 2, 3, 4}, 1), "urn:uuid:5"), "Negotiate good", nil)
	if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "not offered") {
		t.Fatalf("unknown template: got %d %s", w.Code, w.Body.String())
	}
	// Without a resolver no template can be vouched for.
	bare := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).Handler()
	if w := post(bare, rstAs(csrForTemplate(t, offered, 1), "urn:uuid:6"), "Negotiate good", nil); w.Code == http.StatusOK {
		t.Fatal("template request accepted with no resolver")
	}
}

// signedBy wraps content in SignedData signed by cert/key, as Windows does
// with the old certificate when it renews (MS-WSTEP 4.1.5.1).
func signedBy(t *testing.T, content []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	out, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// W20-11: a renewal over Kerberos is audited as wstep.renew, with the
// predecessor's serial, when the old certificate that signed it is this
// hub's and names the same identity. Anything else stays wstep.enroll.
func TestKerberosRenewalIsAuditedAsRenewal(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	audit := &auditLog{}
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).WithAuditFunc(audit.fn).Handler()

	hubCert := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		csr, _ := x509.ParseCertificateRequest(der)
		subject := pkix.Name{CommonName: cn}
		issued, err := engine.IssueCertificate(caID, ca.IssuanceRequest{CSR: csr, Subject: &subject, CallerNamesOnly: true,
			Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if err != nil {
			t.Fatal(err)
		}
		return issued.Certificate, k
	}
	selfMade := func() (*x509.Certificate, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "ws01.corp.example"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		c, _ := x509.ParseCertificate(der)
		return c, k
	}

	prior, priorKey := hubCert("ws01.corp.example")
	other, otherKey := hubCert("ws99.corp.example")
	fake, fakeKey := selfMade()

	for name, tc := range map[string]struct {
		token       []byte
		action      string
		predecessor string
	}{
		"hub predecessor, same identity": {signedBy(t, cmcPKIDataFor(t, hostileCSR(t)), prior, priorKey), "wstep.renew", prior.SerialNumber.Text(16)},
		"hub cert, other identity":       {signedBy(t, cmcPKIDataFor(t, hostileCSR(t)), other, otherKey), "wstep.enroll", ""},
		// The predecessor's certificate copied in, but signed with another
		// key: whoever sent it does not hold the old key.
		"copied predecessor, wrong key": {signedBy(t, cmcPKIDataFor(t, hostileCSR(t)), prior, otherKey), "wstep.enroll", ""},
		"self-made signer":              {signedBy(t, cmcPKIDataFor(t, hostileCSR(t)), fake, fakeKey), "wstep.enroll", ""},
		"bare PKCS#10":                  {hostileCSR(t), "wstep.enroll", ""},
	} {
		audit.events = nil
		cert := issuedFrom(t, post(h, rstAs(tc.token, "urn:uuid:r"), "Negotiate good", nil))
		if cert.Subject.CommonName != "ws01.corp.example" {
			t.Fatalf("%s: subject %q must still come from Kerberos", name, cert.Subject)
		}
		ev := audit.events[len(audit.events)-1]
		if ev.Action != tc.action {
			t.Errorf("%s: audited as %s, want %s", name, ev.Action, tc.action)
		}
		if got := strings.Contains(ev.Detail, "predecessor="); got != (tc.predecessor != "") ||
			(tc.predecessor != "" && !strings.Contains(ev.Detail, "predecessor="+tc.predecessor)) {
			t.Errorf("%s: detail %q, want predecessor %q", name, ev.Detail, tc.predecessor)
		}
	}
}

// W20-09: the template named in the CSR governs WSTEP issuance: its
// validity becomes the issued validity, and its rules are enforced.
func TestTemplatePolicyGovernsWSTEPIssuance(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	tmplOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 8, 4150237, 9, 1}
	var policy ca.TemplatePolicy
	h := NewServer(engine, caID).WithAuthenticator(fakeKerberos(machine)).
		WithTemplateResolver(func(oid string) (TemplateRef, bool) {
			if oid != tmplOID.String() {
				return TemplateRef{}, false
			}
			p := policy
			return TemplateRef{OID: oid, MajorVersion: 1, Policy: &p}, true
		}).Handler()

	// 30-day template: a 30-day certificate. The 5-minute backdate (clamped
	// here to this fresh CA's NotBefore, see ca backdate tests) must not
	// count against MaxValidity, which is measured from the issue time.
	policy = ca.TemplatePolicy{ID: "kk-30d", MaxValidity: 30 * 24 * time.Hour, AllowedEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	before := time.Now().UTC().Truncate(time.Second)
	cert := issuedFrom(t, post(h, rstAs(csrForTemplate(t, tmplOID, 1), "urn:uuid:p1"), "Negotiate good", nil))
	after := time.Now().UTC()
	if cert.NotAfter.Before(before.Add(30*24*time.Hour)) || cert.NotAfter.After(after.Add(30*24*time.Hour)) {
		t.Fatalf("NotAfter %v, want issue time + 30 days", cert.NotAfter)
	}

	// Rules are enforced: an ECDSA CSR against an RSA-only template.
	policy = ca.TemplatePolicy{ID: "rsa-only", AllowedAlgorithms: []string{"RSA"}}
	w := post(h, rstAs(csrForTemplate(t, tmplOID, 1), "urn:uuid:p2"), "Negotiate good", nil)
	if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "algorithm") {
		t.Fatalf("algorithm violation: got %d %s", w.Code, w.Body.String())
	}

	// No template named: the one-year default, no policy.
	plain := issuedFrom(t, post(h, rstAs(hostileCSR(t), "urn:uuid:p3"), "Negotiate good", nil))
	if d := plain.NotAfter.Sub(plain.NotBefore); d < 365*24*time.Hour || d > 365*24*time.Hour+6*time.Minute {
		t.Fatalf("default validity %v", d)
	}
}
