// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

type stubCAService struct{}

func (stubCAService) CreateRootCA(string, pkix.Name, keystore.Algorithm, time.Duration) (*ca.CA, error) {
	return nil, nil
}
func (stubCAService) CreateIntermediateCA(string, pkix.Name, keystore.Algorithm, string, time.Duration) (*ca.CA, error) {
	return nil, nil
}
func (stubCAService) ImportCA(string, []byte) (*ca.CA, error)      { return nil, nil }
func (stubCAService) ImportCAChain(string, []byte) (*ca.CA, error) { return nil, nil }
func (stubCAService) IssueCertificate(string, ca.IssuanceRequest) (*ca.IssuedCertificate, error) {
	return nil, nil
}
func (stubCAService) GetCA(string) (*ca.CA, error)        { return nil, nil }
func (stubCAService) GetCAChain(string) ([]*ca.CA, error) { return nil, nil }
func (stubCAService) ListCAs() ([]*ca.CA, error)          { return nil, nil }
func (stubCAService) UpdateCAStatus(string, string) error { return nil }
func (stubCAService) RotateCA(string, ca.RotateCAOptions) (ca.RotateCAResult, error) {
	return ca.RotateCAResult{}, nil
}

func TestNewServer(t *testing.T) {
	s := NewServer(stubCAService{}, "ca-root-id")
	if s == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestHandlerRejectsNonSOAP(t *testing.T) {
	s := NewServer(stubCAService{}, "ca-root-id")
	h := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/wstep", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("expected non-200, got %d", rec.Code)
	}
}

func TestHandlerReturnsSoapFaultForMalformedBody(t *testing.T) {
	s := NewServer(stubCAService{}, "ca-root-id").WithAuthenticator(asIdentity(aliceID))
	h := s.Handler()

	body := strings.NewReader("<invalid>not soap</invalid>")
	req := httptest.NewRequest(http.MethodPost, "/wstep", body)
	req.Header.Set("Content-Type", "application/soap+xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("expected non-200 for malformed SOAP, got %d", rec.Code)
	}
}

// newTestCAEngine creates a real in-memory CA engine with a root CA for testing.
func newTestCAEngine(t *testing.T) (ca.Service, string) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-wstep-passphrase-32chars!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	rootCA, err := engine.CreateRootCA("Test Root CA", pkix.Name{
		CommonName:   "Test Root CA",
		Organization: []string{"Test"},
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	return engine, rootCA.ID
}

// buildWSTEPRequest builds a WS-Trust RequestSecurityToken SOAP envelope
// containing a base64-encoded PKCS#10 CSR.
func buildWSTEPRequest(csrDER []byte) string {
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wst:BinarySecurityToken>%s</wst:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`, csrB64)
}

func TestHandlerIssuesCertificateFromCSR(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	s := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID))
	h := s.Handler()

	// Generate a client key and CSR.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "wstep-test-client"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	soapBody := buildWSTEPRequest(csrDER)
	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(soapBody))
	req.Header.Set("Content-Type", "application/soap+xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "soap+xml") {
		t.Errorf("expected soap+xml content-type, got %s", rec.Header().Get("Content-Type"))
	}

	cert := issuedFrom(t, rec)
	// The CSR asked for wstep-test-client; the authenticated caller is alice.
	if cert.Subject.CommonName != "alice" {
		t.Errorf("unexpected CN %q", cert.Subject.CommonName)
	}
}

func TestHandlerUnknownAction(t *testing.T) {
	s := NewServer(stubCAService{}, "ca-1").WithAuthenticator(asIdentity(aliceID))
	h := s.Handler()

	body := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action>http://example.com/UnknownAction</a:Action>
  </s:Header>
  <s:Body><x/></s:Body>
</s:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "Fault") {
		t.Errorf("expected SOAP fault for unknown action, got: %s", rec.Body.String())
	}
}

func TestHandlerInvalidBase64CSR(t *testing.T) {
	s := NewServer(stubCAService{}, "ca-1").WithAuthenticator(asIdentity(aliceID))
	h := s.Handler()

	body := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:BinarySecurityToken>!!!not-base64!!!</wst:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "Fault") {
		t.Errorf("expected SOAP fault for invalid base64, got: %s", rec.Body.String())
	}
}

func TestHandlerInvalidCSRBytes(t *testing.T) {
	s := NewServer(stubCAService{}, "ca-1").WithAuthenticator(asIdentity(aliceID))
	h := s.Handler()

	invalidCSRB64 := base64.StdEncoding.EncodeToString([]byte("not-a-csr"))
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:BinarySecurityToken>%s</wst:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`, invalidCSRB64)

	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "Fault") {
		t.Errorf("expected SOAP fault for invalid CSR, got: %s", rec.Body.String())
	}
}

func TestIsWSTEPAction(t *testing.T) {
	cases := []struct {
		action string
		want   bool
	}{
		{"http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep", true},
		{"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/RequestSecurityToken", true},
		{"http://example.com/enrollment/RST/renewCertificate", true},
		{"http://example.com/UnknownAction", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isWSTEPAction(tc.action)
		if got != tc.want {
			t.Errorf("isWSTEPAction(%q) = %v, want %v", tc.action, got, tc.want)
		}
	}
}

func TestHandlerReturnsFaultForMissingCSR(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	s := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID))
	h := s.Handler()

	soapBody := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(soapBody))
	req.Header.Set("Content-Type", "application/soap+xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("expected non-200 for missing CSR, got 200")
	}
	if !strings.Contains(rec.Body.String(), "Fault") {
		t.Errorf("expected SOAP fault in response body, got: %s", rec.Body.String())
	}
}

// buildWSTEPRequestWithTokenType is like buildWSTEPRequest but uses a custom TokenType.
func buildWSTEPRequestWithTokenType(csrDER []byte, tokenType string) string {
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)
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
</s:Envelope>`, tokenType, csrB64)
}

func newTestCSR(t *testing.T) ([]byte, *x509.CertificateRequest) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "template-policy-test"},
	}, k)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return der, csr
}

func TestHandlerWithTemplateLookup_PolicyViolation(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	csrDER, _ := newTestCSR(t)

	const templateOID = "1.3.6.1.4.1.311.21.8.99999"
	lookup := func(tokenType string) (TemplateRef, bool) {
		if tokenType == templateOID {
			// WSTEP issues client-auth certificates; a template that only
			// allows server-auth must refuse them (W20-09). A short
			// MaxValidity is no longer a violation: it becomes the issued
			// validity (TestTemplatePolicyGovernsWSTEPIssuance).
			return userTemplate(ca.TemplatePolicy{
				ID:          "server-only",
				AllowedEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}), true
		}
		return TemplateRef{}, false
	}

	s := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID)).WithTemplateLookup(lookup)
	h := s.Handler()

	body := buildWSTEPRequestWithTokenType(csrDER, templateOID)
	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("expected SOAP fault for policy violation, got 200")
	}
	if !strings.Contains(rec.Body.String(), "Fault") || !strings.Contains(rec.Body.String(), "extended_key_usage") {
		t.Errorf("expected a SOAP fault naming the EKU violation, got: %s", rec.Body.String())
	}
}

func TestHandlerWithTemplateLookup_PolicyPass(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	csrDER, _ := newTestCSR(t)

	const templateOID = "1.3.6.1.4.1.311.21.8.11111"
	lookup := func(tokenType string) (TemplateRef, bool) {
		if tokenType == templateOID {
			return userTemplate(ca.TemplatePolicy{
				ID:                "permissive",
				AllowedAlgorithms: []string{"ECDSA"},
				MaxValidity:       2 * 365 * 24 * time.Hour,
			}), true
		}
		return TemplateRef{}, false
	}

	s := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID)).WithTemplateLookup(lookup)
	h := s.Handler()

	body := buildWSTEPRequestWithTokenType(csrDER, templateOID)
	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid policy, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerWithTemplateLookup_UnknownTokenType_NoPolicy(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	csrDER, _ := newTestCSR(t)

	lookup := func(_ string) (TemplateRef, bool) { return TemplateRef{}, false }
	s := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID)).WithTemplateLookup(lookup)
	h := s.Handler()

	// Unknown OID — lookup returns false → issuance proceeds without policy.
	body := buildWSTEPRequestWithTokenType(csrDER, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when no policy matched, got %d: %s", rec.Code, rec.Body.String())
	}
}

type recordedIssue struct {
	caID, source string
	cn           string
	templateID   string
}

type fakeRecorder struct{ got []recordedIssue }

func (f *fakeRecorder) RecordIssuedCertificate(_ context.Context, caID string, cert *x509.Certificate, _ []byte, source string) error {
	f.got = append(f.got, recordedIssue{caID: caID, source: source, cn: cert.Subject.CommonName})
	return nil
}

// templateRecorder also takes the template, as the hub's recorder does.
type templateRecorder struct{ fakeRecorder }

func (f *templateRecorder) RecordIssuedCertificateWithTemplate(_ context.Context, caID string, cert *x509.Certificate, _ []byte, source, templateID string) error {
	f.got = append(f.got, recordedIssue{caID: caID, source: source, cn: cert.Subject.CommonName, templateID: templateID})
	return nil
}

// W20-15: the inventory row of a template-governed issuance names the
// template; one with no template records through the plain method.
func TestHandlerRecordsGoverningTemplate(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	const templateOID = "1.3.6.1.4.1.311.21.8.22222"
	lookup := func(tokenType string) (TemplateRef, bool) {
		if tokenType == templateOID {
			return userTemplate(ca.TemplatePolicy{ID: "tpl-machine", AllowedAlgorithms: []string{"ECDSA"}}), true
		}
		return TemplateRef{}, false
	}
	rec := &templateRecorder{}
	h := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID)).WithTemplateLookup(lookup).WithIssuedRecorder(rec).Handler()

	for _, tokenType := range []string{templateOID, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"} {
		csrDER, _ := newTestCSR(t)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(buildWSTEPRequestWithTokenType(csrDER, tokenType))))
		if w.Code != http.StatusOK {
			t.Fatalf("TokenType %s: expected 200, got %d: %s", tokenType, w.Code, w.Body.String())
		}
	}
	if len(rec.got) != 2 {
		t.Fatalf("expected 2 recorded issuances, got %d", len(rec.got))
	}
	if g := rec.got[0]; g.templateID != "tpl-machine" || g.source != "wstep" || g.caID != caID {
		t.Errorf("templated issuance recorded %+v, want template tpl-machine", g)
	}
	if g := rec.got[1]; g.templateID != "" {
		t.Errorf("untemplated issuance recorded template %q", g.templateID)
	}
}

// Every certificate WSTEP issues must reach the inventory, like every other
// issuing protocol; an issuance the hub cannot reconstruct is a defect.
func TestHandlerRecordsIssuedCertificate(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	rec := &fakeRecorder{}
	h := NewServer(engine, caID).WithAuthenticator(asIdentity(aliceID)).WithIssuedRecorder(rec).Handler()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "recorded-client"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(buildWSTEPRequest(csrDER)))
	req.Header.Set("Content-Type", "application/soap+xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(rec.got) != 1 {
		t.Fatalf("expected exactly 1 recorded issuance, got %d", len(rec.got))
	}
	if g := rec.got[0]; g.caID != caID || g.source != "wstep" || g.cn != "alice" {
		t.Fatalf("recorded %+v, want caID=%s source=wstep cn=alice", g, caID)
	}
}

// userTemplate is an offered user template with policy p; the tests that use
// it authenticate as a user (alice).
func userTemplate(p ca.TemplatePolicy) TemplateRef {
	return TemplateRef{Name: p.ID, Enrollee: EnrolleeUser, Policy: &p}
}

// W20-17: WSTEP refuses a template of the other kind, whichever way it was
// named, and audits the refusal; XCEP never offers one, so this is a client
// naming a template it was not offered.
func TestHandlerRefusesTemplateOfOtherEnrolleeType(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	const machineOID, userOID = "1.3.6.1.4.1.311.21.8.33333", "1.3.6.1.4.1.311.21.8.44444"
	refs := map[string]TemplateRef{
		machineOID: {Name: "KKMachine", OID: machineOID, Enrollee: EnrolleeMachine, Policy: &ca.TemplatePolicy{ID: "tpl-m"}},
		userOID:    {Name: "KKUser", OID: userOID, Enrollee: EnrolleeUser, Policy: &ca.TemplatePolicy{ID: "tpl-u"}},
	}
	lookup := func(tokenType string) (TemplateRef, bool) { r, ok := refs[tokenType]; return r, ok }
	machineID := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")

	for _, tc := range []struct {
		name     string
		who      Identity
		oid      string
		wantCode int
	}{
		{"user asks for machine template", aliceID, machineOID, http.StatusInternalServerError},
		{"machine asks for user template", machineID, userOID, http.StatusInternalServerError},
		{"user asks for user template", aliceID, userOID, http.StatusOK},
		{"machine asks for machine template", machineID, machineOID, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var audited []AuditEvent
			h := NewServer(engine, caID).WithAuthenticator(asIdentity(tc.who)).WithTemplateLookup(lookup).
				WithAuditFunc(func(_ context.Context, ev AuditEvent) { audited = append(audited, ev) }).Handler()
			csrDER, _ := newTestCSR(t)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(buildWSTEPRequestWithTokenType(csrDER, tc.oid))))
			if tc.wantCode == http.StatusOK {
				if rec.Code != http.StatusOK {
					t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "cannot be issued to") {
				t.Fatalf("expected an enrollee-type fault, got %d: %s", rec.Code, rec.Body.String())
			}
			if len(audited) != 1 || audited[0].Outcome != "denied" || !strings.Contains(audited[0].Detail, "template") {
				t.Fatalf("expected one denied audit row, got %+v", audited)
			}
		})
	}
}

// SUP-A04-3: a template's name policy governs the names WSTEP signs (the
// authenticated machine's FQDN), so a template restricted to another zone
// refuses the enrolment and one covering the host's zone issues.
func TestHandlerEnforcesTemplateNamePolicy(t *testing.T) {
	engine, caID := newTestCAEngine(t)
	const oid = "1.3.6.1.4.1.311.21.8.55555"
	machine := IdentityForPrincipal("WS01$", "CORP.EXAMPLE")
	for _, tc := range []struct {
		name     string
		np       *ca.NamePolicy
		wantCode int
	}{
		{"host outside allowed zone", &ca.NamePolicy{AllowedDNSSuffixes: []string{".other.example"}}, http.StatusInternalServerError},
		{"host inside allowed zone", &ca.NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}, CNMustBeSAN: true}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(tokenType string) (TemplateRef, bool) {
				if tokenType != oid {
					return TemplateRef{}, false
				}
				return TemplateRef{Name: "np", OID: oid, Enrollee: EnrolleeMachine, Policy: &ca.TemplatePolicy{ID: "np", Names: tc.np}}, true
			}
			h := NewServer(engine, caID).WithAuthenticator(asIdentity(machine)).WithTemplateLookup(lookup).Handler()
			csrDER, _ := newTestCSR(t)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wstep", strings.NewReader(buildWSTEPRequestWithTokenType(csrDER, oid))))
			if rec.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode != http.StatusOK && !strings.Contains(rec.Body.String(), "dns_names") {
				t.Fatalf("fault does not name the DNS violation: %s", rec.Body.String())
			}
		})
	}
}
