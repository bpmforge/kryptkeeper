// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/wstep"
)

func defaultTemplates() []Template {
	return []Template{
		{
			Name:          "WebServer",
			OID:           "1.3.6.1.4.1.311.21.8.1",
			DisplayName:   "Web Server",
			SchemaVersion: 2,
			MinKeySize:    2048,
		},
		{
			Name:          "UserAuth",
			OID:           "1.3.6.1.4.1.311.21.8.2",
			DisplayName:   "User Authentication",
			SchemaVersion: 2,
			MinKeySize:    2048,
		},
	}
}

func getPoliciesSOAP(action string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action>%s</a:Action>
  </s:Header>
  <s:Body>
    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client><lastUpdate/><preferredLanguage/></client>
      <requestFilter/>
    </GetPolicies>
  </s:Body>
</s:Envelope>`, action)
}

// signedIn stands in for a completed Kerberos exchange by a domain machine,
// the caller the default (machine) templates are offered to.
func signedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(wstep.WithIdentity(r.Context(), wstep.IdentityForPrincipal("WS01$", "CORP.EXAMPLE"))))
	})
}

// doPost sends body as an authenticated caller unless srv already has an
// authenticator of its own.
func doPost(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	if srv.authenticate == nil {
		srv.WithAuthenticator(signedIn)
	}
	if srv.caCertDER == nil {
		srv.WithIssuer(testCACert(t), "https://hub.corp.example:8443/wstep")
	}
	req := httptest.NewRequest(http.MethodPost, "/xcep", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

// --- Method enforcement ---

func TestXCEPHandler_MethodNotAllowed(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return nil, nil }, "")
	req := httptest.NewRequest(http.MethodGet, "/xcep", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- SOAP fault for unknown action ---

func TestXCEPHandler_UnknownAction(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetCerts"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 SOAP fault, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "s:Fault") {
		t.Error("response does not contain SOAP Fault")
	}
}

// --- Invalid SOAP envelope ---

func TestXCEPHandler_InvalidSOAP(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, "<notsoap>garbage</notsoap>")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid SOAP, got %d", rr.Code)
	}
}

// --- Happy path: valid GetPolicies ---

func TestXCEPHandler_GetPolicies_WellFormedXML(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	for _, want := range []string{"Envelope", "Body", "GetPoliciesResponse"} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing element %q", want)
		}
	}
}

func TestXCEPHandler_GetPolicies_ContainsPolicyID(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "my-custom-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	if !strings.Contains(rr.Body.String(), "my-custom-policy") {
		t.Errorf("response does not contain policyID: %s", rr.Body.String())
	}
}

func TestXCEPHandler_GetPolicies_ContainsTemplateNames(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	body := rr.Body.String()
	for _, name := range []string{"WebServer", "UserAuth"} {
		if !strings.Contains(body, name) {
			t.Errorf("response missing template name %q", name)
		}
	}
}

func TestXCEPHandler_GetPolicies_ContainsOIDs(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	body := rr.Body.String()
	for _, oid := range []string{"1.3.6.1.4.1.311.21.8.1", "1.3.6.1.4.1.311.21.8.2"} {
		if !strings.Contains(body, oid) {
			t.Errorf("response missing OID %q", oid)
		}
	}
}

func TestXCEPHandler_GetPolicies_ContentTypeSOAP(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/soap+xml") {
		t.Errorf("Content-Type = %q, want application/soap+xml", ct)
	}
}

func TestXCEPHandler_GetPolicies_ResponseActionHeader(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return defaultTemplates(), nil }, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	if !strings.Contains(rr.Body.String(), "GetPoliciesResponse") {
		t.Error("SOAP action header does not reference GetPoliciesResponse")
	}
}

// --- Empty template list ---

func TestXCEPHandler_EmptyTemplateList(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return []Template{}, nil }, "empty-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with empty template list, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"Envelope", "Body", "GetPoliciesResponse"} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing element %q", want)
		}
	}
}

// --- Default policy ID ---

func TestNewServer_DefaultPolicyID(t *testing.T) {
	srv := NewServer(func() ([]Template, error) { return []Template{}, nil }, "")
	if srv.policyID != "kryptkeeper-default-policy" {
		t.Errorf("policyID = %q, want %q", srv.policyID, "kryptkeeper-default-policy")
	}
}

// --- Template error ---

func TestXCEPHandler_TemplateError_ReturnsFault(t *testing.T) {
	srv := NewServer(func() ([]Template, error) {
		return nil, fmt.Errorf("database offline")
	}, "test-policy")
	rr := doPost(t, srv, getPoliciesSOAP("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 fault on template error, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "s:Fault") {
		t.Error("expected SOAP fault in response")
	}
}
