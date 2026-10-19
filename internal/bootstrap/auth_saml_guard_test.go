// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

type samlGuardHarness struct {
	t       *testing.T
	mux     *http.ServeMux
	auth    *Authenticator
	sigCtx  *dsig.SigningContext
	idpCert *x509.Certificate
}

func newSAMLGuardHarness(t *testing.T, allowIdPInitiated string) *samlGuardHarness {
	t.Helper()
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	auth := newTestSAMLAuthenticator(t, idpCert)
	// newTestSAMLAuthenticator opens the legacy IdP-initiated path; these
	// tests choose the setting explicitly.
	t.Setenv("APP_SAML_ALLOW_IDP_INITIATED", allowIdPInitiated)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "active"},
	}}, stubAuditProvider{})
	return &samlGuardHarness{t: t, mux: mux, auth: auth, sigCtx: testSAMLSigningContext(t, idpKey, idpCert), idpCert: idpCert}
}

// startLogin drives the SP-initiated redirect and returns the AuthnRequest ID
// the hub recorded.
func (h *samlGuardHarness) startLogin() string {
	h.t.Helper()
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/login", nil))
	if rec.Code != http.StatusFound {
		h.t.Fatalf("saml login = %d (%s)", rec.Code, rec.Body.String())
	}
	h.auth.hardening.saml.mu.Lock()
	defer h.auth.hardening.saml.mu.Unlock()
	if len(h.auth.hardening.saml.requests) != 1 {
		h.t.Fatalf("expected exactly one recorded AuthnRequest ID, got %d", len(h.auth.hardening.saml.requests))
	}
	for id := range h.auth.hardening.saml.requests {
		return id
	}
	return ""
}

func (h *samlGuardHarness) response(assertionID, inResponseTo string) string {
	h.t.Helper()
	p := validSAMLAssertionParams(assertionID, "viewer@example.com", "viewer@example.com", time.Now())
	p.InResponseTo = inResponseTo
	assertionXML := buildSAMLAssertionXML(h.t, p)
	responseXML := buildSAMLResponseXML(h.t, "response-"+assertionID, testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	return encodeSAMLResponse(h.t, signResponseEnvelope(h.t, h.sigCtx, responseXML))
}

func TestSAMLACS_SPInitiated_RequiresIssuedInResponseTo(t *testing.T) {
	h := newSAMLGuardHarness(t, "")
	id := h.startLogin()

	// A response answering some other request is refused...
	if rec := postSAMLResponse(t, h.mux, h.response("assertion-wrong", "_never-issued")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong InResponseTo = %d, want 401", rec.Code)
	} else {
		assertNoSessionCookie(t, rec)
	}
	// ...and did not consume the genuine request.
	rec := postSAMLResponse(t, h.mux, h.response("assertion-ok", id))
	if rec.Code != http.StatusFound || sessionCookieFrom(rec) == nil {
		t.Fatalf("SP-initiated login with the issued request ID = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestSAMLACS_ReplayedResponseRefused(t *testing.T) {
	h := newSAMLGuardHarness(t, "")
	id := h.startLogin()
	resp := h.response("assertion-replay", id)

	if rec := postSAMLResponse(t, h.mux, resp); rec.Code != http.StatusFound {
		t.Fatalf("first use = %d", rec.Code)
	}
	rec := postSAMLResponse(t, h.mux, resp)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed SAMLResponse = %d, want 401", rec.Code)
	}
	assertNoSessionCookie(t, rec)
}

func TestSAMLACS_ReplayedAssertionRefusedEvenWhenIdPInitiatedAllowed(t *testing.T) {
	h := newSAMLGuardHarness(t, "true")
	resp := h.response("assertion-idp-replay", "")
	if rec := postSAMLResponse(t, h.mux, resp); rec.Code != http.StatusFound {
		t.Fatalf("first IdP-initiated use = %d", rec.Code)
	}
	if rec := postSAMLResponse(t, h.mux, resp); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed IdP-initiated assertion = %d, want 401", rec.Code)
	}
}

func TestSAMLACS_IdPInitiatedRefusedUnlessEnabled(t *testing.T) {
	for _, off := range []string{"", "false", "0", "no"} {
		h := newSAMLGuardHarness(t, off)
		rec := postSAMLResponse(t, h.mux, h.response("assertion-unsolicited", ""))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("APP_SAML_ALLOW_IDP_INITIATED=%q: unsolicited response = %d, want 401", off, rec.Code)
		}
		assertNoSessionCookie(t, rec)
	}
	h := newSAMLGuardHarness(t, "true")
	if rec := postSAMLResponse(t, h.mux, h.response("assertion-unsolicited", "")); rec.Code != http.StatusFound {
		t.Fatalf("APP_SAML_ALLOW_IDP_INITIATED=true: unsolicited response = %d, want 302", rec.Code)
	}
}

func TestSAMLACS_RelayStateOpenRedirectNeutralised(t *testing.T) {
	h := newSAMLGuardHarness(t, "true")
	for i, relay := range []string{`/\evil.example`, "//evil.example", "https://evil.example"} {
		form := "RelayState=" + url.QueryEscape(relay) + "&SAMLResponse=" + url.QueryEscape(h.response("assertion-relay-"+strconv.Itoa(i), ""))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
			t.Fatalf("RelayState %q: %d Location=%q, want 302 to /", relay, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestSAMLGuard_RequestIDsAreSingleUseExpiringAndBounded(t *testing.T) {
	var g samlGuardState
	now := time.Now()
	if !g.issueRequest("r1", now) {
		t.Fatal("issue")
	}
	if !g.consumeRequest("r1", now.Add(time.Minute)) {
		t.Fatal("first consume must succeed")
	}
	if g.consumeRequest("r1", now.Add(time.Minute)) {
		t.Fatal("request IDs are single-use")
	}
	g.issueRequest("r2", now)
	if g.consumeRequest("r2", now.Add(samlRequestTTL+time.Second)) {
		t.Fatal("an expired request ID must not match")
	}
	for i := 0; i < maxPendingSAMLRequests; i++ {
		if !g.issueRequest("fill-"+strconv.Itoa(i), now) {
			t.Fatalf("table refused entry %d before the cap", i)
		}
	}
	if g.issueRequest("over", now) {
		t.Fatal("the pending-request table must be bounded")
	}
	if !g.issueRequest("after-expiry", now.Add(samlRequestTTL+time.Second)) {
		t.Fatal("expired entries must be swept so the table drains")
	}
}

func TestSAMLGuard_AssertionReplayCacheHonoursNotOnOrAfterAndCap(t *testing.T) {
	var g samlGuardState
	now := time.Now()
	exp := now.Add(5 * time.Minute)
	if !g.acceptAssertion("a1", exp, now) {
		t.Fatal("first sighting")
	}
	if g.acceptAssertion("a1", exp, now.Add(time.Minute)) {
		t.Fatal("replay inside NotOnOrAfter must be refused")
	}
	if !g.acceptAssertion("a1", exp, exp.Add(time.Second)) {
		t.Fatal("after NotOnOrAfter the entry has expired (and the assertion is invalid anyway)")
	}
	for i := 0; i < maxSAMLReplayEntries; i++ {
		g.acceptAssertion("fill-"+strconv.Itoa(i), now.Add(time.Hour), now)
	}
	if g.acceptAssertion("over", now.Add(time.Hour), now) {
		t.Fatal("a full replay cache must refuse new assertions, not evict old ones")
	}
}

func TestSAMLACS_OversizeBodyRefusedBeforeParsing(t *testing.T) {
	h := newSAMLGuardHarness(t, "true")
	// A valid, signed response padded past the cap must be refused: the
	// limit applies before any parsing or signature work.
	form := url.Values{
		"SAMLResponse": {h.response("assertion-oversize", "")},
		"pad":          {strings.Repeat("A", samlACSMaxBodyBytes)},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("oversize ACS body = %d, want 401", rec.Code)
	}
	assertNoSessionCookie(t, rec)
}
