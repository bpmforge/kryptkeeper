// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	testSAMLIDPIssuer = "https://idp.example.com/saml/metadata"
	testSAMLSPIssuer  = "https://kryptkeeper.example.com/saml/sp"
	testSAMLACSURL    = "https://kryptkeeper.example.com/api/v1/auth/saml/acs"
	testSAMLIDPSSOURL = "https://idp.example.com/saml/sso"
)

// generateTestSAMLIDPCert returns a self-signed RSA cert/key usable as the
// test IdP's signing identity -- the trusted root samlServiceProviderFromConfig
// wires into IDPCertificateStore, matched against goxmldsig's own
// verifyCertificate (validate.go), which also checks the cert's own
// NotBefore/NotAfter against the clock, hence the wide validity window here.
func generateTestSAMLIDPCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

func testSAMLSigningContext(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate) *dsig.SigningContext {
	t.Helper()
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		t.Fatalf("new signing context: %v", err)
	}
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	return ctx
}

type samlAssertionParams struct {
	ID                 string
	NameID             string
	Email              string
	Issuer             string
	Audience           string
	Recipient          string
	NotBefore          time.Time
	NotOnOrAfter       time.Time // Conditions -- the warning-only expiry (acceptance #3)
	ConfirmationExpiry time.Time // SubjectConfirmationData.NotOnOrAfter -- Validate()'s own hard-error expiry
	InResponseTo       string    // SubjectConfirmationData.InResponseTo; empty renders an unsolicited (IdP-initiated) assertion
	Groups             []string  // values of a "groups" attribute (W22-19); empty renders none
}

var samlAssertionTemplate = template.Must(template.New("assertion").Parse(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{.ID}}" Version="2.0" IssueInstant="{{.NotBefore}}">
  <saml:Issuer>{{.Issuer}}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{{.NameID}}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData{{if .InResponseTo}} InResponseTo="{{.InResponseTo}}"{{end}} NotOnOrAfter="{{.ConfirmationExpiry}}" Recipient="{{.Recipient}}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{{.NotBefore}}" NotOnOrAfter="{{.NotOnOrAfter}}">
    <saml:AudienceRestriction>
      <saml:Audience>{{.Audience}}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{{.NotBefore}}" SessionIndex="session-{{.ID}}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="Email">
      <saml:AttributeValue>{{.Email}}</saml:AttributeValue>
    </saml:Attribute>{{if .Groups}}
    <saml:Attribute Name="groups">{{range .Groups}}
      <saml:AttributeValue>{{.}}</saml:AttributeValue>{{end}}
    </saml:Attribute>{{end}}
  </saml:AttributeStatement>
</saml:Assertion>`))

// buildSAMLAssertionXML renders an unsigned <saml:Assertion> fragment. Every
// namespace it uses is declared locally rather than relying on inheriting
// one from wherever it ends up parented, matching the shape of gosaml2's own
// test fixtures (test_constants.go's rawResponse).
func buildSAMLAssertionXML(t *testing.T, p samlAssertionParams) string {
	t.Helper()
	data := struct {
		ID                 string
		NameID             string
		Email              string
		Issuer             string
		Audience           string
		Recipient          string
		NotBefore          string
		NotOnOrAfter       string
		ConfirmationExpiry string
		InResponseTo       string
		Groups             []string
	}{
		ID:                 p.ID,
		NameID:             p.NameID,
		Email:              p.Email,
		Issuer:             p.Issuer,
		Audience:           p.Audience,
		Recipient:          p.Recipient,
		NotBefore:          p.NotBefore.UTC().Format(time.RFC3339),
		NotOnOrAfter:       p.NotOnOrAfter.UTC().Format(time.RFC3339),
		ConfirmationExpiry: p.ConfirmationExpiry.UTC().Format(time.RFC3339),
		InResponseTo:       p.InResponseTo,
		Groups:             p.Groups,
	}
	var buf bytes.Buffer
	if err := samlAssertionTemplate.Execute(&buf, data); err != nil {
		t.Fatalf("render assertion template: %v", err)
	}
	return buf.String()
}

var samlResponseTemplate = template.Must(template.New("response").Parse(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{.ID}}" Version="2.0" IssueInstant="{{.IssueInstant}}" Destination="{{.Destination}}">
  <saml:Issuer>{{.Issuer}}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {{.Assertions}}
</samlp:Response>`))

func buildSAMLResponseXML(t *testing.T, id, destination, issuer string, assertionsXML ...string) string {
	t.Helper()
	data := struct {
		ID           string
		IssueInstant string
		Destination  string
		Issuer       string
		Assertions   string
	}{
		ID:           id,
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  destination,
		Issuer:       issuer,
		Assertions:   strings.Join(assertionsXML, "\n"),
	}
	var buf bytes.Buffer
	if err := samlResponseTemplate.Execute(&buf, data); err != nil {
		t.Fatalf("render response template: %v", err)
	}
	return buf.String()
}

// insertSignature signs el -- which must already be parented in its final
// document position, since gosaml2 validates via etreeutils.NSDetatch on the
// parented element and signing a detached copy risks a canonicalization
// namespace-context mismatch between sign time and validate time -- and
// appends the resulting <ds:Signature> as el's last child. goxmldsig locates
// a Signature purely by namespace+tag and its Reference URI (validate.go's
// findSignature/mapPathToElement), never by position, so this differs from
// the schema-conventional "right after Issuer" placement in appearance only.
func insertSignature(t *testing.T, ctx *dsig.SigningContext, el *etree.Element) {
	t.Helper()
	sigEl, err := ctx.ConstructSignature(el, true)
	if err != nil {
		t.Fatalf("construct signature: %v", err)
	}
	el.AddChild(sigEl)
}

// signResponseEnvelope parses rawXML and signs the Response element itself
// -- the document root, so no ancestor-namespace context ever applies.
func signResponseEnvelope(t *testing.T, ctx *dsig.SigningContext, rawXML string) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(rawXML); err != nil {
		t.Fatalf("parse response xml: %v", err)
	}
	insertSignature(t, ctx, doc.Root())
	return doc
}

// signAssertionInPlace parses rawXML (a full Response with one unsigned
// Assertion child) and signs the Assertion, leaving the Response envelope
// itself unsigned -- gosaml2 falls back to validating individually-signed
// assertions in that case (ValidateEncodedResponse), which is exactly the
// ResponseSignatureValidated == false scenario acceptance #3's third
// rejection covers.
//
// gosaml2 validates a nested assertion via etreeutils.NSDetatch, which
// REBUILDS the element's namespace attributes from scratch out of the full
// in-scope set walked from its ancestors (namespace.go's NSDetatch strips
// existing xmlns attrs, then re-adds every prefix in ctx.prefixes) -- so the
// detached copy carries xmlns:samlp (inherited from the parent Response)
// even though the Assertion element itself never declares it. Signing the
// raw parented element directly skips that step, so the digest would be
// computed over a different (undetached) attribute set than validation
// canonicalizes -- a guaranteed mismatch. Detaching before signing, exactly
// as validation detaches before verifying, keeps both sides consistent.
func signAssertionInPlace(t *testing.T, ctx *dsig.SigningContext, rawXML string) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(rawXML); err != nil {
		t.Fatalf("parse response xml: %v", err)
	}
	assertionEl := doc.Root().FindElement("./Assertion")
	if assertionEl == nil {
		t.Fatal("no Assertion element found to sign")
	}

	parentNSCtx, err := etreeutils.NSBuildParentContext(assertionEl)
	if err != nil {
		t.Fatalf("build parent namespace context: %v", err)
	}
	elNSCtx, err := parentNSCtx.SubContext(assertionEl)
	if err != nil {
		t.Fatalf("build element namespace context: %v", err)
	}
	detached, err := etreeutils.NSDetatch(elNSCtx, assertionEl)
	if err != nil {
		t.Fatalf("detach assertion: %v", err)
	}

	insertSignature(t, ctx, detached)

	assertionIndex := assertionEl.Index()
	doc.Root().RemoveChild(assertionEl)
	doc.Root().InsertChildAt(assertionIndex, detached)
	return doc
}

func encodeSAMLResponse(t *testing.T, doc *etree.Document) string {
	t.Helper()
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize response: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func testSAMLSPConfig(idpCert *x509.Certificate) authValidatorConfig {
	return authValidatorConfig{
		samlLoginEnabled:    true,
		samlIDPSSOURL:       testSAMLIDPSSOURL,
		samlIDPIssuer:       testSAMLIDPIssuer,
		samlSPIssuer:        testSAMLSPIssuer,
		samlACSURL:          testSAMLACSURL,
		samlAudience:        testSAMLSPIssuer,
		samlIDPCertificates: []*x509.Certificate{idpCert},
		loginSigning:        "signing-secret",
	}
}

// newTestSAMLAuthenticator builds a handler-ready Authenticator under a
// GENUINE SAML-only config -- samlLoginEnabled is the only login flag set,
// deliberately, matching the deployment this ticket actually ships
// (APP_SAML_LOGIN_ENABLED=true, password login and OIDC login both off).
//
// It does NOT set oidcLoginEnabled/loginEnabled to route around
// authenticateBootstrap's login-session-JWT gate (auth_bootstrap.go):
// exercising a genuine SAML-only config end-to-end is the point --
// cfg.anyLoginFlowEnabled() accepts samlLoginEnabled on its own (W6-13), so
// a SAML-only session now survives the request after the one that
// established it.
func newTestSAMLAuthenticator(t *testing.T, idpCert *x509.Certificate) *Authenticator {
	t.Helper()
	// The pre-FG-7 tests below post unsolicited (IdP-initiated) responses and
	// are about signatures, audiences and provisioning, not request binding;
	// the request/replay behaviour has its own tests in
	// auth_saml_guard_test.go, which turn this back off.
	t.Setenv("APP_SAML_ALLOW_IDP_INITIATED", "true")
	cfg := testSAMLSPConfig(idpCert)
	cfg.mode = "bootstrap"
	cfg.jwtIssuer = "kryptkeeper"
	cfg.jwtAudience = "kryptkeeper-clients"
	cfg.loginTTL = 5 * time.Minute
	cfg.refreshTTL = 10 * time.Minute
	cfg.samlPostLoginRedirectURL = "/"
	return &Authenticator{
		config:           cfg,
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}
}

func postSAMLResponse(t *testing.T, mux *http.ServeMux, encodedResponse string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"SAMLResponse": {encodedResponse}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kk_token" {
			return c
		}
	}
	return nil
}

func assertNoSessionCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if c := sessionCookieFrom(rec); c != nil {
		t.Fatalf("expected no kk_token session cookie to be set, got one (value len %d)", len(c.Value))
	}
}

func validSAMLAssertionParams(id, nameID, email string, now time.Time) samlAssertionParams {
	return samlAssertionParams{
		ID:                 id,
		NameID:             nameID,
		Email:              email,
		Issuer:             testSAMLIDPIssuer,
		Audience:           testSAMLSPIssuer,
		Recipient:          testSAMLACSURL,
		NotBefore:          now.Add(-1 * time.Hour),
		NotOnOrAfter:       now.Add(1 * time.Hour),
		ConfirmationExpiry: now.Add(1 * time.Hour),
	}
}

// TestSAMLLogin_BuildsAuthURL is acceptance #2's SP-initiated half: the
// literal SAMLServiceProvider.BuildAuthURL(relayState) call, reachable via
// GET /api/v1/auth/saml/login.
func TestSAMLLogin_BuildsAuthURL(t *testing.T) {
	_, idpCert := generateTestSAMLIDPCert(t)
	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (%s)", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location header: %v", err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != testSAMLIDPSSOURL {
		t.Fatalf("expected redirect to the configured IdP SSO URL %q, got %q", testSAMLIDPSSOURL, got)
	}
	if location.Query().Get("SAMLRequest") == "" {
		t.Fatal("expected a SAMLRequest parameter in the redirect")
	}
}

func TestSAMLLogin_ServiceUnavailableWhenNotConfigured(t *testing.T) {
	auth := &Authenticator{
		config:           authValidatorConfig{},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when saml login isn't configured, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestSAMLACS_HappyPath_EstablishesSessionAndDeniesAdminAction is acceptance
// #2 (ACS validates via RetrieveAssertionInfo) and acceptance #5 combined:
// the session established is the same one W6-02 issues, so a non-admin
// role's SAML session authenticates as that role on a subsequent request
// and is denied an admin action -- proving it never reaches
// authenticatePrincipal's raw-bootstrap-token branch.
//
// Runs against a genuine SAML-only config (newTestSAMLAuthenticator sets no
// other login flag), exercising authenticateBootstrap's login-session-JWT
// gate (auth_bootstrap.go) end-to-end now that it accepts cfg.samlLoginEnabled
// (W6-13).
func TestSAMLACS_HappyPath_EstablishesSessionAndDeniesAdminAction(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	assertionXML := buildSAMLAssertionXML(t, validSAMLAssertionParams("assertion-1", "viewer@example.com", "viewer@example.com", now))
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	doc := signResponseEnvelope(t, sigCtx, responseXML)
	encoded := encodeSAMLResponse(t, doc)

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "active"},
	}}, stubAuditProvider{})

	rec := postSAMLResponse(t, mux, encoded)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 on successful SAML login, got %d (%s)", rec.Code, rec.Body.String())
	}
	sessionCookie := sessionCookieFrom(rec)
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("expected the ACS callback to set a kk_token session cookie")
	}

	authzReq := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	authzReq.AddCookie(sessionCookie)
	authzRec := httptest.NewRecorder()
	mux.ServeHTTP(authzRec, authzReq)
	if authzRec.Code != http.StatusOK {
		t.Fatalf("authz-check with saml-issued session: expected 200, got %d (%s)", authzRec.Code, authzRec.Body.String())
	}
	var body struct {
		Authenticated bool   `json:"authenticated"`
		Principal     string `json:"principal"`
		Role          string `json:"role"`
	}
	if err := json.Unmarshal(authzRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode authz-check response: %v", err)
	}
	if !body.Authenticated || body.Principal != "user-1" || body.Role != "pki-viewer" {
		t.Fatalf("expected authenticated pki-viewer principal user-1, got %+v", body)
	}

	adminReq := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"principal_id":"someone","role":"pki-viewer"}`))
	adminReq.AddCookie(sessionCookie)
	adminRec := httptest.NewRecorder()
	mux.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a saml pki-viewer session attempting an admin action, got %d (%s)", adminRec.Code, adminRec.Body.String())
	}
}

func TestSAMLACS_DeprovisionedAccount_Denied(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	assertionXML := buildSAMLAssertionXML(t, validSAMLAssertionParams("assertion-1", "viewer@example.com", "viewer@example.com", now))
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	doc := signResponseEnvelope(t, sigCtx, responseXML)
	encoded := encodeSAMLResponse(t, doc)

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "deactivated"},
	}}, stubAuditProvider{})

	rec := postSAMLResponse(t, mux, encoded)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a deprovisioned account, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

func TestSAMLACS_UnprovisionedIdentity_Denied(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	assertionXML := buildSAMLAssertionXML(t, validSAMLAssertionParams("assertion-1", "nobody@example.com", "nobody@example.com", now))
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	doc := signResponseEnvelope(t, sigCtx, responseXML)
	encoded := encodeSAMLResponse(t, doc)

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{}, stubAuditProvider{})

	rec := postSAMLResponse(t, mux, encoded)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an identity with no provisioned account, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

// TestSAMLACS_ExpiredAssertion_WarningNotError_Rejected is acceptance #3's
// first mandatory rejection: RetrieveAssertionInfo returns a nil error for
// an expired assertion -- the expiry surfaces only on WarningInfo.InvalidTime
// -- so the ACS handler must check that field explicitly, not just err.
func TestSAMLACS_ExpiredAssertion_WarningNotError_Rejected(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	params := validSAMLAssertionParams("assertion-1", "viewer@example.com", "viewer@example.com", now)
	params.NotOnOrAfter = now.Add(-1 * time.Hour) // Conditions expired an hour ago...
	// ...while SubjectConfirmationData stays valid, so Validate()'s own hard
	// expiry check (a different field) does not turn this into a hard error
	// before we ever reach WarningInfo.
	assertionXML := buildSAMLAssertionXML(t, params)
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	doc := signResponseEnvelope(t, sigCtx, responseXML)
	encoded := encodeSAMLResponse(t, doc)

	sp := samlServiceProviderFromConfig(testSAMLSPConfig(idpCert))
	info, err := sp.RetrieveAssertionInfo(encoded)
	if err != nil {
		t.Fatalf("expected RetrieveAssertionInfo to succeed with a warning, not an error, for an expired assertion: %v", err)
	}
	if info.WarningInfo == nil || !info.WarningInfo.InvalidTime {
		t.Fatalf("expected WarningInfo.InvalidTime=true for an expired assertion, got %+v", info.WarningInfo)
	}

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "active"},
	}}, stubAuditProvider{})

	rec := postSAMLResponse(t, mux, encoded)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an expired assertion, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

// TestSAMLACS_WrongAudience_WarningNotError_Rejected is acceptance #3's
// second mandatory rejection, mirroring the expired-assertion case for
// WarningInfo.NotInAudience.
func TestSAMLACS_WrongAudience_WarningNotError_Rejected(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	params := validSAMLAssertionParams("assertion-1", "viewer@example.com", "viewer@example.com", now)
	params.Audience = "https://a-different-service-provider.example.com"
	assertionXML := buildSAMLAssertionXML(t, params)
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	doc := signResponseEnvelope(t, sigCtx, responseXML)
	encoded := encodeSAMLResponse(t, doc)

	sp := samlServiceProviderFromConfig(testSAMLSPConfig(idpCert))
	info, err := sp.RetrieveAssertionInfo(encoded)
	if err != nil {
		t.Fatalf("expected RetrieveAssertionInfo to succeed with a warning, not an error, for a wrong-audience assertion: %v", err)
	}
	if info.WarningInfo == nil || !info.WarningInfo.NotInAudience {
		t.Fatalf("expected WarningInfo.NotInAudience=true for a mismatched audience, got %+v", info.WarningInfo)
	}

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "active"},
	}}, stubAuditProvider{})

	rec := postSAMLResponse(t, mux, encoded)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an assertion addressed to a different audience, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

// TestSAMLACS_UnsignedResponseEnvelope_Rejected is acceptance #3's third
// mandatory rejection: an unsigned Response envelope whose lone Assertion IS
// individually signed and otherwise fully valid still leaves
// AssertionInfo.ResponseSignatureValidated false, and the ACS handler must
// reject on that alone.
func TestSAMLACS_UnsignedResponseEnvelope_Rejected(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	assertionXML := buildSAMLAssertionXML(t, validSAMLAssertionParams("assertion-1", "viewer@example.com", "viewer@example.com", now))
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, assertionXML)
	doc := signAssertionInPlace(t, sigCtx, responseXML) // Response envelope itself stays unsigned.
	encoded := encodeSAMLResponse(t, doc)

	sp := samlServiceProviderFromConfig(testSAMLSPConfig(idpCert))
	info, err := sp.RetrieveAssertionInfo(encoded)
	if err != nil {
		t.Fatalf("expected RetrieveAssertionInfo to succeed (the assertion itself is validly signed): %v", err)
	}
	if info.ResponseSignatureValidated {
		t.Fatal("expected ResponseSignatureValidated=false when only the assertion, not the response envelope, is signed")
	}

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "active"},
	}}, stubAuditProvider{})

	rec := postSAMLResponse(t, mux, encoded)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when the response envelope itself isn't signature-validated, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

// TestSAMLACS_SignatureWrapping_SecondAssertionElement_Rejected is
// acceptance #4's mandatory regression test: a response carrying a
// wrapped/second Assertion element must not yield a session. This is the
// exact shape of crewjam's CVE-2022-41912 ("accepts SAML responses
// containing multiple Assertion elements") and gosaml2's own GMS-2021-103
// lineage -- not a smoke test, but a real forged-identity payload spliced
// into an otherwise-legitimately-signed response.
func TestSAMLACS_SignatureWrapping_SecondAssertionElement_Rejected(t *testing.T) {
	idpKey, idpCert := generateTestSAMLIDPCert(t)
	sigCtx := testSAMLSigningContext(t, idpKey, idpCert)
	now := time.Now()

	legitAssertionXML := buildSAMLAssertionXML(t, validSAMLAssertionParams("assertion-legit", "viewer@example.com", "viewer@example.com", now))
	responseXML := buildSAMLResponseXML(t, "response-1", testSAMLACSURL, testSAMLIDPIssuer, legitAssertionXML)
	doc := signResponseEnvelope(t, sigCtx, responseXML) // legitimately signed by the "IdP"

	// The attacker cannot re-sign anything -- they splice an UNSIGNED,
	// forged Assertion carrying a different identity into the
	// ALREADY-SIGNED response as an additional direct child.
	forgedAssertionXML := buildSAMLAssertionXML(t, validSAMLAssertionParams("assertion-forged", "attacker@evil.example.com", "attacker@evil.example.com", now))
	forgedDoc := etree.NewDocument()
	if err := forgedDoc.ReadFromString(forgedAssertionXML); err != nil {
		t.Fatalf("parse forged assertion: %v", err)
	}
	legitAssertionEl := doc.Root().FindElement("./Assertion")
	if legitAssertionEl == nil {
		t.Fatal("no legitimate Assertion found in the signed response")
	}
	doc.Root().InsertChildAt(legitAssertionEl.Index(), forgedDoc.Root())
	tampered := encodeSAMLResponse(t, doc)

	sp := samlServiceProviderFromConfig(testSAMLSPConfig(idpCert))

	// Pins the vulnerability class at the library layer: a response
	// carrying a wrapped/second Assertion element must fail validation
	// outright.
	if _, err := sp.RetrieveAssertionInfo(tampered); err == nil {
		t.Fatal("expected RetrieveAssertionInfo to reject a response carrying a wrapped/second Assertion element")
	}

	// Proves the forged payload is a REAL attack, not inert tampering: a
	// throwaway SP with signature validation off -- never reachable from
	// production configuration -- reads the attacker's identity first.
	// This is the red-check for this test: it demonstrates what an
	// unprotected implementation would have done.
	unsafeSP := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      testSAMLIDPIssuer,
		ServiceProviderIssuer:       testSAMLSPIssuer,
		AssertionConsumerServiceURL: testSAMLACSURL,
		AudienceURI:                 testSAMLSPIssuer,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}},
		SkipSignatureValidation:     true,
	}
	unsafeInfo, err := unsafeSP.RetrieveAssertionInfo(tampered)
	if err != nil {
		t.Fatalf("expected the throwaway unsafe SP to accept the tampered response (demonstrating the attack is live): %v", err)
	}
	if unsafeInfo.NameID != "attacker@evil.example.com" {
		t.Fatalf("expected the unsafe SP to read the attacker's identity first, got %q", unsafeInfo.NameID)
	}

	auth := newTestSAMLAuthenticator(t, idpCert)
	mux := http.NewServeMux()
	registerAuthHandlersWithUsers(mux, auth, &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "viewer@example.com", Role: "pki-viewer", Status: "active"},
		{ID: "attacker", Email: "attacker@evil.example.com", Role: "pki-admin", Status: "active"},
	}}, stubAuditProvider{})
	rec := postSAMLResponse(t, mux, tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a signature-wrapped response, got %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSessionCookie(t, rec)
}

func TestSafeRelativeRedirect(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		fallback string
		want     string
	}{
		{"relative path kept", "/dashboard", "/", "/dashboard"},
		{"empty falls back", "", "/", "/"},
		{"absolute url rejected", "https://evil.example.com/", "/", "/"},
		{"protocol-relative url rejected", "//evil.example.com/", "/", "/"},
		{"bare path without leading slash rejected", "dashboard", "/", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeRelativeRedirect(tc.raw, tc.fallback); got != tc.want {
				t.Errorf("safeRelativeRedirect(%q, %q) = %q, want %q", tc.raw, tc.fallback, got, tc.want)
			}
		})
	}
}
