// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type issuerEnv struct {
	mux   *http.ServeMux
	auth  *Authenticator
	store *memoryAuthorizedIssuerStore
	audit *expiryAudit
}

func newIssuerEnv(t *testing.T) *issuerEnv {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	e := &issuerEnv{mux: http.NewServeMux(), auth: newReportsTestAuth(t), store: &memoryAuthorizedIssuerStore{}, audit: &expiryAudit{}}
	registerAuthorizedIssuerHandlers(e.mux, e.auth, e.store, nil, e.audit)
	return e
}

func (e *issuerEnv) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, r)
	return rec
}

func (e *issuerEnv) key(t *testing.T, name, role, tenant string, scopes ...string) string {
	t.Helper()
	_, tok, err := e.auth.CreateAPIKey(name, name, role, scopes, "", tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func issuerBody(name, kind, value string) []byte {
	b, _ := json.Marshal(map[string]string{"name": name, "kind": kind, "value": value})
	return b
}

const adminToken = "reports-test-token"

func TestAuthorizedIssuerLifecycleAndAudit(t *testing.T) {
	e := newIssuerEnv(t)
	rec := e.do(bearerReq(adminToken, http.MethodPost, authorizedIssuerPrefix, issuerBody("Corp ADCS", "issuer_dn", "CN=Corp Issuing CA, O=Corp")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data AuthorizedIssuer `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Data.ID == "" || created.Data.Kind != "issuer_dn" || created.Data.CreatedBy == "" {
		t.Fatalf("created body: %s", rec.Body.String())
	}
	if e.audit.count(auditAuthorizedIssuerCreate, AuditOutcomeSuccess) != 1 {
		t.Fatal("create success not audited")
	}

	if rec := e.do(bearerReq(adminToken, http.MethodPost, authorizedIssuerPrefix, issuerBody("again", "issuer_dn", "CN=Corp Issuing CA, O=Corp"))); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rec.Code)
	}

	rec = e.do(bearerReq(adminToken, http.MethodGet, authorizedIssuerPrefix, nil))
	var list struct {
		Data []AuthorizedIssuer `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Data) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	if rec := e.do(bearerReq(adminToken, http.MethodDelete, authorizedIssuerPrefix+"/"+created.Data.ID, nil)); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if e.audit.count(auditAuthorizedIssuerDelete, AuditOutcomeSuccess) != 1 {
		t.Fatal("delete success not audited")
	}
	if rec := e.do(bearerReq(adminToken, http.MethodDelete, authorizedIssuerPrefix+"/"+created.Data.ID, nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", rec.Code)
	}
	if e.audit.count(auditAuthorizedIssuerDelete, AuditOutcomeFailure) != 1 {
		t.Fatal("not-found delete must be audited as failure")
	}
}

func TestAuthorizedIssuerValidationIsAuditedAndRejected(t *testing.T) {
	e := newIssuerEnv(t)
	for name, body := range map[string][]byte{
		"empty body":         nil,
		"no name":            issuerBody("", "issuer_dn", "CN=x"),
		"bad kind":           issuerBody("n", "wildcard", "*"),
		"dn without =":       issuerBody("n", "issuer_dn", "Corp CA"),
		"short spki":         issuerBody("n", "spki_sha256", "abcd"),
		"ca_cert not PEM":    issuerBody("n", "ca_cert", "not a certificate"),
		"ca_cert end entity": issuerBody("n", "ca_cert", string(pemOf(trustIssue(t, nil, "leaf.test", false).cert))),
	} {
		before := e.audit.count(auditAuthorizedIssuerCreate, AuditOutcomeFailure)
		rec := e.do(bearerReq(adminToken, http.MethodPost, authorizedIssuerPrefix, body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if e.audit.count(auditAuthorizedIssuerCreate, AuditOutcomeFailure) != before+1 {
			t.Errorf("%s: validation failure not audited", name)
		}
	}
	if n := len(e.store.rows); n != 0 {
		t.Fatalf("%d rows stored from invalid requests", n)
	}
}

func TestAuthorizedIssuerCACertAndSPKIAreCanonicalised(t *testing.T) {
	e := newIssuerEnv(t)
	root := trustIssue(t, nil, "Corp Root", true)
	rec := e.do(bearerReq(adminToken, http.MethodPost, authorizedIssuerPrefix, issuerBody("root", "ca_cert", "\n  "+string(pemOf(root.cert))+"  \n")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("ca_cert: %d %s", rec.Code, rec.Body.String())
	}
	upper := "AB:CD" + strings.Repeat("01", 30)
	rec = e.do(bearerReq(adminToken, http.MethodPost, authorizedIssuerPrefix, issuerBody("key", "spki_sha256", upper)))
	var out struct {
		Data AuthorizedIssuer `json:"data"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Data.Value != strings.ToLower(strings.ReplaceAll(upper, ":", "")) {
		t.Fatalf("spki: %d %s", rec.Code, rec.Body.String())
	}
	certs, rules := authorizedIssuerAnchors(e.store.rows)
	if len(certs) != 1 || len(rules) != 1 || rules[0].Kind != "spki_sha256" {
		t.Fatalf("anchors: %d certs %+v", len(certs), rules)
	}
}

func TestAuthorizedIssuerRBAC(t *testing.T) {
	e := newIssuerEnv(t)
	viewer := e.key(t, "viewer", "viewer", "", "certs:read")
	if rec := e.do(bearerReq(viewer, http.MethodPost, authorizedIssuerPrefix, issuerBody("n", "issuer_dn", "CN=x"))); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer create: %d", rec.Code)
	}
	if e.audit.count(auditAuthorizedIssuerCreate, AuditOutcomeDenied) != 1 {
		t.Fatal("denied create not audited")
	}
	if rec := e.do(bearerReq(viewer, http.MethodDelete, authorizedIssuerPrefix+"/x", nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer delete: %d", rec.Code)
	}
	if e.audit.count(auditAuthorizedIssuerDelete, AuditOutcomeDenied) != 1 {
		t.Fatal("denied delete not audited")
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, authorizedIssuerPrefix, nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if rec := e.do(bearerReq(adminToken, http.MethodPut, authorizedIssuerPrefix, nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d", rec.Code)
	}
}

func TestAuthorizedIssuerStoreUnavailableAnswers503(t *testing.T) {
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	mux, audit := http.NewServeMux(), &expiryAudit{}
	registerAuthorizedIssuerHandlers(mux, newReportsTestAuth(t), nil, nil, audit)
	for _, r := range []*http.Request{
		bearerReq(adminToken, http.MethodGet, authorizedIssuerPrefix, nil),
		bearerReq(adminToken, http.MethodPost, authorizedIssuerPrefix, issuerBody("n", "issuer_dn", "CN=x")),
		bearerReq(adminToken, http.MethodDelete, authorizedIssuerPrefix+"/x", nil),
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d", r.Method, rec.Code)
		}
	}
}

// Tenants never see or remove each other's declarations.
func TestAuthorizedIssuerTenantIsolation(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	e := newIssuerEnv(t)
	acme := e.key(t, "acme", "pki-admin", "acme", "*")
	globex := e.key(t, "globex", "pki-admin", "globex", "*")

	rec := e.do(bearerReq(acme, http.MethodPost, authorizedIssuerPrefix, issuerBody("acme ca", "issuer_dn", "CN=Acme CA")))
	var created struct {
		Data AuthorizedIssuer `json:"data"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &created) != nil {
		t.Fatalf("acme create: %d %s", rec.Code, rec.Body.String())
	}
	if e.store.rows[0].Tenant != "acme" {
		t.Fatalf("stored tenant = %q", e.store.rows[0].Tenant)
	}
	count := func(tok string) int {
		var l struct {
			Data []AuthorizedIssuer `json:"data"`
		}
		rec := e.do(bearerReq(tok, http.MethodGet, authorizedIssuerPrefix, nil))
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &l) != nil {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		return len(l.Data)
	}
	if count(acme) != 1 || count(globex) != 0 {
		t.Fatalf("acme sees %d, globex sees %d", count(acme), count(globex))
	}
	if rec := e.do(bearerReq(globex, http.MethodDelete, authorizedIssuerPrefix+"/"+created.Data.ID, nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: %d", rec.Code)
	}
	if e.audit.count(auditAuthorizedIssuerDelete, AuditOutcomeDenied) != 1 || len(e.store.rows) != 1 {
		t.Fatal("cross-tenant delete must be denied, audited and leave the row")
	}
	// The same declaration in another tenant is independent.
	if rec := e.do(bearerReq(globex, http.MethodPost, authorizedIssuerPrefix, issuerBody("same", "issuer_dn", "CN=Acme CA"))); rec.Code != http.StatusCreated {
		t.Fatalf("globex create: %d", rec.Code)
	}
	if count(adminToken) != 2 {
		t.Fatal("an unscoped administrator sees every tenant")
	}
	if rec := e.do(bearerReq(acme, http.MethodDelete, authorizedIssuerPrefix+"/"+created.Data.ID, nil)); rec.Code != http.StatusOK {
		t.Fatalf("own delete: %d", rec.Code)
	}
}
