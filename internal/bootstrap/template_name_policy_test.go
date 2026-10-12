// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// SUP-A04-3: the name policy is part of the template — validated on create
// and replace, persisted, returned in the API shape, clearable.
func TestTemplateNamePolicyAPIRoundTrip(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	filePath := filepath.Join(t.TempDir(), "templates.json")
	if err := os.WriteFile(filePath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, NewFileTemplateProviderFromEnv(), NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	do := func(method, path, body, ifMatch string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	tpl := func(name, np string) string {
		extra := ""
		if np != "" {
			extra = `,"name_policy":` + np
		}
		return `{"name":"` + name + `","display_name":"` + name + `","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P1D","active":true` + extra + `}`
	}
	good := `{"allowed_dns_suffixes":[".corp.example"],"allowed_dns_names":["exact.example"],"allow_ip_sans":false,"allow_uri_sans":true,"allowed_uri_prefixes":["spiffe://prod.example/"],"cn_must_be_san":true}`

	rec := do(http.MethodPost, "/api/v1/templates", tpl("np-tpl", good), "")
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"name_policy":{"allowed_dns_suffixes":[".corp.example"]`) {
		t.Fatalf("create with name_policy: %d %s", rec.Code, rec.Body.String())
	}
	id := between(rec.Body.String(), `"id":"`, `"`)

	if got := do(http.MethodGet, "/api/v1/templates/"+id, "", ""); !strings.Contains(got.Body.String(), `"cn_must_be_san":true`) {
		t.Fatalf("GET lacks name_policy: %s", got.Body.String())
	}
	if plain := do(http.MethodPost, "/api/v1/templates", tpl("plain", ""), ""); plain.Code != http.StatusCreated || strings.Contains(plain.Body.String(), "name_policy") {
		t.Fatalf("template without name_policy changed shape: %d %s", plain.Code, plain.Body.String())
	}

	for name, bad := range map[string]string{
		"blank suffix":         `{"allowed_dns_suffixes":[" "]}`,
		"wildcard suffix":      `{"allowed_dns_suffixes":["*.example.com"]}`,
		"prefix without allow": `{"allowed_uri_prefixes":["spiffe://a/"]}`,
		"prefix not a uri":     `{"allow_uri_sans":true,"allowed_uri_prefixes":["a"]}`,
	} {
		r := do(http.MethodPost, "/api/v1/templates", tpl("bad-"+strings.ReplaceAll(name, " ", "-"), bad), "")
		if r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "name_policy:") {
			t.Errorf("%s: %d %s, want 400 naming name_policy", name, r.Code, r.Body.String())
		}
	}

	cleared := do(http.MethodPut, "/api/v1/templates/"+id, tpl("np-tpl", ""), "1")
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), "name_policy") {
		t.Fatalf("clear: %d %s", cleared.Code, cleared.Body.String())
	}
	if r := do(http.MethodPut, "/api/v1/templates/"+id, tpl("np-tpl", `{"allowed_dns_suffixes":["."]}`), "2"); r.Code != http.StatusBadRequest {
		t.Fatalf("replace with invalid policy: %d", r.Code)
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	return s[:strings.Index(s, b)]
}

func newNamePolicyProvider(t *testing.T, np *ca.NamePolicy) (CertificateProvider, string, *fakeTemplateProvider) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-name-policy-passphrase-32!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("NP Root", pkix.Name{CommonName: "NP Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	templates := &fakeTemplateProvider{templates: map[string]TemplateItem{
		"tpl-np": {ID: "tpl-np", Active: true, AllowedAlgorithms: []string{"ECDSA"}, ValidityPeriod: "24h", NamePolicy: np},
	}}
	return WithTemplateProvider(NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false), templates), root.ID, templates
}

// The API issuance path: SANs come from the CSR, so the template's name policy
// is what stops a requester naming a host outside it.
func TestIssueCertificateAPIPathEnforcesTemplateNamePolicy(t *testing.T) {
	np := &ca.NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}, CNMustBeSAN: true}
	provider, caID, _ := newNamePolicyProvider(t, np)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		csr  string
		ok   bool
	}{
		{"in suffix", generateTestCSRPEM(t, "a.corp.example", "a.corp.example"), true},
		{"SAN outside suffix", generateTestCSRPEM(t, "a.corp.example", "a.corp.example", "www.bank.example"), false},
		{"CN not among SANs", generateTestCSRPEM(t, "www.bank.example", "a.corp.example"), false},
		{"IP SAN refused", generateTestCSRPEMWithIP(t, "a.corp.example", "a.corp.example", "10.1.2.3"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-np", CSRPEM: tc.csr})
			if tc.ok && err != nil {
				t.Fatalf("expected issuance, got %v", err)
			}
			if !tc.ok && !errors.Is(err, ca.ErrPolicyViolation) {
				t.Fatalf("expected ErrPolicyViolation, got %v", err)
			}
		})
	}

	// A template with no name_policy is unchanged: any names issue.
	provider2, caID2, _ := newNamePolicyProvider(t, nil)
	if _, err := provider2.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID2, TemplateID: "tpl-np",
		CSRPEM: generateTestCSRPEMWithIP(t, "x.bank.example", "x.bank.example", "10.1.2.3")}); err != nil {
		t.Fatalf("template without name_policy refused: %v", err)
	}
}

// Renewal used to pass only TemplateID, so it escaped the template name
// policy. It now carries it (name policy only; see RenewCertificate).
func TestRenewCertificateEnforcesTemplateNamePolicy(t *testing.T) {
	provider, caID, templates := newNamePolicyProvider(t, nil)
	ctx := context.Background()
	first, err := provider.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-np",
		CSRPEM: generateTestCSRPEM(t, "a.corp.example", "a.corp.example")})
	if err != nil {
		t.Fatal(err)
	}

	// The template gains a name policy after the first issuance.
	tpl := templates.templates["tpl-np"]
	tpl.NamePolicy = &ca.NamePolicy{AllowedDNSSuffixes: []string{".corp.example"}}
	templates.templates["tpl-np"] = tpl

	_, err = provider.RenewCertificate(ctx, first.FingerprintSHA256, CertificateRenewRequest{
		CSRPEM: generateTestCSRPEM(t, "a.corp.example", "a.corp.example", "www.bank.example")})
	if !errors.Is(err, ca.ErrPolicyViolation) {
		t.Fatalf("renewal with an out-of-policy SAN: got %v, want ErrPolicyViolation", err)
	}
	if _, err = provider.RenewCertificate(ctx, first.FingerprintSHA256, CertificateRenewRequest{
		CSRPEM: generateTestCSRPEM(t, "a.corp.example", "a.corp.example")}); err != nil {
		t.Fatalf("compliant renewal refused: %v", err)
	}
}
