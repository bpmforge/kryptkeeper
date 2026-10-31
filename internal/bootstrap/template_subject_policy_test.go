// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixed subject RDNs are part of the template: validated on create and
// replace, persisted, returned, cleared by a PUT without them, and carried
// into the engine policy every issuing path uses.
func TestTemplateSubjectPolicyAPIRoundTrip(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	filePath := filepath.Join(t.TempDir(), "templates.json")
	if err := os.WriteFile(filePath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_TEMPLATE_FILE", filePath)
	auth := NewAuthenticatorFromEnv()
	templates := NewFileTemplateProviderFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForTemplate{}, stubAuditProviderForTemplate{}, stubCAProviderForTemplate{}, templates, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

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
	tpl := func(name, sp string) string {
		extra := ""
		if sp != "" {
			extra = `,"subject_policy":` + sp
		}
		return `{"name":"` + name + `","display_name":"` + name + `","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","active":true` + extra + `}`
	}
	good := `{"fixed_rdns":[{"type":"DC","value":"foo"},{"type":"DC","value":"bar"}]}`

	rec := do(http.MethodPost, "/api/v1/templates", tpl("acme-dc", good), "")
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"subject_policy":{"fixed_rdns":[{"type":"DC","value":"foo"},{"type":"DC","value":"bar"}]}`) {
		t.Fatalf("create with subject_policy: %d %s", rec.Code, rec.Body.String())
	}
	id := between(rec.Body.String(), `"id":"`, `"`)

	item, found, err := templates.GetTemplate(t.Context(), id)
	if err != nil || !found {
		t.Fatalf("get: %v %v", found, err)
	}
	pol := TemplatePolicy(item)
	if pol.Subject == nil || len(pol.Subject.FixedRDNs) != 2 {
		t.Fatalf("engine policy lacks the fixed RDNs: %+v", pol.Subject)
	}

	for name, bad := range map[string]string{
		"CN fixed":  `{"fixed_rdns":[{"type":"CN","value":"x"}]}`,
		"dotted DC": `{"fixed_rdns":[{"type":"DC","value":"foo.bar"}]}`,
		"empty":     `{"fixed_rdns":[{"type":"O","value":""}]}`,
	} {
		r := do(http.MethodPost, "/api/v1/templates", tpl("bad-"+strings.ReplaceAll(name, " ", "-"), bad), "")
		if r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "subject_policy:") {
			t.Errorf("%s: %d %s, want 400 naming subject_policy", name, r.Code, r.Body.String())
		}
	}

	put := do(http.MethodPut, "/api/v1/templates/"+id, tpl("acme-dc", ""), `"1"`)
	if put.Code != http.StatusOK || strings.Contains(put.Body.String(), "subject_policy") {
		t.Fatalf("PUT without subject_policy should clear it: %d %s", put.Code, put.Body.String())
	}
}
