// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/sshkeys"
)

// A01S-4: the SSH policy is part of the template — validated on create and
// replace, persisted, returned in the API's JSON shape, and clearable.
func TestTemplateSSHPolicyAPIRoundTrip(t *testing.T) {
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
	tpl := func(name, sshPolicy string) string {
		extra := ""
		if sshPolicy != "" {
			extra = `,"ssh_policy":` + sshPolicy
		}
		return `{"name":"` + name + `","display_name":"` + name + `","key_usage":["digitalSignature"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA"],"validity_period":"P1D","active":true` + extra + `}`
	}
	good := `{"cert_types":["user","host"],"allowed_principals":["deploy","ops"],"host_patterns":["*.corp.example","build01.corp.example"],"max_ttl_hours":8}`

	rec := do(http.MethodPost, "/api/v1/templates", tpl("ssh-tpl", good), "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with ssh_policy: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID        string `json:"id"`
			SSHPolicy *struct {
				CertTypes         []string `json:"cert_types"`
				AllowedPrincipals []string `json:"allowed_principals"`
				HostPatterns      []string `json:"host_patterns"`
				MaxTTLHours       float64  `json:"max_ttl_hours"`
			} `json:"ssh_policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Data.SSHPolicy == nil {
		t.Fatalf("response lacks ssh_policy: %v %s", err, rec.Body.String())
	}
	sp := created.Data.SSHPolicy
	if len(sp.CertTypes) != 2 || len(sp.AllowedPrincipals) != 2 || len(sp.HostPatterns) != 2 || sp.MaxTTLHours != 8 {
		t.Fatalf("ssh_policy shape wrong: %+v", sp)
	}

	if got := do(http.MethodGet, "/api/v1/templates/"+created.Data.ID, "", ""); !strings.Contains(got.Body.String(), `"ssh_policy":{"cert_types":["user","host"]`) {
		t.Fatalf("GET lacks ssh_policy: %s", got.Body.String())
	}
	plain := do(http.MethodPost, "/api/v1/templates", tpl("plain", ""), "")
	if plain.Code != http.StatusCreated || strings.Contains(plain.Body.String(), "ssh_policy") {
		t.Fatalf("plain template: %d %s", plain.Code, plain.Body.String())
	}

	for name, bad := range map[string]string{
		"wildcard principal": `{"cert_types":["user"],"allowed_principals":["*"],"max_ttl_hours":8}`,
		"no principals":      `{"cert_types":["user"],"max_ttl_hours":8}`,
		"ttl over ceiling":   `{"cert_types":["user"],"allowed_principals":["a"],"max_ttl_hours":25}`,
		"bad host pattern":   `{"cert_types":["host"],"host_patterns":["a.*.example"],"max_ttl_hours":1}`,
		"no types":           `{"allowed_principals":["a"],"max_ttl_hours":1}`,
	} {
		r := do(http.MethodPost, "/api/v1/templates", tpl("bad-"+strings.ReplaceAll(name, " ", "-"), bad), "")
		if r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "invalid ssh policy") {
			t.Errorf("%s: %d %s, want 400 invalid ssh policy", name, r.Code, r.Body.String())
		}
	}

	put := do(http.MethodPut, "/api/v1/templates/"+created.Data.ID, tpl("ssh-tpl", `{"cert_types":["user"],"allowed_principals":["deploy"],"max_ttl_hours":4}`), "1")
	if put.Code != http.StatusOK || !strings.Contains(put.Body.String(), `"allowed_principals":["deploy"]`) {
		t.Fatalf("replace: %d %s", put.Code, put.Body.String())
	}
	cleared := do(http.MethodPut, "/api/v1/templates/"+created.Data.ID, tpl("ssh-tpl", ""), "2")
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), "ssh_policy") {
		t.Fatalf("clear: %d %s", cleared.Code, cleared.Body.String())
	}
	bad := do(http.MethodPut, "/api/v1/templates/"+created.Data.ID, tpl("ssh-tpl", `{"cert_types":["user"],"allowed_principals":["root*"],"max_ttl_hours":4}`), "3")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("replace with invalid policy: %d", bad.Code)
	}
}

func TestFileTemplateProviderPersistsSSHPolicy(t *testing.T) {
	t.Setenv("APP_TEMPLATE_FILE", filepath.Join(t.TempDir(), "templates.json"))
	p := NewTemplateProviderFromEnv()
	created, err := p.CreateTemplate(context.Background(), TemplateUpsertRequest{
		Name: "ssh", DisplayName: "SSH", KeyUsage: []string{"digitalSignature"},
		ExtendedKeyUsage: []string{"clientAuth"}, AllowedAlgorithms: []string{"ECDSA"},
		ValidityPeriod: "P1D", Active: true,
		SSHPolicy: &sshkeys.Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"deploy"}, MaxTTLHours: 8},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, found, err := NewTemplateProviderFromEnv().GetTemplate(context.Background(), created.ID)
	if err != nil || !found || got.SSHPolicy == nil || got.SSHPolicy.AllowedPrincipals[0] != "deploy" {
		t.Fatalf("ssh_policy not persisted: %+v found=%v err=%v", got, found, err)
	}
	_, err = p.CreateTemplate(context.Background(), TemplateUpsertRequest{
		Name: "ssh2", DisplayName: "SSH2", KeyUsage: []string{"digitalSignature"},
		ExtendedKeyUsage: []string{"clientAuth"}, AllowedAlgorithms: []string{"ECDSA"},
		ValidityPeriod: "P1D", Active: true,
		SSHPolicy: &sshkeys.Policy{CertTypes: []string{"user"}, AllowedPrincipals: []string{"*"}, MaxTTLHours: 8},
	})
	if !errors.Is(err, errTemplateInvalidCreate) {
		t.Fatalf("invalid policy accepted by the provider: %v", err)
	}
}
