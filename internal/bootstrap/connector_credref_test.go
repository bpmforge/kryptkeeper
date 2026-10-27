// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Sec-scan C-02/C-01/C-03/C-11: connector create binds only credentials the
// caller may use, pins ambient cloud auth to the real endpoints, and the
// listing scrubs health detail.

func postConnector(t *testing.T, mux *http.ServeMux, typ, cfg, credRef string) (int, string) {
	t.Helper()
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]string{
		"name": typ + "-x", "type": typ, "config_json": cfg, "credential_ref": credRef,
	})
	return rec.Code, rec.Body.String()
}

func TestConnectorCreateCredentialRefChecks(t *testing.T) {
	creds := &upstreamTestCreds{
		payloads: map[string]string{"ok": `{"api_key":"k"}`, "foreign": `{"api_key":"k"}`, "tok": `{"token":"t"}`, "iam": `{"service_account_json":"{}"}`},
		meta: map[string]OutboundCredentialMeta{
			"foreign": {ID: "foreign", CredentialType: CredentialTypeAPIToken, Tenant: "other"},
			"tok":     {ID: "tok", CredentialType: CredentialTypeAPIToken, Tenant: DefaultTenant},
			"iam":     {ID: "iam", CredentialType: CredentialTypeCloudIAM, Tenant: DefaultTenant},
		},
	}
	mux, _, audit := newUpstreamTestMux(t, creds)
	dc := `{"organization_id":1}`
	gcp := `{"project":"p","location":"l","ca_pool":"c"}`

	if code, _ := postConnector(t, mux, "digicert", dc, "ok"); code != http.StatusCreated {
		t.Fatalf("known credential: %d", code)
	}
	code, body := postConnector(t, mux, "digicert", dc, "missing")
	if code != http.StatusBadRequest || !strings.Contains(body, "credential_ref does not name a credential you may use") {
		t.Fatalf("unknown credential: %d %s", code, body)
	}
	// Wrong-type credential for a cloud kind gets the same uniform answer.
	code, body2 := postConnector(t, mux, "gcp_cas", gcp, "tok")
	if code != http.StatusBadRequest || !strings.Contains(body2, "credential_ref does not name a credential you may use") {
		t.Fatalf("api_token for gcp_cas: %d %s", code, body2)
	}
	if code, _ := postConnector(t, mux, "gcp_cas", gcp, "iam"); code != http.StatusCreated {
		t.Fatalf("cloud_iam for gcp_cas: %d", code)
	}
	var failures int
	for _, e := range audit.entries {
		if e.Action == "connector.create" && e.Outcome == AuditOutcomeFailure {
			failures++
		}
	}
	if failures < 2 {
		t.Errorf("want failure audit rows for refused creates, got %d", failures)
	}

	// Foreign-tenant credential is refused for a tenant-scoped principal.
	pd := AuthPrincipal{ID: "u", Tenant: "acme", TenantScoped: true}
	t.Setenv("MULTI_TENANCY", "on")
	if connectorCredentialUsable(context.Background(), creds, pd, ConnectorRecord{Type: "digicert", CredentialRef: "foreign"}) {
		t.Error("foreign tenant credential must not be usable")
	}
	if connectorCredentialUsable(context.Background(), creds, pd, ConnectorRecord{Type: "digicert", CredentialRef: "ok"}) {
		t.Error("default-tenant credential must not be usable by another tenant")
	}
}

func TestConnectorCreateCredentialRefNeedsStore(t *testing.T) {
	mux, _, _ := newUpstreamTestMux(t, nil)
	code, _ := postConnector(t, mux, "digicert", `{"organization_id":1}`, "ok")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("nil credential store: %d", code)
	}
}

func TestAmbientAuthPinnedToRealEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, typ, cfg string
		ok             bool
	}{
		{"gcp ambient default", "gcp_cas", `{"project":"p","location":"l","ca_pool":"c","auth":"ambient"}`, true},
		{"gcp ambient real", "gcp_cas", `{"project":"p","location":"l","ca_pool":"c","auth":"ambient","base_url":"https://privateca.googleapis.com/"}`, true},
		{"gcp ambient attacker", "gcp_cas", `{"project":"p","location":"l","ca_pool":"c","auth":"ambient","base_url":"https://evil.example"}`, false},
		{"gcp sa custom base", "gcp_cas", `{"project":"p","location":"l","ca_pool":"c","auth":"service_account","base_url":"https://proxy.example"}`, true},
		{"aws ambient endpoint", "aws_pca", `{"certificate_authority_arn":"a","region":"r","auth":"ambient","endpoint_url":"https://evil.example"}`, false},
		{"aws ambient plain", "aws_pca", `{"certificate_authority_arn":"a","region":"r","auth":"ambient"}`, true},
		{"aws static endpoint", "aws_pca", `{"certificate_authority_arn":"a","region":"r","endpoint_url":"https://pca.internal"}`, true},
	} {
		err := validateUpstreamConnector(ConnectorRecord{Type: tc.typ, ConfigJSON: tc.cfg, CredentialRef: "c"})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestConnectorUsesAmbientAuth(t *testing.T) {
	if !connectorUsesAmbientAuth(ConnectorRecord{Type: "aws_pca", ConfigJSON: `{"auth":"ambient"}`}) ||
		!connectorUsesAmbientAuth(ConnectorRecord{Type: "gcp_cas", ConfigJSON: `{"auth":"ambient"}`}) {
		t.Error("ambient aws/gcp must be detected")
	}
	if connectorUsesAmbientAuth(ConnectorRecord{Type: "vault_pki", ConfigJSON: `{"auth":"ambient"}`}) ||
		connectorUsesAmbientAuth(ConnectorRecord{Type: "gcp_cas", ConfigJSON: `{}`}) {
		t.Error("non-ambient must not be detected")
	}
}

func TestConnectorListScrubsHealthDetail(t *testing.T) {
	creds := &upstreamTestCreds{payloads: map[string]string{"cv": `{"token":"vault-token"}`}}
	mux, store, _ := newUpstreamTestMux(t, creds)
	// Unreachable upstream whose error text may carry a URL; the list must run
	// the same scrubber as /test.
	if _, err := store.Create(context.Background(), ConnectorRecord{ID: "conn-s", Name: "v", Type: "vault_pki",
		ConfigJSON: `{"base_url":"http://127.0.0.1:1","role":"web"}`, CredentialRef: "cv"}); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, mux, http.MethodGet, "/api/v1/connectors", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var resp struct {
		Data []connectorListEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Data) != 1 {
		t.Fatalf("decode: %v %s", err, rec.Body.String())
	}
	if d := resp.Data[0].Health.Detail; d != scrubUpstreamError(d) {
		t.Errorf("list detail not scrubbed: %q", d)
	}
}
