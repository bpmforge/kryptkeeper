// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock Azure Key Vault (REST api-version 7.4 secrets) and the Microsoft
// identity token endpoint for the azure-keyvault plugin (W27-28). The secret
// bundle shapes (id, value, attributes.enabled) follow the Key Vault REST
// reference; reading a disabled version is 403 as Key Vault answers.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

const azureClientSecret = "azkv-client-secret-123"

type azkvDevice struct {
	ts *httptest.Server
	*verStore
}

func newAzkvDevice(t *testing.T) *azkvDevice {
	d := &azkvDevice{verStore: newVerStore(t, NewCert(t, "azkv-initial"), NewCert(t, "azkv-stale"))}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	return d
}

func (d *azkvDevice) Reset()               { d.mu.Lock(); d.reset(); d.mu.Unlock() }
func (d *azkvDevice) FailNext(step string) { d.failNext(step) }
func (d *azkvDevice) Served() string       { d.mu.Lock(); defer d.mu.Unlock(); return d.servedLocked() }

func (d *azkvDevice) Env() delivery.Env {
	return anyHostEnv(d.ts, map[string]string{"vault_url": "https://example.com", "tenant_id": "tenant-1", "client_id": "client-1", "client_secret": azureClientSecret},
		[]string{"client_secret"}, map[string]string{"secret_name": "shop-cert"})
}

func azVersionID(n int) string { return fmt.Sprintf("%032x", n) }

func (d *azkvDevice) bundle(n int, value string) map[string]any {
	return map[string]any{"value": value, "id": "https://example.com/secrets/shop-cert/" + azVersionID(n),
		"attributes": map[string]any{"enabled": d.enabled[n-1], "created": 1493938410}}
}

func (d *azkvDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != azureClientSecret || r.PostForm.Get("scope") != "https://vault.azure.net/.default" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		reply(map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": "az-token"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer az-token" || r.URL.Query().Get("api-version") != "7.4" {
		http.Error(w, `{"error":{"code":"Unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method == "GET" && r.URL.Path == "/secrets" {
		reply(map[string]any{"value": []any{}})
		return
	}
	if len(parts) < 2 || parts[0] != "secrets" || parts[1] != "shop-cert" {
		http.NotFound(w, r)
		return
	}
	n := d.latest()
	if len(parts) == 3 {
		n = 0
		for i := 1; i <= d.latest(); i++ {
			if azVersionID(i) == parts[2] {
				n = i
			}
		}
	}
	switch r.Method {
	case "GET":
		if n == 0 {
			http.Error(w, `{"error":{"code":"SecretNotFound"}}`, http.StatusNotFound)
			return
		}
		pem, ok := d.readLocked(n)
		if !ok {
			http.Error(w, `{"error":{"code":"Forbidden"}}`, http.StatusForbidden)
			return
		}
		reply(d.bundle(n, pem))
	case "PUT":
		var b struct{ Value string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		v, ok := d.writeLocked(b.Value)
		if !ok {
			http.Error(w, `{"error":{"code":"InternalServerError"}}`, http.StatusInternalServerError)
			return
		}
		reply(d.bundle(v, b.Value))
	case "PATCH":
		var b struct {
			Attributes struct {
				Enabled *bool `json:"enabled"`
			} `json:"attributes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if n == 0 || b.Attributes.Enabled == nil || *b.Attributes.Enabled || !d.disableLocked(n) {
			http.Error(w, `{"error":{"code":"InternalServerError"}}`, http.StatusInternalServerError)
			return
		}
		reply(d.bundle(n, ""))
	default:
		http.NotFound(w, r)
	}
}

func TestAzureKeyVaultPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/azure-keyvault"))
	if p.Manifest().Verification != abi.VerificationReadback {
		t.Fatal("azure-keyvault plugin must declare read-back verification")
	}
	Suite(t, p, newAzkvDevice(t))
}
