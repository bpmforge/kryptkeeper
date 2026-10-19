// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock Azure for the azure plugin (W27-30): the Microsoft identity token
// endpoint, Key Vault certificate import (api-version 7.4) and ARM documents
// for an Application Gateway (2023-09-01) and a Front Door secret
// (2023-05-01). Requests are routed by Host. Both services serve the
// certificate on the public name, so the plugin is graded with the normal TLS
// verification: Served is the fingerprint of the Key Vault certificate
// version the binding references.

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

const (
	azConfSecret = "azure-conformance-secret-123"
	azSub        = "11111111-2222-3333-4444-555555555555"
	azGWPath     = "/subscriptions/" + azSub + "/resourceGroups/rg1/providers/Microsoft.Network/applicationGateways/gw1"
	azFDPath     = "/subscriptions/" + azSub + "/resourceGroups/rg1/providers/Microsoft.Cdn/profiles/prof1/secrets/sec1"
)

type azureDevice struct {
	ts       *httptest.Server
	mode     string
	mu       sync.Mutex
	versions map[string]string // KV certificate version -> leaf PEM
	bound    string            // version the binding references
	fresh    string            // version of the most recent import
	next     int
	fail     failSet
	initial  Cert
}

func azVersion(n int) string { return fmt.Sprintf("%032x", n) }

func newAzureDevice(t *testing.T, mode string) *azureDevice {
	d := &azureDevice{mode: mode, initial: NewCert(t, "azure-initial-"+mode)}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	d.Reset()
	return d
}

func (d *azureDevice) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.versions = map[string]string{azVersion(1): string(d.initial.CertPEM)}
	d.bound, d.fresh, d.next, d.fail = azVersion(1), "", 1, failSet{}
}

func (d *azureDevice) FailNext(step string) { d.mu.Lock(); d.fail[step] = true; d.mu.Unlock() }

func (d *azureDevice) Served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Fingerprint(d.versions[d.bound])
}

func (d *azureDevice) Env() delivery.Env {
	target := map[string]string{"mode": d.mode, "subscription_id": azSub, "resource_group": "rg1", "keyvault_cert_name": "shop-cert"}
	if d.mode == "appgw" {
		target["gateway_name"], target["ssl_certificate_name"] = "gw1", "web-cert"
	} else {
		target["profile_name"], target["secret_name"] = "prof1", "sec1"
	}
	return anyHostEnv(d.ts, map[string]string{"vault_url": "https://example.com", "tenant_id": "tenant-1", "client_id": "client-1", "client_secret": azConfSecret},
		[]string{"client_secret"}, target)
}

func (d *azureDevice) sid(version string) string {
	return "https://example.com/secrets/shop-cert/" + version
}

func (d *azureDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(status int, code string) {
		w.WriteHeader(status)
		reply(map[string]any{"error": map[string]string{"code": code}})
	}
	switch r.Host {
	case "login.microsoftonline.com":
		_ = r.ParseForm()
		scope := r.PostForm.Get("scope")
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" || r.PostForm.Get("client_secret") != azConfSecret ||
			(scope != "https://vault.azure.net/.default" && scope != "https://management.azure.com/.default") {
			fail(http.StatusUnauthorized, "invalid_client")
			return
		}
		reply(map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": "tok:" + scope})
	case "example.com":
		d.vault(w, r, reply, fail)
	case "management.azure.com":
		d.arm(w, r, reply, fail)
	default:
		http.NotFound(w, r)
	}
}

func (d *azureDevice) vault(w http.ResponseWriter, r *http.Request, reply func(any), fail func(int, string)) {
	if r.Header.Get("Authorization") != "Bearer tok:https://vault.azure.net/.default" || r.URL.Query().Get("api-version") != "7.4" {
		fail(http.StatusUnauthorized, "Unauthorized")
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/certificates":
		reply(map[string]any{"value": []any{}})
	case r.Method == "POST" && r.URL.Path == "/certificates/shop-cert/import":
		if d.fail.take("upload") {
			fail(http.StatusInternalServerError, "InternalServerError")
			return
		}
		var b struct{ Value string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		raw, err := base64.StdEncoding.DecodeString(b.Value)
		blk, rest := pem.Decode(raw)
		keyBlk, _ := pem.Decode(rest)
		if err != nil || blk == nil || keyBlk == nil || keyBlk.Type != "PRIVATE KEY" {
			fail(http.StatusBadRequest, "BadParameter")
			return
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			fail(http.StatusBadRequest, "BadParameter")
			return
		}
		d.next++
		ver := azVersion(d.next)
		d.versions[ver], d.fresh = string(pem.EncodeToMemory(blk)), ver
		reply(map[string]any{"id": "https://example.com/certificates/shop-cert/" + ver, "sid": d.sid(ver), "cer": base64.StdEncoding.EncodeToString(blk.Bytes)})
	default:
		http.NotFound(w, r)
	}
}

func (d *azureDevice) arm(w http.ResponseWriter, r *http.Request, reply func(any), fail func(int, string)) {
	if r.Header.Get("Authorization") != "Bearer tok:https://management.azure.com/.default" {
		fail(http.StatusUnauthorized, "AuthenticationFailed")
		return
	}
	isGW := r.URL.Path == azGWPath
	if !isGW && r.URL.Path != azFDPath {
		fail(http.StatusNotFound, "ResourceNotFound")
		return
	}
	switch r.Method {
	case "GET":
		if isGW {
			reply(map[string]any{"name": "gw1", "etag": "W/\"1\"", "properties": map[string]any{"provisioningState": "Succeeded",
				"sslCertificates": []any{map[string]any{"name": "web-cert", "properties": map[string]any{"keyVaultSecretId": d.sid(d.bound)}}}}})
			return
		}
		reply(map[string]any{"name": "sec1", "properties": map[string]any{"provisioningState": "Succeeded", "parameters": map[string]any{
			"type": "CustomerCertificate", "secretSource": map[string]any{"id": "/subscriptions/x/providers/Microsoft.KeyVault/vaults/v/secrets/shop-cert"},
			"secretVersion": d.bound, "useLatestVersion": false}}})
	case "PUT":
		var doc struct {
			Properties struct {
				SSLCertificates []struct {
					Name       string
					Properties struct {
						KeyVaultSecretID string `json:"keyVaultSecretId"`
					}
				} `json:"sslCertificates"`
				Parameters struct {
					SecretVersion    string `json:"secretVersion"`
					UseLatestVersion bool   `json:"useLatestVersion"`
				} `json:"parameters"`
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&doc)
		version := doc.Properties.Parameters.SecretVersion
		if isGW {
			if len(doc.Properties.SSLCertificates) != 1 || doc.Properties.SSLCertificates[0].Name != "web-cert" {
				fail(http.StatusBadRequest, "InvalidRequest")
				return
			}
			id := doc.Properties.SSLCertificates[0].Properties.KeyVaultSecretID
			version = id[strings.LastIndex(id, "/")+1:]
		} else if doc.Properties.Parameters.UseLatestVersion {
			fail(http.StatusBadRequest, "InvalidRequest")
			return
		}
		if _, ok := d.versions[version]; !ok {
			fail(http.StatusBadRequest, "InvalidRequest")
			return
		}
		step := "rollback"
		if version == d.fresh {
			step = "bind"
		}
		if d.fail.take(step) {
			fail(http.StatusInternalServerError, "InternalServerError")
			return
		}
		d.bound = version
		reply(map[string]any{"properties": map[string]any{"provisioningState": "Succeeded"}})
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func TestAzurePluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/azure"))
	for _, mode := range []string{"appgw", "frontdoor"} {
		t.Run(mode, func(t *testing.T) { Suite(t, p, newAzureDevice(t, mode)) })
	}
}
