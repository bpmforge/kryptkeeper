// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// pluginDevice is the example plugin's HTTPS device API (plugins/example),
// reached as https://example.com so TLS is verified against httptest's
// certificate.
type pluginDevice struct {
	ts      *httptest.Server
	mu      sync.Mutex
	certs   map[string]string
	keys    map[string]string
	binding string
}

func newPluginDevice(t *testing.T) *pluginDevice {
	d := &pluginDevice{certs: map[string]string{"old": "none"}, keys: map[string]string{}, binding: "old"}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer dev-token-0123456789" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.URL.Path == "/api/status":
		case r.Method == http.MethodPost && r.URL.Path == "/api/certs":
			d.certs[body["name"]], d.keys[body["name"]] = body["cert_pem"], body["key_pem"]
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/binding":
			_ = json.NewEncoder(w).Encode(map[string]string{"cert": d.binding})
		case r.Method == http.MethodPut && r.URL.Path == "/api/binding":
			d.binding = body["cert"]
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(d.ts.Close)
	return d
}

func (d *pluginDevice) client() *http.Client {
	addr := d.ts.Listener.Addr().String()
	tr := d.ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr}
}

func (d *pluginDevice) served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	rest := []byte(d.certs[d.binding])
	b, _ := pem.Decode(rest)
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

// W20-20: a renewal for an install_mode "plugin" target goes through the
// enabled plugin to the device, the hub verifies what it serves, and the
// run is audited.
func TestPluginTargetRenewalEndToEnd(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	mgr := NewDeliveryPluginManager(db, false, nil, nil)
	wasm, _ := examplePlugin(t)
	if _, err := mgr.Install(ctx, manifestVariant(t, "1.0.0", nil), wasm, "", "admin"); err != nil {
		t.Fatalf("install: %v", err)
	}

	issue := func(cn string) string {
		issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
			CAID: getFirstCAID(t, engine), CSRPEM: generateTestCSRPEM(t, cn, cn), TemplateID: "file-backed-default", TeamID: "team-plugin",
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return issued.CertificateItem.FingerprintSHA256
	}
	dev := newPluginDevice(t)
	audit := &scepRecordingAudit{}
	exec := NewRenewalExecutor(provider, &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-plugin", CredentialType: CredentialTypeAPIToken},
		payload: []byte(`{"base_url":"https://example.com","token":"dev-token-0123456789","unrelated":"dropped"}`),
	}).WithPluginDeliverer(mgr, audit)
	exec.pushClient = dev.client()
	exec.verifier = func(context.Context, string) (string, error) { return dev.served(), nil }
	target := ManagedTarget{ID: "tgt-plugin", Name: "Edge VIP", Host: "vip.example.com", InstallMode: "plugin",
		CredentialRef: "cred-plugin", PluginID: "kryptkeeper.example-device", PluginSettings: map[string]string{"listener": "vip-443"}}

	// Not yet enabled: refused before a serial is spent.
	fp := issue("plugin-a.example.com")
	if _, err := exec.ExecuteRenewal(ctx, fp, target, RenewalInstallProfile{}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("disabled plugin: %v", err)
	}
	if after, _, _ := provider.GetCertificate(ctx, fp); after.SuccessorFP != nil {
		t.Fatal("a refused plugin renewal spent a serial")
	}

	if err := mgr.enable(ctx, "kryptkeeper.example-device", "1.0.0", "approver"); err != nil {
		t.Fatal(err)
	}

	// A missing required target setting is refused before renewal too.
	noListener := target
	noListener.PluginSettings = nil
	if _, err := exec.ExecuteRenewal(ctx, fp, noListener, RenewalInstallProfile{}); err == nil || !strings.Contains(err.Error(), "plugin_settings.listener") {
		t.Fatalf("missing setting: %v", err)
	}

	res, err := exec.ExecuteRenewal(ctx, fp, target, RenewalInstallProfile{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Renewed || res.InstallOutcome != "installed_verified" || !res.Verified {
		t.Fatalf("expected a verified plugin delivery: %+v", res)
	}
	if !strings.Contains(dev.keys["edge-vip"], "PRIVATE KEY") {
		t.Fatal("the granted plugin did not deliver the key to the device")
	}

	var pushRow *AuditEntry
	for i, e := range audit.entries {
		if e.Action == "delivery_plugin.push" {
			pushRow = &audit.entries[i]
		}
		if strings.Contains(e.ChangeSummary, "dev-token-0123456789") || strings.Contains(e.ChangeSummary, "PRIVATE KEY") {
			t.Fatalf("audit carries a secret: %+v", e)
		}
	}
	if pushRow == nil || pushRow.Outcome != "success" || !strings.Contains(pushRow.ChangeSummary, "version=1.0.0") || !strings.Contains(pushRow.ChangeSummary, "verified=true") {
		t.Fatalf("push audit row: %+v", pushRow)
	}
}

func TestPluginTargetNeedsPluginID(t *testing.T) {
	if err := validatePluginTarget("plugin", ""); err == nil {
		t.Error("plugin target without plugin_id accepted")
	}
	if err := validatePluginTarget("f5", "kryptkeeper.example-device"); err == nil {
		t.Error("non-plugin target with plugin_id accepted")
	}
	if err := validatePluginTarget("plugin", "kryptkeeper.example-device"); err != nil {
		t.Errorf("valid plugin target refused: %v", err)
	}
}

// The migrated schema stores and returns a plugin target (000068).
func TestPluginTargetPersists(t *testing.T) {
	db := setupIntegrationDB(t)
	store := &sqliteManagedTargetStore{db: db}
	ctx := context.Background()
	created, err := store.Create(ctx, ManagedTarget{ID: "t1", Name: "vip", Host: "vip.example.com", DiscoveryMode: "none",
		InstallMode: "plugin", RenewalMethod: "acme", PluginID: "kryptkeeper.example-device",
		PluginSettings: map[string]string{"listener": "vip-443"}, Tenant: DefaultTenant, CreatedAt: "2026-10-08T00:00:00Z", UpdatedAt: "2026-10-08T00:00:00Z"})
	if err != nil {
		t.Fatalf("create plugin target: %v", err)
	}
	got, err := store.Get(ctx, created.ID)
	if err != nil || got.InstallMode != "plugin" || got.PluginID != "kryptkeeper.example-device" || got.PluginSettings["listener"] != "vip-443" {
		t.Fatalf("read back %+v err %v", got, err)
	}
}

func TestPluginHTTPClientTrust(t *testing.T) {
	if c, err := pluginHTTPClient(nil, ""); err != nil || c != nil {
		t.Fatalf("no CA: %v %v", c, err)
	}
	if _, err := pluginHTTPClient(nil, "not a pem"); err == nil {
		t.Fatal("a bad tls_ca_pem was accepted")
	}
	dev := newPluginDevice(t)
	der := dev.ts.Certificate().Raw
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	c, err := pluginHTTPClient(nil, caPEM)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, dev.ts.URL+"/api/status", nil)
	req.Header.Set("Authorization", "Bearer dev-token-0123456789")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("the CA from tls_ca_pem was not trusted: %v", err)
	}
	_ = resp.Body.Close()
}
