// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W38-08: ACME DNS-01 through a real first-party dns01 plugin (compiled to
// wasm, installed in a plugin manager on a migrated SQLite database), run by
// the real ACME connector against the repo's ACME server. The "vendor" is a
// local TLS stand-in shaped like the DigitalOcean DNS API; the ACME server's
// validator and the connector's propagation check both read what the plugin
// wrote there, so a challenge only passes if the plugin really published it.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/tests/plugins/conformance"
)

const vendorToken = "dop_v1_live-stand-in-token-0123456789abcdef"

// fakeDO is a DigitalOcean-shaped DNS API serving the zone example.test.
type fakeDO struct {
	standIn *standIn
	mu      sync.Mutex
	nextID  int
	recs    map[string][]doRec // fqdn -> records
	log     []string
	status  int // when non-zero, every request answers it (vendor outage)
}

type doRec struct {
	id    int
	value string
}

func newFakeDO(t *testing.T) *fakeDO {
	f := &fakeDO{recs: map[string][]doRec{}, nextID: 100}
	f.standIn = &standIn{ts: httptest.NewTLSServer(http.HandlerFunc(f.serve))}
	t.Cleanup(f.standIn.ts.Close)
	return f
}

func (f *fakeDO) lookup(name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	recs, ok := f.recs[strings.TrimSuffix(name, ".")]
	if !ok || len(recs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.value)
	}
	return out, nil
}

func (f *fakeDO) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.recs {
		n += len(r)
	}
	return n
}

func (f *fakeDO) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, r.Method+" "+r.URL.Path+" auth="+strconv.FormatBool(r.Header.Get("Authorization") == "Bearer "+vendorToken)+" host="+r.Host)
	if r.Header.Get("Authorization") != "Bearer "+vendorToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v2/domains"), "/"), "/")
	if parts[0] != "example.test" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case len(parts) == 1:
		_, _ = io.WriteString(w, `{"domain":{"name":"example.test"}}`)
	case len(parts) == 2 && r.Method == http.MethodPost:
		var b struct{ Type, Name, Data string }
		raw, _ := io.ReadAll(r.Body)
		if json.Unmarshal(raw, &b) != nil || b.Type != "TXT" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		f.nextID++
		fqdn := b.Name + ".example.test"
		f.recs[fqdn] = append(f.recs[fqdn], doRec{f.nextID, b.Data})
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"domain_record":{"id":`+strconv.Itoa(f.nextID)+`}}`)
	case len(parts) == 3 && r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(parts[2])
		for fqdn, recs := range f.recs {
			for i, rec := range recs {
				if rec.id == id {
					f.recs[fqdn] = append(recs[:i], recs[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// installDNSPlugin builds plugins/<name>, installs and enables it, and
// returns its id.
func installDNSPlugin(t *testing.T, mgr *DeliveryPluginManager, name, kind string) string {
	t.Helper()
	dir := repoDir("plugins/" + name)
	wasm := conformance.Build(t, dir)
	v, err := mgr.Install(context.Background(), conformance.PinManifest(t, dir, wasm), wasm, "", "admin")
	if err != nil {
		t.Fatalf("install %s: %v", name, err)
	}
	if v.Kind != kind {
		t.Fatalf("%s kind %q, want %q", name, v.Kind, kind)
	}
	if err := mgr.enable(context.Background(), v.PluginID, v.Version, "approver"); err != nil {
		t.Fatal(err)
	}
	return v.PluginID
}

type pluginDNSFixture struct {
	vendor   *fakeDO
	mgr      *DeliveryPluginManager
	pluginID string
	creds    *renewalFakeCredStore
	audit    *recordingAuditProvider
	conn     *acmeIssuerConnector
}

func newPluginDNSFixture(t *testing.T) *pluginDNSFixture {
	t.Helper()
	fx := &pluginDNSFixture{vendor: newFakeDO(t), audit: &recordingAuditProvider{}}
	fx.mgr = NewDeliveryPluginManager(notifyPluginDB(t), false, nil, nil)
	fx.pluginID = installDNSPlugin(t, fx.mgr, "digitalocean-dns", abi.KindDNS01)
	fx.creds = &renewalFakeCredStore{
		meta:    OutboundCredentialMeta{ID: "cred-do", CredentialType: CredentialTypeAPIToken},
		payload: []byte(`{"api_token":"` + vendorToken + `"}`),
	}

	// The CA validates against what the vendor really holds.
	upstream := newDNS01UpstreamWith(t, fx.vendor.lookup)
	cfg, _ := json.Marshal(acmeConnectorConfig{
		DirectoryURL: upstream + "/acme/directory", Challenge: "dns-01", DNSProvider: "plugin", DNSPropagation: "authoritative",
		DNSPluginID: fx.pluginID, DNSPluginCredential: "cred-do",
	})
	fx.conn = NewACMEIssuerConnector(ConnectorRecord{ID: "conn-plugin-dns", Type: "acme", ConfigJSON: string(cfg)}, nil, fx.creds).(*acmeIssuerConnector)
	fx.conn.allowLoopbackForTest = true
	fx.conn.dnsPluginHost = &dnsPluginHost{plugins: func() *DeliveryPluginManager { return fx.mgr }, audit: fx.audit, client: fx.vendor.standIn.client()}
	fx.conn.lookupNS = func(context.Context, string) ([]*net.NS, error) { return []*net.NS{{Host: "ns1.example.test."}}, nil }
	fx.conn.lookupTXT = func(_ context.Context, _, name string) ([]string, error) { return fx.vendor.lookup(name) }
	fx.conn.dnsInterval = 10 * time.Millisecond
	return fx
}

func (fx *pluginDNSFixture) issue(t *testing.T) (connectors.IssueResult, error) {
	t.Helper()
	return fx.conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")})
}

func (fx *pluginDNSFixture) auditActions(outcome AuditOutcome) []string {
	fx.audit.mu.Lock()
	defer fx.audit.mu.Unlock()
	var out []string
	for _, e := range fx.audit.entries {
		if e.Outcome == outcome {
			out = append(out, e.Action)
		}
	}
	return out
}

func TestACMEDNS01ThroughAPluginEndToEnd(t *testing.T) {
	fx := newPluginDNSFixture(t)
	res, err := fx.issue(t)
	if err != nil {
		t.Fatalf("issue through the plugin: %v", err)
	}
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatal("no certificate")
	}
	if n := fx.vendor.total(); n != 0 {
		t.Errorf("%d challenge records left at the vendor", n)
	}
	var methods []string
	for _, l := range fx.vendor.log {
		if strings.Contains(l, "auth=false") || !strings.Contains(l, "host=api.digitalocean.com") {
			t.Errorf("request not shaped as the vendor expects: %s", l)
		}
		methods = append(methods, strings.SplitN(l, " ", 2)[0])
	}
	if !contains(methods, "POST") || !contains(methods, "DELETE") {
		t.Errorf("vendor saw %v, want a create and a delete", fx.vendor.log)
	}
	got := fx.auditActions(AuditOutcomeSuccess)
	if !contains(got, "delivery_plugin.dns01_present") || !contains(got, "delivery_plugin.dns01_cleanup") {
		t.Errorf("audit actions %v", got)
	}
	fx.audit.mu.Lock()
	defer fx.audit.mu.Unlock()
	for _, e := range fx.audit.entries {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), vendorToken) {
			t.Errorf("audit row carries the vendor token: %s", raw)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestACMEDNS01PluginVendorOutageFailsWithoutLeavingRecords(t *testing.T) {
	fx := newPluginDNSFixture(t)
	fx.vendor.status = http.StatusInternalServerError
	_, err := fx.issue(t)
	if err == nil || !strings.Contains(err.Error(), "dns-01 plugin") || strings.Contains(err.Error(), vendorToken) {
		t.Fatalf("err %v", err)
	}
	if fx.vendor.total() != 0 {
		t.Fatal("records left behind")
	}
	if !contains(fx.auditActions(AuditOutcomeFailure), "delivery_plugin.dns01_present") {
		t.Errorf("a failed present must be audited: %v", fx.auditActions(AuditOutcomeFailure))
	}
}

func TestACMEDNS01PluginRejectedTokenNamesTheCauseNotTheToken(t *testing.T) {
	fx := newPluginDNSFixture(t)
	fx.creds.payload = []byte(`{"api_token":"dop_v1_wrong-token-0123456789"}`)
	_, err := fx.issue(t)
	if err == nil || !strings.Contains(err.Error(), "token was refused") || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("err %v", err)
	}
}

func TestACMEDNS01PluginFailsClosed(t *testing.T) {
	t.Run("credential of another tenant", func(t *testing.T) {
		fx := newPluginDNSFixture(t)
		fx.creds.meta.Tenant = "other-tenant"
		fx.conn.tenant = "acme-corp"
		_, err := fx.issue(t)
		if err == nil || !strings.Contains(err.Error(), `credential "cred-do" does not exist`) {
			t.Fatalf("err %v", err)
		}
		if len(fx.vendor.log) != 0 {
			t.Fatal("the vendor was contacted with another tenant's credential")
		}
	})
	t.Run("plugin not enabled", func(t *testing.T) {
		fx := newPluginDNSFixture(t)
		if err := fx.mgr.Disable(context.Background(), fx.pluginID); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.issue(t); err == nil || !strings.Contains(err.Error(), "dns-01 plugin") {
			t.Fatalf("err %v", err)
		}
		if len(fx.vendor.log) != 0 {
			t.Fatal("a disabled plugin ran")
		}
	})
	t.Run("plugins off", func(t *testing.T) {
		fx := newPluginDNSFixture(t)
		fx.conn.dnsPluginHost = &dnsPluginHost{plugins: func() *DeliveryPluginManager { return nil }}
		if _, err := fx.issue(t); err == nil || !strings.Contains(err.Error(), "turned off") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("plugin of another kind", func(t *testing.T) {
		fx := newPluginDNSFixture(t)
		notifyID := installDNSPlugin(t, fx.mgr, "pagerduty", abi.KindNotify)
		fx.conn.cfg.DNSPluginID = notifyID
		if _, err := fx.issue(t); err == nil || !strings.Contains(err.Error(), "not a dns01 plugin") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("no host wired", func(t *testing.T) {
		fx := newPluginDNSFixture(t)
		fx.conn.dnsPluginHost = nil
		sharedDNSPluginHost.Store(nil)
		if _, err := fx.issue(t); err == nil || !strings.Contains(err.Error(), "turned off") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestDNSPluginConfigValidation(t *testing.T) {
	for cfg, want := range map[string]string{
		`{"challenge":"dns-01","dns_provider":"plugin"}`:                                                   "dns_plugin_id",
		`{"challenge":"dns-01","dns_provider":"plugin","dns_plugin_id":"x.y"}`:                             "dns_plugin_credential",
		`{"challenge":"dns-01","dns_provider":"plugin","dns_plugin_credential":"c"}`:                       "dns_plugin_id",
		`{"challenge":"dns-01","dns_provider":"plugin","dns_plugin_id":"x.y","dns_plugin_credential":"c"}`: "",
	} {
		err := validateACMEConnectorConfig(cfg)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v, want %q", cfg, err, want)
		}
	}
	if !contains(supportedDNSProviders(), "plugin") {
		t.Errorf("plugin not registered: %v", supportedDNSProviders())
	}
}
