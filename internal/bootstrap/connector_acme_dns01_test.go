// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	kkacme "kryptkeeper/internal/acme"
	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/keystore"
)

// memZone is a DNS zone in memory: the fake provider writes it, the ACME
// server's validator and the connector's propagation check read it.
type memZone struct {
	mu       sync.Mutex
	txt      map[string][]string
	presents []string
	removed  []string
	value    func(string) string // rewrites what is published (for the wrong-value case)
	intended map[string]string   // what the connector asked for, before any rewrite
}

func (z *memZone) Present(_ context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.intended == nil {
		z.intended = map[string]string{}
	}
	z.intended[fqdn] = value
	if z.value != nil {
		value = z.value(value)
	}
	z.txt[fqdn] = append(z.txt[fqdn], value)
	z.presents = append(z.presents, fqdn)
	return "example.test", func(context.Context) error {
		z.mu.Lock()
		defer z.mu.Unlock()
		delete(z.txt, fqdn)
		z.removed = append(z.removed, fqdn)
		return nil
	}, nil
}

func (z *memZone) lookup(name string) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if v, ok := z.txt[strings.TrimSuffix(name, ".")]; ok {
		return append([]string(nil), v...), nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func newDNS01Upstream(t *testing.T, zone *memZone) string {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("acme-test-passphrase-32chars-ok!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Upstream ACME Root", pkix.Name{CommonName: "Upstream ACME Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(nil)
	srv := kkacme.NewServerWithStore(ts.URL, engine, root.ID, kkacme.NewMemStore(), ca.NewMemRevocationStore())
	srv.SetTXTResolver(zone.lookup)
	ts.Config.Handler = srv.Handler()
	t.Cleanup(ts.Close)
	return ts.URL
}

func newDNS01Connector(upstream string, zone *memZone) *acmeIssuerConnector {
	cfg, _ := json.Marshal(acmeConnectorConfig{DirectoryURL: upstream + "/acme/directory", Challenge: "dns-01", DNSProvider: "cloudflare"})
	c := NewACMEIssuerConnector(ConnectorRecord{ID: "conn-dns01", Type: "acme", ConfigJSON: string(cfg)}, nil, nil).(*acmeIssuerConnector)
	c.allowLoopbackForTest = true // upstream is http on loopback
	c.newDNS = func(acmeCredentialPayload) (dnsProvider, error) { return zone, nil }
	c.lookupNS = func(context.Context, string) ([]*net.NS, error) { return []*net.NS{{Host: "ns1.example.test."}}, nil }
	c.lookupTXT = func(_ context.Context, _, name string) ([]string, error) { return zone.lookup(name) }
	c.dnsInterval = 10 * time.Millisecond
	return c
}

func TestACMEConnectorDNS01EndToEnd(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	conn := newDNS01Connector(newDNS01Upstream(t, zone), zone)

	res, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")})
	if err != nil {
		t.Fatalf("dns-01 issue: %v", err)
	}
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatal("no certificate")
	}
	if len(zone.presents) != 1 || zone.presents[0] != "_acme-challenge.shop.example.test" {
		t.Errorf("published %v", zone.presents)
	}
	if len(zone.removed) != 1 || len(zone.txt) != 0 {
		t.Errorf("TXT records not removed: removed=%v left=%v", zone.removed, zone.txt)
	}
}

// The CA sees a wrong value: its problem surfaces, and the record still
// comes down.
func TestACMEConnectorDNS01WrongValueFailsAndCleansUp(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	conn := newDNS01Connector(newDNS01Upstream(t, zone), zone)
	// The record goes up altered: our propagation check reads what we
	// asked for, the CA reads what is actually there.
	zone.value = func(string) string { return "wrong" }
	conn.lookupTXT = func(_ context.Context, _, name string) ([]string, error) {
		zone.mu.Lock()
		defer zone.mu.Unlock()
		if v, ok := zone.intended[name]; ok {
			return []string{v}, nil
		}
		return nil, errors.New("nx")
	}
	_, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")})
	if err == nil || !strings.Contains(err.Error(), "challenge validation") {
		t.Fatalf("want the CA's validation failure, got %v", err)
	}
	if len(zone.removed) != 1 {
		t.Errorf("record not cleaned up after a failure: removed=%v", zone.removed)
	}
}

// Propagation never completes: the order stops at the deadline, names the
// nameserver, and still removes the record.
func TestACMEConnectorDNS01PropagationTimeout(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	conn := newDNS01Connector(newDNS01Upstream(t, zone), zone)
	conn.lookupTXT = func(context.Context, string, string) ([]string, error) { return nil, errors.New("nx") }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := conn.Issue(ctx, connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")})
	if err == nil || !strings.Contains(err.Error(), "not visible at ns1.example.test") {
		t.Fatalf("want a propagation timeout naming the nameserver, got %v", err)
	}
	if len(zone.removed) != 1 {
		t.Errorf("record not cleaned up after a timeout: removed=%v", zone.removed)
	}
}

func TestACMEConnectorDNS01Config(t *testing.T) {
	for name, c := range map[string]struct {
		cfg     acmeConnectorConfig
		payload acmeCredentialPayload
		want    string
	}{
		"no provider":      {acmeConnectorConfig{Challenge: "dns-01"}, acmeCredentialPayload{}, "needs config_json.dns_provider"},
		"unknown provider": {acmeConnectorConfig{Challenge: "dns-01", DNSProvider: "route53"}, acmeCredentialPayload{}, "not supported"},
		"no token":         {acmeConnectorConfig{Challenge: "dns-01", DNSProvider: "cloudflare"}, acmeCredentialPayload{}, "needs cloudflare_api_token"},
	} {
		conn := &acmeIssuerConnector{cfg: c.cfg}
		if _, err := conn.dnsProvider(c.payload); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	conn := &acmeIssuerConnector{cfg: acmeConnectorConfig{Challenge: "dns-01", DNSProvider: "cloudflare"}}
	if p, err := conn.dnsProvider(acmeCredentialPayload{CloudflareAPIToken: "tok"}); err != nil || p == nil {
		t.Errorf("cloudflare with a token: %v", err)
	}
}

// A fake Cloudflare API: the zone is found from the record's parents, the
// TXT record is created with a quoted value and bearer auth, and removed by
// id; an API error carries Cloudflare's message, never the token.
func TestCloudflareDNSPresentAndCleanup(t *testing.T) {
	const token = "cf-test-token-not-real"
	var mu sync.Mutex
	var calls []string
	var created map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "kryptkeeper.io" {
				_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone-1","name":"kryptkeeper.io"}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"result":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			_ = json.NewDecoder(r.Body).Decode(&created)
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec-9"}}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-1/dns_records/rec-9":
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec-9"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":7003,"message":"no route"}]}`)
		}
	}))
	defer api.Close()

	cf := newCloudflareDNS(token)
	cf.apiBase = api.URL
	zone, cleanup, err := cf.Present(context.Background(), "_acme-challenge.kk-uat.kryptkeeper.io", "abc_DEF-123")
	if err != nil {
		t.Fatal(err)
	}
	if zone != "kryptkeeper.io" {
		t.Errorf("zone %q", zone)
	}
	if created["type"] != "TXT" || created["name"] != "_acme-challenge.kk-uat.kryptkeeper.io" || created["content"] != `"abc_DEF-123"` || created["ttl"] != float64(60) {
		t.Errorf("created record: %v", created)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /zones?name=kk-uat.kryptkeeper.io",
		"GET /zones?name=kryptkeeper.io",
		"POST /zones/zone-1/dns_records?",
		"DELETE /zones/zone-1/dns_records/rec-9?",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}

	bad := newCloudflareDNS("wrong-token")
	bad.apiBase = api.URL
	_, _, err = bad.Present(context.Background(), "_acme-challenge.kk-uat.kryptkeeper.io", "v")
	if err == nil || !strings.Contains(err.Error(), "Authentication error") || strings.Contains(err.Error(), "wrong-token") {
		t.Errorf("auth failure: %v", err)
	}
	nozone := newCloudflareDNS(token)
	nozone.apiBase = api.URL
	if _, _, err := nozone.Present(context.Background(), "_acme-challenge.shop.example.com", "v"); err == nil || !strings.Contains(err.Error(), "no Cloudflare zone") {
		t.Errorf("unknown zone: %v", err)
	}
}

func TestWaitForTXTNeedsEveryNameserver(t *testing.T) {
	seen := map[string]bool{"ns1": true}
	ns := func(context.Context, string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ns1."}, {Host: "ns2."}}, nil
	}
	lookup := func(_ context.Context, server, _ string) ([]string, error) {
		if seen[server] {
			return []string{"v"}, nil
		}
		return nil, errors.New("nx")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := waitForTXT(ctx, ns, lookup, "z", "n", "v", 10*time.Millisecond); err == nil || !strings.Contains(err.Error(), "ns2") {
		t.Errorf("one lagging nameserver must hold the order: %v", err)
	}
	seen["ns2"] = true
	if err := waitForTXT(context.Background(), ns, lookup, "z", "n", "v", 10*time.Millisecond); err != nil {
		t.Errorf("both serve it: %v", err)
	}
}
