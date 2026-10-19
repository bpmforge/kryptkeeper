// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
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
	cfg, _ := json.Marshal(acmeConnectorConfig{DirectoryURL: upstream + "/acme/directory", Challenge: "dns-01", DNSProvider: "cloudflare", DNSPropagation: "authoritative"})
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
		"unknown provider": {acmeConnectorConfig{Challenge: "dns-01", DNSProvider: "nosuchdns"}, acmeCredentialPayload{}, "not supported"},
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

// ---- W27-21: route53 / azure / gcp adapters against stateful fakes ---------

// dnsFixture is one adapter wired to its fake. values() is the TXT rrset at
// fqdn as plain strings; seed adds a foreign value; failWrites makes every
// mutating call return 500.
type dnsFixture struct {
	p          dnsProvider
	fqdn       string
	zone       string
	noZoneFQDN string
	secrets    []string
	values     func() []string
	seed       func(v string)
	failWrites func(bool)
	authSeen   func() bool // every request carried the expected credentials
}

const dnsTestFQDN = "_acme-challenge.shop.example.com"

func eqStrings(a, b []string) bool {
	sa, sb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	return strings.Join(sa, "\x00") == strings.Join(sb, "\x00")
}

// --- Route 53 fake ---

type fakeR53 struct {
	mu      sync.Mutex
	rr      map[string][]string // fqdn (no dot) -> quoted values as stored
	fail    bool
	badAuth bool
	srv     *httptest.Server
}

const (
	r53Access = "AKIDTESTNOTREAL"
	r53Secret = "r53-secret-key-not-real-0123456789"
	r53Token  = "r53-session-token-not-real"
)

func newFakeR53(t *testing.T) *fakeR53 {
	f := &fakeR53{rr: map[string][]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, "Credential="+r53Access+"/20260102/us-east-1/route53/aws4_request") || r.Header.Get("X-Amz-Security-Token") != r53Token {
			f.badAuth = true
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>%s</Message></Error></ErrorResponse>`, auth)
			return
		}
		body, _ := io.ReadAll(r.Body)
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && path == "/2013-04-01/hostedzonesbyname":
			if r.URL.Query().Get("dnsname") == "example.com" {
				io.WriteString(w, `<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones></ListHostedZonesByNameResponse>`)
				return
			}
			// Route 53 returns the next zone alphabetically: not our candidate.
			io.WriteString(w, `<ListHostedZonesByNameResponse><HostedZones><HostedZone><Id>/hostedzone/Z9</Id><Name>zzz.org.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones></ListHostedZonesByNameResponse>`)
		case r.Method == http.MethodGet && path == "/2013-04-01/hostedzone/Z1/rrset":
			name := strings.TrimSuffix(r.URL.Query().Get("name"), ".")
			io.WriteString(w, `<ListResourceRecordSetsResponse><ResourceRecordSets>`)
			if vals := f.rr[name]; len(vals) > 0 {
				fmt.Fprintf(w, `<ResourceRecordSet><Name>%s.</Name><Type>TXT</Type><TTL>300</TTL><ResourceRecords>`, name)
				for _, v := range vals {
					fmt.Fprintf(w, `<ResourceRecord><Value>%s</Value></ResourceRecord>`, v)
				}
				io.WriteString(w, `</ResourceRecords></ResourceRecordSet>`)
			}
			io.WriteString(w, `</ResourceRecordSets></ListResourceRecordSetsResponse>`)
		case r.Method == http.MethodPost && path == "/2013-04-01/hostedzone/Z1/rrset/":
			if f.fail {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `<ErrorResponse><Error><Code>InternalFailure</Code><Message>%s %s</Message></Error></ErrorResponse>`, auth, r53Secret)
				return
			}
			var req struct {
				Changes []struct {
					Action string   `xml:"Action"`
					Name   string   `xml:"ResourceRecordSet>Name"`
					TTL    int      `xml:"ResourceRecordSet>TTL"`
					Values []string `xml:"ResourceRecordSet>ResourceRecords>ResourceRecord>Value"`
				} `xml:"ChangeBatch>Changes>Change"`
			}
			if xml.Unmarshal(body, &req) != nil || len(req.Changes) != 1 || !strings.Contains(string(body), `xmlns="https://route53.amazonaws.com/doc/2013-04-01/"`) {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `<ErrorResponse><Error><Code>MalformedInput</Code><Message>bad request</Message></Error></ErrorResponse>`)
				return
			}
			c := req.Changes[0]
			name := strings.TrimSuffix(c.Name, ".")
			switch c.Action {
			case "UPSERT":
				f.rr[name] = c.Values
			case "DELETE":
				if !eqStrings(f.rr[name], c.Values) || c.TTL != 300 {
					w.WriteHeader(http.StatusBadRequest)
					io.WriteString(w, `<ErrorResponse><Error><Code>InvalidChangeBatch</Code><Message>values or TTL do not match</Message></Error></ErrorResponse>`)
					return
				}
				delete(f.rr, name)
			}
			io.WriteString(w, `<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newR53Fixture(t *testing.T) *dnsFixture {
	f := newFakeR53(t)
	p, err := newRoute53DNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: json.RawMessage(
		`{"access_key_id":"` + r53Access + `","secret_access_key":"` + r53Secret + `","session_token":"` + r53Token + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	a := p.(*route53DNS)
	a.apiBase = f.srv.URL
	a.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	return &dnsFixture{
		p: p, fqdn: dnsTestFQDN, zone: "example.com", noZoneFQDN: "_acme-challenge.shop.example.org",
		secrets: []string{r53Access, r53Secret, r53Token},
		values: func() []string {
			f.mu.Lock()
			defer f.mu.Unlock()
			var out []string
			for _, v := range f.rr[dnsTestFQDN] {
				out = append(out, unquoteTXT(v))
			}
			return out
		},
		seed:       func(v string) { f.mu.Lock(); f.rr[dnsTestFQDN] = append(f.rr[dnsTestFQDN], quoteTXT(v)); f.mu.Unlock() },
		failWrites: func(b bool) { f.mu.Lock(); f.fail = b; f.mu.Unlock() },
		authSeen:   func() bool { f.mu.Lock(); defer f.mu.Unlock(); return !f.badAuth },
	}
}

// --- Azure fake ---

type fakeAzure struct {
	mu         sync.Mutex
	rr         map[string][]string // relative name -> values
	fail       bool
	badAuth    bool
	tokenCalls int
	srv        *httptest.Server
}

const (
	azTenant = "tenant-1"
	azSecret = "az-client-secret-not-real"
	azToken  = "az-access-token-not-real"
	azZoneID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.com"
)

func newFakeAzure(t *testing.T) *fakeAzure {
	f := &fakeAzure{rr: map[string][]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/"+azTenant+"/oauth2/v2.0/token" {
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != azSecret || r.Form.Get("scope") != "https://management.azure.com/.default" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			f.tokenCalls++
			io.WriteString(w, `{"access_token":"`+azToken+`","expires_in":3600}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer "+azToken {
			f.badAuth = true
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":{"code":"AuthFailed","message":"%s"}}`, r.Header.Get("Authorization"))
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/subscriptions/sub-1/providers/Microsoft.Network/dnszones":
			if r.URL.Query().Get("page") != "2" {
				fmt.Fprintf(w, `{"value":[{"id":"/subscriptions/sub-1/x/dnszones/other.org","name":"other.org"}],"nextLink":"http://%s%s?api-version=2018-05-01&page=2"}`, r.Host, r.URL.Path)
				return
			}
			fmt.Fprintf(w, `{"value":[{"id":"/subscriptions/sub-1/x/dnszones/com","name":"com"},{"id":"%s","name":"example.com"}]}`, azZoneID)
		case strings.HasPrefix(r.URL.Path, azZoneID+"/TXT/"):
			rel := strings.TrimPrefix(r.URL.Path, azZoneID+"/TXT/")
			switch r.Method {
			case http.MethodGet:
				vals, ok := f.rr[rel]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					io.WriteString(w, `{"error":{"code":"NotFound","message":"nope"}}`)
					return
				}
				recs := ""
				for i, v := range vals {
					if i > 0 {
						recs += ","
					}
					recs += `{"value":["` + v + `"]}`
				}
				io.WriteString(w, `{"properties":{"TTL":60,"TXTRecords":[`+recs+`]}}`)
			case http.MethodPut:
				if f.fail {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, `{"error":{"code":"Boom","message":"%s %s"}}`, r.Header.Get("Authorization"), azSecret)
					return
				}
				var req struct {
					Properties struct {
						TXT []struct{ Value []string } `json:"TXTRecords"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &req)
				var vals []string
				for _, v := range req.Properties.TXT {
					vals = append(vals, strings.Join(v.Value, ""))
				}
				f.rr[rel] = vals
				io.WriteString(w, `{}`)
			case http.MethodDelete:
				if f.fail {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, `{"error":{"code":"Boom","message":"delete failed"}}`)
					return
				}
				delete(f.rr, rel)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newAzureFixture(t *testing.T) (*dnsFixture, *fakeAzure) {
	f := newFakeAzure(t)
	p, err := newAzureDNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: json.RawMessage(
		`{"tenant_id":"` + azTenant + `","client_id":"cid","client_secret":"` + azSecret + `","subscription_id":"sub-1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	a := p.(*azureDNS)
	a.apiBase, a.tokenBase = f.srv.URL, f.srv.URL
	return &dnsFixture{
		p: p, fqdn: dnsTestFQDN, zone: "example.com", noZoneFQDN: "_acme-challenge.shop.example.org",
		secrets: []string{azSecret, azToken},
		values: func() []string {
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]string(nil), f.rr["_acme-challenge.shop"]...)
		},
		seed: func(v string) {
			f.mu.Lock()
			f.rr["_acme-challenge.shop"] = append(f.rr["_acme-challenge.shop"], v)
			f.mu.Unlock()
		},
		failWrites: func(b bool) { f.mu.Lock(); f.fail = b; f.mu.Unlock() },
		authSeen:   func() bool { f.mu.Lock(); defer f.mu.Unlock(); return !f.badAuth },
	}, f
}

func azureFx(t *testing.T) *dnsFixture { fx, _ := newAzureFixture(t); return fx }

func TestAzureDNSTokenIsCachedAndReused(t *testing.T) {
	fx, f := newAzureFixture(t)
	for i := 0; i < 3; i++ {
		_, cleanup, err := fx.p.Present(context.Background(), fx.fqdn, fmt.Sprintf("v%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenCalls != 1 {
		t.Errorf("token requests = %d, want 1", f.tokenCalls)
	}
}

// --- GCP fake ---

type fakeGCP struct {
	mu      sync.Mutex
	rr      map[string][]string // fqdn (no dot) -> quoted rrdatas
	ttl     int64
	fail    bool
	badAuth bool
	srv     *httptest.Server
}

const gcpTestToken = "gcp-access-token-not-real"

func newFakeGCP(t *testing.T, wantToken string) *fakeGCP {
	f := &fakeGCP{rr: map[string][]string{}, ttl: 300}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			f.badAuth = true
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":{"message":"bad %s"}}`, r.Header.Get("Authorization"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		const zp = "/dns/v1/projects/proj-1/managedZones"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == zp:
			if r.URL.Query().Get("dnsName") == "example.com." {
				io.WriteString(w, `{"managedZones":[{"name":"priv","dnsName":"example.com.","visibility":"private"},{"name":"zone-1","dnsName":"example.com.","visibility":"public"}]}`)
				return
			}
			io.WriteString(w, `{"managedZones":[]}`)
		case r.Method == http.MethodGet && r.URL.Path == zp+"/zone-1/rrsets":
			name := strings.TrimSuffix(r.URL.Query().Get("name"), ".")
			if vals := f.rr[name]; len(vals) > 0 {
				b, _ := json.Marshal(map[string]any{"rrsets": []gcpRRSet{{Name: name + ".", Type: "TXT", TTL: f.ttl, RRDatas: vals}}})
				w.Write(b)
				return
			}
			io.WriteString(w, `{"rrsets":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == zp+"/zone-1/changes":
			if f.fail {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error":{"message":"%s %s"}}`, r.Header.Get("Authorization"), wantToken)
				return
			}
			var ch struct{ Additions, Deletions []gcpRRSet }
			_ = json.Unmarshal(body, &ch)
			for _, d := range ch.Deletions {
				n := strings.TrimSuffix(d.Name, ".")
				if !eqStrings(f.rr[n], d.RRDatas) || d.TTL != f.ttl {
					w.WriteHeader(http.StatusPreconditionFailed)
					io.WriteString(w, `{"error":{"message":"deletion does not match"}}`)
					return
				}
				delete(f.rr, n)
			}
			for _, a := range ch.Additions {
				f.rr[strings.TrimSuffix(a.Name, ".")] = a.RRDatas
			}
			io.WriteString(w, `{"status":"pending"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newGCPFixture(t *testing.T) *dnsFixture {
	f := newFakeGCP(t, gcpTestToken)
	p, err := newGCPDNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: json.RawMessage(
		`{"project_id":"proj-1","access_token":"` + gcpTestToken + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	p.(*gcpDNS).apiBase = f.srv.URL
	return &dnsFixture{
		p: p, fqdn: dnsTestFQDN, zone: "example.com", noZoneFQDN: "_acme-challenge.shop.example.org",
		secrets: []string{gcpTestToken},
		values: func() []string {
			f.mu.Lock()
			defer f.mu.Unlock()
			var out []string
			for _, v := range f.rr[dnsTestFQDN] {
				out = append(out, unquoteTXT(v))
			}
			return out
		},
		seed:       func(v string) { f.mu.Lock(); f.rr[dnsTestFQDN] = append(f.rr[dnsTestFQDN], quoteTXT(v)); f.mu.Unlock() },
		failWrites: func(b bool) { f.mu.Lock(); f.fail = b; f.mu.Unlock() },
		authSeen:   func() bool { f.mu.Lock(); defer f.mu.Unlock(); return !f.badAuth },
	}
}

// --- shared scenarios ---

func runDNSPresentAndCleanup(t *testing.T, fx *dnsFixture) {
	ctx := context.Background()
	zone, cleanup, err := fx.p.Present(ctx, fx.fqdn, "abc_DEF-123")
	if err != nil {
		t.Fatal(err)
	}
	if zone != fx.zone {
		t.Errorf("zone %q, want %q", zone, fx.zone)
	}
	if got := fx.values(); !eqStrings(got, []string{"abc_DEF-123"}) {
		t.Errorf("published %v", got)
	}
	if err := cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fx.values(); len(got) != 0 {
		t.Errorf("TXT left behind: %v", got)
	}
	if !fx.authSeen() {
		t.Error("a request lacked the expected credentials")
	}
	if _, _, err := fx.p.Present(ctx, fx.noZoneFQDN, "v"); err == nil || !strings.Contains(err.Error(), "holds "+fx.noZoneFQDN) {
		t.Errorf("no-zone error: %v", err)
	}
}

func runDNSSharedName(t *testing.T, fx *dnsFixture) {
	ctx := context.Background()
	fx.seed("foreign-value")
	_, cleanA, err := fx.p.Present(ctx, fx.fqdn, "value-A")
	if err != nil {
		t.Fatal(err)
	}
	_, cleanB, err := fx.p.Present(ctx, fx.fqdn, "value-B")
	if err != nil {
		t.Fatal(err)
	}
	if got := fx.values(); !eqStrings(got, []string{"foreign-value", "value-A", "value-B"}) {
		t.Fatalf("after two presents: %v", got)
	}
	if err := cleanA(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fx.values(); !eqStrings(got, []string{"foreign-value", "value-B"}) {
		t.Fatalf("after first cleanup: %v", got)
	}
	if err := cleanB(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fx.values(); !eqStrings(got, []string{"foreign-value"}) {
		t.Fatalf("after second cleanup the foreign value must remain alone: %v", got)
	}
	if err := cleanB(ctx); err != nil { // idempotent
		t.Fatalf("repeat cleanup: %v", err)
	}
}

func runDNSWriteFailure(t *testing.T, fx *dnsFixture) {
	fx.failWrites(true)
	if _, _, err := fx.p.Present(context.Background(), fx.fqdn, "v"); err == nil {
		t.Fatal("write failure was swallowed")
	}
	if got := fx.values(); len(got) != 0 {
		t.Errorf("record left after a failed write: %v", got)
	}
}

func runDNSCleanupFailure(t *testing.T, fx *dnsFixture) {
	ctx := context.Background()
	_, cleanup, err := fx.p.Present(ctx, fx.fqdn, "v")
	if err != nil {
		t.Fatal(err)
	}
	fx.failWrites(true)
	if err := cleanup(ctx); err == nil {
		t.Fatal("cleanup failure was swallowed")
	}
	fx.failWrites(false)
	if err := cleanup(ctx); err != nil || len(fx.values()) != 0 {
		t.Errorf("retry after the outage: err=%v left=%v", err, fx.values())
	}
}

func TestRoute53DNSPresentAndCleanup(t *testing.T) { runDNSPresentAndCleanup(t, newR53Fixture(t)) }
func TestAzureDNSPresentAndCleanup(t *testing.T)   { runDNSPresentAndCleanup(t, azureFx(t)) }
func TestGCPDNSPresentAndCleanup(t *testing.T)     { runDNSPresentAndCleanup(t, newGCPFixture(t)) }

func TestRoute53DNSSharedNameKeepsBothValuesAndForeignValue(t *testing.T) {
	runDNSSharedName(t, newR53Fixture(t))
}
func TestAzureDNSSharedNameKeepsBothValuesAndForeignValue(t *testing.T) {
	runDNSSharedName(t, azureFx(t))
}
func TestGCPDNSSharedNameKeepsBothValuesAndForeignValue(t *testing.T) {
	runDNSSharedName(t, newGCPFixture(t))
}

func TestRoute53DNSWriteFailureLeavesNoRecord(t *testing.T) { runDNSWriteFailure(t, newR53Fixture(t)) }
func TestAzureDNSWriteFailureLeavesNoRecord(t *testing.T)   { runDNSWriteFailure(t, azureFx(t)) }
func TestGCPDNSWriteFailureLeavesNoRecord(t *testing.T)     { runDNSWriteFailure(t, newGCPFixture(t)) }

func TestRoute53DNSCleanupFailureIsReportedNotSwallowed(t *testing.T) {
	runDNSCleanupFailure(t, newR53Fixture(t))
}
func TestAzureDNSCleanupFailureIsReportedNotSwallowed(t *testing.T) {
	runDNSCleanupFailure(t, azureFx(t))
}
func TestGCPDNSCleanupFailureIsReportedNotSwallowed(t *testing.T) {
	runDNSCleanupFailure(t, newGCPFixture(t))
}

func TestRoute53DNSHostedZoneIDPinned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2013-04-01/hostedzone/Z1" {
			io.WriteString(w, `<GetHostedZoneResponse><HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name></HostedZone></GetHostedZoneResponse>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p, _ := newRoute53DNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: json.RawMessage(`{"access_key_id":"a","secret_access_key":"b","hosted_zone_id":"/hostedzone/Z1"}`)})
	r := p.(*route53DNS)
	r.apiBase = srv.URL
	if z, err := r.zoneFor(context.Background(), dnsTestFQDN); err != nil || z != "example.com" {
		t.Errorf("pinned zone: %q %v", z, err)
	}
	if _, err := r.zoneFor(context.Background(), "_acme-challenge.shop.example.org"); err == nil {
		t.Error("a pinned zone must refuse names it does not hold")
	}
}

func TestGCPDNSServiceAccountJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	sa, _ := json.Marshal(map[string]string{"client_email": "kk@proj-1.iam.gserviceaccount.com", "private_key": keyPEM})
	dnsCfg, _ := json.Marshal(map[string]string{"project_id": "proj-1", "service_account_json": string(sa)})

	var tokenURL string
	var tokenCalls int
	var verifyErr string
	f := newFakeGCP(t, "minted-token")
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		_ = r.ParseForm()
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 {
			verifyErr = "bad grant or assertion shape"
		} else {
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
				verifyErr = "signature: " + err.Error()
			}
			var hdr map[string]string
			var cl map[string]any
			h, _ := base64.RawURLEncoding.DecodeString(parts[0])
			c, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(h, &hdr)
			_ = json.Unmarshal(c, &cl)
			iat, _ := cl["iat"].(float64)
			exp, _ := cl["exp"].(float64)
			if hdr["alg"] != "RS256" || cl["iss"] != "kk@proj-1.iam.gserviceaccount.com" || cl["scope"] != gcpDNSScope || cl["aud"] != tokenURL || exp-iat != 3600 {
				verifyErr = fmt.Sprintf("claims: %v %v", hdr, cl)
			}
		}
		io.WriteString(w, `{"access_token":"minted-token","expires_in":3600}`)
	}))
	t.Cleanup(tok.Close)
	tokenURL = tok.URL

	p, err := newGCPDNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: dnsCfg})
	if err != nil {
		t.Fatal(err)
	}
	g := p.(*gcpDNS)
	g.apiBase, g.tokenURL = f.srv.URL, tokenURL
	for i := 0; i < 2; i++ {
		_, cleanup, err := g.Present(context.Background(), dnsTestFQDN, "v")
		if err != nil {
			t.Fatal(err)
		}
		if err := cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if verifyErr != "" {
		t.Error(verifyErr)
	}
	if tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cached)", tokenCalls)
	}
	if f.badAuth {
		t.Error("DNS calls did not carry the minted token")
	}
	both, _ := json.Marshal(map[string]string{"project_id": "p", "service_account_json": string(sa), "access_token": "t"})
	if _, err := newGCPDNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: both}); err == nil {
		t.Error("service_account_json plus access_token must be rejected")
	}
}

// The fakes echo Authorization (and the secret itself) in their 4xx/5xx
// replies; no credential may reach the log or any returned error.
func TestDNSAdaptersNeverLogOrReturnSecrets(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	var texts, secrets []string
	for _, fx := range []*dnsFixture{newR53Fixture(t), azureFx(t), newGCPFixture(t)} {
		secrets = append(secrets, fx.secrets...)
		ctx := context.Background()
		_, cleanup, err := fx.p.Present(ctx, fx.fqdn, "v1")
		if err != nil {
			t.Fatal(err)
		}
		fx.failWrites(true)
		if _, _, err = fx.p.Present(ctx, fx.fqdn, "v2"); err == nil {
			t.Fatal("expected a write failure")
		}
		texts = append(texts, err.Error())
		if err := cleanup(ctx); err == nil {
			t.Fatal("expected a cleanup failure")
		} else {
			texts = append(texts, err.Error())
		}
		fx.failWrites(false)
		_, _, err = fx.p.Present(ctx, fx.noZoneFQDN, "v3")
		texts = append(texts, err.Error())
	}
	// Wrong credentials: the fake answers 403 echoing the Authorization header.
	bad, _ := newRoute53DNSFromConfig(acmeConnectorConfig{}, acmeCredentialPayload{DNS: json.RawMessage(`{"access_key_id":"` + r53Access + `","secret_access_key":"other-secret-xyz"}`)})
	bad.(*route53DNS).apiBase = newFakeR53(t).srv.URL
	secrets = append(secrets, "other-secret-xyz")
	if _, _, err := bad.Present(context.Background(), dnsTestFQDN, "v"); err == nil {
		t.Fatal("bad credentials accepted")
	} else {
		texts = append(texts, err.Error())
	}
	texts = append(texts, buf.String())
	for _, text := range texts {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("secret %q leaked in: %s", s, text)
			}
		}
		if len(text) > 600 {
			t.Errorf("error text not bounded (%d chars)", len(text))
		}
	}
}

func TestDNSProviderRegistry(t *testing.T) {
	got := supportedDNSProviders()
	for _, want := range []string{"azure", "cloudflare", "gcp", "route53"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("%s not registered: %v", want, got)
		}
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("not sorted: %v", got)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("duplicate registration must panic")
			}
		}()
		registerDNSProvider("route53", newRoute53DNSFromConfig)
	}()
	if _, err := newDNSProviderFromConfig(acmeConnectorConfig{DNSProvider: "nosuchdns"}, acmeCredentialPayload{}); err == nil || !strings.Contains(err.Error(), strings.Join(supportedDNSProviders(), ", ")) {
		t.Errorf("unknown provider text: %v", err)
	}
	for _, name := range []string{"route53", "azure", "gcp"} {
		if _, err := newDNSProviderFromConfig(acmeConnectorConfig{DNSProvider: name}, acmeCredentialPayload{}); err == nil || !strings.Contains(err.Error(), `needs a "dns" object`) {
			t.Errorf("%s without credentials: %v", name, err)
		}
	}
}

func TestTXTHelpers(t *testing.T) {
	if got := mergeTXT([]string{`"a"`}, `"a"`); len(got) != 1 {
		t.Errorf("merge duplicated: %v", got)
	}
	if got := withoutTXT([]string{`"a" "b"`, `"c"`}, `"ab"`); len(got) != 1 || got[0] != `"c"` {
		t.Errorf("multi-chunk match: %v", got)
	}
	if q := quoteTXT(`a"b\c`); unquoteTXT(q) != `a"b\c` {
		t.Errorf("round trip: %s", q)
	}
	if redact("tok=abc", "abc", "") != "tok=[redacted]" {
		t.Error("redact")
	}
}

func TestConnectorCreateAcceptsDNSProviders(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterConnectorHandlers(mux, auth, newConnectorTestStore(t), provider, nil, audit)

	create := func(cfg string) *httptest.ResponseRecorder {
		return doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]any{
			"name": "acme", "type": "acme", "config_json": cfg,
		})
	}
	for _, name := range []string{"route53", "azure", "gcp", "cloudflare"} {
		if rec := create(`{"challenge":"dns-01","dns_provider":"` + name + `"}`); rec.Code != http.StatusCreated {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	rec := create(`{"challenge":"dns-01","dns_provider":"nosuchdns"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), strings.Join(supportedDNSProviders(), ", ")) {
		t.Errorf("unknown provider: %d %s", rec.Code, rec.Body.String())
	}
	const leak = "sk-should-never-be-stored"
	rec = create(`{"dns_provider":"route53","client_secret":"` + leak + `"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "credential_ref") || strings.Contains(rec.Body.String(), leak) {
		t.Errorf("secret in config: %d %s", rec.Code, rec.Body.String())
	}
	if rec := create(`{"directory_url":"https://x/dir"}`); rec.Code != http.StatusCreated {
		t.Errorf("config without dns_provider must still pass: %d", rec.Code)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	n := 0
	for _, e := range audit.entries {
		if e.Action == "connector.create" {
			n++
		}
		if raw, _ := json.Marshal(e); strings.Contains(string(raw), leak) {
			t.Errorf("audit row carries the secret: %s", raw)
		}
	}
	if n != 7 {
		t.Errorf("connector.create audit rows = %d, want 7 (every outcome)", n)
	}
}
