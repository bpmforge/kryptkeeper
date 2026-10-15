// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/connectors"
)

// Real response shapes, captured from the two public DoH JSON endpoints.
const (
	// Cloudflare quotes TXT data (long values arrive as several quoted chunks).
	cloudflareDoHTXT = `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
"Question":[{"name":"_acme-challenge.shop.example.test","type":16}],
"Answer":[{"name":"_acme-challenge.shop.example.test","type":16,"TTL":60,"data":"\"tok_en-123\""}]}`
	// Google returns the string unquoted, with the name's trailing dot and a Comment.
	googleDoHTXT = `{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
"Question":[{"name":"_acme-challenge.shop.example.test.","type":16}],
"Answer":[{"name":"_acme-challenge.shop.example.test.","type":16,"TTL":60,"data":"tok_en-123"}],
"Comment":"Response from 203.0.113.53."}`
	googleDoHNXDOMAIN = `{"Status":3,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
"Question":[{"name":"_acme-challenge.shop.example.test.","type":16}],
"Authority":[{"name":"example.test.","type":6,"TTL":300,"data":"ns.example.test. hostmaster.example.test. 1 7200 3600 1209600 300"}]}`
	cloudflareDoHServfail = `{"Status":2,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"x.example.test","type":16}]}`
	// A CNAME in front of the TXT: the CNAME record is not TXT data.
	cloudflareDoHCNAME = `{"Status":0,"Answer":[
{"name":"_acme-challenge.shop.example.test","type":5,"TTL":60,"data":"delegated.example.test."},
{"name":"delegated.example.test","type":16,"TTL":60,"data":"\"tok_en-123\" \"-part2\""}]}`
)

func TestParseDoHTXT(t *testing.T) {
	for name, tc := range map[string]struct {
		body     string
		want     []string
		notFound bool
		fail     bool
	}{
		"cloudflare":   {body: cloudflareDoHTXT, want: []string{"tok_en-123"}},
		"google":       {body: googleDoHTXT, want: []string{"tok_en-123"}},
		"cname+chunks": {body: cloudflareDoHCNAME, want: []string{"tok_en-123-part2"}},
		"nxdomain":     {body: googleDoHNXDOMAIN, notFound: true},
		"noerror empty": {body: `{"Status":0,"Authority":[{"name":"example.test.","type":6,"TTL":300,"data":"x"}]}`,
			notFound: true},
		"servfail": {body: cloudflareDoHServfail, fail: true},
		"garbage":  {body: `<html>`, fail: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseDoHTXT(strings.NewReader(tc.body), "n")
			switch {
			case tc.fail:
				if err == nil || answered(err) {
					t.Fatalf("want a failure that is not an answer, got %v / %v", got, err)
				}
			case tc.notFound:
				if !answered(err) || err == nil {
					t.Fatalf("want a not-found answer, got %v / %v", got, err)
				}
			default:
				if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
			}
		})
	}
}

func TestPropagationConfig(t *testing.T) {
	p, err := acmeConnectorConfig{}.propagation(false)
	if err != nil || p.mode != "auto" || p.timeout != 3*time.Minute || p.delay != 30*time.Second || p.dohURL != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("defaults: %+v %v", p, err)
	}
	p, err = acmeConnectorConfig{DNSPropagation: "DoH", DNSDoHURL: "https://dns.google/resolve", DNSPropagationTimeout: "10m"}.propagation(false)
	if err != nil || p.mode != "doh" || p.timeout != 10*time.Minute || p.dohURL != "https://dns.google/resolve" {
		t.Fatalf("explicit: %+v %v", p, err)
	}
	for name, cfg := range map[string]acmeConnectorConfig{
		"unknown mode":   {DNSPropagation: "magic"},
		"over max":       {DNSPropagationTimeout: "11m"},
		"zero":           {DNSPropagationTimeout: "0s"},
		"not a duration": {DNSPropagationTimeout: "soon"},
		"delay over max": {DNSPropagationDelay: "1h"},
		"http doh":       {DNSDoHURL: "http://dns.example.test/q"},
		"doh creds":      {DNSDoHURL: "https://user:pw@dns.example.test/q"},
		"doh no host":    {DNSDoHURL: "https:///q"},
	} {
		if _, err := cfg.propagation(false); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := (acmeConnectorConfig{DNSDoHURL: "http://127.0.0.1:1/q"}).propagation(true); err != nil {
		t.Errorf("test seam must allow http: %v", err)
	}
}

// fakeDNS counts what each propagation method was asked.
type fakeDNS struct {
	mu         sync.Mutex
	nsCalls    []string // nameservers queried
	resolvers  []string // addresses passed to the recursive lookup
	dohCalls   int
	authority  func(ns string) ([]string, error)
	recursive  func(addr string) ([]string, error)
	doh        func() ([]string, error)
	zoneNS     []*net.NS
	nsLookupFn func() ([]*net.NS, error)
}

func (f *fakeDNS) connector() *acmeIssuerConnector {
	c := &acmeIssuerConnector{id: "c-test"}
	c.lookupNS = func(context.Context, string) ([]*net.NS, error) {
		if f.nsLookupFn != nil {
			return f.nsLookupFn()
		}
		return f.zoneNS, nil
	}
	c.lookupTXT = func(_ context.Context, server, _ string) ([]string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		// A configured resolver address (or "" for the system resolver) is
		// the recursive path; anything named like a nameserver is authoritative.
		if strings.HasPrefix(server, "ns") {
			f.nsCalls = append(f.nsCalls, server)
			return f.authority(server)
		}
		f.resolvers = append(f.resolvers, server)
		return f.recursive(server)
	}
	c.lookupDoH = func(context.Context, string, string) ([]string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.dohCalls++
		return f.doh()
	}
	return c
}

var (
	errTimeout   = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	errRefused   = &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	errNXDomain  = &net.DNSError{Err: "no such host", IsNotFound: true}
	fakeNSServer = []*net.NS{{Host: "ns1.example.test."}, {Host: "ns2.example.test."}}
)

func wait(c *acmeIssuerConnector, cfg acmeConnectorConfig, st *dnsCheckState) error {
	p, err := cfg.propagation(true)
	if err != nil {
		return err
	}
	return c.waitPropagation(context.Background(), p, st, "example.test", "_acme-challenge.shop.example.test", "v", 5*time.Millisecond)
}

func TestPropagationModes(t *testing.T) {
	t.Run("authoritative needs every nameserver", func(t *testing.T) {
		f := &fakeDNS{zoneNS: fakeNSServer, authority: func(string) ([]string, error) { return []string{"v"}, nil }}
		st := &dnsCheckState{}
		if err := wait(f.connector(), acmeConnectorConfig{DNSPropagation: "authoritative"}, st); err != nil {
			t.Fatal(err)
		}
		if len(f.nsCalls) != 2 || f.dohCalls != 0 || len(f.resolvers) != 0 || st.method != "authoritative" {
			t.Fatalf("calls ns=%v doh=%d resolvers=%v method=%s", f.nsCalls, f.dohCalls, f.resolvers, st.method)
		}
	})

	t.Run("resolver uses the configured address", func(t *testing.T) {
		f := &fakeDNS{recursive: func(string) ([]string, error) { return []string{"other", "v"}, nil }}
		st := &dnsCheckState{}
		if err := wait(f.connector(), acmeConnectorConfig{DNSPropagation: "resolver", DNSResolver: "10.0.0.2:5353"}, st); err != nil {
			t.Fatal(err)
		}
		if len(f.resolvers) != 1 || f.resolvers[0] != "10.0.0.2:5353" || len(f.nsCalls) != 0 || f.dohCalls != 0 {
			t.Fatalf("resolvers=%v ns=%v doh=%d", f.resolvers, f.nsCalls, f.dohCalls)
		}
	})

	t.Run("resolver defaults to the system resolver", func(t *testing.T) {
		f := &fakeDNS{recursive: func(string) ([]string, error) { return []string{"v"}, nil }}
		if err := wait(f.connector(), acmeConnectorConfig{DNSPropagation: "resolver"}, &dnsCheckState{}); err != nil {
			t.Fatal(err)
		}
		if len(f.resolvers) != 1 || f.resolvers[0] != "" {
			t.Fatalf("resolvers=%q", f.resolvers)
		}
	})

	t.Run("doh polls until the record appears", func(t *testing.T) {
		n := 0
		f := &fakeDNS{doh: func() ([]string, error) {
			if n++; n < 3 {
				return nil, errNXDomain
			}
			return []string{"v"}, nil
		}}
		if err := wait(f.connector(), acmeConnectorConfig{DNSPropagation: "doh"}, &dnsCheckState{}); err != nil {
			t.Fatal(err)
		}
		if f.dohCalls != 3 || len(f.nsCalls) != 0 {
			t.Fatalf("doh=%d ns=%v", f.dohCalls, f.nsCalls)
		}
	})

	t.Run("none waits the delay and asks nobody", func(t *testing.T) {
		f := &fakeDNS{}
		start := time.Now()
		if err := wait(f.connector(), acmeConnectorConfig{DNSPropagation: "none", DNSPropagationDelay: "60ms"}, &dnsCheckState{}); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) < 60*time.Millisecond || f.dohCalls+len(f.nsCalls)+len(f.resolvers) != 0 {
			t.Fatalf("elapsed %v, queries %d", time.Since(start), f.dohCalls+len(f.nsCalls)+len(f.resolvers))
		}
	})

	t.Run("timeout is honoured and names what is missing", func(t *testing.T) {
		f := &fakeDNS{zoneNS: fakeNSServer, authority: func(ns string) ([]string, error) {
			if ns == "ns1.example.test" {
				return []string{"v"}, nil
			}
			return nil, errNXDomain
		}}
		start := time.Now()
		err := wait(f.connector(), acmeConnectorConfig{DNSPropagation: "authoritative", DNSPropagationTimeout: "80ms"}, &dnsCheckState{})
		if err == nil || !strings.Contains(err.Error(), "not visible at ns2.example.test") || strings.Contains(err.Error(), "ns1") {
			t.Fatalf("got %v", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("ran %v past an 80ms deadline", time.Since(start))
		}
	})
}

func TestPropagationAutoFallback(t *testing.T) {
	blocked := func(error) func(string) ([]string, error) {
		return func(string) ([]string, error) { return nil, errTimeout }
	}
	for name, netErr := range map[string]error{"timeout": errTimeout, "refused": errRefused} {
		t.Run("authoritative "+name+" falls back to doh", func(t *testing.T) {
			f := &fakeDNS{
				zoneNS:    fakeNSServer,
				authority: func(string) ([]string, error) { return nil, netErr },
				doh:       func() ([]string, error) { return []string{"v"}, nil },
			}
			st := &dnsCheckState{}
			if err := wait(f.connector(), acmeConnectorConfig{}, st); err != nil {
				t.Fatal(err)
			}
			if st.method != "doh" || f.dohCalls != 1 || len(f.resolvers) != 0 {
				t.Fatalf("method=%s doh=%d resolvers=%v", st.method, f.dohCalls, f.resolvers)
			}
			// The settled method sticks for the next identifier in the order.
			f.nsCalls = nil
			if err := wait(f.connector(), acmeConnectorConfig{}, st); err != nil || len(f.nsCalls) != 0 {
				t.Fatalf("second identifier: %v, authoritative asked again: %v", err, f.nsCalls)
			}
		})
	}

	t.Run("doh also unreachable falls back to the resolver", func(t *testing.T) {
		f := &fakeDNS{
			zoneNS:    fakeNSServer,
			authority: blocked(nil),
			doh:       func() ([]string, error) { return nil, errors.New("doh query: connection refused") },
			recursive: func(string) ([]string, error) { return []string{"v"}, nil },
		}
		st := &dnsCheckState{}
		if err := wait(f.connector(), acmeConnectorConfig{DNSResolver: "192.0.2.53"}, st); err != nil {
			t.Fatal(err)
		}
		if st.method != "resolver" || f.resolvers[0] != "192.0.2.53" {
			t.Fatalf("method=%s resolvers=%v", st.method, f.resolvers)
		}
	})

	t.Run("nameserver lookup failure also falls back", func(t *testing.T) {
		f := &fakeDNS{
			nsLookupFn: func() ([]*net.NS, error) { return nil, errTimeout },
			doh:        func() ([]string, error) { return []string{"v"}, nil },
		}
		st := &dnsCheckState{}
		if err := wait(f.connector(), acmeConnectorConfig{}, st); err != nil || st.method != "doh" {
			t.Fatalf("method=%s err=%v", st.method, err)
		}
	})

	// A reachable nameserver that has no record yet is propagation lag, not
	// a blocked network: falling back would hide a real failure behind a
	// resolver that may serve a stale negative answer.
	t.Run("NXDOMAIN does not fall back", func(t *testing.T) {
		f := &fakeDNS{
			zoneNS:    fakeNSServer,
			authority: func(string) ([]string, error) { return nil, errNXDomain },
			doh:       func() ([]string, error) { return []string{"v"}, nil },
			recursive: func(string) ([]string, error) { return []string{"v"}, nil },
		}
		err := wait(f.connector(), acmeConnectorConfig{DNSPropagationTimeout: "80ms"}, &dnsCheckState{})
		if err == nil || !strings.Contains(err.Error(), "not visible at") {
			t.Fatalf("want an authoritative timeout, got %v", err)
		}
		if f.dohCalls != 0 || len(f.resolvers) != 0 {
			t.Fatalf("fell back despite an authoritative answer: doh=%d resolvers=%v", f.dohCalls, f.resolvers)
		}
	})

	t.Run("one answering nameserver is enough to stay authoritative", func(t *testing.T) {
		f := &fakeDNS{
			zoneNS: fakeNSServer,
			authority: func(ns string) ([]string, error) {
				if ns == "ns1.example.test" {
					return []string{"v"}, nil
				}
				return nil, errTimeout
			},
			doh: func() ([]string, error) { return []string{"v"}, nil },
		}
		err := wait(f.connector(), acmeConnectorConfig{DNSPropagationTimeout: "80ms"}, &dnsCheckState{})
		if err == nil || !strings.Contains(err.Error(), "ns2.example.test") || f.dohCalls != 0 {
			t.Fatalf("err=%v doh=%d", err, f.dohCalls)
		}
	})

	t.Run("all methods dead ends at the deadline naming the last method", func(t *testing.T) {
		f := &fakeDNS{
			zoneNS:    fakeNSServer,
			authority: blocked(nil),
			doh:       func() ([]string, error) { return nil, errTimeout },
			recursive: func(string) ([]string, error) { return nil, errNXDomain },
		}
		err := wait(f.connector(), acmeConnectorConfig{DNSPropagationTimeout: "80ms"}, &dnsCheckState{})
		if err == nil || !strings.Contains(err.Error(), "via the resolver") {
			t.Fatalf("got %v", err)
		}
	})
}

// The real DoH client: the wire request carries only the query, the
// response shapes of both public endpoints parse, and nothing sensitive
// leaves the hub.
func TestDoHLookupRequest(t *testing.T) {
	var got *http.Request
	body := cloudflareDoHTXT
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	c := &acmeIssuerConnector{id: "c", allowLoopbackForTest: true}

	for name, b := range map[string]string{"cloudflare": cloudflareDoHTXT, "google": googleDoHTXT} {
		body = b
		txts, err := c.dohLookup(context.Background(), srv.URL+"/dns-query?ct=application/dns-json", "_acme-challenge.shop.example.test")
		if err != nil || len(txts) != 1 || txts[0] != "tok_en-123" {
			t.Fatalf("%s: %q %v", name, txts, err)
		}
	}
	if got.Method != http.MethodGet || got.Header.Get("Accept") != "application/dns-json" {
		t.Errorf("method/accept: %s %q", got.Method, got.Header.Get("Accept"))
	}
	q := got.URL.Query()
	if q.Get("name") != "_acme-challenge.shop.example.test" || q.Get("type") != "TXT" || q.Get("ct") != "application/dns-json" {
		t.Errorf("query %v", q)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Auth-Key", "X-Auth-Email"} {
		if got.Header.Get(h) != "" {
			t.Errorf("DoH request carried %s", h)
		}
	}

	// A non-200 and an unreachable endpoint are failures, not answers.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer bad.Close()
	if _, err := c.dohLookup(context.Background(), bad.URL, "n"); err == nil || answered(err) {
		t.Errorf("502: %v", err)
	}
	if _, err := c.dohLookup(context.Background(), "http://127.0.0.1:1/", "n"); err == nil || answered(err) {
		t.Errorf("unreachable: %v", err)
	}
	// Without the test seam the egress guard refuses plain http and loopback.
	strict := &acmeIssuerConnector{id: "c"}
	if _, err := strict.dohLookup(context.Background(), srv.URL, "n"); err == nil {
		t.Error("egress guard did not apply to the DoH endpoint")
	}
}

// The reported failure end to end: authoritative queries never get through
// (outbound 53 blocked), so the old behaviour (mode authoritative) times out
// while the default completes the order through DoH.
func TestDNS01PortBlockedNetwork(t *testing.T) {
	setup := func(mode string) (*acmeIssuerConnector, *memZone) {
		zone := &memZone{txt: map[string][]string{}}
		conn := newDNS01Connector(newDNS01Upstream(t, zone), zone)
		conn.cfg.DNSPropagation = mode
		conn.cfg.DNSPropagationTimeout = "1s"
		conn.lookupTXT = func(context.Context, string, string) ([]string, error) { return nil, errTimeout }
		conn.lookupDoH = func(_ context.Context, _, name string) ([]string, error) { return zone.lookup(name) }
		return conn, zone
	}
	csr := func() connectors.IssueRequest {
		return connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")}
	}

	conn, zone := setup("authoritative")
	if _, err := conn.Issue(context.Background(), csr()); err == nil || !strings.Contains(err.Error(), "not visible at ns1.example.test") {
		t.Fatalf("authoritative on a port-53-blocked network: %v", err)
	}
	if len(zone.removed) != 1 {
		t.Errorf("record left behind: %v", zone.removed)
	}

	conn, _ = setup("") // the default
	if _, err := conn.Issue(context.Background(), csr()); err != nil {
		t.Fatalf("default (auto) must fall back to DoH: %v", err)
	}

	conn, _ = setup("none")
	conn.cfg.DNSPropagationDelay = "10ms"
	conn.lookupDoH = func(context.Context, string, string) ([]string, error) {
		t.Error("none must not query DNS")
		return nil, nil
	}
	if _, err := conn.Issue(context.Background(), csr()); err != nil {
		t.Fatalf("none: %v", err)
	}
}

func TestDNS01BadPropagationConfigFailsBeforePublishing(t *testing.T) {
	zone := &memZone{txt: map[string][]string{}}
	conn := newDNS01Connector(newDNS01Upstream(t, zone), zone)
	conn.cfg.DNSPropagationTimeout = "1h"
	_, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, "shop.example.test")})
	if err == nil || !strings.Contains(err.Error(), "dns_propagation_timeout") || len(zone.presents) != 0 {
		t.Fatalf("err=%v presents=%v", err, zone.presents)
	}
}
