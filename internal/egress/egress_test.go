// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestCheckIPTable(t *testing.T) {
	all := Policy{AllowPrivate: true, AllowLoopback: true}
	cases := []struct {
		ip      string
		policy  Policy
		blocked bool
	}{
		{"169.254.169.254", all, true},
		{"fe80::1", all, true},
		{"::ffff:169.254.169.254", all, true},
		{"0.0.0.0", all, true},
		{"224.0.0.1", all, true},
		{"ff02::1", all, true},
		{"64:ff9b::a9fe:a9fe", all, true},
		{"64:ff9b::7f00:1", Policy{AllowPrivate: true}, true},
		{"64:ff9b::a00:5", Policy{AllowPrivate: true}, false},
		{"64:ff9b::a00:5", Policy{}, true},
		{"64:ff9b:1::7f00:1", all, true},
		{"0.0.0.1", all, true},
		{"0.255.255.255", all, true},
		{"127.0.0.1", Policy{AllowPrivate: true}, true},
		{"::ffff:127.0.0.1", Policy{AllowPrivate: true}, true},
		{"::1", Policy{AllowPrivate: true}, true},
		{"127.0.0.1", Policy{AllowLoopback: true}, false},
		{"::ffff:127.0.0.1", Policy{AllowLoopback: true}, false},
		{"10.1.2.3", Policy{AllowPrivate: true}, false},
		{"10.1.2.3", Policy{}, true},
		{"192.168.1.1", Policy{}, true},
		{"fd00::1", Policy{}, true},
		{"fd00::1", Policy{AllowPrivate: true}, false},
		{"100.64.0.1", Policy{}, true},
		{"93.184.216.34", Policy{}, false},
		{"2606:4700::1111", Policy{}, false},
	}
	for _, tc := range cases {
		err := tc.policy.checkIP(netip.MustParseAddr(tc.ip))
		if (err != nil) != tc.blocked {
			t.Errorf("%s policy=%+v: blocked=%v want %v (%v)", tc.ip, tc.policy, err != nil, tc.blocked, err)
		}
		if err != nil && !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("%s: error does not wrap ErrBlockedDestination", tc.ip)
		}
	}
}

func TestClientDialGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()

	if _, err := NewClient(Policy{AllowPrivate: true, Timeout: 2 * time.Second}).Get(srv.URL); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("loopback should be blocked, got %v", err)
	}
	resp, err := NewClient(Policy{AllowLoopback: true, Timeout: 2 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback allowed: %v", err)
	}
	resp.Body.Close()

	_, err = NewClient(Policy{AllowPrivate: true, AllowLoopback: true, Timeout: 2 * time.Second}).Get("http://169.254.169.254/latest/meta-data/")
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("metadata must be blocked, got %v", err)
	}
}

func TestClientIgnoresProxyEnv(t *testing.T) {
	proxyHit := false
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHit = true }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	_, _ = NewClient(Policy{AllowLoopback: true, Timeout: time.Second}).Get("http://example.invalid:9/")
	if proxyHit {
		t.Fatal("client used proxy from environment")
	}
}

func TestSchemeAndPortRules(t *testing.T) {
	c := NewClient(Policy{AllowLoopback: true, RequireHTTPS: true, Timeout: time.Second})
	if _, err := c.Get("http://127.0.0.1:1/"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("http must be refused when HTTPS required: %v", err)
	}
	if _, err := NewClient(Policy{AllowLoopback: true}).Get("ftp://127.0.0.1/"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("ftp must be refused: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := NewClient(Policy{AllowLoopback: true, AllowedPorts: []int{443}}).Get(srv.URL); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("port outside allow-list must be refused: %v", err)
	}
}

func TestRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer target.Close()
	hop := func(to string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, to, http.StatusFound)
		}))
	}
	toMeta := hop("http://169.254.169.254/latest/")
	defer toMeta.Close()
	toOther := hop(target.URL) // different loopback port => different host
	defer toOther.Close()

	follow := NewClient(Policy{AllowPrivate: true, AllowLoopback: true, MaxRedirects: 3, Timeout: 2 * time.Second})
	if _, err := follow.Get(toMeta.URL); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("redirect to metadata must be blocked: %v", err)
	}
	resp, err := follow.Get(toOther.URL)
	if err != nil {
		t.Fatalf("redirect should be followed: %v", err)
	}
	resp.Body.Close()

	same := NewClient(Policy{AllowLoopback: true, MaxRedirects: 3, SameHostRedirectsOnly: true, Timeout: 2 * time.Second})
	if _, err := same.Get(toOther.URL); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("cross-host redirect must be refused: %v", err)
	}
	none := NewClient(Policy{AllowLoopback: true, Timeout: 2 * time.Second})
	if _, err := none.Get(toOther.URL); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("redirects must be refused at MaxRedirects=0: %v", err)
	}
}

func TestRedirectHopLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()
	c := NewClient(Policy{AllowLoopback: true, MaxRedirects: 2, SameHostRedirectsOnly: true, Timeout: 2 * time.Second})
	if _, err := c.Get(srv.URL); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("hop limit must trip: %v", err)
	}
}

func TestPolicyFromEnv(t *testing.T) {
	base := Policy{AllowPrivate: true}
	if !PolicyFromEnv(base).AllowPrivate {
		t.Fatal("default must keep private allowed")
	}
	t.Setenv(EnvDenyPrivate, "true")
	if PolicyFromEnv(base).AllowPrivate {
		t.Fatal("env switch must disable private")
	}
}
