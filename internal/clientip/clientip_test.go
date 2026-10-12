// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(remote string, hdr map[string][]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestResolve(t *testing.T) {
	const trusted = "10.0.0.0/24, 192.168.5.0/24, fd00::/8"
	cases := []struct {
		name      string
		cidrs     string
		remote    string
		hdr       map[string][]string
		want      string
		forwarded bool
	}{
		{"no trusted set ignores XFF", "", "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"203.0.113.9"}}, "10.0.0.5", false},
		{"untrusted peer XFF ignored", trusted, "198.51.100.7:1", map[string][]string{"X-Forwarded-For": {"1.1.1.1"}}, "198.51.100.7", false},
		{"untrusted peer X-Real-IP ignored", trusted, "198.51.100.7:1", map[string][]string{"X-Real-IP": {"1.1.1.1"}}, "198.51.100.7", false},
		{"rightmost untrusted beats spoofed left entry", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"6.6.6.6, 203.0.113.9"}}, "203.0.113.9", true},
		{"spoofed entry with trusted hop after real", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"6.6.6.6, 203.0.113.9, 192.168.5.2"}}, "203.0.113.9", true},
		{"two trusted proxies, client first", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"203.0.113.9, 192.168.5.2"}}, "203.0.113.9", true},
		{"split XFF header lines", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"6.6.6.6", "203.0.113.9"}}, "203.0.113.9", true},
		{"all hops trusted returns originator", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"192.168.5.9, 10.0.0.9"}}, "192.168.5.9", true},
		{"X-Real-IP only when XFF absent", trusted, "10.0.0.5:1", map[string][]string{"X-Real-IP": {"203.0.113.9"}}, "203.0.113.9", true},
		{"XFF wins over X-Real-IP", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"203.0.113.9"}, "X-Real-IP": {"7.7.7.7"}}, "203.0.113.9", true},
		{"trusted peer, no headers", trusted, "10.0.0.5:1", nil, "10.0.0.5", false},
		{"garbage rightmost entry falls back to peer", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"6.6.6.6, not-an-ip"}}, "10.0.0.5", false},
		{"garbage X-Real-IP falls back to peer", trusted, "10.0.0.5:1", map[string][]string{"X-Real-IP": {"nope"}}, "10.0.0.5", false},
		{"port in XFF entry tolerated", trusted, "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"203.0.113.9:4444"}}, "203.0.113.9", true},
		{"IPv4-mapped IPv6 normalised", trusted, "[::ffff:10.0.0.5]:1", map[string][]string{"X-Forwarded-For": {"::ffff:203.0.113.9"}}, "203.0.113.9", true},
		{"IPv6 client behind v6 proxy", trusted, "[fd00::1]:1", map[string][]string{"X-Forwarded-For": {"2001:db8::7"}}, "2001:db8::7", true},
		{"malformed CIDR entry never trusts", "bogus, 10.0.0.0/33", "10.0.0.5:1", map[string][]string{"X-Forwarded-For": {"203.0.113.9"}}, "10.0.0.5", false},
		{"unparseable peer", trusted, "garbage", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, fwd := New(tc.cidrs).Resolve(req(tc.remote, tc.hdr))
			if got != tc.want || fwd != tc.forwarded {
				t.Fatalf("Resolve = (%q, %v), want (%q, %v)", got, fwd, tc.want, tc.forwarded)
			}
		})
	}
}

func TestPeerTrusted(t *testing.T) {
	r := New("10.0.0.0/24")
	if !r.PeerTrusted("10.0.0.5:99") || r.PeerTrusted("10.0.1.5:99") || r.PeerTrusted("") {
		t.Fatal("PeerTrusted disagrees with the configured CIDR")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvTrustedProxyCIDRs, "10.0.0.0/24")
	if !FromEnv().PeerTrusted("10.0.0.5:1") {
		t.Fatal("FromEnv did not read " + EnvTrustedProxyCIDRs)
	}
}
