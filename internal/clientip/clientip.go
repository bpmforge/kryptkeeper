// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package clientip derives the caller address that IP-keyed controls (rate
// limits) bucket by. It is the single place that decides how far to trust
// forwarding headers, so two limiters can never disagree about who a client
// is.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
)

// EnvTrustedProxyCIDRs names the comma-separated CIDR list of reverse proxies
// whose forwarding headers are believed. Default empty: trust nobody.
const EnvTrustedProxyCIDRs = "APP_TRUSTED_PROXY_CIDRS"

// Resolver holds a parsed trusted-proxy set. It is immutable after
// construction, so it is safe to share between goroutines.
type Resolver struct {
	trusted []netip.Prefix
}

// New parses a comma-separated CIDR list. A malformed entry is skipped, so a
// misconfiguration degrades to "that entry is not trusted", never to "trust
// everyone".
func New(cidrs string) *Resolver {
	var trusted []netip.Prefix
	for _, part := range strings.Split(cidrs, ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(part)); err == nil {
			trusted = append(trusted, p.Masked())
		}
	}
	return &Resolver{trusted: trusted}
}

// envResolver memoises the last parse so FromEnv, called from free functions on
// every audit event, rate-limit check and cookie decision, parses the CIDR
// list once per distinct value instead of once per call. Injecting a Resolver
// instead would mean threading it through emitAuditEvent and its ~780 call
// sites; the cache holds only an immutable value derived from the env string,
// and a changed env (tests, or a reload) is still picked up.
var envResolver atomic.Pointer[envParse]

type envParse struct {
	raw string
	res *Resolver
}

// FromEnv returns a Resolver for APP_TRUSTED_PROXY_CIDRS.
func FromEnv() *Resolver {
	raw := os.Getenv(EnvTrustedProxyCIDRs)
	if c := envResolver.Load(); c != nil && c.raw == raw {
		return c.res
	}
	c := &envParse{raw: raw, res: New(raw)}
	envResolver.Store(c)
	return c.res
}

// ParseAddr parses a bare IP or a host:port pair into a canonical address
// (zone dropped, IPv4-mapped IPv6 unmapped). It reports false for anything
// that is not an IP literal, so garbage in a header never becomes a bucket key.
func ParseAddr(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

func (r *Resolver) trusts(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PeerTrusted reports whether remoteAddr (an http.Request.RemoteAddr) is
// inside the trusted-proxy set.
func (r *Resolver) PeerTrusted(remoteAddr string) bool {
	addr, ok := ParseAddr(remoteAddr)
	return ok && r.trusts(addr)
}

// Resolve returns the client address for req and whether it was taken from a
// forwarding header (true) rather than being the TCP peer (false).
//
// Headers are believed only when the TCP peer is a trusted proxy. Then
// X-Forwarded-For is walked from the RIGHT, skipping hops that are
// themselves trusted proxies, and the first untrusted entry wins: a proxy
// appends what it saw, so only entries to the right of the first untrusted
// hop were written by infrastructure we control; everything left of it is
// client-supplied and can be anything. X-Real-IP is consulted only when
// X-Forwarded-For is absent. A malformed entry stops the walk and yields the
// peer, so garbage can neither mint a key nor be skipped to reach a spoofed
// value further left.
func (r *Resolver) Resolve(req *http.Request) (string, bool) {
	peer, ok := ParseAddr(req.RemoteAddr)
	if !ok {
		return "", false
	}
	if !r.trusts(peer) {
		return peer.String(), false
	}
	if xff := strings.Join(req.Header.Values("X-Forwarded-For"), ","); strings.TrimSpace(xff) != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, ok := ParseAddr(hops[i])
			if !ok {
				return peer.String(), false
			}
			// Every hop being a trusted proxy means the chain is all
			// infrastructure; its leftmost entry is the originating address.
			if !r.trusts(hop) || i == 0 {
				return hop.String(), true
			}
		}
	}
	if real, ok := ParseAddr(req.Header.Get("X-Real-IP")); ok {
		return real.String(), true
	}
	return peer.String(), false
}

// ClientIP is Resolve without the provenance flag.
func (r *Resolver) ClientIP(req *http.Request) string {
	ip, _ := r.Resolve(req)
	return ip
}
