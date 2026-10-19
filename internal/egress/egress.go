// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package egress builds HTTP clients for operator-configured outbound URLs
// (notification webhooks, inventory sources, upstream ACME directories). Those
// URLs are attacker-influenced input: without a guard they turn the hub into a
// request forwarder for cloud metadata (169.254.169.254) and an internal port
// scanner. The guard runs on the address actually dialled, after DNS
// resolution and for every redirect hop, so a hostname that resolves to a
// forbidden address cannot slip through.
//
// An internal PKI hub legitimately talks to private-network services, so the
// default policy used by callers allows RFC1918/ULA space; link-local,
// unspecified and multicast space is refused unconditionally.
//
// The claim this package backs is limited to user-supplied URL calls; discovery scanners and fixed-endpoint cloud/vendor clients are listed with reasons in lint_test.go.
package egress

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedDestination is wrapped by every refusal so callers can map it to
// a generic message instead of reflecting the raw network error.
var ErrBlockedDestination = errors.New("egress: destination blocked")

// BlockedMessage tells an operator why a configured destination was refused
// and what they can change. There is deliberately no allowlist for loopback or
// link-local space: the guard is not relaxed for convenience.
const BlockedMessage = "Blocked by the hub's outbound egress guard: loopback, link-local and cloud-metadata addresses are never allowed. " +
	"Point the destination at a LAN or public address instead (private ranges are allowed unless KRYPTKEEPER_EGRESS_DENY_PRIVATE=true). See docs/ops/EGRESS.md."

// ExplainBlocked returns BlockedMessage when errText came from this guard.
func ExplainBlocked(errText string) (string, bool) {
	if strings.Contains(errText, ErrBlockedDestination.Error()) {
		return BlockedMessage, true
	}
	return "", false
}

// EnvDenyPrivate, when "true", makes PolicyFromEnv refuse RFC1918/ULA/CGNAT
// space too, for deployments that only talk to public SaaS.
const EnvDenyPrivate = "KRYPTKEEPER_EGRESS_DENY_PRIVATE"

// Policy describes what an egress client may reach. Link-local (including
// cloud metadata), unspecified and multicast addresses are always refused.
type Policy struct {
	AllowPrivate  bool          // RFC1918, ULA fc00::/7, CGNAT 100.64/10
	AllowLoopback bool          // 127/8, ::1
	AllowedPorts  []int         // empty = any port
	MaxRedirects  int           // 0 = redirects are refused
	Timeout       time.Duration // whole-request timeout; 0 = 30s
	RequireHTTPS  bool
	// SameHostRedirectsOnly refuses a redirect to a different host (or a
	// scheme downgrade) so credentials set on the first request are never
	// replayed to a third party.
	SameHostRedirectsOnly bool
	// RootCAs, when non-nil, replaces the system roots for TLS verification
	// (devices fronted by an internal CA). The address policy still applies.
	RootCAs *x509.CertPool
}

// PolicyFromEnv returns p with AllowPrivate switched off when
// KRYPTKEEPER_EGRESS_DENY_PRIVATE=true.
func PolicyFromEnv(p Policy) Policy {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(EnvDenyPrivate)), "true") {
		p.AllowPrivate = false
	}
	return p
}

var (
	cgnat    = netip.MustParsePrefix("100.64.0.0/10")
	thisNet  = netip.MustParsePrefix("0.0.0.0/8")
	nat64Pfx = netip.MustParsePrefix("64:ff9b::/96")
	// RFC 8215 local-use NAT64 prefix: a deployment can map any IPv4 address
	// (loopback, metadata) into it, and unlike 64:ff9b::/96 the embedding
	// offset is deployment-defined, so refuse the whole range, not unwrap it.
	nat64LocalPfx = netip.MustParsePrefix("64:ff9b:1::/48")
	// Cloud metadata services that sit outside link-local and would otherwise
	// pass as private (ULA) or CGNAT space, which on-prem integrations need:
	// AWS IMDS over IPv6 and Alibaba Cloud's metadata endpoint.
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("fd00:ec2::254"),
		netip.MustParseAddr("100.100.100.200"),
	}
)

// CheckIP reports whether p allows dialling ip, wrapping ErrBlockedDestination
// when it does not. It is the single address-policy table: other packages
// that dial requester-influenced hosts (ACME http-01) use it instead of
// keeping a weaker copy.
func (p Policy) CheckIP(ip netip.Addr) error { return p.checkIP(ip) }

// DialControl returns a net.Dialer.Control hook that applies p's address
// policy to the address actually being connected to, after DNS resolution.
func (p Policy) DialControl() func(network, address string, c syscall.RawConn) error {
	return p.control
}

func (p Policy) checkIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if nat64LocalPfx.Contains(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
	}
	if nat64Pfx.Contains(ip) {
		// NAT64 embeds an IPv4 address; judge the embedded address.
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
		}
	}
	switch {
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified(), thisNet.Contains(ip):
		return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
	case ip.IsLoopback():
		if !p.AllowLoopback {
			return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
		}
	case ip.IsPrivate() || cgnat.Contains(ip):
		if !p.AllowPrivate {
			return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
		}
	}
	return nil
}

func (p Policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address", ErrBlockedDestination)
	}
	return p.checkIP(ap.Addr())
}

// checkURL enforces scheme and port rules on the first request and on every
// redirect hop (it runs in the transport).
func (p Policy) checkURL(req *http.Request) error {
	u := req.URL
	switch u.Scheme {
	case "https":
	case "http":
		if p.RequireHTTPS {
			return fmt.Errorf("%w: https required", ErrBlockedDestination)
		}
	default:
		return fmt.Errorf("%w: scheme %q", ErrBlockedDestination, u.Scheme)
	}
	if len(p.AllowedPorts) == 0 {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if n, err := strconv.Atoi(port); err == nil {
		for _, ok := range p.AllowedPorts {
			if ok == n {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: port %s", ErrBlockedDestination, port)
}

type guardTransport struct {
	base   http.RoundTripper
	policy Policy
}

func (g guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.policy.checkURL(req); err != nil {
		return nil, err
	}
	return g.base.RoundTrip(req)
}

// NewClient returns an HTTP client bound by policy. The transport ignores
// proxy environment variables (a proxy would dial on the client's behalf and
// bypass the address guard) and does not reuse connections.
func NewClient(policy Policy) *http.Client {
	timeout := policy.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: policy.control}
	base := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	if policy.RootCAs != nil {
		base.TLSClientConfig = &tls.Config{RootCAs: policy.RootCAs, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: guardTransport{base: base, policy: policy},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > policy.MaxRedirects {
				return fmt.Errorf("%w: redirect refused", ErrBlockedDestination)
			}
			if policy.SameHostRedirectsOnly {
				first := via[0].URL
				if !strings.EqualFold(req.URL.Host, first.Host) || (first.Scheme == "https" && req.URL.Scheme != "https") {
					return fmt.Errorf("%w: cross-host redirect refused", ErrBlockedDestination)
				}
			}
			return nil
		},
	}
}
