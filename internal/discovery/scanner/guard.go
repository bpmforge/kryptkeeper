// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kryptkeeper/internal/egress"
)

const (
	// EnvDenyCIDRs adds operator CIDRs to the always-on link-local deny list
	// (OWASP-A10-003).
	EnvDenyCIDRs = "KRYPTKEEPER_DISCOVERY_DENY_CIDRS"
	// EnvMaxTargets overrides DefaultMaxTargets (OWASP-A04-005).
	EnvMaxTargets = "KRYPTKEEPER_DISCOVERY_MAX_TARGETS"
	// DefaultMaxTargets caps the expanded host:port count of one scan.
	DefaultMaxTargets = 65536
)

var (
	// ErrTargetDenied: the scan target falls inside the deny list.
	ErrTargetDenied = errors.New("scan target is in a denied network range")
	// ErrTooManyTargets: the scan would expand past the per-scan cap.
	ErrTooManyTargets = errors.New("scan target expands to too many addresses")
)

// builtinDeny is never scannable: link-local space holds cloud metadata
// (169.254.169.254) and has no certificate-bearing estate.
var builtinDeny = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

// DenyCIDRsFromEnv returns the built-in link-local ranges plus any valid
// CIDRs or addresses in KRYPTKEEPER_DISCOVERY_DENY_CIDRS. Invalid tokens are
// ignored.
func DenyCIDRsFromEnv() []netip.Prefix {
	out := append([]netip.Prefix(nil), builtinDeny...)
	for _, tok := range strings.Split(os.Getenv(EnvDenyCIDRs), ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if p, err := netip.ParsePrefix(tok); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// MaxTargetsFromEnv returns the per-scan expanded-target cap.
func MaxTargetsFromEnv() int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(EnvMaxTargets))); err == nil && n > 0 {
		return n
	}
	return DefaultMaxTargets
}

func denied(deny []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range deny {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckTarget validates one scan target (bare host, host:port, IP, or CIDR)
// before a job is queued. portsPerHost is how many ports each address will be
// probed on. Hostnames are not resolved here; the dialers
// (guardedDialer) re-check the resolved address when connecting.
func CheckTarget(target string, portsPerHost int, deny []netip.Prefix, maxTargets int) error {
	if portsPerHost < 1 {
		portsPerHost = 1
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host, portsPerHost = h, 1
	}
	if pfx, err := netip.ParsePrefix(host); err == nil {
		pfx = pfx.Masked()
		for _, d := range deny {
			if d.Bits() <= pfx.Bits() && d.Contains(pfx.Addr()) {
				return ErrTargetDenied
			}
		}
		hostBits := pfx.Addr().BitLen() - pfx.Bits()
		if hostBits > 32 || (uint64(1)<<hostBits)*uint64(portsPerHost) > uint64(maxTargets) {
			return ErrTooManyTargets
		}
		return nil
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && denied(deny, ip) {
		return ErrTargetDenied
	}
	return nil
}

// dialPolicy is the address policy applied to every address a scanner
// actually connects to. Private space and loopback stay scannable (inventorying
// internal networks is the product's purpose, and a scope has no per-operator
// loopback notion to key on); link-local/cloud-metadata, unspecified and
// multicast are refused by egress, plus the operator deny CIDRs.
var dialPolicy = egress.Policy{AllowPrivate: true, AllowLoopback: true}

// guardedDialer returns a dialer that checks the resolved address at connect
// time. CheckTarget only sees the literal target, so a hostname that resolves
// (or rebinds) to 169.254.169.254 would otherwise be dialled.
func guardedDialer(timeout time.Duration) *net.Dialer {
	deny := DenyCIDRsFromEnv()
	return &net.Dialer{Timeout: timeout, Control: func(network, address string, c syscall.RawConn) error {
		if err := dialPolicy.DialControl()(network, address, c); err != nil {
			return ErrTargetDenied
		}
		if ap, err := netip.ParseAddrPort(address); err == nil && denied(deny, ap.Addr()) {
			return ErrTargetDenied
		}
		return nil
	}}
}
