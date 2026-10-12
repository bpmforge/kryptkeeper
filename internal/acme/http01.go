// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"kryptkeeper/internal/egress"
)

// http01Dial replaces the guarded dialer in tests (see SetHTTP01DialContext).
type http01Dial func(ctx context.Context, network, addr string) (net.Conn, error)

// http01DialControl is the dial guard for validation fetches. It runs on the
// address actually being connected to, after DNS resolution and for every
// redirect hop, so a hostname that resolves to loopback, cloud metadata
// (169.254.169.254) or a NAT64/IPv4-mapped form of either cannot make the CA
// fetch internal services. It is the shared egress table rather than a local
// copy so the two cannot drift apart. RFC1918/ULA ranges stay reachable
// (AllowPrivate): this is an internal CA whose main clients are internal
// servers (FG-1).
func http01DialControl() func(network, address string, c syscall.RawConn) error {
	return egress.Policy{AllowPrivate: true}.DialControl()
}

// http01CheckRedirect follows at most 10 redirects, and only to http/https
// URLs on the default ports; the dial guard still applies to each hop.
func http01CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("http-01: too many redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("http-01: redirect to scheme %q refused", req.URL.Scheme)
	}
	if p := req.URL.Port(); p != "" && p != "80" && p != "443" {
		return fmt.Errorf("http-01: redirect to port %s refused", p)
	}
	return nil
}

// newHTTP01Client builds the validation client. A nil dial uses the guarded
// production dialer. The transport has no Proxy, so environment proxy
// settings cannot route validation around the dial guard.
func newHTTP01Client(dial http01Dial) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, Control: http01DialControl()}).DialContext
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: http01CheckRedirect,
		Transport: &http.Transport{
			DialContext:         dial,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// SetHTTP01DialContext replaces the dialer http-01 validation uses, so an
// in-process test can route a DNS name like shop.example.test:80 to a local
// listener. Production servers never call it.
func (s *Server) SetHTTP01DialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.http01Dial = dial
}
