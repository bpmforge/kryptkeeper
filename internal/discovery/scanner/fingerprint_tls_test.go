// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSStackTable(t *testing.T) {
	if len(tlsStackEntries) == 0 {
		t.Fatal("embedded table did not load")
	}
	valid := map[string]bool{"schannel": true, "openssl": true, "jsse": true, "go": true, "boringssl": true, "gnutls": true, "nss": true}
	for i, e := range tlsStackEntries {
		if !valid[e.Stack] {
			t.Errorf("entry %d: unknown stack %q", i, e.Stack)
		}
		if e.Extensions == "" && e.Suite == "" && e.Ticket == nil && e.SizeClass == "" {
			t.Errorf("entry %d (%s) is all wildcards", i, e.Stack)
		}
		// Unverified entries are predictions; they may not outvote anything.
		if !e.Verified && e.Weight > tlsStackWeight {
			t.Errorf("entry %d (%s) is unverified but claims weight %d > %d", i, e.Stack, e.Weight, tlsStackWeight)
		}
		if e.Weight <= 0 {
			t.Errorf("entry %d (%s) has no weight", i, e.Stack)
		}
	}
}

func TestLoadTLSStackTableMalformedDegrades(t *testing.T) {
	if got := loadTLSStackTable([]byte("{nope")); got != nil {
		t.Fatalf("malformed table must load as empty, got %+v", got)
	}
}

func TestMatchTLSStack(t *testing.T) {
	yes, no := true, false
	entries := []TLSStackEntry{
		{Stack: "openssl", Extensions: "ff01,000b", Ticket: &yes, Weight: 25},
		{Stack: "openssl", Extensions: "ff01,000b", Weight: 25},
		{Stack: "go", Extensions: "ff01,0017", Weight: 25},
		{Stack: "jsse", Suite: "c02f", SizeClass: "s", Weight: 25},
		{Stack: "nss", Extensions: "aaaa", Weight: 25},
		{Stack: "gnutls", Extensions: "aaaa", Weight: 25},
	}
	cases := []struct {
		name string
		f    tlsFeatures
		want string
	}{
		{"exact ext + ticket", tlsFeatures{extensions: []uint16{0xff01, 0x000b}, ticket: true}, "openssl"},
		{"wildcard ticket", tlsFeatures{extensions: []uint16{0xff01, 0x000b}, ticket: no}, "openssl"},
		{"extension order matters", tlsFeatures{extensions: []uint16{0x000b, 0xff01}}, ""},
		{"suite + size", tlsFeatures{suite: 0xc02f, sizeClass: "s"}, "jsse"},
		{"suite right, size wrong", tlsFeatures{suite: 0xc02f, sizeClass: "l"}, ""},
		{"unknown combination", tlsFeatures{extensions: []uint16{0x1234}}, ""},
		{"ambiguous equal-specificity entries read unknown", tlsFeatures{extensions: []uint16{0xaaaa}}, ""},
	}
	for _, c := range cases {
		if got, _ := matchTLSStack(entries, c.f); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got, _ := matchTLSStack(nil, tlsFeatures{}); got != "" {
		t.Error("empty table matches nothing")
	}
}

func TestTLSStackEvidenceShape(t *testing.T) {
	entries := []TLSStackEntry{{Stack: "jsse", Extensions: "0017", Weight: 25}}
	ev := tlsStackEvidence(entries, tlsFeatures{extensions: []uint16{0x0017}})
	if len(ev) != 1 || ev[0].Signal != SignalTLSStack || ev[0].Value != "jsse" || ev[0].Weight != 25 || ev[0].Tech != "" {
		t.Fatalf("evidence = %+v", ev)
	}
	if tlsStackEvidence(entries, tlsFeatures{extensions: []uint16{0x9999}}) != nil {
		t.Fatal("an unknown combination must yield no evidence row")
	}
}

func TestPlatformTieBreakOnlyWithoutStrongerSignal(t *testing.T) {
	stack := NewEvidence(SignalTLSStack, "jsse", "")
	if fp := Resolve([]Evidence{stack}); fp.Platform != PlatformJava || fp.TLSStack != "jsse" || fp.Tech != TechUnknown {
		t.Fatalf("stack alone: %+v", fp)
	}
	// A header voting windows decides alone, even though the stack says java.
	iis := NewEvidence(SignalHTTPHeader, "Server: Microsoft-IIS/10.0", "iis")
	if fp := Resolve([]Evidence{stack, iis}); fp.Platform != PlatformWindows || fp.TLSStack != "jsse" {
		t.Fatalf("stronger signal must win: %+v", fp)
	}
	// Even a weak port vote beats the stack: the stack is the last resort.
	port := NewEvidence(SignalPort, "rdp", "rdp")
	if fp := Resolve([]Evidence{stack, port}); fp.Platform != PlatformWindows {
		t.Fatalf("port vote should outrank the stack: %+v", fp)
	}
	if fp := Resolve([]Evidence{NewEvidence(SignalTLSStack, "schannel", "")}); fp.Platform != PlatformWindows {
		t.Fatalf("schannel -> windows: %+v", fp)
	}
	if fp := Resolve([]Evidence{NewEvidence(SignalTLSStack, "openssl", "")}); fp.Platform != PlatformUnknown {
		t.Fatalf("openssl implies no platform: %+v", fp)
	}
}

func TestStackClientHelloShape(t *testing.T) {
	h, err := stackClientHello("web.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x16 || int(binary.BigEndian.Uint16(h[3:5])) != len(h)-5 || h[5] != 0x01 {
		t.Fatalf("not a well-formed ClientHello record: % x", h[:12])
	}
	if !bytes.Contains(h, []byte("web.example.com")) {
		t.Fatal("a hostname target must send SNI")
	}
	ip, _ := stackClientHello("192.0.2.1")
	if bytes.Contains(ip, []byte("192.0.2.1")) {
		t.Fatal("an IP literal must not be sent as SNI")
	}
}

// A real crypto/tls server answers with the extension order the "go" row was
// observed from; the probe must classify it end to end.
func TestTLSStackProbeGoServer(t *testing.T) {
	cfg, _ := fixtureTLSConfig(t, "go.test")
	cfg.MaxVersion = tls.VersionTLS12
	l := listenLocal(t)
	serveTLS(t, l, cfg)
	for _, host := range []string{"127.0.0.1", "localhost"} {
		ev := probeTLSStack(context.Background(), host, portOf(l), 3*time.Second)
		if len(ev) != 1 || ev[0].Value != "go" {
			t.Fatalf("host %s: evidence = %+v", host, ev)
		}
	}
}

func TestTLSStackProbeIgnoresNonTLSAndTLS13Only(t *testing.T) {
	plain := listenLocal(t)
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	if ev := probeTLSStack(context.Background(), "127.0.0.1", portOf(plain), time.Second); ev != nil {
		t.Fatalf("plain HTTP produced evidence: %+v", ev)
	}
	cfg, _ := fixtureTLSConfig(t, "tls13.test")
	cfg.MinVersion = tls.VersionTLS13
	l := listenLocal(t)
	serveTLS(t, l, cfg)
	if ev := probeTLSStack(context.Background(), "127.0.0.1", portOf(l), time.Second); ev != nil {
		t.Fatalf("TLS1.3-only server (alert to a 1.2 hello) produced evidence: %+v", ev)
	}
}

// D-206: the extra connection happens only in deep scans.
func TestStackProbeRunsOnlyInDeepScans(t *testing.T) {
	cfg, _ := fixtureTLSConfig(t, "go.test")
	cfg.MaxVersion = tls.VersionTLS12
	l := listenLocal(t)
	var n atomic.Int32
	counted := &acceptCounter{Listener: l, n: &n}
	serveTLS(t, counted, cfg)

	capture := func(deep bool) DiscoveredEndpoint {
		s := New(ScanConfig{Timeout: 3 * time.Second, Deep: deep})
		return finalizeFingerprint(s.scanEndpointOnce(context.Background(), net.JoinHostPort("127.0.0.1", itoa(portOf(l)))), protocolForPort(portOf(l)))
	}
	n.Store(0)
	ep := capture(false)
	if got := n.Load(); got != 1 || ep.Fingerprint.TLSStack != "unknown" {
		t.Fatalf("non-deep: %d connections, stack %q", got, ep.Fingerprint.TLSStack)
	}
	n.Store(0)
	ep = capture(true)
	if n.Load() < 2 || ep.Fingerprint.TLSStack != "go" {
		t.Fatalf("deep: %d connections, stack %q", n.Load(), ep.Fingerprint.TLSStack)
	}
}

type acceptCounter struct {
	net.Listener
	n *atomic.Int32
}

func (a *acceptCounter) Accept() (net.Conn, error) {
	c, err := a.Listener.Accept()
	if err == nil {
		a.n.Add(1)
	}
	return c, err
}

// Features observed from real servers in the W34-20 corpus; each must resolve
// to the stack that produced it.
func TestTLSStackTableMatchesCorpusObservations(t *testing.T) {
	obs := []struct {
		server, exts, stack string
		suite               uint16
		size                string
	}{
		{"openldap ldaps", "ff01,000b,0023,0017", "openssl", 0xc030, "xs"},
		{"dovecot imaps", "ff01,000b,0023,0017", "openssl", 0xc02f, "xs"},
		{"redis tls", "ff01,000b,0023,0017", "openssl", 0xc02f, "xs"},
		{"nginx", "ff01,000b,0023,0010,0017", "openssl", 0xc02f, "s"},
		{"apache httpd", "ff01,000b,0023,0010,0017", "openssl", 0xc02f, "s"},
		{"vault", "0023,ff01,0017,0010,000b", "go", 0xc02f, "s"},
		{"tomcat jsse", "0017,0023,ff01", "jsse", 0xc02f, "l"},
	}
	for _, o := range obs {
		var ids []uint16
		for _, h := range strings.Split(o.exts, ",") {
			var id uint16
			if _, err := fmt.Sscanf(h, "%x", &id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		got, entry := matchTLSStack(tlsStackEntries, tlsFeatures{suite: o.suite, extensions: ids, ticket: true, sizeClass: o.size})
		if got != o.stack || !entry.Verified {
			t.Errorf("%s: got %q (verified=%v), want verified %q", o.server, got, entry.Verified, o.stack)
		}
	}
}
