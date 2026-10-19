// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// tlv encodes one BER element with a definite length.
func tlv(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	out := []byte{tag}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// rootDSEReply builds the two LDAP messages a server sends for a rootDSE read:
// a SearchResultEntry with attrs and a SearchResultDone with code. A nil attrs
// sends only the Done.
func rootDSEReply(id byte, attrs map[string][]string, order []string, code byte) []byte {
	idTLV := tlv(0x02, []byte{id})
	var out []byte
	if attrs != nil {
		var list []byte
		for _, name := range order {
			var vals []byte
			for _, v := range attrs[name] {
				vals = append(vals, tlv(0x04, []byte(v))...)
			}
			list = append(list, tlv(0x30, tlv(0x04, []byte(name)), tlv(0x31, vals))...)
		}
		out = append(out, tlv(0x30, idTLV, tlv(0x64, tlv(0x04), tlv(0x30, list)))...)
	}
	done := tlv(0x65, tlv(0x0a, []byte{code}), tlv(0x04), tlv(0x04))
	return append(out, tlv(0x30, idTLV, done)...)
}

// serveRootDSE answers one search request on conn. It reads the request frame
// (a single BER SEQUENCE) and echoes its message id.
func serveRootDSE(conn net.Conn, attrs map[string][]string, order []string, code byte) {
	r := bufio.NewReader(conn)
	hdr := make([]byte, 2)
	if _, err := readFull(r, hdr); err != nil {
		return
	}
	n := int(hdr[1])
	if n&0x80 != 0 {
		ext := make([]byte, n&0x7f)
		if _, err := readFull(r, ext); err != nil {
			return
		}
		n = 0
		for _, b := range ext {
			n = n<<8 | int(b)
		}
	}
	body := make([]byte, n)
	if _, err := readFull(r, body); err != nil || len(body) < 3 {
		return
	}
	_, _ = conn.Write(rootDSEReply(body[2], attrs, order, code))
}

// Attributes exactly as OpenLDAP 2.6 (Alpine 3.20, slapd.conf with an mdb
// database) returned them to `ldapsearch -x -s base -b "" '*' '+'` on
// 2026-10-17: no vendorName, configContext cn=config, OpenLDAProotDSE.
var openLDAPRootDSE = map[string][]string{
	"objectclass":          {"top", "OpenLDAProotDSE"},
	"configcontext":        {"cn=config"},
	"namingcontexts":       {"dc=example,dc=org"},
	"supportedldapversion": {"3"},
}

func TestClassifyRootDSE(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string][]string
		tech  string
	}{
		{"OpenLDAP as observed", openLDAPRootDSE, "ldap-openldap"},
		{"OpenLDAP by configContext alone", map[string][]string{"configcontext": {"cn=config"}}, "ldap-openldap"},
		{"AD", map[string][]string{
			"supportedcapabilities": {"1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670"},
			"defaultnamingcontext":  {"DC=corp,DC=local"},
		}, "ldap-ad"},
		{"AD capability without a naming context is not enough", map[string][]string{"supportedcapabilities": {"1.2.840.113556.1.4.800"}}, ""},
		{"naming context without the capability is not AD", map[string][]string{"defaultnamingcontext": {"DC=x"}}, ""},
		{"389 Directory Server", map[string][]string{"vendorname": {"389 Project"}, "vendorversion": {"389-Directory/2.4.5 B2024.100"}}, "ldap-389ds"},
		{"389 outranks its own configContext", map[string][]string{"vendorname": {"389 Project"}, "configcontext": {"cn=config"}}, "ldap-389ds"},
		{"unrecognised vendor", map[string][]string{"vendorname": {"Acme Directory"}}, ""},
		{"empty", map[string][]string{}, ""},
	}
	for _, c := range cases {
		if tech, _ := classifyRootDSE(c.attrs); tech != c.tech {
			t.Errorf("%s: got %q want %q", c.name, tech, c.tech)
		}
	}
}

func startTLSRootDSE(t *testing.T, attrs map[string][]string, order []string, code byte) (string, int) {
	t.Helper()
	tlsCfg, _ := fixtureTLSConfig(t, "ldap.example.com")
	return startListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 512)
		if n, err := conn.Read(buf); err != nil || n < 5 {
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, buf[4], 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		srv := tls.Server(conn, tlsCfg)
		if srv.Handshake() != nil {
			return
		}
		serveRootDSE(srv, attrs, order, code)
	})
}

func activeScanner(active bool) *ProtocolScanner {
	p := NewProtocolScanner(3 * time.Second)
	p.active = active
	return p
}

func rootDSEOf(ev []Evidence) (Evidence, bool) {
	for _, e := range ev {
		if e.Signal == SignalRootDSE {
			return e, true
		}
	}
	return Evidence{}, false
}

func TestLDAPStartTLSRootDSEBranches(t *testing.T) {
	adOrder := []string{"supportedCapabilities", "defaultNamingContext"}
	ad := map[string][]string{"supportedCapabilities": {"1.2.840.113556.1.4.800"}, "defaultNamingContext": {"DC=corp,DC=local"}}
	cases := []struct {
		name  string
		attrs map[string][]string
		order []string
		code  byte
		tech  string // "" with ok=true means a row with no vote
		value string
		ok    bool
	}{
		{"AD", ad, adOrder, 0, "ldap-ad", "rootDSE supportedCapabilities=1.2.840.113556.1.4.800 defaultNamingContext present", true},
		{"OpenLDAP", map[string][]string{"objectClass": {"top", "OpenLDAProotDSE"}, "configContext": {"cn=config"}}, []string{"objectClass", "configContext"}, 0, "ldap-openldap", "rootDSE objectClass=OpenLDAProotDSE", true},
		{"389", map[string][]string{"vendorName": {"389 Project"}, "vendorVersion": {"389-Directory/2.4"}}, []string{"vendorName", "vendorVersion"}, 0, "ldap-389ds", "rootDSE vendorName=389 Project vendorVersion=389-Directory/2.4", true},
		{"answered, no tell", map[string][]string{"vendorName": {"Acme"}}, []string{"vendorName"}, 0, "", "answered, no known vendor tell", true},
		{"refused: insufficient access", nil, nil, 50, "", "refused", true},
		{"refused: strong auth required", nil, nil, 8, "", "refused", true},
		{"refused: operations error", nil, nil, 1, "", "refused", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, port := startTLSRootDSE(t, c.attrs, c.order, c.code)
			ep := activeScanner(true).ScanSTARTTLS(context.Background(), host, port, "ldap")
			if ep.Error != "" || len(ep.Certs) != 1 {
				t.Fatalf("capture: %q", ep.Error)
			}
			e, ok := rootDSEOf(ep.signals)
			if ok != c.ok || e.Tech != c.tech || e.Value != c.value || e.Weight != 60 {
				t.Fatalf("rootdse evidence = %+v ok=%v", e, ok)
			}
			// A refusal or an unknown vendor votes for nothing: the headline is unchanged.
			if c.tech == "" {
				if fp := Resolve(ep.signals); fp.Tech != TechUnknown {
					t.Fatalf("no-vote row changed the headline: %+v", fp)
				}
			}
		})
	}
}

func TestLDAPRootDSEIsSkippedUnlessActive(t *testing.T) {
	host, port := startTLSRootDSE(t, map[string][]string{"configContext": {"cn=config"}}, []string{"configContext"}, 0)
	ep := activeScanner(false).ScanSTARTTLS(context.Background(), host, port, "ldap")
	if _, ok := rootDSEOf(ep.signals); ok || len(ep.Certs) != 1 {
		t.Fatalf("a fast/targeted scan must not read the rootDSE: %+v", ep.signals)
	}
}

func TestScanConfigActiveProbeGating(t *testing.T) {
	if New(ScanConfig{}).protocol.active || New(ScanConfig{Ports: []int{389}}).protocol.active {
		t.Fatal("fast and targeted scans are passive")
	}
	if !New(ScanConfig{ActiveProbes: true}).protocol.active || !New(ScanConfig{Deep: true}).protocol.active {
		t.Fatal("full and deep scans run the active probes")
	}
}

func TestLDAPRootDSEIsBoundedByTheTimeout(t *testing.T) {
	tlsCfg, _ := fixtureTLSConfig(t, "ldap.example.com")
	var stalled atomic.Bool
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 512)
		if n, err := conn.Read(buf); err != nil || n < 5 {
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, buf[4], 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		srv := tls.Server(conn, tlsCfg)
		if srv.Handshake() != nil {
			return
		}
		_, _ = srv.Read(buf) // take the search, never answer
		stalled.Store(true)
		time.Sleep(3 * time.Second)
	})
	p := NewProtocolScanner(time.Second)
	p.active = true
	start := time.Now()
	ep := p.ScanSTARTTLS(context.Background(), host, port, "ldap")
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("probe overran the %v timeout: %v", time.Second, time.Since(start))
	}
	if len(ep.Certs) != 1 {
		t.Fatalf("the certificate must still be captured: %q", ep.Error)
	}
	if _, ok := rootDSEOf(ep.signals); ok {
		t.Fatalf("a stalled server must yield no rootdse row (nothing was learned): %+v", ep.signals)
	}
}

// LDAPS: the read runs on the TLS connection the scan already holds.
func TestImplicitLDAPSRootDSE(t *testing.T) {
	tlsCfg, _ := fixtureTLSConfig(t, "ldaps.example.com")
	var accepts atomic.Int32
	ln := listenLocal(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer c.Close()
				srv := tls.Server(c, tlsCfg)
				if srv.Handshake() == nil {
					serveRootDSE(srv, map[string][]string{"supportedCapabilities": {"1.2.840.113556.1.4.800"}, "defaultNamingContext": {"DC=a"}},
						[]string{"supportedCapabilities", "defaultNamingContext"}, 0)
				}
			}()
		}
	}()
	run := func(cfg ScanConfig) (DiscoveredEndpoint, int32) {
		accepts.Store(0)
		cfg.Timeout = 3 * time.Second
		s := New(cfg)
		conn, _, err := s.dialTLS(context.Background(), "127.0.0.1", portOf(ln), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ep := s.finishTLSCapture(DiscoveredEndpoint{Host: "127.0.0.1", Port: 636, Protocol: "ldaps", Reachable: true}, conn, conn.ConnectionState(), "127.0.0.1", 636, "ldaps")
		return ep, accepts.Load()
	}
	ep, n := run(ScanConfig{ActiveProbes: true})
	if e, ok := rootDSEOf(ep.signals); !ok || e.Tech != "ldap-ad" {
		t.Fatalf("full scan: %+v", ep.signals)
	}
	if n != 1 {
		t.Fatalf("rootDSE opened %d connections, want 1", n)
	}
	if ep, _ := run(ScanConfig{}); len(ep.signals) != 0 {
		if _, ok := rootDSEOf(ep.signals); ok {
			t.Fatal("a non-full scan must not read the rootDSE")
		}
	}
}
