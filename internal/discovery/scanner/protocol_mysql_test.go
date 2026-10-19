// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// mysqlGreetingPacket builds an initial handshake packet (protocol 10).
func mysqlGreetingPacket(version string, caps uint32) []byte {
	p := []byte{mysqlProtocolVersion10}
	p = append(p, version...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, 7) // thread id
	p = append(p, "abcdefgh"...)               // salt part 1
	p = append(p, 0)                           // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(caps))
	p = append(p, mysqlCharsetUTF8mb4)
	p = binary.LittleEndian.AppendUint16(p, 2) // status
	p = binary.LittleEndian.AppendUint16(p, uint16(caps>>16))
	p = append(p, make([]byte, 11)...)
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}, p...)
}

// mysqlFixture greets, and when the client sends an SSLRequest, upgrades.
func mysqlFixture(t *testing.T, version string, caps uint32, cfg *tls.Config) (string, int) {
	t.Helper()
	return startListener(t, func(conn net.Conn) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // bound the fixture
		if _, err := conn.Write(mysqlGreetingPacket(version, caps)); err != nil {
			return
		}
		var h [4]byte
		if _, err := readFull(conn, h[:]); err != nil {
			return
		}
		body := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
		if _, err := readFull(conn, body); err != nil || len(body) != 32 {
			return
		}
		if binary.LittleEndian.Uint32(body)&mysqlClientSSL == 0 {
			return
		}
		srv := tls.Server(conn, cfg)
		_ = srv.Handshake()
	})
}

func TestMySQLCapturesCertAfterSSLRequest(t *testing.T) {
	cfg, cn := fixtureTLSConfig(t, "db.example.com")
	host, port := mysqlFixture(t, "8.0.35", mysqlClientSSL|mysqlClientProtocol41, cfg)
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "mysql")
	if ep.Error != "" || len(ep.Certs) != 1 || ep.Certs[0].CommonName != cn {
		t.Fatalf("capture: %q %+v", ep.Error, ep.Certs)
	}
	if ep.Protocol != "mysql" || len(ep.Findings) != 0 {
		t.Fatalf("protocol %q findings %v", ep.Protocol, ep.Findings)
	}
	fp := Resolve(ep.signals)
	if fp.Tech != "mysql" || fp.Confidence != ConfidenceMedium || !hasEvidence(ep.signals, "mysql", "8.0.35") {
		t.Fatalf("fingerprint = %+v (%+v)", fp, ep.signals)
	}
}

func TestMariaDBIsNamedFromItsGreeting(t *testing.T) {
	cfg, _ := fixtureTLSConfig(t, "maria.example.com")
	host, port := mysqlFixture(t, "5.5.5-10.11.6-MariaDB-1:10.11.6+maria~ubu2204", mysqlClientSSL, cfg)
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "mysql")
	if fp := Resolve(ep.signals); fp.Tech != "other:mariadb" {
		t.Fatalf("fingerprint = %+v", fp)
	}
}

func TestMySQLWithoutSSLCapabilityIsTLSDisabledFinding(t *testing.T) {
	cfg, _ := fixtureTLSConfig(t, "unused")
	host, port := mysqlFixture(t, "5.7.44", mysqlClientProtocol41, cfg)
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "mysql")
	if !ep.Reachable || !HasFinding(ep.Findings, FindingMySQLTLSDisabled) || len(ep.Certs) != 0 {
		t.Fatalf("want reachable + %s, got %+v", FindingMySQLTLSDisabled, ep)
	}
	if !contains(HighSeverityEndpointFindings, FindingMySQLTLSDisabled) {
		t.Fatal("MYSQL_TLS_DISABLED must be a high-severity endpoint finding")
	}
}

func TestParseMySQLGreetingRejectsMalformed(t *testing.T) {
	good := mysqlGreetingPacket("8.0.1", mysqlClientSSL)[4:]
	if g, err := parseMySQLGreeting(good); err != nil || g.Version != "8.0.1" || !g.SSL() {
		t.Fatalf("good: %+v %v", g, err)
	}
	for name, b := range map[string][]byte{
		"empty":            nil,
		"error packet":     {0xff, 0x15, 0x04, '#', 'H', 'Y', '0', '0', '0'},
		"old protocol":     {9, 'x', 0},
		"no NUL":           {10, 'a', 'b'},
		"truncated":        {10, 'a', 0, 1, 2},
		"truncated salt":   append([]byte{10, 'a', 0}, make([]byte, 10)...),
		"only high caps":   nil,
		"version past end": {10, 'a', 'b', 'c'},
	} {
		if _, err := parseMySQLGreeting(b); err == nil && name != "only high caps" {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestMySQLSSLRequestShape(t *testing.T) {
	p := mysqlSSLRequest()
	if len(p) != 4+32 || p[0] != 32 || p[3] != 1 {
		t.Fatalf("header/length: % x", p[:5])
	}
	if binary.LittleEndian.Uint32(p[4:])&mysqlClientSSL == 0 {
		t.Fatal("SSLRequest must carry the SSL capability")
	}
}

func TestMySQLNonMySQLPeerIsRecordedReachable(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	})
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "mysql")
	if !ep.Reachable || ep.Error == "" || len(ep.Certs) != 0 {
		t.Fatalf("non-MySQL peer: %+v", ep)
	}
}
