// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// W14-03: protocol-aware scanning against fixture listeners — STARTTLS
// (line + binary), SSH KEXINIT, and RDP.

func fixtureTLSConfig(t *testing.T, cn string) (*tls.Config, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, cn
}

// startListener runs handle for one accepted connection and returns the
// host, port to dial.
func startListener(t *testing.T, handle func(conn net.Conn)) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handle(conn)
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestSMTPStartTLSCapturesCert(t *testing.T) {
	tlsCfg, cn := fixtureTLSConfig(t, "mail.example.com")
	skipVerb := false
	host, port := startListener(t, func(conn net.Conn) {
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("220 mail.example.com ESMTP\r\n"))
		_, _ = r.ReadString('\n') // EHLO
		_, _ = conn.Write([]byte("250-mail.example.com\r\n250 STARTTLS\r\n"))
		line, _ := r.ReadString('\n') // STARTTLS
		if skipVerb {
			return
		}
		if !strings.HasPrefix(line, "STARTTLS") {
			return
		}
		_, _ = conn.Write([]byte("220 go ahead\r\n"))
		srv := tls.Server(conn, tlsCfg)
		_ = srv.Handshake()
		_ = srv.Close()
	})
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "smtp")
	if ep.Error != "" {
		t.Fatalf("scan error: %s", ep.Error)
	}
	if len(ep.Certs) != 1 || ep.Certs[0].CommonName != cn {
		t.Fatalf("expected the served cert: %+v", ep.Certs)
	}
	if ep.Protocol != "starttls-smtp" {
		t.Fatalf("protocol tag: %q", ep.Protocol)
	}
}

func TestPostgresStartTLSCapturesCert(t *testing.T) {
	tlsCfg, cn := fixtureTLSConfig(t, "db.example.com")
	host, port := startListener(t, func(conn net.Conn) {
		buf := make([]byte, 8)
		_, _ = readFull(conn, buf)
		if binary.BigEndian.Uint32(buf[4:]) != 80877103 {
			_, _ = conn.Write([]byte("N"))
			return
		}
		_, _ = conn.Write([]byte("S")) // SSL supported
		srv := tls.Server(conn, tlsCfg)
		_ = srv.Handshake()
		_ = srv.Close()
	})
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "postgres")
	if ep.Error != "" || len(ep.Certs) != 1 || ep.Certs[0].CommonName != cn {
		t.Fatalf("postgres capture: %s %+v", ep.Error, ep.Certs)
	}
}

func TestSSHCapturesHostKeyAlgorithms(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n') // our banner
		// Build a KEXINIT with two name-lists: kex, then host-key.
		var payload []byte
		payload = append(payload, 20)                  // msg type
		payload = append(payload, make([]byte, 16)...) // cookie
		writeNameList := func(s string) {
			var l [4]byte
			binary.BigEndian.PutUint32(l[:], uint32(len(s)))
			payload = append(payload, l[:]...)
			payload = append(payload, []byte(s)...)
		}
		writeNameList("curve25519-sha256")        // kex_algorithms
		writeNameList("rsa-sha2-512,ssh-ed25519") // server_host_key_algorithms
		// Wrap: uint32 pkt_len, byte pad_len, payload, padding.
		padLen := byte(4)
		pktLen := uint32(1 + len(payload) + int(padLen))
		var out []byte
		var l4 [4]byte
		binary.BigEndian.PutUint32(l4[:], pktLen)
		out = append(out, l4[:]...)
		out = append(out, padLen)
		out = append(out, payload...)
		out = append(out, make([]byte, padLen)...)
		_, _ = conn.Write(out)
	})
	ep := NewProtocolScanner(3*time.Second).ScanSSH(context.Background(), host, port)
	if ep.Error != "" {
		t.Fatalf("ssh scan: %s", ep.Error)
	}
	if !strings.Contains(ep.Banner, "OpenSSH") {
		t.Fatalf("banner: %q", ep.Banner)
	}
	if len(ep.HostKeyAlgorithms) != 2 || ep.HostKeyAlgorithms[1] != "ssh-ed25519" {
		t.Fatalf("host-key algorithms: %v", ep.HostKeyAlgorithms)
	}
	if len(ep.Certs) != 0 {
		t.Fatal("classic SSH carries no certificate")
	}
}

func TestRDPTLSSecurityCapturesCert(t *testing.T) {
	tlsCfg, cn := fixtureTLSConfig(t, "rdp.example.com")
	host, port := startListener(t, func(conn net.Conn) {
		req := make([]byte, 19)
		_, _ = readFull(conn, req)
		// Connection Confirm: TPKT(4) + X.224 CC(7) + Neg Rsp(8) = 19.
		resp := []byte{
			0x03, 0x00, 0x00, 0x13,
			0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CC
			0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, // Neg Rsp: type 2 (grant), PROTOCOL_SSL
		}
		_, _ = conn.Write(resp)
		srv := tls.Server(conn, tlsCfg)
		_ = srv.Handshake()
		_ = srv.Close()
	})
	ep := NewProtocolScanner(3*time.Second).ScanRDP(context.Background(), host, port)
	if ep.Error != "" || len(ep.Certs) != 1 || ep.Certs[0].CommonName != cn {
		t.Fatalf("rdp capture: %s %+v", ep.Error, ep.Certs)
	}
}

// Review fix (crypto challenger #1): a hostile RDP endpoint sending a
// TPKT length < 4 must NOT panic the scan worker.
func TestRDPMalformedTPKTDoesNotPanic(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		req := make([]byte, 19)
		_, _ = readFull(conn, req)
		_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x00}) // TPKT length 0 → total-4 = -4
	})
	ep := NewProtocolScanner(2*time.Second).ScanRDP(context.Background(), host, port)
	if ep.Error == "" {
		t.Fatal("malformed X.224 confirm must error, not panic")
	}
}

func TestPostgresDeclinedSSLRequestIsTLSDisabledFinding(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		buf := make([]byte, 8)
		_, _ = readFull(conn, buf)
		_, _ = conn.Write([]byte("N"))
		_ = conn.Close()
	})
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "postgres")
	if !ep.Reachable || !HasFinding(ep.Findings, FindingPostgresTLSDisabled) {
		t.Fatalf("want POSTGRES_TLS_DISABLED finding, got reachable=%v findings=%v err=%q", ep.Reachable, ep.Findings, ep.Error)
	}
	// withHandshakeFinding must not stack a second, misleading finding on it.
	if got := withHandshakeFinding(ep); HasFinding(got.Findings, FindingTLSHandshakeFailed) {
		t.Fatalf("handshake-failed finding added on top: %v", got.Findings)
	}
}

func TestEndpointFindingsScore(t *testing.T) {
	for issues, want := range map[string]int{
		"NOT_TLS: x": EndpointFindingScore, "TLS_HANDSHAKE_FAILED: x": EndpointFindingScore,
		"POSTGRES_TLS_DISABLED: x": EndpointFindingScore, "Weak cipher: RC4": 0,
	} {
		if got := EndpointFindingsScore([]string{issues}); got != want {
			t.Errorf("%q = %d, want %d", issues, got, want)
		}
	}
}
