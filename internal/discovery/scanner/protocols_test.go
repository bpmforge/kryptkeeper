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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
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

// ldapStartTLSFixture answers one StartTLS extended request with resultCode,
// echoing the request's message id, then (on success) serves TLS.
func ldapStartTLSFixture(t *testing.T, resultCode byte, tlsCfg *tls.Config) (string, int) {
	t.Helper()
	return startListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 512)
		if n, err := conn.Read(buf); err != nil || n < 5 {
			return
		}
		id := buf[4] // 30 LL 02 01 <id>
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x78, 0x07, 0x0a, 0x01, resultCode, 0x04, 0x00, 0x04, 0x00})
		if resultCode == 0 {
			_ = tls.Server(conn, tlsCfg).Handshake()
		}
	})
}

func TestLDAPStartTLSCapturesCert(t *testing.T) {
	tlsCfg, cn := fixtureTLSConfig(t, "ldap.example.com")
	host, port := ldapStartTLSFixture(t, 0, tlsCfg)
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "ldap")
	if ep.Error != "" || ep.Protocol != "starttls-ldap" || len(ep.Certs) != 1 || ep.Certs[0].CommonName != cn {
		t.Fatalf("ldap capture: %+v", ep)
	}
	sum := sha256.Sum256(tlsCfg.Certificates[0].Certificate[0])
	if got, want := strings.ToLower(ep.Certs[0].Fingerprint), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("fingerprint %s want %s", got, want)
	}
}

func assertRefusalRecorded(t *testing.T, ep DiscoveredEndpoint, contains string) {
	t.Helper()
	if !ep.Reachable || !strings.HasPrefix(ep.Error, "starttls refused") || !strings.Contains(ep.Error, contains) || len(ep.Certs) != 0 {
		t.Fatalf("refusal not recorded reachable: %+v", ep)
	}
	if !HasFinding(withHandshakeFinding(ep).Findings, FindingTLSHandshakeFailed) {
		t.Fatalf("missing %s finding: %+v", FindingTLSHandshakeFailed, ep)
	}
}

func TestLDAPStartTLSRefusedIsRecordedReachable(t *testing.T) {
	host, port := ldapStartTLSFixture(t, 2, nil)
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "ldap")
	assertRefusalRecorded(t, ep, "")
}

func TestSMTPStartTLSRefusedIsRecordedReachable(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("220 x ESMTP\r\n"))
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("250 x\r\n"))
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("454 TLS not available\r\n"))
	})
	assertRefusalRecorded(t, NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "smtp"), "454")
}

func TestIMAPStartTLSRefusedIsRecordedReachable(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("* OK ready\r\n"))
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("a1 NO STARTTLS unavailable\r\n"))
	})
	assertRefusalRecorded(t, NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "imap"), "NO STARTTLS")
}

func TestRDPNLAOnlyDeclinedIsRecordedNotDropped(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		req := make([]byte, 19)
		_, _ = readFull(conn, req)
		// RDP_NEG_FAILURE: type 3, failure code 5 (HYBRID_REQUIRED_BY_SERVER).
		_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0, 0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00})
	})
	got := withHandshakeFinding(NewProtocolScanner(3*time.Second).ScanRDP(context.Background(), host, port))
	if got.Protocol != "rdp" || !got.Reachable || got.Error != "server declined TLS security" || !HasFinding(got.Findings, FindingTLSHandshakeFailed) {
		t.Fatalf("nla-only not recorded: %+v", got)
	}
}

func TestCatalogueIncludesLDAPStartTLS(t *testing.T) {
	if e := protocolForPort(389); e.kind != probeSTARTTLS || e.starttls != "ldap" {
		t.Fatalf("389 entry: %+v", e)
	}
	if !intsContain(PortsForScanType("targeted"), 389) {
		t.Fatal("389 not in targeted tier")
	}
}

// W34-02: greeting banners that used to be discarded now identify the server.

func TestMailBannerClassification(t *testing.T) {
	cases := map[string]string{
		"220 mail.example.com ESMTP Postfix (Ubuntu)":                 "postfix",
		"220 mx.example.com ESMTP Exim 4.96 Tue, 01 Jan 2030":         "exim",
		"220 mx.example.com ESMTP Sendmail 8.17.1/8.17.1; Tue":        "sendmail",
		"220 EX01.corp.local Microsoft ESMTP MAIL Service ready at x": "exchange",
		"* OK [CAPABILITY IMAP4rev1] Dovecot (Ubuntu) ready.":         "dovecot",
		"* OK example.com Cyrus IMAP 3.8.1 server ready":              "cyrus",
		"* OK The Microsoft Exchange IMAP4 service is ready.":         "exchange",
		"+OK Dovecot ready.":         "dovecot",
		"220 mail.example.com ESMTP": "",
		"* OK ready":                 "",
	}
	for banner, want := range cases {
		if got := mailTech(banner); got != want {
			t.Errorf("mailTech(%q) = %q, want %q", banner, got, want)
		}
		ev := bannerEvidence(banner)
		if (want == "") != (len(ev) == 0) {
			t.Errorf("bannerEvidence(%q) = %+v, want evidence iff %q", banner, ev, want)
		}
		if want != "" && (ev[0].Signal != SignalBanner || ev[0].Tech != want || ev[0].Weight != 60) {
			t.Errorf("bannerEvidence(%q) = %+v", banner, ev)
		}
	}
}

func TestSSHBannerClassification(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13": "openssh",
		"SSH-2.0-Cisco-1.25":                     "other:cisco",
		"SSH-2.0-mod_sftp/0.9.9":                 "other:mod_sftp",
		"SSH-2.0-dropbear_2022.83":               "",
	}
	for banner, want := range cases {
		if got := sshBannerTech(banner); got != want {
			t.Errorf("sshBannerTech(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestSMTPGreetingIdentifiesServerEvenWhenSTARTTLSRefused(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("220 mail.example.com ESMTP Postfix\r\n"))
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("250 mail.example.com\r\n"))
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("454 TLS not available\r\n"))
	})
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "smtp")
	fp := Resolve(ep.signals)
	if fp.Tech != "postfix" || fp.Platform != PlatformLinux {
		t.Fatalf("fingerprint = %+v (signals %+v)", fp, ep.signals)
	}
}

func TestIMAPGreetingOnSuccessfulSTARTTLS(t *testing.T) {
	tlsCfg, _ := fixtureTLSConfig(t, "imap.example.com")
	host, port := startListener(t, func(conn net.Conn) {
		r := bufio.NewReader(conn)
		_, _ = conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n"))
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("a1 OK Begin TLS negotiation now.\r\n"))
		srv := tls.Server(conn, tlsCfg)
		_ = srv.Handshake()
		_ = srv.Close()
	})
	ep := NewProtocolScanner(3*time.Second).ScanSTARTTLS(context.Background(), host, port, "imap")
	if ep.Error != "" || len(ep.Certs) != 1 {
		t.Fatalf("capture: %s %+v", ep.Error, ep.Certs)
	}
	if fp := Resolve(ep.signals); fp.Tech != "dovecot" {
		t.Fatalf("fingerprint = %+v", fp)
	}
}

func TestSSHBannerBecomesEvidence(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-Cisco-1.25\r\n"))
	})
	ep := NewProtocolScanner(3*time.Second).ScanSSH(context.Background(), host, port)
	if ep.Banner != "SSH-2.0-Cisco-1.25" {
		t.Fatalf("banner = %q", ep.Banner)
	}
	// Port default says openssh at weight 10; the banner outvotes it.
	fp := Resolve(append(append([]Evidence{}, ep.signals...), portEvidence("ssh")...))
	if fp.Tech != "other:cisco" || fp.Confidence != ConfidenceMedium {
		t.Fatalf("fingerprint = %+v", fp)
	}
}

func TestImplicitTLSMailGreetingReadOnSameConnection(t *testing.T) {
	tlsCfg, _ := fixtureTLSConfig(t, "imaps.example.com")
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
				srv := tls.Server(c, tlsCfg)
				if srv.Handshake() == nil {
					_, _ = srv.Write([]byte("* OK Dovecot ready.\r\n"))
				}
				_ = srv.Close()
			}()
		}
	}()
	s := New(ScanConfig{Timeout: 3 * time.Second})
	conn, _, err := s.dialTLS(context.Background(), "127.0.0.1", portOf(ln), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ep := s.finishTLSCapture(DiscoveredEndpoint{Host: "127.0.0.1", Port: 993, Protocol: "imaps", Reachable: true}, conn, conn.ConnectionState(), "127.0.0.1", 993, "imaps")
	if fp := Resolve(ep.signals); fp.Tech != "dovecot" {
		t.Fatalf("fingerprint = %+v", fp)
	}
	if n := accepts.Load(); n != 1 {
		t.Fatalf("passive signals opened %d connections, want 1", n)
	}
}
