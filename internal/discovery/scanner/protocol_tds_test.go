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

// tdsPreLoginResponse builds a server PRELOGIN reply with the given version
// and ENCRYPTION option.
func tdsPreLoginResponse(major, minor byte, build uint16, enc byte) []byte {
	const tableLen = 3*5 + 1
	version := []byte{major, minor, byte(build >> 8), byte(build), 0, 0}
	encrypt := []byte{enc}
	instance := []byte{0x00}
	var table, body []byte
	off := tableLen
	for i, d := range [][]byte{version, encrypt, instance} {
		table = append(table, []byte{tdsOptVersion, tdsOptEncrypt, tdsOptInstance}[i])
		table = binary.BigEndian.AppendUint16(table, uint16(off))
		table = binary.BigEndian.AppendUint16(table, uint16(len(d)))
		body = append(body, d...)
		off += len(d)
	}
	table = append(table, tdsOptTerminate)
	return tdsPacket(tdsTabular, 1, append(table, body...))
}

// tdsFixture answers PRELOGIN with enc and, unless enc is NOT_SUP, runs the TLS
// handshake in TDS framing with cfg.
func tdsFixture(t *testing.T, enc byte, cfg *tls.Config) (string, int) {
	t.Helper()
	return startListener(t, func(conn net.Conn) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // bound the fixture
		var h [tdsHeaderLen]byte
		if _, err := readFull(conn, h[:]); err != nil || h[0] != tdsPreLogin {
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(h[2:4]))-tdsHeaderLen)
		if _, err := readFull(conn, body); err != nil {
			return
		}
		if _, err := conn.Write(tdsPreLoginResponse(15, 0, 2000, enc)); err != nil {
			return
		}
		if enc == tdsEncryptNotSup {
			return
		}
		srv := tls.Server(&tdsTLSConn{Conn: conn}, cfg)
		_ = srv.Handshake()
	})
}

func TestTDSPreLoginRequestIsWellFormed(t *testing.T) {
	pkt := tdsPreLoginRequest()
	if pkt[0] != tdsPreLogin || pkt[1] != tdsStatusEOM || int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		t.Fatalf("bad header: % x", pkt[:8])
	}
	// The server-side parser accepts our own request, which proves the option
	// table and offsets are self-consistent.
	r, err := parseTDSPreLogin(pkt[tdsHeaderLen:])
	if err != nil || r.Encryption != tdsEncryptOn {
		t.Fatalf("parse own request: %+v %v", r, err)
	}
}

func TestParseTDSPreLoginRejectsMalformed(t *testing.T) {
	valid := tdsPreLoginResponse(16, 0, 1000, tdsEncryptReq)[tdsHeaderLen:]
	if r, err := parseTDSPreLogin(valid); err != nil || r.Version != "16.0.1000" || r.Encryption != tdsEncryptReq {
		t.Fatalf("valid: %+v %v", r, err)
	}
	cases := map[string][]byte{
		"empty":                 nil,
		"unterminated":          {tdsOptVersion, 0, 9, 0, 6},
		"truncated option":      {tdsOptVersion, 0, 9},
		"offset out of range":   {tdsOptEncrypt, 0xff, 0xff, 0, 1, tdsOptTerminate},
		"no encryption option":  {tdsOptVersion, 0, 6, 0, 6, tdsOptTerminate, 15, 0, 0, 0, 0, 0},
		"length past the end":   {tdsOptEncrypt, 0, 6, 0xff, 0xff, tdsOptTerminate},
		"terminator only":       {tdsOptTerminate},
		"single byte":           {0x01},
		"huge offset and count": {tdsOptVersion, 0xff, 0xff, 0xff, 0xff, tdsOptTerminate},
	}
	for name, b := range cases {
		if _, err := parseTDSPreLogin(b); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestTDSCapturesCertThroughFramedHandshake(t *testing.T) {
	cfg, cn := fixtureTLSConfig(t, "sql.example.com")
	for name, enc := range map[string]byte{"required": tdsEncryptReq, "on": tdsEncryptOn, "login only": tdsEncryptOff} {
		t.Run(name, func(t *testing.T) {
			host, port := tdsFixture(t, enc, cfg)
			ep := NewProtocolScanner(3*time.Second).ScanTDS(context.Background(), host, port)
			if ep.Error != "" || len(ep.Certs) != 1 || ep.Certs[0].CommonName != cn {
				t.Fatalf("capture: %q %+v", ep.Error, ep.Certs)
			}
			if ep.Protocol != "mssql" || len(ep.Findings) != 0 {
				t.Fatalf("protocol %q findings %v", ep.Protocol, ep.Findings)
			}
			fp := Resolve(ep.signals)
			if fp.Tech != "mssql" || fp.Confidence != ConfidenceMedium {
				t.Fatalf("fingerprint = %+v", fp)
			}
			if !hasEvidence(ep.signals, "mssql", "version 15.0.2000") {
				t.Fatalf("version missing from evidence: %+v", ep.signals)
			}
		})
	}
}

// The SQL Server default certificate leaves a self-signed cert and the
// SSL_Self_Signed_Fallback tell, so the endpoint is mssql with two independent
// strong signals.
func TestTDSDefaultCertificateIsSelfSignedMSSQL(t *testing.T) {
	cfg, _ := fixtureTLSConfig(t, "SSL_Self_Signed_Fallback")
	host, port := tdsFixture(t, tdsEncryptReq, cfg)
	ep := NewProtocolScanner(3*time.Second).ScanTDS(context.Background(), host, port)
	if len(ep.Certs) != 1 {
		t.Fatalf("capture: %q", ep.Error)
	}
	if !hasFlag(ep.Certs[0].RiskFlags, "SELF_SIGNED") {
		t.Fatalf("flags = %v, want SELF_SIGNED", ep.Certs[0].RiskFlags)
	}
	if fp := Resolve(ep.signals); fp.Tech != "mssql" || fp.Confidence != ConfidenceHigh {
		t.Fatalf("fingerprint = %+v", fp)
	}
}

func TestTDSNotSupportedIsTLSDisabledFinding(t *testing.T) {
	cfg, _ := fixtureTLSConfig(t, "unused")
	host, port := tdsFixture(t, tdsEncryptNotSup, cfg)
	ep := NewProtocolScanner(3*time.Second).ScanTDS(context.Background(), host, port)
	if !ep.Reachable || !HasFinding(ep.Findings, FindingMSSQLTLSDisabled) || len(ep.Certs) != 0 {
		t.Fatalf("want reachable + %s, got %+v", FindingMSSQLTLSDisabled, ep)
	}
	if !HasFinding(ep.Findings, FindingMSSQLTLSDisabled) || !contains(HighSeverityEndpointFindings, FindingMSSQLTLSDisabled) {
		t.Fatal("MSSQL_TLS_DISABLED must be a high-severity endpoint finding")
	}
	if fp := Resolve(ep.signals); fp.Tech != "mssql" {
		t.Fatalf("a TDS answer identifies SQL Server even without TLS: %+v", fp)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestTDSNonTDSPeerIsRecordedReachable(t *testing.T) {
	host, port := startListener(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	ep := NewProtocolScanner(3*time.Second).ScanTDS(context.Background(), host, port)
	if !ep.Reachable || ep.Error == "" || len(ep.Certs) != 0 {
		t.Fatalf("non-TDS peer: %+v", ep)
	}
}

func TestTDSTLSConnReassemblesAndSplits(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := &tdsTLSConn{Conn: a}
	big := make([]byte, 2*tdsMaxPacket)
	for i := range big {
		big[i] = byte(i)
	}
	go func() { _, _ = w.Write(big) }() // returns once the pipe is drained
	r := &tdsTLSConn{Conn: b}
	got := make([]byte, 0, len(big))
	buf := make([]byte, 1000)
	for len(got) < len(big) {
		n, err := r.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	for i := range big {
		if got[i] != big[i] {
			t.Fatalf("byte %d differs", i)
		}
	}
}

func TestTDSTLSConnRejectsHostileHeader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _, _ = b.Write([]byte{0x99, 0x01, 0x00, 0x10, 0, 0, 0, 0}) }() // wrong packet type
	if _, err := (&tdsTLSConn{Conn: a}).Read(make([]byte, 8)); err == nil {
		t.Fatal("unexpected packet type must be refused")
	}
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	go func() { _, _ = d.Write([]byte{tdsPreLogin, 0x01, 0x00, 0x02, 0, 0, 0, 0}) }() // length below the header
	if _, err := (&tdsTLSConn{Conn: c}).Read(make([]byte, 8)); err == nil {
		t.Fatal("implausible length must be refused")
	}
}
