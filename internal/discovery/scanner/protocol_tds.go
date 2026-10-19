// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// W34-05: SQL Server. TDS negotiates encryption in a PRELOGIN exchange and then
// runs the TLS handshake with every handshake record wrapped in a TDS packet,
// so a plain tls.Dial never reaches the certificate. This is the same framing
// the TDS client libraries use; the fixture servers in the tests speak it, and
// real servers confirm it in W34-20.

const (
	tdsPreLogin     = 0x12 // packet type of PRELOGIN and of the TLS handshake carried in it
	tdsTabular      = 0x04 // packet type of the PRELOGIN response
	tdsStatusEOM    = 0x01
	tdsHeaderLen    = 8
	tdsMaxPacket    = 4096
	tdsMaxResponse  = 8192
	tdsOptVersion   = 0x00
	tdsOptEncrypt   = 0x01
	tdsOptInstance  = 0x02
	tdsOptThreadID  = 0x03
	tdsOptMARS      = 0x04
	tdsOptTerminate = 0xff
)

// TDS ENCRYPTION option values.
const (
	tdsEncryptOff    = 0x00
	tdsEncryptOn     = 0x01
	tdsEncryptNotSup = 0x02
	tdsEncryptReq    = 0x03
)

// tdsPreLoginRequest builds the client PRELOGIN. The client offers encryption
// (ENCRYPT_ON) so a server that can do TLS will; one that answers NOT_SUP
// cannot, which is the finding.
func tdsPreLoginRequest() []byte {
	// Option table: VERSION, ENCRYPTION, INSTOPT, THREADID, MARS, terminator.
	// Offsets are from the start of the payload.
	const tableLen = 5*5 + 1
	version := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	encrypt := []byte{tdsEncryptOn}
	instance := []byte{0x00}
	thread := []byte{0x00, 0x00, 0x00, 0x00}
	mars := []byte{0x00}
	data := [][]byte{version, encrypt, instance, thread, mars}
	tokens := []byte{tdsOptVersion, tdsOptEncrypt, tdsOptInstance, tdsOptThreadID, tdsOptMARS}

	var table, body []byte
	off := tableLen
	for i, d := range data {
		table = append(table, tokens[i])
		table = binary.BigEndian.AppendUint16(table, uint16(off))
		table = binary.BigEndian.AppendUint16(table, uint16(len(d)))
		body = append(body, d...)
		off += len(d)
	}
	table = append(table, tdsOptTerminate)
	payload := append(table, body...)
	return tdsPacket(tdsPreLogin, 1, payload)
}

func tdsPacket(typ byte, id byte, payload []byte) []byte {
	pkt := []byte{typ, tdsStatusEOM}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(tdsHeaderLen+len(payload)))
	pkt = append(pkt, 0, 0, id, 0) // SPID, packet id, window
	return append(pkt, payload...)
}

// tdsPreLoginReply is what the server said about itself.
type tdsPreLoginReply struct {
	Version    string // major.minor.build, e.g. "15.0.2000"
	Encryption byte
}

// parseTDSPreLogin reads the option table of a PRELOGIN response payload. It
// bounds every offset against the payload: the bytes come from the network.
func parseTDSPreLogin(payload []byte) (tdsPreLoginReply, error) {
	var r tdsPreLoginReply
	haveEncrypt := false
	for i := 0; ; i += 5 {
		if i >= len(payload) {
			return r, fmt.Errorf("prelogin option table not terminated")
		}
		token := payload[i]
		if token == tdsOptTerminate {
			break
		}
		if i+5 > len(payload) {
			return r, fmt.Errorf("truncated prelogin option")
		}
		off := int(binary.BigEndian.Uint16(payload[i+1:]))
		n := int(binary.BigEndian.Uint16(payload[i+3:]))
		if off+n > len(payload) {
			return r, fmt.Errorf("prelogin option out of range")
		}
		data := payload[off : off+n]
		switch token {
		case tdsOptVersion:
			if len(data) >= 4 {
				r.Version = fmt.Sprintf("%d.%d.%d", data[0], data[1], binary.BigEndian.Uint16(data[2:4]))
			}
		case tdsOptEncrypt:
			if len(data) >= 1 {
				r.Encryption, haveEncrypt = data[0], true
			}
		}
	}
	if !haveEncrypt {
		return r, fmt.Errorf("prelogin response has no encryption option")
	}
	return r, nil
}

// tdsTLSConn carries a TLS handshake inside TDS packets: each Write becomes
// one or more PRELOGIN packets, each Read strips the header of the packet it
// is reading from. Once the handshake is over the scan stops; nothing else is
// ever sent through it.
type tdsTLSConn struct {
	net.Conn
	remaining int // payload bytes left in the packet being read
	nextID    byte
}

func (c *tdsTLSConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), tdsMaxPacket-tdsHeaderLen)
		c.nextID++
		if _, err := c.Conn.Write(tdsPacket(tdsPreLogin, c.nextID, p[:n])); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *tdsTLSConn) Read(p []byte) (int, error) {
	for c.remaining == 0 {
		var h [tdsHeaderLen]byte
		if _, err := readFull(c.Conn, h[:]); err != nil {
			return 0, err
		}
		if h[0] != tdsPreLogin && h[0] != tdsTabular {
			return 0, fmt.Errorf("unexpected TDS packet type 0x%02x during handshake", h[0])
		}
		total := int(binary.BigEndian.Uint16(h[2:4]))
		if total < tdsHeaderLen || total > 32768 {
			return 0, fmt.Errorf("implausible TDS packet length %d", total)
		}
		c.remaining = total - tdsHeaderLen
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	return n, err
}

// ScanTDS runs PRELOGIN, then the framed TLS handshake, and captures the
// certificate. A server answering ENCRYPT_NOT_SUP is recorded as
// MSSQL_TLS_DISABLED, mirroring POSTGRES_TLS_DISABLED.
func (p *ProtocolScanner) ScanTDS(ctx context.Context, host string, port int) DiscoveredEndpoint {
	tag := "mssql"
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Error: err.Error()}
	}
	if _, err := conn.Write(tdsPreLoginRequest()); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "prelogin: " + err.Error()}
	}
	var h [tdsHeaderLen]byte
	if _, err := readFull(conn, h[:]); err != nil || h[0] != tdsTabular {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "not a TDS prelogin response"}
	}
	total := int(binary.BigEndian.Uint16(h[2:4]))
	if total < tdsHeaderLen+6 || total > tdsMaxResponse {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "implausible TDS prelogin length"}
	}
	payload := make([]byte, total-tdsHeaderLen)
	if _, err := readFull(conn, payload); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "prelogin body: " + err.Error()}
	}
	reply, err := parseTDSPreLogin(payload)
	if err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: err.Error()}
	}
	evidence := NewEvidence(SignalTDS, fmt.Sprintf("TDS prelogin version %s encryption %s", orUnknown(reply.Version), tdsEncryptionName(reply.Encryption)), "mssql")

	if reply.Encryption == tdsEncryptNotSup {
		conn.Close()
		ep := DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, ScannedAt: time.Now().UTC(),
			Error:    "server does not offer TLS (ENCRYPT_NOT_SUP)",
			Findings: []string{FindingMSSQLTLSDisabled + ": server answered ENCRYPT_NOT_SUP"},
			signals:  []Evidence{evidence},
		}
		return ep
	}
	ep := p.tlsCapture(&tdsTLSConn{Conn: conn}, host, tag, port)
	ep.signals = append(ep.signals, evidence)
	return ep
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func tdsEncryptionName(v byte) string {
	switch v {
	case tdsEncryptOff:
		return "off"
	case tdsEncryptOn:
		return "on"
	case tdsEncryptNotSup:
		return "not_supported"
	case tdsEncryptReq:
		return "required"
	}
	return fmt.Sprintf("0x%02x", v)
}
