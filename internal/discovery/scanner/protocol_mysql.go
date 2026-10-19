// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// W34-05: MySQL and MariaDB. The server speaks first with an initial handshake
// packet carrying its version and capability flags; a client that wants TLS
// answers with a short SSLRequest packet and starts the TLS handshake on the
// same connection. Fixture servers cover the unit path; W34-20 checks real
// servers.

const (
	mysqlClientSSL         = 0x0800
	mysqlClientProtocol41  = 0x0200
	mysqlClientSecureConn  = 0x8000
	mysqlClientPluginAuth  = 0x00080000
	mysqlMaxGreeting       = 4096
	mysqlProtocolVersion10 = 10
	mysqlCharsetUTF8mb4    = 45
)

// mysqlGreeting is the parts of the initial handshake the scan uses.
type mysqlGreeting struct {
	Version      string
	Capabilities uint32
}

func (g mysqlGreeting) SSL() bool { return g.Capabilities&mysqlClientSSL != 0 }

// parseMySQLGreeting decodes the payload of an initial handshake (protocol
// version 10): version string, thread id, 8 bytes of salt, filler, then the
// low 16 capability bits (the SSL flag lives there) and, when present, the
// high 16.
func parseMySQLGreeting(payload []byte) (mysqlGreeting, error) {
	var g mysqlGreeting
	if len(payload) < 1 {
		return g, fmt.Errorf("empty greeting")
	}
	if payload[0] == 0xff {
		return g, fmt.Errorf("server refused the connection")
	}
	if payload[0] != mysqlProtocolVersion10 {
		return g, fmt.Errorf("unsupported MySQL protocol version %d", payload[0])
	}
	end := bytes.IndexByte(payload[1:], 0)
	if end < 0 {
		return g, fmt.Errorf("unterminated server version")
	}
	g.Version = string(payload[1 : 1+end])
	off := 1 + end + 1 // after the NUL
	// thread id (4) + salt part 1 (8) + filler (1) + capabilities low (2)
	if off+4+8+1+2 > len(payload) {
		return g, fmt.Errorf("truncated greeting")
	}
	off += 4 + 8 + 1
	g.Capabilities = uint32(binary.LittleEndian.Uint16(payload[off:]))
	off += 2
	// charset (1) + status (2) + capabilities high (2)
	if off+1+2+2 <= len(payload) {
		g.Capabilities |= uint32(binary.LittleEndian.Uint16(payload[off+3:])) << 16
	}
	return g, nil
}

// mysqlSSLRequest is the 32-byte payload that asks the server to switch to TLS.
func mysqlSSLRequest() []byte {
	caps := uint32(mysqlClientSSL | mysqlClientProtocol41 | mysqlClientSecureConn | mysqlClientPluginAuth)
	payload := binary.LittleEndian.AppendUint32(nil, caps)
	payload = binary.LittleEndian.AppendUint32(payload, 1<<24) // max packet size
	payload = append(payload, mysqlCharsetUTF8mb4)
	payload = append(payload, make([]byte, 23)...) // reserved
	pkt := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 1}
	return append(pkt, payload...)
}

// mysqlTech names the server family from its version string: MariaDB's
// greeting carries "MariaDB", MySQL's does not.
func mysqlTech(version string) string {
	if strings.Contains(strings.ToLower(version), "mariadb") {
		return "other:mariadb"
	}
	return "mysql"
}

// scanMySQL reads the greeting, requests TLS, and captures the certificate. A
// greeting without the SSL capability is MYSQL_TLS_DISABLED.
func (p *ProtocolScanner) scanMySQL(ctx context.Context, host string, port int) DiscoveredEndpoint {
	tag := "mysql"
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Error: err.Error()}
	}
	var h [4]byte
	if _, err := readFull(conn, h[:]); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "greeting header: " + err.Error()}
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n < 1 || n > mysqlMaxGreeting {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "not a MySQL greeting"}
	}
	payload := make([]byte, n)
	if _, err := readFull(conn, payload); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "greeting body: " + err.Error()}
	}
	g, err := parseMySQLGreeting(payload)
	if err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "greeting: " + err.Error()}
	}
	evidence := NewEvidence(SignalBanner, "MySQL greeting version "+g.Version, mysqlTech(g.Version))

	if !g.SSL() {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, ScannedAt: time.Now().UTC(),
			Error:    "server does not offer TLS (no SSL capability)",
			Findings: []string{FindingMySQLTLSDisabled + ": greeting lacks the SSL capability"},
			signals:  []Evidence{evidence},
		}
	}
	if _, err := conn.Write(mysqlSSLRequest()); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "sslrequest: " + err.Error(), signals: []Evidence{evidence}}
	}
	ep := p.tlsCapture(conn, host, tag, port)
	ep.signals = append(ep.signals, evidence)
	return ep
}
