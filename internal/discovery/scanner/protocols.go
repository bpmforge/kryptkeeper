// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// W14-03: protocol-aware scanning. The plain scanner only captures
// certificates on sockets that speak TLS from byte one; these paths
// reach the certs hiding behind a plaintext STARTTLS preamble, plus
// the SSH host-key algorithm advertisement and RDP's TLS security
// layer. Every captured cert is the SAME DiscoveredCert (certToDiscovered)
// into the one inventory.
//
// LDAP StartTLS is deliberately absent: its extended-operation request
// is BER-encoded, the same binary-LDAP protocol the W13-04 go-ldap
// decision gates — it lands with that dependency, not hand-rolled.

// ProtocolScanner captures certs/metadata over non-plain-TLS protocols.
type ProtocolScanner struct {
	dialer  *net.Dialer
	timeout time.Duration
}

func NewProtocolScanner(timeout time.Duration) *ProtocolScanner {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ProtocolScanner{dialer: &net.Dialer{Timeout: timeout}, timeout: timeout}
}

func (p *ProtocolScanner) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	conn, err := p.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(p.timeout)) // best-effort bound; a failed set still lets the scan proceed under the dialer timeout
	return conn, nil
}

func (p *ProtocolScanner) tlsCapture(conn net.Conn, host, protocol string, port int) DiscoveredEndpoint {
	ep := DiscoveredEndpoint{Host: host, Port: port, Protocol: protocol, Reachable: true, ScannedAt: time.Now().UTC()}
	tconn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tconn.Handshake(); err != nil {
		ep.Error = "tls handshake: " + err.Error()
		return ep
	}
	ep.TLSVersion = tlsVersionString(tconn.ConnectionState().Version)
	for i, cert := range tconn.ConnectionState().PeerCertificates {
		dc := certToDiscovered(cert, host, i == 0)
		dc.Served = true
		ep.Certs = append(ep.Certs, dc)
	}
	return ep
}

// starttlsLineVerb is the plaintext preamble for line-based protocols.
type starttlsLineVerb struct {
	greet    func(r *bufio.Reader) error // consume the banner
	send     string                      // the STARTTLS verb line
	expectOK func(line string) bool      // predicate on the reply
	tag      string
}

var lineProtocols = map[string]starttlsLineVerb{
	"smtp": {
		greet: func(r *bufio.Reader) error { return expectPrefix(r, "220") },
		send:  "STARTTLS\r\n", expectOK: func(l string) bool { return strings.HasPrefix(l, "220") },
		tag: "starttls-smtp",
	},
	"imap": {
		greet: func(r *bufio.Reader) error { return expectPrefix(r, "* OK") },
		send:  "a1 STARTTLS\r\n", expectOK: func(l string) bool { return strings.Contains(l, "OK") },
		tag: "starttls-imap",
	},
	"pop3": {
		greet: func(r *bufio.Reader) error { return expectPrefix(r, "+OK") },
		send:  "STLS\r\n", expectOK: func(l string) bool { return strings.HasPrefix(l, "+OK") },
		tag: "starttls-pop3",
	},
}

func expectPrefix(r *bufio.Reader, prefix string) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		return fmt.Errorf("unexpected banner %q", strings.TrimSpace(line))
	}
	return nil
}

// ScanSTARTTLS negotiates STARTTLS for a line-based protocol (smtp,
// imap, pop3) or the binary postgres path, then captures the cert.
func (p *ProtocolScanner) ScanSTARTTLS(ctx context.Context, host string, port int, protocol string) DiscoveredEndpoint {
	if protocol == "postgres" {
		return p.scanPostgres(ctx, host, port)
	}
	verb, ok := lineProtocols[protocol]
	if !ok {
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: "starttls-" + protocol, Error: "unsupported starttls protocol"}
	}
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: verb.tag, Error: err.Error()}
	}
	r := bufio.NewReader(conn)
	if err := verb.greet(r); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: verb.tag, Reachable: true, Error: "greet: " + err.Error()}
	}
	// SMTP wants an EHLO before STARTTLS; harmless for others that
	// ignore an unknown verb, but only SMTP requires it.
	if protocol == "smtp" {
		_, _ = conn.Write([]byte("EHLO kryptkeeper.scan\r\n"))
		_ = drainMultiline(r) // EHLO reply drained best-effort; STARTTLS still attempted
	}
	if _, err := conn.Write([]byte(verb.send)); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: verb.tag, Reachable: true, Error: "send: " + err.Error()}
	}
	line, err := r.ReadString('\n')
	if err != nil || !verb.expectOK(strings.TrimSpace(line)) {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: verb.tag, Reachable: true, Error: "starttls refused: " + strings.TrimSpace(line)}
	}
	return p.tlsCapture(conn, host, verb.tag, port)
}

// drainMultiline consumes an SMTP-style multiline reply (250-… lines
// until a "250 " space-separated final line).
func drainMultiline(r *bufio.Reader) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if len(line) >= 4 && line[3] == ' ' {
			return nil
		}
	}
}

// scanPostgres does the binary SSLRequest negotiation.
func (p *ProtocolScanner) scanPostgres(ctx context.Context, host string, port int) DiscoveredEndpoint {
	tag := "starttls-postgres"
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Error: err.Error()}
	}
	// SSLRequest: int32 length=8, int32 magic=80877103.
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:], 8)
	binary.BigEndian.PutUint32(msg[4:], 80877103)
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "sslrequest: " + err.Error()}
	}
	reply := make([]byte, 1)
	if _, err := conn.Read(reply); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "read: " + err.Error()}
	}
	if reply[0] != 'S' {
		conn.Close()
		// 'N' is a well-formed refusal, not a failed handshake: report it as
		// its own finding. Any other byte is not a Postgres answer at all.
		ep := DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, ScannedAt: time.Now().UTC(),
			Error: "server does not offer TLS (replied " + strconv.Quote(string(reply)) + ")"}
		if reply[0] == 'N' {
			ep.Findings = []string{FindingPostgresTLSDisabled + ": server declined the SSLRequest"}
		}
		return ep
	}
	return p.tlsCapture(conn, host, tag, port)
}

// ScanSSH reads the SSH banner and the server's advertised host-key
// algorithms from KEXINIT. Classic SSH carries no certificate; the
// algorithm list feeds the algorithm-sunset/PQC story.
func (p *ProtocolScanner) ScanSSH(ctx context.Context, host string, port int) DiscoveredEndpoint {
	ep := DiscoveredEndpoint{Host: host, Port: port, Protocol: "ssh", ScannedAt: time.Now().UTC()}
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		ep.Error = err.Error()
		return ep
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	banner, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "SSH-") {
		ep.Error = "not an SSH banner"
		return ep
	}
	ep.Banner = strings.TrimSpace(banner)
	_, _ = conn.Write([]byte("SSH-2.0-Kryptkeeper-Scan\r\n"))

	// Read the KEXINIT binary packet: uint32 pkt_len, byte pad_len,
	// payload (msg type 20, 16-byte cookie, then name-lists).
	var hdr [5]byte
	if _, err := readFull(r, hdr[:]); err != nil {
		ep.Error = "kexinit header: " + err.Error()
		return ep
	}
	pktLen := binary.BigEndian.Uint32(hdr[0:4])
	if pktLen < 2 || pktLen > 1<<20 {
		ep.Error = "implausible kexinit length"
		return ep
	}
	payload := make([]byte, pktLen-1) // hdr already consumed pad_len byte
	if _, err := readFull(r, payload); err != nil {
		ep.Error = "kexinit payload: " + err.Error()
		return ep
	}
	// payload[0] = msg type (20), payload[1:17] = cookie, then the
	// name-lists. kex_algorithms is first, server_host_key_algorithms
	// second.
	if len(payload) < 17 || payload[0] != 20 {
		ep.Error = "not a KEXINIT message"
		return ep
	}
	off := 17
	if _, off, err = readNameList(payload, off); err != nil { // kex_algorithms (skipped)
		ep.Error = "kex list: " + err.Error()
		return ep
	}
	hostKeyAlgs, _, err := readNameList(payload, off) // server_host_key_algorithms
	if err != nil {
		ep.Error = "host-key list: " + err.Error()
		return ep
	}
	ep.HostKeyAlgorithms = hostKeyAlgs
	return ep
}

func readNameList(b []byte, off int) ([]string, int, error) {
	if off+4 > len(b) {
		return nil, off, fmt.Errorf("truncated length")
	}
	n := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if off+n > len(b) {
		return nil, off, fmt.Errorf("truncated name-list")
	}
	list := string(b[off : off+n])
	off += n
	if list == "" {
		return nil, off, nil
	}
	return strings.Split(list, ","), off, nil
}

// ScanRDP negotiates RDP's TLS security layer (X.224 Connection Request
// with an RDP Negotiation Request for PROTOCOL_SSL) and captures the
// cert.
func (p *ProtocolScanner) ScanRDP(ctx context.Context, host string, port int) DiscoveredEndpoint {
	tag := "rdp"
	conn, err := p.dial(ctx, host, port)
	if err != nil {
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Error: err.Error()}
	}
	// TPKT(4) + X.224 CR(7) + RDP Negotiation Request(8) = 19 bytes.
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, length 19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR (len 14, CR PDU, dst/src ref, class)
		0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, // RDP Neg Req: type 1, flags 0, len 8, PROTOCOL_SSL
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "x224 request: " + err.Error()}
	}
	// Read the Connection Confirm: TPKT header then the negotiation
	// response type byte (0x02 = grant).
	var tpkt [4]byte
	if _, err := readFull(conn, tpkt[:]); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "x224 confirm: " + err.Error()}
	}
	// Bounds-check the TPKT length from the wire before allocating: a
	// hostile endpoint could send a length < 4 (make([]byte, negative)
	// panics) or an absurd size. TPKT v3 header + X.224 CC(7) + neg
	// rsp(8) needs at least 12 bytes total; cap the read defensively.
	total := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if tpkt[0] != 0x03 || total < 12 || total > 4096 {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "malformed X.224 Connection Confirm"}
	}
	rest := make([]byte, total-4)
	if _, err := readFull(conn, rest); err != nil {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "x224 body: " + err.Error()}
	}
	// The RDP Negotiation Response type byte follows the 7-byte X.224
	// CC header (rest[7]); 0x02 = TYPE_RDP_NEG_RSP granting a protocol.
	if len(rest) < 8 || rest[7] != 0x02 {
		conn.Close()
		return DiscoveredEndpoint{Host: host, Port: port, Protocol: tag, Reachable: true, Error: "server declined TLS security"}
	}
	return p.tlsCapture(conn, host, tag, port)
}

func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
