// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/rand"
	_ "embed" // tls_stack_table.json
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// The TLS stack table is data, not code: the ServerHello tells are predictions
// until W34-20 checks them against real servers, and that check must be able
// to flip an entry without touching Go.
//
//go:embed testdata/tls_stack_table.json
var tlsStackTableJSON []byte

// tlsStackWeight is the most an unverified entry may claim. A stack tell never
// names the headline tech; it only breaks platform ties.
const tlsStackWeight = 25

// TLSStackEntry is one row of the table. Empty Extensions or SizeClass and a
// nil Ticket are wildcards; Suite is hex ("c02f") or empty for any.
type TLSStackEntry struct {
	Stack      string `json:"stack"`
	Suite      string `json:"suite,omitempty"`
	Extensions string `json:"extensions,omitempty"`
	Ticket     *bool  `json:"ticket,omitempty"`
	SizeClass  string `json:"size_class,omitempty"`
	Verified   bool   `json:"verified"`
	Weight     int    `json:"weight"`
	Note       string `json:"note,omitempty"`
}

type tlsStackTable struct {
	Entries []TLSStackEntry `json:"entries"`
}

// tlsStackEntries is loaded once at init; a malformed embedded table is a
// build defect, so it is logged and the probe degrades to "unknown".
var tlsStackEntries = loadTLSStackTable(tlsStackTableJSON)

func loadTLSStackTable(raw []byte) []TLSStackEntry {
	var t tlsStackTable
	if err := json.Unmarshal(raw, &t); err != nil {
		logging.Warnf("tls stack table unreadable, stack fingerprinting disabled: %v", err)
		return nil
	}
	return t.Entries
}

// tlsFeatures are the observed ServerHello features the table is keyed on.
type tlsFeatures struct {
	suite      uint16
	extensions []uint16
	ticket     bool
	sizeClass  string
}

// serverHelloSizeClass buckets the ServerHello record length, which differs by
// library because of the extension set and any padding.
func serverHelloSizeClass(n int) string {
	switch {
	case n <= 70:
		return "xs"
	case n <= 100:
		return "s"
	case n <= 140:
		return "m"
	default:
		return "l"
	}
}

func featuresOf(sh serverHello) tlsFeatures {
	// The server_name echo appears only when the client sent SNI, which it does
	// for names and not for IP literals; it says nothing about the stack.
	exts := slices.DeleteFunc(slices.Clone(sh.extensions), func(id uint16) bool { return id == 0x0000 })
	return tlsFeatures{
		suite:      sh.suite,
		extensions: exts,
		ticket:     slices.Contains(sh.extensions, 0x0023),
		sizeClass:  serverHelloSizeClass(sh.recordLen),
	}
}

func extensionString(ids []uint16) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%04x", id)
	}
	return strings.Join(parts, ",")
}

// matchTLSStack returns the stack the table assigns to f, or "" when nothing
// or something ambiguous matches. The most specific matching entry wins; two
// equally specific entries naming different stacks are ambiguous and read as
// unknown rather than guessing.
func matchTLSStack(entries []TLSStackEntry, f tlsFeatures) (string, TLSStackEntry) {
	exts := extensionString(f.extensions)
	best, bestSpec, tied := TLSStackEntry{}, -1, false
	for _, e := range entries {
		spec := 0
		if e.Suite != "" {
			if !strings.EqualFold(e.Suite, fmt.Sprintf("%04x", f.suite)) {
				continue
			}
			spec++
		}
		if e.Extensions != "" {
			if !strings.EqualFold(e.Extensions, exts) {
				continue
			}
			spec++
		}
		if e.Ticket != nil {
			if *e.Ticket != f.ticket {
				continue
			}
			spec++
		}
		if e.SizeClass != "" {
			if e.SizeClass != f.sizeClass {
				continue
			}
			spec++
		}
		switch {
		case spec > bestSpec:
			best, bestSpec, tied = e, spec, false
		case spec == bestSpec && e.Stack != best.Stack:
			tied = true
		}
	}
	if bestSpec < 0 || tied || bestSpec == 0 {
		return "", TLSStackEntry{}
	}
	return best.Stack, best
}

// tlsStackEvidence is the evidence row for f, or nil for an unknown
// combination. Value carries the stack name; Resolve reads it into
// Fingerprint.TLSStack and its platform vote.
func tlsStackEvidence(entries []TLSStackEntry, f tlsFeatures) []Evidence {
	stack, entry := matchTLSStack(entries, f)
	if stack == "" {
		return nil
	}
	e := NewEvidence(SignalTLSStack, stack, "")
	if entry.Weight > 0 && entry.Weight < e.Weight {
		e.Weight = entry.Weight
	}
	return []Evidence{e}
}

// stackClientHello builds a TLS 1.2 ClientHello with the extensions a stock
// client sends, so servers answer with the ServerHello extension set the table
// is keyed on. TLS 1.3 is not offered: its ServerHello hides the tells.
func stackClientHello(host string) ([]byte, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("client random: %w", err)
	}
	suites := []uint16{0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	body := []byte{0x03, 0x03}
	body = append(body, random[:]...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0)

	var ext []byte
	add := func(id uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, id)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	if _, err := netip.ParseAddr(host); err != nil && host != "" { // SNI is for names, never literals
		name := []byte(host)
		sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
		sni = append(sni, 0)
		sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
		add(0x0000, append(sni, name...))
	}
	add(0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})             // supported_groups x25519, P-256, P-384
	add(0x000b, []byte{0x01, 0x00})                                                 // ec_point_formats: uncompressed
	add(0x000d, []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01}) // signature_algorithms
	add(0x0023, nil)                                                                // session_ticket: ask for tickets
	add(0x0017, nil)                                                                // extended_master_secret
	add(0xff01, []byte{0x00})                                                       // renegotiation_info
	add(0x0010, []byte{0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})   // ALPN
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...), nil
}

// probeTLSStack opens one extra connection, sends stackClientHello and
// classifies the ServerHello. It never completes the handshake. Deep scans
// only (D-206): this is the one fingerprint signal that is not free.
func probeTLSStack(ctx context.Context, host string, port int, timeout time.Duration) []Evidence {
	hello, err := stackClientHello(host)
	if err != nil {
		return nil
	}
	conn, err := guardedDialer(timeout).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout)) // best-effort bound; the dialer timeout still applies
	if _, err := conn.Write(hello); err != nil {
		return nil
	}
	sh, ok := readServerHello(conn)
	if !ok || !sh.complete || sh.version != 0x0303 {
		return nil
	}
	return tlsStackEvidence(tlsStackEntries, featuresOf(sh))
}

// TLSStackObservation is what the stack probe saw, for calibrating the table
// against real servers (W34-20). Extensions is the server_name-free ordered
// hex list the table is keyed on.
type TLSStackObservation struct {
	Suite      string `json:"suite"`
	Extensions string `json:"extensions"`
	Ticket     bool   `json:"ticket"`
	SizeClass  string `json:"size_class"`
	Stack      string `json:"stack"` // the table's verdict, "" when unknown
}

// ObserveTLSStack runs the deep-scan stack probe and returns the raw features
// beside the table's verdict. ok is false when the server did not answer a
// TLS 1.2 ClientHello with a ServerHello.
func ObserveTLSStack(ctx context.Context, host string, port int, timeout time.Duration) (TLSStackObservation, bool) {
	hello, err := stackClientHello(host)
	if err != nil {
		return TLSStackObservation{}, false
	}
	conn, err := guardedDialer(timeout).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return TLSStackObservation{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout)) // best-effort bound; the dialer timeout still applies
	if _, err := conn.Write(hello); err != nil {
		return TLSStackObservation{}, false
	}
	sh, ok := readServerHello(conn)
	if !ok || !sh.complete || sh.version != 0x0303 {
		return TLSStackObservation{}, false
	}
	f := featuresOf(sh)
	stack, _ := matchTLSStack(tlsStackEntries, f)
	return TLSStackObservation{
		Suite: fmt.Sprintf("%04x", f.suite), Extensions: extensionString(f.extensions),
		Ticket: f.ticket, SizeClass: f.sizeClass, Stack: stack,
	}, true
}
