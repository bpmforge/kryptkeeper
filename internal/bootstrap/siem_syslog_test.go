// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net"
	"strings"
	"testing"
	"time"
)

// RC2-N-03: a resource id decoded from a URL path can carry CR/LF or other
// control characters; the RFC 5424 message must stay one line in both formats.
func TestFormatRFC5424NeutralisesControlCharacters(t *testing.T) {
	ev := SIEMEvent{
		EventType:    "cert.revoked",
		Timestamp:    "2026-10-10T00:00:00Z",
		Severity:     "info",
		ActorID:      "admin\r\n<134>1 forged",
		ResourceType: "cert\x00ificate",
		ResourceID:   "abc\n<134>1 2026-10-10T00:00:00Z h kryptkeeper - forged - evil\u2028x\x1b[31m",
	}
	for _, format := range []string{"json", "cef"} {
		msg := formatRFC5424(ev, format)
		for _, r := range msg {
			if r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029' {
				t.Fatalf("format %s: message contains control character %U: %q", format, r, msg)
			}
		}
		if strings.Contains(msg, "\n<134>") {
			t.Fatalf("format %s: forged record started a new line: %q", format, msg)
		}
	}
}

func TestWriteSyslogFrameHonoursWriteDeadline(t *testing.T) {
	// net.Pipe writes block until the peer reads, which is what a collector
	// that stopped reading looks like once its socket buffer is full.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- writeSyslogFrame(client, "<134>1 stalled", 50*time.Millisecond) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("write to a non-reading peer returned nil; want a deadline error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write did not honour its deadline; a stalled collector would wedge the sender")
	}
}
