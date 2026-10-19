// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundInstallDetailCapsAtOneKB(t *testing.T) {
	trace := strings.Repeat("at org.apache.catalina.Foo.bar(Foo.java:42)\n", 100) // ~4.4 KB
	got := boundInstallDetail(trace)
	if len(got) > maxInstallDetailBytes {
		t.Fatalf("detail is %d bytes, cap is %d", len(got), maxInstallDetailBytes)
	}
	if !strings.HasSuffix(got, installDetailTruncMarker) {
		t.Fatalf("truncated detail must say so: %q", got[len(got)-30:])
	}
	if short := "config test failed"; boundInstallDetail(short) != short {
		t.Fatal("short detail must pass through unchanged")
	}
}

func TestBoundInstallDetailRedactsBeforeTruncatingAndNeverCutsInsideRedaction(t *testing.T) {
	const secret = "s3cr3t-keystore-pw"
	// Slide the secret across every offset near the cut so one placement lands
	// the "[redacted]" token straddling the boundary.
	cutAt := maxInstallDetailBytes - len(installDetailTruncMarker)
	for off := cutAt - len("[redacted]") - 2; off <= cutAt+2; off++ {
		in := strings.Repeat("x", off) + secret + strings.Repeat("y", 4000)
		got := boundInstallDetail(in, secret)
		if strings.Contains(got, secret) || strings.Contains(got, secret[:6]) {
			t.Fatalf("offset %d: secret (or prefix) leaked: %q", off, got[off-2:])
		}
		body := strings.TrimSuffix(got, installDetailTruncMarker)
		if i := strings.LastIndex(body, "[r"); i >= 0 && !strings.HasPrefix(body[i:], "[redacted]") {
			t.Fatalf("offset %d: cut inside a redaction: %q", off, body[i:])
		}
		if len(got) > maxInstallDetailBytes || !utf8.ValidString(got) {
			t.Fatalf("offset %d: len=%d valid=%v", off, len(got), utf8.ValidString(got))
		}
	}
}

func TestBoundInstallDetailKeepsRuneBoundary(t *testing.T) {
	got := boundInstallDetail(strings.Repeat("é", 2000))
	if !utf8.ValidString(got) || len(got) > maxInstallDetailBytes {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
}
