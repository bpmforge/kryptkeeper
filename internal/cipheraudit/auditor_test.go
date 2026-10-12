// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cipheraudit

import (
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewAuditor(t *testing.T) {
	a := NewAuditor(2 * time.Second)
	if a == nil {
		t.Fatal("expected non-nil auditor")
	}
}

func TestNewAuditorDefaultTimeout(t *testing.T) {
	a := NewAuditor(0)
	if a == nil {
		t.Fatal("expected non-nil auditor with default timeout")
	}
}

func TestScoreToGrade(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{90, "A"},
		{80, "B"},
		{70, "B"},
		{60, "C"},
		{50, "C"},
		{49, "F"},
		{0, "F"},
	}
	for _, tc := range cases {
		got := scoreToGrade(tc.score)
		if got != tc.want {
			t.Errorf("scoreToGrade(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0200, "0x0200"}, // unknown
	}
	for _, tc := range cases {
		got := tlsVersionName(tc.v)
		if got != tc.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny("TLS_RSA_WITH_RC4_128_SHA", "RC4") {
		t.Error("expected RC4 to be found")
	}
	if !containsAny("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "CBC") {
		t.Error("expected 3DES/CBC to be found")
	}
	if containsAny("TLS_AES_256_GCM_SHA384", "RC4", "DES", "3DES") {
		t.Error("expected no weak cipher match")
	}
	if containsAny("", "RC4") {
		t.Error("empty string should not match")
	}
	if containsAny("RC", "RC4") {
		t.Error("partial match should not match")
	}
}

func TestScoreTLSConfigTLS13(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_256_GCM_SHA384,
	}
	score, issues := scoreTLSConfig(state)
	if score != 100 {
		t.Errorf("TLS 1.3 GCM should score 100, got %d (issues: %v)", score, issues)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %v", issues)
	}
}

func TestScoreTLSConfigTLS12(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	score, issues := scoreTLSConfig(state)
	if score != 90 {
		t.Errorf("TLS 1.2 GCM expected 90, got %d", score)
	}
	_ = issues
}

func TestScoreTLSConfigTLS11(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS11,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}
	score, issues := scoreTLSConfig(state)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "TLS 1.1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TLS 1.1 deprecation issue, got %v", issues)
	}
	_ = score
}

func TestScoreTLSConfigTLS10(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS10,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}
	score, issues := scoreTLSConfig(state)
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "TLS 1.0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TLS 1.0 deprecation issue, got %v", issues)
	}
	if score > 50 {
		t.Errorf("TLS 1.0 should score ≤50, got %d", score)
	}
}

func TestScoreTLSConfigUnknownVersion(t *testing.T) {
	state := tls.ConnectionState{
		Version:     0x0200,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	score, issues := scoreTLSConfig(state)
	_ = score
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "Unknown") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown version issue, got %v", issues)
	}
}

func TestAuditMultipleEmptyTargets(t *testing.T) {
	a := NewAuditor(100 * time.Millisecond)
	result := a.AuditMultiple(nil)
	if result.TotalScanned != 0 {
		t.Errorf("expected 0 total, got %d", result.TotalScanned)
	}
}

func TestAuditMultipleSkipsInvalidTarget(t *testing.T) {
	a := NewAuditor(100 * time.Millisecond)
	result := a.AuditMultiple([]string{"no-port-here"})
	if result.TotalScanned != 0 {
		t.Errorf("invalid target should be skipped, got %d scanned", result.TotalScanned)
	}
}

func TestAuditEndpointConnectionFailed(t *testing.T) {
	a := NewAuditor(200 * time.Millisecond)
	ep := a.AuditEndpoint("127.0.0.1", 19999) // nothing listening
	if ep.Grade != "F" {
		t.Errorf("expected grade F for unreachable host, got %s", ep.Grade)
	}
	if len(ep.Issues) == 0 {
		t.Error("expected at least one issue for connection failure")
	}
}

func TestAuditEndpointRealTLS(t *testing.T) {
	ts := httptest.NewTLSServer(nil)
	defer ts.Close()

	// Parse host and port from the test server URL.
	addr := strings.TrimPrefix(ts.URL, "https://")
	var host string
	var port int
	_, _ = host, port
	// Use AuditMultiple to exercise the host:port parsing path.
	a := NewAuditor(5 * time.Second)
	result := a.AuditMultiple([]string{addr})
	if result.TotalScanned != 1 {
		t.Fatalf("expected 1 endpoint scanned, got %d", result.TotalScanned)
	}
	ep := result.Endpoints[0]
	if ep.Grade == "" {
		t.Error("expected a grade")
	}
	// Grade counter should be incremented.
	total := result.GradeA + result.GradeB + result.GradeC + result.GradeF
	if total != 1 {
		t.Errorf("expected grade counter total=1, got %d", total)
	}
}

func TestAuditMultipleGradeCounters(t *testing.T) {
	// Grade F from unreachable endpoints.
	a := NewAuditor(100 * time.Millisecond)
	result := a.AuditMultiple([]string{"127.0.0.1:19991", "127.0.0.1:19992"})
	if result.TotalScanned != 2 {
		t.Fatalf("expected 2 scanned, got %d", result.TotalScanned)
	}
	if result.GradeF != 2 {
		t.Errorf("expected 2 grade-F, got %d", result.GradeF)
	}
}
