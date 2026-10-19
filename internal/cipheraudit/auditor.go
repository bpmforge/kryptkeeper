// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cipheraudit

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"kryptkeeper/internal/egress"
)

var auditDialPolicy = egress.Policy{AllowPrivate: true, AllowLoopback: true}

// EndpointTLSConfig holds the TLS configuration details for an endpoint.
type EndpointTLSConfig struct {
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	TLSVersion      string    `json:"tls_version"`
	CipherSuite     string    `json:"cipher_suite"`
	SupportedSuites []string  `json:"supported_suites"`
	Protocol        string    `json:"protocol"`
	Score           int       `json:"score"` // 0-100
	Grade           string    `json:"grade"` // A-F
	Issues          []string  `json:"issues"`
	ScannedAt       time.Time `json:"scanned_at"`
}

// AuditResult holds the results of a cipher suite audit across endpoints.
type AuditResult struct {
	Endpoints    []EndpointTLSConfig `json:"endpoints"`
	TotalScanned int                 `json:"total_scanned"`
	GradeA       int                 `json:"grade_a"`
	GradeB       int                 `json:"grade_b"`
	GradeC       int                 `json:"grade_c"`
	GradeF       int                 `json:"grade_f"`
}

// Auditor performs TLS cipher suite auditing on endpoints.
type Auditor struct {
	timeout time.Duration
}

// NewAuditor creates a cipher suite auditor.
func NewAuditor(timeout time.Duration) *Auditor {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Auditor{timeout: timeout}
}

// AuditEndpoint checks the TLS configuration of a single endpoint.
func (a *Auditor) AuditEndpoint(host string, port int) EndpointTLSConfig {
	result := EndpointTLSConfig{
		Host:      host,
		Port:      port,
		ScannedAt: time.Now().UTC(),
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	// Hosts come from discovery results and are re-resolved here, so the
	// metadata/link-local block is applied at connect time, not only when the
	// scanner first saw the name. Private space and loopback stay auditable,
	// matching the scanner's own dial policy.
	dialer := &net.Dialer{Timeout: a.timeout, Control: auditDialPolicy.DialControl()}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("connection failed: %v", err))
		result.Score = 0
		result.Grade = "F"
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.TLSVersion = tlsVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.Protocol = state.NegotiatedProtocol

	result.Score, result.Issues = scoreTLSConfig(state)
	result.Grade = scoreToGrade(result.Score)
	return result
}

// AuditMultiple audits several endpoints and returns aggregate results.
func (a *Auditor) AuditMultiple(targets []string) AuditResult {
	result := AuditResult{}
	for _, t := range targets {
		host, portStr, err := net.SplitHostPort(t)
		if err != nil {
			continue
		}
		port := 443
		fmt.Sscanf(portStr, "%d", &port)

		ep := a.AuditEndpoint(host, port)
		result.Endpoints = append(result.Endpoints, ep)
		result.TotalScanned++

		switch ep.Grade {
		case "A":
			result.GradeA++
		case "B":
			result.GradeB++
		case "C":
			result.GradeC++
		default:
			result.GradeF++
		}
	}
	return result
}

func scoreTLSConfig(state tls.ConnectionState) (int, []string) {
	score := 100
	var issues []string

	// TLS version scoring.
	switch state.Version {
	case tls.VersionTLS13:
		// Best — no deduction.
	case tls.VersionTLS12:
		score -= 10
	case tls.VersionTLS11:
		score -= 40
		issues = append(issues, "TLS 1.1 is deprecated (RFC 8996)")
	case tls.VersionTLS10:
		score -= 50
		issues = append(issues, "TLS 1.0 is deprecated (RFC 8996)")
	default:
		score -= 60
		issues = append(issues, "Unknown or very old TLS version")
	}

	// Cipher suite scoring.
	suite := tls.CipherSuiteName(state.CipherSuite)
	if containsAny(suite, "RC4", "DES", "3DES") {
		score -= 30
		issues = append(issues, "Weak cipher: "+suite)
	}
	if containsAny(suite, "CBC") && state.Version < tls.VersionTLS13 {
		score -= 10
		issues = append(issues, "CBC mode cipher (vulnerable to padding oracle attacks)")
	}
	if !containsAny(suite, "GCM", "CHACHA20", "CCM") && state.Version < tls.VersionTLS13 {
		score -= 15
		issues = append(issues, "Non-AEAD cipher suite")
	}

	if score < 0 {
		score = 0
	}
	return score, issues
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 70:
		return "B"
	case score >= 50:
		return "C"
	default:
		return "F"
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
