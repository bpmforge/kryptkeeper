// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

// SQL Server and RDP do not start TLS at byte one: SQL Server wraps the
// handshake in TDS PRELOGIN packets and RDP starts it after an X.224
// negotiation, so the plain-TLS verifiers in verify.go never reach the
// certificate. These verifiers reuse the discovery scanner's own protocol
// probes (the framing that is already proven against real servers there)
// instead of a second implementation that could drift from them. The scanner's
// dialer applies the hub's egress/deny policy.

const protocolVerifyTimeout = 10 * time.Second

// NewTDSVerifier verifies SQL Server's served leaf via the PRELOGIN-framed TLS
// handshake.
func NewTDSVerifier() Verifier {
	return protocolVerifier(func(ctx context.Context, s *scanner.ProtocolScanner, host string, port int) scanner.DiscoveredEndpoint {
		return s.ScanTDS(ctx, host, port)
	})
}

// NewRDPVerifier verifies the RDP listener's served leaf via the X.224
// negotiation followed by the TLS handshake.
func NewRDPVerifier() Verifier {
	return protocolVerifier(func(ctx context.Context, s *scanner.ProtocolScanner, host string, port int) scanner.DiscoveredEndpoint {
		return s.ScanRDP(ctx, host, port)
	})
}

func protocolVerifier(probe func(context.Context, *scanner.ProtocolScanner, string, int) scanner.DiscoveredEndpoint) Verifier {
	return func(ctx context.Context, hostPort string) (string, error) {
		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			return "", errors.New("verify address must be host:port")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("verify address has an invalid port")
		}
		ep := probe(ctx, scanner.NewProtocolScanner(protocolVerifyTimeout), host, port)
		// Errors are generic on purpose: the text lands in API responses and
		// audit rows, and a raw dial error would make this an internal port
		// scanner (same rule as verifierWithPolicy).
		if len(ep.Certs) == 0 {
			if strings.Contains(ep.Error, scanner.ErrTargetDenied.Error()) {
				return "", errors.New("verify address is not permitted")
			}
			return "", errors.New("no certificate served at the verify address")
		}
		return FingerprintSHA256(ep.Certs[0].Raw), nil
	}
}
