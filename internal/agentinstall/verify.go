// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net"
	"strings"
	"time"

	"kryptkeeper/internal/egress"
)

// Verifier confirms a renewed cert is actually being served at hostPort by
// TLS-dialing it and returning the SHA-256 fingerprint of the served leaf
// certificate (lowercase hex, no colons).
type Verifier func(ctx context.Context, hostPort string) (servedFingerprint string, err error)

// defaultVerifier dials hostPort over TLS and fingerprints the served leaf. It
// does NOT validate the chain or hostname — the caller compares the returned
// fingerprint to the one it expects, which is the actual security check.
// defaultVerifier is the verifier for installers running ON the managed host
// (the agent), where the served certificate is verified over loopback by
// design. Hub-side installs use HubVerifier instead.
func defaultVerifier(ctx context.Context, hostPort string) (string, error) {
	return verifierWithPolicy(egress.Policy{AllowPrivate: true, AllowLoopback: true})(ctx, hostPort)
}

// HubVerifier is the verify-after-install dial for installs the hub drives.
// The address is operator- or caller-influenced, so it goes through the egress
// policy: RFC1918 stays reachable (managed servers are private; honours
// KRYPTKEEPER_EGRESS_DENY_PRIVATE), while loopback and link-local/metadata are
// refused on the address actually dialled, so a hostname resolving there is
// caught too (RC1-A-04).
func HubVerifier(ctx context.Context, hostPort string) (string, error) {
	return verifierWithPolicy(egress.PolicyFromEnv(egress.Policy{AllowPrivate: true}))(ctx, hostPort)
}

// verifierWithPolicy is the TLS-dial verifier bound to an address policy.
// Errors are deliberately generic: the text lands in API responses and audit
// rows, and a raw dial error would turn this into an internal port scanner.
func verifierWithPolicy(p egress.Policy) Verifier {
	return func(ctx context.Context, hostPort string) (string, error) {
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second, Control: p.DialControl()},
			Config:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fingerprint compared by caller
		}
		conn, err := d.DialContext(ctx, "tcp", hostPort)
		if err != nil {
			if errors.Is(err, egress.ErrBlockedDestination) {
				return "", errors.New("verify address is not permitted")
			}
			logging.Warnf("agentinstall: verify dial %s failed: %v", hostPort, err)
			return "", errors.New("tls dial to the verify address failed")
		}
		defer conn.Close()

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			return "", fmt.Errorf("verify: not a TLS connection")
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return "", errors.New("verify: no certificate served at the verify address")
		}
		return FingerprintSHA256(state.PeerCertificates[0].Raw), nil
	}
}

// FingerprintSHA256 returns the lowercase hex SHA-256 of a DER-encoded cert.
func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// normalizeFingerprint lowercases and strips colons/whitespace so fingerprints
// from different sources (e.g. "AA:BB" vs "aabb") compare equal.
func normalizeFingerprint(fp string) string {
	fp = strings.ToLower(strings.TrimSpace(fp))
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return fp
}
