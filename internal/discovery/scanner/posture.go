// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// W14-04: the crypto-posture probe. Cert inventory says what you
// ISSUED; this says what an endpoint actually negotiates AND offers on
// the wire — including post-quantum key exchange, the ML-KEM-on-the-
// wire signal cert-side pqc_readiness cannot provide. This is the
// crypto inventory the CBOM story claims.

// PQCPosture captures post-quantum key-exchange facts.
type PQCPosture struct {
	HybridNegotiated bool   `json:"hybrid_negotiated"`
	HybridOffered    bool   `json:"hybrid_offered"`
	Group            string `json:"group,omitempty"` // negotiated key-exchange group name
}

// CryptoPosture is one endpoint's on-the-wire cryptographic facts.
type CryptoPosture struct {
	Host              string     `json:"host"`
	Port              int        `json:"port"`
	NegotiatedVersion string     `json:"negotiated_version"`
	NegotiatedCipher  string     `json:"negotiated_cipher"`
	NegotiatedGroup   string     `json:"negotiated_group"`
	OfferedVersions   []string   `json:"offered_versions"`
	WeakFindings      []string   `json:"weak_findings"`
	PQC               PQCPosture `json:"pqc"`
	Error             string     `json:"error,omitempty"`
}

// PostureProber probes endpoint crypto posture.
type PostureProber struct {
	dialer  *net.Dialer
	timeout time.Duration
}

func NewPostureProber(timeout time.Duration) *PostureProber {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &PostureProber{dialer: &net.Dialer{Timeout: timeout}, timeout: timeout}
}

var probeVersions = []uint16{
	tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13,
}

// curveName renders a CurveID, naming the ML-KEM hybrid explicitly.
func curveName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case 0:
		return ""
	}
	return fmt.Sprintf("CurveID(0x%04x)", uint16(id))
}

func isPQCGroup(name string) bool {
	u := strings.ToUpper(name)
	return strings.Contains(u, "MLKEM") || strings.Contains(u, "KYBER")
}

// PostureFromState extracts the NEGOTIATED crypto posture from a handshake
// that already happened — free, no extra connection. This is the headline
// signal (was ML-KEM actually negotiated on the wire?) that the capture
// path can record for every TLS endpoint. The OFFERED-version enumeration
// (ProbeEndpoint) needs extra handshakes and is reserved for deep scans.
func PostureFromState(host string, port int, state tls.ConnectionState) CryptoPosture {
	cp := CryptoPosture{
		Host:              host,
		Port:              port,
		NegotiatedVersion: tlsVersionString(state.Version),
		NegotiatedCipher:  tls.CipherSuiteName(state.CipherSuite),
		NegotiatedGroup:   curveName(state.CurveID),
	}
	cp.PQC.Group = cp.NegotiatedGroup
	if isPQCGroup(cp.NegotiatedGroup) {
		cp.PQC.HybridNegotiated = true
	}
	if state.Version < tls.VersionTLS12 {
		cp.WeakFindings = append(cp.WeakFindings, "negotiated "+cp.NegotiatedVersion+" below TLS 1.2")
	}
	for _, weak := range []string{"RC4", "3DES", "_CBC_", "NULL", "EXPORT"} {
		if strings.Contains(strings.ToUpper(cp.NegotiatedCipher), weak) {
			cp.WeakFindings = append(cp.WeakFindings, "weak cipher: "+cp.NegotiatedCipher)
			break
		}
	}
	return cp
}

// ProbeEndpoint captures negotiated and offered crypto posture.
func (p *PostureProber) ProbeEndpoint(ctx context.Context, host string, port int) CryptoPosture {
	cp := CryptoPosture{Host: host, Port: port}
	target := net.JoinHostPort(host, fmt.Sprint(port))

	// Default handshake for the negotiated facts.
	state, err := p.handshake(ctx, target, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		cp.Error = err.Error()
		return cp
	}
	cp.NegotiatedVersion = tlsVersionString(state.Version)
	cp.NegotiatedCipher = tls.CipherSuiteName(state.CipherSuite)
	cp.NegotiatedGroup = curveName(state.CurveID)
	cp.PQC.Group = cp.NegotiatedGroup
	if isPQCGroup(cp.NegotiatedGroup) {
		cp.PQC.HybridNegotiated = true
	}

	// Offered versions: one handshake per version, pinned Min=Max.
	for _, ver := range probeVersions {
		st, err := p.handshake(ctx, target, &tls.Config{
			ServerName: host, InsecureSkipVerify: true,
			MinVersion: ver, MaxVersion: ver,
		})
		if err != nil {
			continue
		}
		name := tlsVersionString(st.Version)
		cp.OfferedVersions = append(cp.OfferedVersions, name)
		if st.Version <= tls.VersionTLS11 {
			cp.WeakFindings = append(cp.WeakFindings, "offers "+name+" (deprecated)")
		}
	}

	// PQC offer probe: offer ONLY the ML-KEM hybrid group.
	if st, err := p.handshake(ctx, target, &tls.Config{
		ServerName: host, InsecureSkipVerify: true,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}); err == nil && isPQCGroup(curveName(st.CurveID)) {
		cp.PQC.HybridOffered = true
	}

	// Weak cipher findings on the negotiated suite.
	if state.Version < tls.VersionTLS12 {
		cp.WeakFindings = append(cp.WeakFindings, "negotiated "+cp.NegotiatedVersion+" below TLS 1.2")
	}
	for _, weak := range []string{"RC4", "3DES", "_CBC_", "NULL", "EXPORT"} {
		if strings.Contains(strings.ToUpper(cp.NegotiatedCipher), weak) {
			cp.WeakFindings = append(cp.WeakFindings, "weak cipher: "+cp.NegotiatedCipher)
			break
		}
	}
	return cp
}

func (p *PostureProber) handshake(ctx context.Context, target string, cfg *tls.Config) (tls.ConnectionState, error) {
	conn, err := p.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.timeout)) // best-effort bound; dialer timeout still applies
	tconn := tls.Client(conn, cfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tconn.ConnectionState(), nil
}
