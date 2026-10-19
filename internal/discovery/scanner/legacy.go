// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"
)

// Endpoint-level finding codes. An endpoint finding is stored in
// endpoints.issues as "CODE" or "CODE: detail", beside cipheraudit's issue
// strings, so the code is always the prefix up to the first colon.
const (
	// FindingNotTLS: the port accepted a TCP connection but does not speak
	// TLS (a plain HTTP server on 443, a database on an HTTPS port).
	FindingNotTLS = "NOT_TLS"
	// FindingTLSHandshakeFailed: the port accepted a connection and the TLS
	// handshake failed for a reason other than a missing TLS stack.
	FindingTLSHandshakeFailed = "TLS_HANDSHAKE_FAILED"
	// FindingPostgresTLSDisabled: a Postgres server answered the SSLRequest
	// with 'N' -- it speaks the protocol but refuses TLS, so client traffic
	// (credentials included) is plaintext. Distinct from a failed handshake:
	// nothing went wrong, TLS is simply off.
	FindingPostgresTLSDisabled = "POSTGRES_TLS_DISABLED"
	// FindingMSSQLTLSDisabled: SQL Server answered the TDS PRELOGIN with
	// ENCRYPT_NOT_SUP -- it speaks TDS but offers no TLS, so logins are
	// plaintext. FindingMySQLTLSDisabled is the same for a MySQL greeting that
	// does not advertise the SSL capability.
	FindingMSSQLTLSDisabled = "MSSQL_TLS_DISABLED"
	FindingMySQLTLSDisabled = "MYSQL_TLS_DISABLED"
	// FindingDeprecatedTLS: the server negotiates SSLv3, TLS 1.0 or TLS 1.1
	// (RFC 8996).
	FindingDeprecatedTLS = "DEPRECATED_TLS_VERSION"

	// Install-posture findings (W34-08), produced from a host scan of the files
	// a service uses. None is a substring of another flag or finding code: the
	// risk SQL matches by LIKE.
	//
	// FindingPrivilegedInstallPath: a cert, key or keystore the service
	// account cannot replace (root-owned, service not root). Medium; high when
	// the target auto-renews and no privileged credential exists, which is
	// marked in the detail (PrivilegedHighPrefix) because severity is not part
	// of the code.
	FindingPrivilegedInstallPath = "PRIVILEGED_INSTALL_PATH"
	// FindingInsufficientPrivilege: the scan account could not read paths for
	// lack of privilege. One per target, naming the uid, the privilege mode,
	// the paths (capped, with the total) and the fix for that mode. Medium: it
	// is a target finding, not a certificate one.
	FindingInsufficientPrivilege = "INSUFFICIENT_PRIVILEGE"
	// FindingServiceRunsAsRoot: an application server that runs as uid 0.
	FindingServiceRunsAsRoot = "SERVICE_RUNS_AS_ROOT"
	// FindingKeyWorldReadable: a private key whose mode grants group or other read.
	FindingKeyWorldReadable = "KEY_WORLD_READABLE"
	// FindingHomeDirKeystore: a keystore a service uses lives under /root or /home.
	FindingHomeDirKeystore = "HOME_DIR_KEYSTORE"

	// PrivilegedHighPrefix opens the detail of a PRIVILEGED_INSTALL_PATH that
	// is high severity.
	PrivilegedHighPrefix = FindingPrivilegedInstallPath + ": severity=high"
)

// FindingCode returns the code of an endpoint finding: everything before the
// first colon, or the whole string when it has no detail.
func FindingCode(finding string) string {
	code, _, _ := strings.Cut(finding, ":")
	return code
}

// HasFinding reports whether findings contains an entry with the given code.
func HasFinding(findings []string, code string) bool {
	return slices.ContainsFunc(findings, func(f string) bool { return FindingCode(f) == code })
}

// HighSeverityCertFlags are the certificate risk flags that make an endpoint
// "risky" regardless of its numeric score: a score is a sum, so several of
// these land at 40-60 and a threshold alone hides a certificate that is
// already expired or self-signed.
var HighSeverityCertFlags = []string{
	"EXPIRED", "SELF_SIGNED", "WEAK_KEY", "WEAK_SIGNATURE",
}

// HighSeverityEndpointCertFlags are the endpoint-scoped flags (see
// EndpointFlags) that make the endpoint serving them risky: a certificate that
// does not vouch for the name it is served at, or that chains to an untrusted
// root. INCOMPLETE_CHAIN is a finding but not, on its own, "risky".
var HighSeverityEndpointCertFlags = []string{FlagHostnameMismatch, FlagUntrustedRoot}

// FindingCertFlags are the certificate flags counted as findings. It is every
// high-severity flag plus the lower-severity ones; PQC_VULNERABLE is
// deliberately absent because it is informational and every RSA/ECDSA
// certificate carries it.
var FindingCertFlags = append(append(append([]string{}, HighSeverityCertFlags...), HighSeverityEndpointCertFlags...),
	"EXPIRING_7_DAYS", "EXPIRING_30_DAYS", FlagIncompleteChain)

// HighSeverityEndpointFindings are the endpoint-level findings that make an
// endpoint risky: a deprecated protocol, or an open port that should be
// protected by TLS and is not -- plaintext (NOT_TLS, POSTGRES_TLS_DISABLED) or
// a handshake that does not complete (TLS_HANDSHAKE_FAILED). The last two used
// to differ (NOT_TLS risky, handshake failure not) although both mean "a
// service answers here and no working TLS protects it". Scan targets are
// ports expected to speak TLS (implicit or via STARTTLS/SSLRequest/X.224), so
// a failed negotiation there is a finding, not noise.
var HighSeverityEndpointFindings = []string{FindingDeprecatedTLS, FindingNotTLS, FindingTLSHandshakeFailed, FindingPostgresTLSDisabled, FindingMSSQLTLSDisabled, FindingMySQLTLSDisabled,
	FindingServiceRunsAsRoot, FindingKeyWorldReadable}

// IsHighSeverityFinding reports whether an endpoint finding makes its endpoint
// risky: a code in HighSeverityEndpointFindings, or a PRIVILEGED_INSTALL_PATH
// the hub marked high.
func IsHighSeverityFinding(finding string) bool {
	return slices.Contains(HighSeverityEndpointFindings, FindingCode(finding)) || strings.HasPrefix(finding, PrivilegedHighPrefix)
}

// MarkPrivilegedPathHigh rewrites a PRIVILEGED_INSTALL_PATH finding as high
// severity; other findings are returned unchanged.
func MarkPrivilegedPathHigh(finding string) string {
	rest, ok := strings.CutPrefix(finding, FindingPrivilegedInstallPath+": ")
	if !ok {
		return finding
	}
	return PrivilegedHighPrefix + "; " + rest
}

// EndpointFindingScore is the risk score an endpoint earns from its own
// findings, so that an endpoint with no certificate (and therefore no
// certificate score) is not shown as risk 0 while flagged risky.
const EndpointFindingScore = 20

// EndpointFindingsScore returns EndpointFindingScore when any of issues is a
// high-severity endpoint finding, else 0.
func EndpointFindingsScore(issues []string) int {
	for _, i := range issues {
		if IsHighSeverityFinding(i) {
			return EndpointFindingScore
		}
	}
	return 0
}

const (
	versionSSL30 = 0x0300
	versionTLS10 = 0x0301
	versionTLS11 = 0x0302
)

// legacyClientHello builds a ClientHello that offers at most TLS 1.1 with the
// CBC/RC4/3DES suites a legacy-only server would still hold. No extensions:
// a server that wants SNI to answer is outside this probe. Go's crypto/tls
// cannot be asked for these suites, which is why the bytes are hand-built.
func legacyClientHello() ([]byte, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("client random: %w", err)
	}
	suites := []uint16{0xc014, 0xc013, 0xc00a, 0xc009, 0x0039, 0x0033, 0x0035, 0x002f, 0x000a, 0x0005, 0x0004}
	body := []byte{byte(versionTLS11 >> 8), byte(versionTLS11 & 0xff)}
	body = append(body, random[:]...)
	body = append(body, 0) // empty session id
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // one compression method: null

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	// The record layer advertises 1.0 as RFC 8446 s5.1 recommends for a first
	// flight, so a strict 1.0 server does not reject the record itself.
	rec := []byte{0x16, byte(versionTLS10 >> 8), byte(versionTLS10 & 0xff), byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...), nil
}

// probeLegacyServerHello sends a ClientHello capped at TLS 1.1 and reads the
// server's answer. It reports the ServerHello version only when that version
// is SSLv3, TLS 1.0 or TLS 1.1; an alert, a modern version or anything that is
// not a ServerHello reports false. The handshake is never completed, nothing
// is verified and no certificate is read: this is a protocol-version probe,
// not a trust decision. It runs only after the ordinary handshake has failed.
func probeLegacyServerHello(ctx context.Context, host string, port int, timeout time.Duration) (uint16, bool) {
	hello, err := legacyClientHello()
	if err != nil {
		return 0, false
	}
	d := guardedDialer(timeout)
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout)) // best-effort bound; the dialer timeout still applies
	if _, err := conn.Write(hello); err != nil {
		return 0, false
	}
	sh, ok := readServerHello(conn)
	if !ok {
		return 0, false
	}
	switch sh.version {
	case versionSSL30, versionTLS10, versionTLS11:
		return sh.version, true
	}
	return 0, false
}

// maxServerHelloRecord bounds what is read after the record header; a
// ServerHello is a few hundred bytes and anything larger is not one.
const maxServerHelloRecord = 16 << 10

// serverHello is the part of a ServerHello the probes use.
type serverHello struct {
	version    uint16
	suite      uint16
	extensions []uint16 // in the order the server sent them
	recordLen  int      // length of the handshake record carrying it
	complete   bool     // suite and extensions were parsed; false when only the version was readable
}

// readServerHello reads one handshake record and parses a ServerHello from it.
// ok is false for an alert, a non-handshake record or any message that is not
// a ServerHello. A hello whose body is cut short still reports its version,
// which is all the legacy-version probe needs.
func readServerHello(r io.Reader) (serverHello, bool) {
	// record header (5) + handshake type (1) + handshake length (3) + version (2)
	var head [11]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return serverHello{}, false
	}
	if head[0] != 0x16 || head[5] != 0x02 {
		return serverHello{}, false
	}
	sh := serverHello{version: binary.BigEndian.Uint16(head[9:11]), recordLen: int(binary.BigEndian.Uint16(head[3:5]))}
	// Bytes of the record after the 6 consumed handshake bytes (type, length, version).
	rest := sh.recordLen - 6
	if rest < 0 || rest > maxServerHelloRecord {
		return sh, true
	}
	body := make([]byte, rest)
	if _, err := io.ReadFull(r, body); err != nil {
		return sh, true
	}
	// random (32), session id (1+n), suite (2), compression (1), [extensions (2+n)]
	off := 32
	if off >= len(body) {
		return sh, true
	}
	off += 1 + int(body[off])
	if off+3 > len(body) {
		return sh, true
	}
	sh.suite = binary.BigEndian.Uint16(body[off:])
	off += 3
	sh.complete = true
	if off+2 > len(body) {
		return sh, true
	}
	extLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if off+extLen > len(body) {
		sh.complete = false
		return sh, true
	}
	ext := body[off : off+extLen]
	for len(ext) >= 4 {
		id, l := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		sh.extensions = append(sh.extensions, id)
		if 4+l > len(ext) {
			break
		}
		ext = ext[4+l:]
	}
	return sh, true
}
