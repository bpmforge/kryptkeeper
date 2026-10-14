// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/ca"
)

// DiscoveredCert holds metadata extracted from a TLS handshake.
type DiscoveredCert struct {
	Fingerprint        string
	SerialNumber       string
	CommonName         string
	SubjectDN          string
	IssuerDN           string
	DNSNames           []string
	ValidFrom          time.Time
	ValidUntil         time.Time
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	IsCA               bool
	RiskScore          int
	RiskFlags          []string
	Raw                []byte
}

// DiscoveredEndpoint holds a scanned network endpoint.
type DiscoveredEndpoint struct {
	Host       string
	Port       int
	Protocol   string
	TLSVersion string
	Certs      []DiscoveredCert
	Error      string
	ScannedAt  time.Time
	// W14-03: protocol-aware scan extras. Banner is the SSH server
	// banner; HostKeyAlgorithms are the SSH server's advertised
	// host-key algorithms (feeds algorithm-sunset/PQC scoring).
	Banner            string   `json:",omitempty"`
	HostKeyAlgorithms []string `json:",omitempty"`
	// ServerTech is the web/server technology fingerprinted from the HTTP
	// Server header over the TLS connection (iis|apache|nginx|haproxy|…),
	// so the estate knows WHICH automation a host needs rather than
	// assuming IIS on Windows or nginx on Linux. RecommendedInstallMode
	// is the install_mode that fingerprint implies.
	ServerTech             string `json:",omitempty"`
	RecommendedInstallMode string `json:",omitempty"`
	// CryptoPosture is the on-the-wire TLS posture — negotiated version/
	// cipher/group and, crucially, whether ML-KEM hybrid key exchange was
	// negotiated (the live PQC signal the cert inventory cannot see). Always
	// filled cheaply from the capture handshake; deep scans additionally
	// enumerate OFFERED versions.
	CryptoPosture *CryptoPosture `json:",omitempty"`
}

// ScanResult is the output of a scan job.
type ScanResult struct {
	JobID        string
	Status       string // completed, failed
	Endpoints    []DiscoveredEndpoint
	TotalScanned int
	CertsFound   int
	ErrorCount   int
	StartedAt    time.Time
	CompletedAt  time.Time
}

// ScanConfig controls scanner behavior.
type ScanConfig struct {
	Targets       []string      // host:port or CIDR
	Ports         []int         // ports to scan (default: 443)
	Concurrency   int           // max parallel goroutines
	Timeout       time.Duration // per-host timeout
	TLSSkipVerify bool          // skip cert chain validation
	// Deep runs a full TCP-connect port sweep per host FIRST, then captures
	// every open port — the slow, thorough mode. DeepPortLo/Hi narrow the
	// sweep range (0 = full 1–65535).
	Deep       bool
	DeepPortLo int
	DeepPortHi int
}

// Scanner performs TLS certificate discovery.
type Scanner struct {
	config   ScanConfig
	protocol *ProtocolScanner
	// captureRetries retries a failed capture (deep mode only): a deep
	// scan's own port flood, or a fragile single-connection listener, can
	// make the immediately-following TLS/SSH capture fail transiently.
	// Retrying once a moment later rescues it. Zero for normal scans, which
	// must stay fast.
	captureRetries int
}

// New creates a scanner with the given config.
func New(config ScanConfig) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 50
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if len(config.Ports) == 0 {
		config.Ports = []int{443}
	}
	sc := &Scanner{config: config, protocol: NewProtocolScanner(config.Timeout)}
	if config.Deep {
		sc.captureRetries = 1
	}
	return sc
}

// Scan executes a discovery scan against all configured targets.
func (s *Scanner) Scan(ctx context.Context, jobID string) *ScanResult {
	result := &ScanResult{
		JobID:     jobID,
		Status:    "completed",
		StartedAt: time.Now().UTC(),
	}

	targets := s.expandTargets()
	if s.config.Deep {
		targets = s.expandDeep(ctx, targets)
	}
	sem := make(chan struct{}, s.config.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Status = "failed"
			result.CompletedAt = time.Now().UTC()
			return result
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()

			ep := s.scanEndpoint(ctx, t)
			mu.Lock()
			result.Endpoints = append(result.Endpoints, ep)
			result.TotalScanned++
			if ep.Error != "" {
				result.ErrorCount++
			}
			for range ep.Certs {
				result.CertsFound++
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	result.CompletedAt = time.Now().UTC()
	// A scan is FAILED only when nothing was reachable at all (every probed
	// endpoint errored). Reaching services and finding no certs — routine
	// for a deep sweep across many non-TLS open ports, or a host that
	// simply serves nothing cert-bearing — is a COMPLETED scan with no
	// findings, not a failure. The old "any error + zero certs = failed"
	// rule wrongly failed those.
	if result.TotalScanned > 0 && result.ErrorCount == result.TotalScanned {
		result.Status = "failed"
	}
	return result
}

func (s *Scanner) scanEndpoint(ctx context.Context, target string) DiscoveredEndpoint {
	ep := s.scanEndpointOnce(ctx, target)
	// Deep mode: one retry after a brief settle if the capture errored —
	// the port flood or a fragile listener can make the first attempt fail
	// transiently while the service is genuinely up.
	for attempt := 0; attempt < s.captureRetries && ep.Error != "" && len(ep.Certs) == 0; attempt++ {
		select {
		case <-ctx.Done():
			return ep
		case <-time.After(1 * time.Second):
		}
		ep = s.scanEndpointOnce(ctx, target)
	}
	return ep
}

func (s *Scanner) scanEndpointOnce(ctx context.Context, target string) DiscoveredEndpoint {
	host, port, err := parseTarget(target)
	if err != nil {
		return DiscoveredEndpoint{Error: fmt.Sprintf("invalid target: %v", err), ScannedAt: time.Now().UTC()}
	}
	// Dispatch by port to the right capture: implicit TLS, STARTTLS, SSH or
	// RDP. Before this, every port got a plain tls.Dial — SSH host keys and
	// STARTTLS certs (mail, Postgres) were never captured because the whole
	// ProtocolScanner had no caller.
	entry := protocolForPort(port)
	switch entry.kind {
	case probeSSH:
		return s.protocol.ScanSSH(ctx, host, port)
	case probeRDP:
		return s.protocol.ScanRDP(ctx, host, port)
	case probeSTARTTLS:
		return s.protocol.ScanSTARTTLS(ctx, host, port, entry.starttls)
	default:
		return s.captureTLS(ctx, host, port, entry)
	}
}

// captureTLS dials implicit TLS and records the leaf-checked certs. entry
// carries the service classification (ldaps, imaps, winrm-https, …) so an
// LDAPS or WinRM endpoint is recorded as what it IS, not a generic "tls".
func (s *Scanner) captureTLS(_ context.Context, host string, port int, entry protocolEntry) DiscoveredEndpoint {
	proto := entry.protocol
	if proto == "" {
		proto = "tls"
	}
	ep := DiscoveredEndpoint{Host: host, Port: port, Protocol: proto, ScannedAt: time.Now().UTC()}
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, fmt.Sprint(port)), &tls.Config{
		InsecureSkipVerify: true, // we want the cert regardless of chain validity
	})
	if err != nil {
		ep.Error = fmt.Sprintf("tls dial: %v", err)
		return ep
	}
	defer conn.Close()
	state := conn.ConnectionState()
	ep.TLSVersion = tlsVersionString(state.Version)
	for i, cert := range state.PeerCertificates {
		// Only the LEAF (first cert) is bound to this endpoint's hostname.
		ep.Certs = append(ep.Certs, certToDiscovered(cert, host, i == 0))
	}
	// Over the SAME established TLS connection, ask for the HTTP Server
	// header to fingerprint the web technology. HTTPS-family ports only;
	// LDAPS/AMQPS/etc. would not answer HTTP. Best-effort — a service that
	// does not speak HTTP just yields no fingerprint, never an error.
	// Fingerprint on known HTTP ports always; in deep mode, on ANY port we
	// got a TLS cert from, since a deep scan finds HTTP on arbitrary ports
	// (8444, 7443, …) the catalogue would never list. The HEAD read is
	// deadline-bounded, so a non-HTTP TLS service (LDAPS) just yields no
	// fingerprint rather than hanging.
	if (isHTTPPort(port) || s.config.Deep) && len(ep.Certs) > 0 {
		if tech := fingerprintServer(conn, host, s.config.Timeout); tech != "" {
			ep.ServerTech = tech
		}
	}
	// The recommendation draws on BOTH the web-server fingerprint (when we
	// got one) and the service protocol — so an LDAPS/WinRM/k8s endpoint
	// gets a sensible automation hint even though it serves no HTTP.
	ep.RecommendedInstallMode = recommendInstallMode(ep.ServerTech, proto)
	// Record the on-the-wire crypto posture from THIS handshake (free) —
	// including whether ML-KEM was actually negotiated. A deep scan also
	// enumerates the offered TLS versions and probes for ML-KEM support
	// (extra handshakes, so gated to the slow mode).
	posture := PostureFromState(host, port, state)
	if s.config.Deep {
		full := s.postureProber().ProbeEndpoint(context.Background(), host, port)
		if full.Error == "" {
			posture.OfferedVersions = full.OfferedVersions
			posture.PQC.HybridOffered = full.PQC.HybridOffered
			if len(full.WeakFindings) > len(posture.WeakFindings) {
				posture.WeakFindings = full.WeakFindings
			}
		}
	}
	ep.CryptoPosture = &posture
	return ep
}

// postureProber lazily builds a prober sharing the scanner's timeout.
func (s *Scanner) postureProber() *PostureProber {
	return NewPostureProber(s.config.Timeout)
}

// isHTTPPort reports whether a port is expected to speak HTTP over its TLS
// layer (so a Server-header probe is worthwhile).
func isHTTPPort(port int) bool {
	switch port {
	case 443, 8443, 4443, 9443, 10443, 6443:
		return true
	default:
		return false
	}
}

// fingerprintServer sends a minimal HTTP HEAD over the already-open TLS
// connection and classifies the Server response header.
func fingerprintServer(conn net.Conn, host string, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))        // best-effort read deadline; a fingerprint probe failure is non-fatal
	defer func() { _ = conn.SetDeadline(time.Time{}) }() // clear deadline; error irrelevant on a closing conn
	req := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Kryptkeeper-Scan\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return classifyServerHeader(string(buf[:n]))
}

// classifyServerHeader maps an HTTP response's Server header to a
// normalized technology tag. Unknown-but-present servers return the raw
// token so the estate still records SOMETHING rather than losing it.
func classifyServerHeader(resp string) string {
	lower := strings.ToLower(resp)
	for _, line := range strings.Split(resp, "\r\n") {
		if !strings.HasPrefix(strings.ToLower(line), "server:") {
			continue
		}
		val := strings.ToLower(strings.TrimSpace(line[len("server:"):]))
		switch {
		case strings.Contains(val, "microsoft-iis") || strings.Contains(val, "iis"):
			return "iis"
		case strings.Contains(val, "apache"):
			return "apache"
		case strings.Contains(val, "nginx"):
			return "nginx"
		case strings.Contains(val, "haproxy"):
			return "haproxy"
		case strings.Contains(val, "caddy"):
			return "caddy"
		case strings.Contains(val, "envoy"):
			return "envoy"
		case strings.Contains(val, "litespeed"):
			return "litespeed"
		case val == "":
			return ""
		default:
			// Record the first token of an unrecognized server verbatim.
			return strings.Fields(val)[0]
		}
	}
	// Some servers (notably hardened IIS) suppress the Server header but
	// still leak identity elsewhere; a couple of cheap tells.
	if strings.Contains(lower, "x-aspnet-version") || strings.Contains(lower, "x-powered-by: asp.net") {
		return "iis"
	}
	return ""
}

// recommendInstallMode maps a fingerprint — the web-server technology when
// one was read, otherwise the service protocol — to the install_mode whose
// renewal automation fits it. Empty means "the estate should decide": an
// ambiguous or unknown service where guessing would mislead.
func recommendInstallMode(webTech, protocol string) string {
	// A concrete web-server fingerprint is the strongest signal.
	switch webTech {
	case "iis":
		return "iis"
	case "nginx", "apache", "haproxy", "caddy", "litespeed", "envoy":
		return "ssh" // file-drop + reload over SSH
	}
	// No web fingerprint — fall back to the service class.
	switch protocol {
	case "winrm-https":
		// WinRM is the Windows management channel; the shipped Windows
		// automation is the IIS installer over WinRM.
		return "iis"
	case "kubernetes-api":
		return "k8s"
	case "postgres", "etcd", "etcd-peer", "amqps", "mqtts", "ldaps-gc":
		// File-based certs a config-management push replaces over SSH.
		return "ssh"
	default:
		// https/https-alt with no Server header, ldaps (could be AD or
		// OpenLDAP), rdp, ssh, mail — too ambiguous to assert an install
		// mode; leave it to the operator rather than guess wrong.
		return ""
	}
}

// expandDeep replaces every target host with one host:port per OPEN port
// found by a TCP-connect sweep. A target already pinned to a specific port
// is left as-is (the operator asked for exactly that port). Hosts come from
// expandTargets, so a CIDR is swept per-IP.
func (s *Scanner) expandDeep(ctx context.Context, targets []string) []string {
	lo, hi := deepPortRange(s.config)
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		host, portStr, err := net.SplitHostPort(t)
		if err == nil && portStr != "" {
			out = append(out, t) // explicitly pinned port — honor it
			continue
		}
		host = t
		if h, _, e := net.SplitHostPort(t); e == nil {
			host = h
		}
		// A deep scan is a strict SUPERSET of a full scan: always capture
		// the known cert/key ports, PLUS every open port the sweep finds.
		// A connect sweep can drop a SYN to a real port under its own load,
		// so unioning the catalogue guarantees a deep scan never captures
		// LESS than a full one — it only ever adds.
		ports := mergeInts(portsForTier(tierFull), deepOpenPorts(ctx, host, lo, hi))
		for _, p := range ports {
			out = append(out, net.JoinHostPort(host, itoa(p)))
		}
	}
	return out
}

// mergeInts unions two int slices preserving first-seen order, dropping
// duplicates.
func mergeInts(a, b []int) []int {
	seen := make(map[int]bool, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, list := range [][]int{a, b} {
		for _, v := range list {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func (s *Scanner) expandTargets() []string {
	var expanded []string
	deny := DenyCIDRsFromEnv()
	maxTargets := MaxTargetsFromEnv()
	for _, t := range s.config.Targets {
		_, ipNet, err := net.ParseCIDR(t)
		if err == nil {
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
				// Backstop for targets that bypass the API check (scheduler,
				// config): never expand past the cap or into the deny list.
				if len(expanded) >= maxTargets {
					break
				}
				if addr, ok := netip.AddrFromSlice(ip); ok && denied(deny, addr) {
					continue
				}
				if s.config.Deep {
					// Deep mode discovers ports itself — emit the bare host.
					expanded = append(expanded, ip.String())
					continue
				}
				for _, port := range s.config.Ports {
					expanded = append(expanded, fmt.Sprintf("%s:%d", ip, port))
				}
			}
			continue
		}
		if h, _, err := net.SplitHostPort(t); err == nil {
			if addr, perr := netip.ParseAddr(h); perr == nil && denied(deny, addr) {
				continue
			}
			expanded = append(expanded, t)
			continue
		}
		if addr, perr := netip.ParseAddr(t); perr == nil && denied(deny, addr) {
			continue
		}
		if s.config.Deep {
			expanded = append(expanded, t) // bare host — expandDeep sweeps it
			continue
		}
		for _, port := range s.config.Ports {
			expanded = append(expanded, fmt.Sprintf("%s:%d", t, port))
		}
	}
	return expanded
}

// CertToDiscovered maps a parsed certificate into the discovery model for
// sources outside the network scanner (agentless WinRM store enumeration,
// W18-12) so they persist through the same upsert and risk scoring.
func CertToDiscovered(cert *x509.Certificate, scannedHost string, isLeaf bool) DiscoveredCert {
	return certToDiscovered(cert, scannedHost, isLeaf)
}

func certToDiscovered(cert *x509.Certificate, scannedHost string, isLeaf bool) DiscoveredCert {
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	riskScore, riskFlags := computeCertRisk(cert, scannedHost, isLeaf)
	return DiscoveredCert{
		Fingerprint:        fingerprint,
		SerialNumber:       cert.SerialNumber.String(),
		CommonName:         cert.Subject.CommonName,
		SubjectDN:          cert.Subject.String(),
		IssuerDN:           cert.Issuer.String(),
		DNSNames:           cert.DNSNames,
		ValidFrom:          cert.NotBefore,
		ValidUntil:         cert.NotAfter,
		PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		RiskScore:          riskScore,
		RiskFlags:          riskFlags,
		Raw:                cert.Raw,
	}
}

func computeCertRisk(cert *x509.Certificate, scannedHost string, isLeaf bool) (int, []string) {
	score := 0
	var flags []string
	now := time.Now()

	// Self-signed leaf: subject == issuer on a cert that is not a CA is the
	// classic "someone stood up a service with a throwaway cert" finding —
	// exactly what a default IIS/localhost cert is. A self-signed ROOT is
	// normal (that is what a trust anchor is), so only flag non-CA certs.
	if !cert.IsCA && bytesEqualName(cert.RawSubject, cert.RawIssuer) {
		score += 30
		flags = append(flags, "SELF_SIGNED")
	}

	// Hostname mismatch: the leaf does not vouch for the address it was
	// served on. Only meaningful for the leaf and only when we scanned a
	// DNS name or IP we can check against (VerifyHostname handles both
	// SAN DNS names and IP SANs).
	if isLeaf && scannedHost != "" {
		if err := cert.VerifyHostname(scannedHost); err != nil {
			score += 20
			flags = append(flags, "HOSTNAME_MISMATCH")
		}
	}

	// Undersized RSA key (< 2048 bits) is a real weakness independent of
	// PQC — flagged separately so it is not masked by the PQC label.
	if rsaKeyBitsUnder2048(cert) {
		score += 30
		flags = append(flags, "WEAK_KEY")
	}

	if cert.NotAfter.Before(now) {
		score += 40
		flags = append(flags, "EXPIRED")
	} else if cert.NotAfter.Before(now.Add(7 * 24 * time.Hour)) {
		score += 25
		flags = append(flags, "EXPIRING_7_DAYS")
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		score += 15
		flags = append(flags, "EXPIRING_30_DAYS")
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA, x509.ECDSA:
		score += 10
		flags = append(flags, "PQC_VULNERABLE")
	}

	if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.MD5WithRSA {
		score += 30
		flags = append(flags, "WEAK_SIGNATURE")
	}

	if score > 100 {
		score = 100
	}
	return score, flags
}

// bytesEqualName compares two raw DER-encoded distinguished names.
func bytesEqualName(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// rsaKeyBitsUnder2048 reports whether cert carries an RSA public key shorter
// than 2048 bits. Non-RSA keys return false.
func rsaKeyBitsUnder2048(cert *x509.Certificate) bool {
	if cert.PublicKeyAlgorithm != x509.RSA {
		return false
	}
	if pk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		return pk.N.BitLen() < 2048
	}
	return false
}

func parseTarget(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port := 443
	if portStr != "" {
		_, err := fmt.Sscanf(portStr, "%d", &port)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %s", portStr)
		}
	}
	return host, port, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ScanHost is a convenience function that scans a single host:port.
func ScanHost(ctx context.Context, target string, timeout time.Duration) (*DiscoveredEndpoint, error) {
	s := New(ScanConfig{
		Targets:     []string{target},
		Concurrency: 1,
		Timeout:     timeout,
	})
	result := s.Scan(ctx, "single-scan")
	if len(result.Endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints scanned")
	}
	ep := result.Endpoints[0]
	if ep.Error != "" {
		return &ep, fmt.Errorf("scan error: %s", ep.Error)
	}
	return &ep, nil
}
