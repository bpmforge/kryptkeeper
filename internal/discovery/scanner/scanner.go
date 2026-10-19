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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

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
	// SourcePath is the file the cert was read from on the scanned host
	// (agentless SSH); the hub persists it on certificate_endpoints.source_path.
	SourcePath string
	// Served: the cert came out of a TLS-presented peer chain, so ApplyTrust
	// may judge it as a chain. Store enumerations, SSH and mesh sources leave
	// it false and are never classified.
	Served bool
	// ChainCA marks an intermediate/root from a served chain. Set by
	// ApplyTrust; such certs are kept out of the leaf inventory.
	ChainCA bool
	// TrustClass/ChainComplete/ChainTrusted are the ApplyTrust verdict for a
	// served leaf (see ClassifyChain). Empty class = never classified.
	// ChainCompleteKnown is false when completeness could not be judged, in
	// which case ChainComplete is meaningless (stored as NULL).
	TrustClass string
	// IssuerClass refines TrustClass with the operator's authorized issuers
	// (hub|authorized|public|private_unknown|self_signed|unknown); empty when
	// it was not judged.
	IssuerClass        string
	ChainComplete      bool
	ChainCompleteKnown bool
	ChainTrusted       bool
	// IssuedByADCS marks a certificate carrying the Microsoft template
	// extensions, i.e. issued by an AD CS enterprise CA; ADCSTemplate is the
	// template name when the extension named one. Not persisted yet: the
	// issuer-class work reads it from here.
	IssuedByADCS bool   `json:",omitempty"`
	ADCSTemplate string `json:",omitempty"`
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
	// Reachable: the TCP connection succeeded, so something is listening even
	// if Error is set. A closed or filtered port is Error with Reachable false
	// and is never recorded (a range scan would flood the inventory); an open
	// port that failed the TLS handshake is Reachable and is.
	Reachable bool `json:",omitempty"`
	// Findings are endpoint-level findings (FindingNotTLS and friends), each
	// "CODE" or "CODE: detail". They are persisted with the endpoint so a host
	// that is up but not serving a usable certificate does not vanish.
	Findings []string `json:",omitempty"`
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
	// Fingerprint is the resolved technology behind this endpoint with the
	// evidence that backs it (FR-P27). ServerTech stays populated for readers
	// that predate it and equals Fingerprint.Tech when that is a web server.
	Fingerprint *Fingerprint `json:",omitempty"`
	// HostObs carries what a host-side scan saw about the machine itself; nil for
	// every network-scanned endpoint.
	HostObs *HostObservations `json:",omitempty"`
	// signals are the raw observations collected during capture; Resolve folds
	// them (plus the port default) into Fingerprint once the capture is over.
	signals []Evidence
}

// ScanResult is the output of a scan job.
type ScanResult struct {
	JobID        string
	Status       string // completed, completed_with_errors, failed
	Endpoints    []DiscoveredEndpoint
	TotalScanned int
	CertsFound   int
	ErrorCount   int
	// Reachable counts endpoints something answered on (TLS or not);
	// ReachableFailed those that answered but failed; Unreachable the ports
	// that refused or timed out. Reachable == 0 is what makes a scan "failed".
	Reachable       int
	ReachableFailed int
	Unreachable     int
	StartedAt       time.Time
	CompletedAt     time.Time
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
	// ActiveProbes enables the fingerprint probes that cost more than the
	// connection a scan already makes (LDAP rootDSE): set for full scans and
	// implied by Deep. Fast and targeted scans leave it off (D-206).
	ActiveProbes bool
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
	sc.protocol.active = config.ActiveProbes || config.Deep
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
			switch {
			case ep.Error == "":
				result.Reachable++
			case ep.Reachable:
				result.Reachable++
				result.ReachableFailed++
			default:
				result.Unreachable++
			}
			for range ep.Certs {
				result.CertsFound++
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	result.CompletedAt = time.Now().UTC()
	// A scan is FAILED only when nothing answered at all. Reaching services
	// and finding no certs — routine for a deep sweep across many non-TLS
	// open ports — is a COMPLETED scan, not a failure. Hosts that answered
	// but failed (plain HTTP on 443, a handshake error) are recorded as
	// endpoints, and the job says so: completed_with_errors, not a silent
	// "completed" that hides them.
	switch {
	case result.TotalScanned > 0 && result.Reachable == 0:
		result.Status = "failed"
	case result.ReachableFailed > 0:
		result.Status = "completed_with_errors"
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
	var ep DiscoveredEndpoint
	switch entry.kind {
	case probeSSH:
		ep = s.protocol.ScanSSH(ctx, host, port)
	case probeRDP:
		ep = withHandshakeFinding(s.protocol.ScanRDP(ctx, host, port))
	case probeTDS:
		ep = withHandshakeFinding(s.protocol.ScanTDS(ctx, host, port))
	case probeSTARTTLS:
		ep = withHandshakeFinding(s.protocol.ScanSTARTTLS(ctx, host, port, entry.starttls))
	default:
		ep = s.captureTLS(ctx, host, port, entry)
	}
	return finalizeFingerprint(ep, entry)
}

// finalizeFingerprint resolves the signals gathered during capture into the
// endpoint's fingerprint and derives the fields that depend on it. A port
// nothing answered on is left alone: it is never persisted.
func finalizeFingerprint(ep DiscoveredEndpoint, entry protocolEntry) DiscoveredEndpoint {
	if !ep.Reachable && ep.Error != "" {
		return ep
	}
	fp := Resolve(append(append([]Evidence{}, ep.signals...), portEvidence(entry.protocol)...))
	ep.Fingerprint = &fp
	if IsWebServerTech(fp.Tech) {
		ep.ServerTech = fp.Tech
	}
	// A port default alone is a guess, and a guess must not steer automation:
	// only a fingerprint with a real observation behind it recommends a mode.
	if fp.Confidence != ConfidenceLow && len(ep.Certs) > 0 {
		ep.RecommendedInstallMode = recommendInstallMode(ep.ServerTech, ep.Protocol)
	}
	return ep
}

// withHandshakeFinding records an STARTTLS/RDP endpoint that answered but
// never produced a TLS session (no STARTTLS offer, declined security layer,
// failed handshake) as TLS_HANDSHAKE_FAILED so it is kept rather than dropped.
func withHandshakeFinding(ep DiscoveredEndpoint) DiscoveredEndpoint {
	if ep.Error != "" && ep.Reachable && len(ep.Findings) == 0 {
		ep.Findings = append(ep.Findings, FindingTLSHandshakeFailed+": "+ep.Error)
	}
	return ep
}

// dialTLS opens a TCP connection and runs the handshake as two steps so a
// refused port (not reachable) is distinguishable from a handshake that failed
// on an open one (reachable). cfg.ServerName is set from host: tls.Dial did
// that implicitly, tls.Client does not.
func (s *Scanner) dialTLS(ctx context.Context, host string, port int, cfg *tls.Config) (conn *tls.Conn, reachable bool, err error) {
	dialer := guardedDialer(s.config.Timeout)
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, false, err
	}
	_ = raw.SetDeadline(time.Now().Add(s.config.Timeout)) // best-effort bound on the handshake; the dialer timeout still applies
	cfg = cfg.Clone()
	cfg.ServerName = host
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, true, err
	}
	_ = raw.SetDeadline(time.Time{}) // clear: later reads set their own deadlines
	return c, true, nil
}

// captureTLS dials implicit TLS and records the leaf-checked certs. entry
// carries the service classification (ldaps, imaps, winrm-https, …) so an
// LDAPS or WinRM endpoint is recorded as what it IS, not a generic "tls".
//
// A port that accepts the connection but cannot complete a handshake is
// still an endpoint: NOT_TLS when the peer is not speaking TLS at all,
// DEPRECATED_TLS_VERSION when it only offers SSLv3/TLS 1.0/1.1, otherwise
// TLS_HANDSHAKE_FAILED. Only a refused or silent port is an unrecorded miss.
func (s *Scanner) captureTLS(ctx context.Context, host string, port int, entry protocolEntry) DiscoveredEndpoint {
	proto := entry.protocol
	if proto == "" {
		proto = "tls"
	}
	ep := DiscoveredEndpoint{Host: host, Port: port, Protocol: proto, ScannedAt: time.Now().UTC()}
	conn, reachable, err := s.dialTLS(ctx, host, port, &tls.Config{
		InsecureSkipVerify: true, // we want the cert regardless of chain validity
	})
	ep.Reachable = reachable
	if err != nil && !reachable {
		ep.Error = fmt.Sprintf("tls dial: %v", err)
		return ep
	}
	if err != nil {
		return s.classifyHandshakeFailure(ctx, ep, host, port, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return s.finishTLSCapture(ep, conn, state, host, port, proto)
}

// classifyHandshakeFailure turns a failed handshake on an open port into a
// finding. The legacy retry is a separate connection with MinVersion lowered
// to TLS 1.0 (crypto/tls only offers 1.2+ unless asked); it is reached only
// after the normal handshake failed, so ordinary verification is untouched and
// a modern server never sees it. It captures, it does not verify: the certs it
// returns go through the same trust classification as any other.
func (s *Scanner) classifyHandshakeFailure(ctx context.Context, ep DiscoveredEndpoint, host string, port int, err error) DiscoveredEndpoint {
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		ep.Error = "not a TLS service: " + err.Error()
		ep.Findings = []string{FindingNotTLS + ": " + rhe.Msg}
		return ep
	}
	conn, _, lerr := s.dialTLS(ctx, host, port, &tls.Config{
		InsecureSkipVerify: true, // capture only; trust is judged later by ClassifyChain
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	})
	if lerr == nil {
		defer conn.Close()
		state := conn.ConnectionState()
		ep.Findings = []string{FindingDeprecatedTLS + ": " + tlsVersionString(state.Version)}
		return s.finishTLSCapture(ep, conn, state, host, port, ep.Protocol)
	}
	// Go may refuse the legacy suites a server insists on; read the version
	// off the wire instead, no certificate.
	if v, ok := probeLegacyServerHello(ctx, host, port, s.config.Timeout); ok {
		ep.TLSVersion = tlsVersionString(v)
		ep.Findings = []string{FindingDeprecatedTLS + ": " + ep.TLSVersion}
		return ep
	}
	ep.Error = "tls handshake: " + err.Error()
	ep.Findings = []string{FindingTLSHandshakeFailed + ": " + err.Error()}
	return ep
}

// finishTLSCapture records certs, fingerprint and posture from an established
// handshake.
func (s *Scanner) finishTLSCapture(ep DiscoveredEndpoint, conn *tls.Conn, state tls.ConnectionState, host string, port int, proto string) DiscoveredEndpoint {
	ep.TLSVersion = tlsVersionString(state.Version)
	for i, cert := range state.PeerCertificates {
		// Only the LEAF (first cert) is bound to this endpoint's hostname.
		dc := certToDiscovered(cert, host, i == 0)
		dc.Served = true
		ep.Certs = append(ep.Certs, dc)
	}
	ep.signals = append(ep.signals, certEvidence(state.PeerCertificates)...)
	// Over the SAME established TLS connection, read what the service says
	// about itself: the greeting of an implicit-TLS mail port, otherwise the
	// HTTP response. HTTPS-family ports only; LDAPS/AMQPS/etc. would not
	// answer HTTP. Best-effort — a service that does not speak HTTP just
	// yields no fingerprint, never an error. Probe known HTTP ports always;
	// in deep mode, ANY port we got a TLS cert from, since a deep scan finds
	// HTTP on arbitrary ports (8444, 7443, …) the catalogue would never list.
	// Both reads are deadline-bounded, so a non-HTTP TLS service (LDAPS) just
	// yields no fingerprint rather than hanging. Neither opens a connection.
	switch {
	case len(ep.Certs) == 0:
	case (s.config.ActiveProbes || s.config.Deep) && isLDAPImplicitTLS(proto):
		ep.signals = append(ep.signals, implicitLDAPRootDSE(conn, s.config.Timeout)...)
	case isMailImplicitTLS(proto):
		ep.signals = append(ep.signals, greetingEvidence(conn, proto, s.config.Timeout)...)
	case isHTTPPort(port) || s.config.Deep:
		tech, ev := probeHTTP(conn, host, port, s.config.Timeout)
		if tech != "" {
			ep.ServerTech = tech
		}
		ep.signals = append(ep.signals, ev...)
	}
	// Record the on-the-wire crypto posture from THIS handshake (free) —
	// including whether ML-KEM was actually negotiated. A deep scan also
	// enumerates the offered TLS versions and probes for ML-KEM support
	// (extra handshakes, so gated to the slow mode).
	posture := PostureFromState(host, port, state)
	if s.config.Deep && len(ep.Certs) > 0 {
		ep.signals = append(ep.signals, probeTLSStack(context.Background(), host, port, s.config.Timeout)...)
	}
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

func isLDAPImplicitTLS(protocol string) bool { return protocol == "ldaps" || protocol == "ldaps-gc" }

// implicitLDAPRootDSE runs the rootDSE read over the already-established LDAPS
// connection. The ldap connection is closed afterwards; the underlying TLS
// connection is closed by the caller as well, which is harmless.
func implicitLDAPRootDSE(conn net.Conn, timeout time.Duration) []Evidence {
	lc := ldap.NewConn(conn, true)
	lc.Start()
	defer lc.Close()
	return rootDSEEvidence(lc, timeout)
}

// isHTTPPort reports whether a port is expected to speak HTTP over its TLS
// layer (so a Server-header probe is worthwhile).
func isHTTPPort(port int) bool {
	switch port {
	case 443, 8443, 4443, 9443, 10443, 6443, 5986:
		return true
	default:
		return false
	}
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
		return classifyServerValue(strings.ToLower(strings.TrimSpace(line[len("server:"):])))
	}
	// Some servers (notably hardened IIS) suppress the Server header but
	// still leak identity elsewhere; a couple of cheap tells.
	if strings.Contains(lower, "x-aspnet-version") || strings.Contains(lower, "x-powered-by: asp.net") {
		return "iis"
	}
	return ""
}

// classifyServerValue maps a lower-cased Server header value to a technology
// tag, or its first token when unrecognised.
func classifyServerValue(val string) string {
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
		_, portStr, err := net.SplitHostPort(t)
		if err == nil && portStr != "" {
			out = append(out, t) // explicitly pinned port — honor it
			continue
		}
		host := t
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
	adcs := ParseADCS(cert)
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
		IssuedByADCS:       adcs.IssuedByADCS,
		ADCSTemplate:       adcs.TemplateName,
	}
}

func computeCertRisk(cert *x509.Certificate, scannedHost string, isLeaf bool) (int, []string) {
	score := 0
	var flags []string
	now := time.Now()

	// Self-signed leaf: the cert a server presents for its own endpoint that
	// vouches only for itself -- a default IIS/localhost/`openssl req -x509`
	// cert. IsCA is deliberately NOT consulted: openssl stamps basicConstraints
	// CA:TRUE on every self-signed cert it makes, so exempting CAs hid the
	// commonest throwaway cert there is. A self-signed ROOT further up a served
	// chain (isLeaf=false) is a trust anchor and stays unflagged.
	if isLeaf && isSelfSigned(cert) {
		score += 30
		flags = append(flags, "SELF_SIGNED")
	}

	if isLeaf && hostnameMismatch(cert, scannedHost) {
		score += 20
		flags = append(flags, FlagHostnameMismatch)
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

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.MD5WithRSA, x509.MD2WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		score += 30
		flags = append(flags, "WEAK_SIGNATURE")
	}

	if score > 100 {
		score = 100
	}
	return score, flags
}

// isSelfSigned reports subject == issuer AND a signature that verifies under
// the cert's own public key. Matching names alone is only a claim, and
// CheckSignatureFrom would also demand CA bits and KeyUsage -- the same trap
// as the old IsCA exemption. An unverifiable algorithm reads as not
// self-signed: flagging what cannot be proven would be a false finding.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytesEqualName(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// hostnameMismatch reports whether cert fails to vouch for the address it was
// scanned at. A cert is immutable but the scan target is not, so the verdict
// must only reflect what the target can prove: an IP literal says nothing
// about DNS names, so a DNS-only cert reached by IP (every CIDR/full sweep)
// is not a mismatch. IP targets are judged only when the cert carries IP SANs,
// where a miss is a genuine mismatch. This also keeps the shared certificate
// row's risk from flapping with which kind of scan ran last.
func hostnameMismatch(cert *x509.Certificate, scannedHost string) bool {
	host := strings.TrimSpace(scannedHost)
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if len(cert.IPAddresses) == 0 {
			return false
		}
		host = addr.Unmap().String()
	}
	return cert.VerifyHostname(host) != nil
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
	case 0x0300:
		return "SSLv3"
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
