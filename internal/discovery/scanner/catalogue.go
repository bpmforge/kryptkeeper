// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

// probeKind is how a port is inspected. Every kind either yields an X.509
// certificate or, for SSH, host-key material — the two things this product
// tracks.
type probeKind int

const (
	probeTLS      probeKind = iota // implicit TLS: dial TLS immediately
	probeSTARTTLS                  // line/binary protocol that upgrades to TLS
	probeSSH                       // SSH: banner + host-key algorithms, no cert
	probeRDP                       // RDP: X.224 negotiation, then TLS
)

// scanTier bounds which breadths include a port. fast ⊂ targeted ⊂ full.
type scanTier int

const (
	tierFast     scanTier = iota // the one standard port per protocol
	tierTargeted                 // + common alternates
	tierFull                     // + the long tail
)

// protocolEntry is one known certificate/key-bearing port.
type protocolEntry struct {
	port     int
	protocol string    // the tag recorded on the endpoint
	kind     probeKind // how to inspect it
	starttls string    // ScanSTARTTLS protocol arg (probeSTARTTLS only)
	tier     scanTier  // smallest breadth that includes it
}

// certProtocolCatalogue is the single source of truth for what a network
// scan inspects. "Known protocols that use certs" plus SSH for keys — the
// tiers derive from it so fast/targeted/full never drift out of sync, and
// protocolForPort classifies a custom port by looking here first.
//
// STARTTLS ports are FIRST-CLASS here (unlike the plain scanner, which
// could only dial implicit TLS): a mail or Postgres cert hiding behind a
// plaintext preamble is now reachable.
var certProtocolCatalogue = []protocolEntry{
	// HTTPS and its common alternates.
	{443, "https", probeTLS, "", tierFast},
	{8443, "https-alt", probeTLS, "", tierTargeted},
	{4443, "https-alt", probeTLS, "", tierFull},
	{9443, "https-alt", probeTLS, "", tierFull},
	{10443, "https-alt", probeTLS, "", tierFull},
	{6443, "kubernetes-api", probeTLS, "", tierFull},

	// SSH — host keys, not certs. In fast because "keys" was explicitly asked for.
	{22, "ssh", probeSSH, "", tierFast},

	// Directory.
	{636, "ldaps", probeTLS, "", tierFast},
	{3269, "ldaps-gc", probeTLS, "", tierFull},

	// Mail — implicit TLS and STARTTLS both.
	{993, "imaps", probeTLS, "", tierFast},
	{995, "pop3s", probeTLS, "", tierTargeted},
	{465, "smtps", probeTLS, "", tierFast},
	{25, "smtp", probeSTARTTLS, "smtp", tierTargeted},
	{587, "smtp-submission", probeSTARTTLS, "smtp", tierTargeted},
	{143, "imap", probeSTARTTLS, "imap", tierFull},
	{110, "pop3", probeSTARTTLS, "pop3", tierFull},

	// Databases with a STARTTLS-style upgrade.
	{5432, "postgres", probeSTARTTLS, "postgres", tierTargeted},

	// Remote access and management.
	{3389, "rdp", probeRDP, "", tierFast},
	{5986, "winrm-https", probeTLS, "", tierFast},

	// Infrastructure and brokers.
	{2379, "etcd", probeTLS, "", tierFull},
	{2380, "etcd-peer", probeTLS, "", tierFull},
	{5671, "amqps", probeTLS, "", tierFull},
	{8883, "mqtts", probeTLS, "", tierFull},
}

// catalogueByPort indexes the catalogue for O(1) classification.
var catalogueByPort = func() map[int]protocolEntry {
	m := make(map[int]protocolEntry, len(certProtocolCatalogue))
	for _, e := range certProtocolCatalogue {
		m[e.port] = e
	}
	return m
}()

// protocolForPort classifies a port. A port not in the catalogue — a
// custom port an org standardized on — is treated as implicit TLS, the
// most likely shape for a cert-bearing service and a safe default (a plain
// TLS dial against a non-TLS service just errors, it does not misreport).
func protocolForPort(port int) protocolEntry {
	if e, ok := catalogueByPort[port]; ok {
		return e
	}
	return protocolEntry{port: port, protocol: "tls", kind: probeTLS}
}

// portsForTier returns the catalogue ports at or below tier, deduplicated
// and in catalogue order (stable).
func portsForTier(tier scanTier) []int {
	seen := make(map[int]bool)
	out := make([]int, 0, len(certProtocolCatalogue))
	for _, e := range certProtocolCatalogue {
		if e.tier <= tier && !seen[e.port] {
			seen[e.port] = true
			out = append(out, e.port)
		}
	}
	return out
}

// PortsForScanType maps a scan_type to its port list. Unknown types fall
// back to the fast tier rather than an empty list, so a scan never
// silently checks zero ports.
func PortsForScanType(scanType string) []int {
	switch scanType {
	case "full", "network", "deep":
		return portsForTier(tierFull)
	case "targeted":
		return portsForTier(tierTargeted)
	default:
		return portsForTier(tierFast)
	}
}
