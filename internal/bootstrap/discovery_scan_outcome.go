// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"kryptkeeper/internal/discovery/scanner"
)

const (
	scanStatusCompleted           = "completed"
	scanStatusCompletedWithErrors = "completed_with_errors"
	scanStatusFailed              = "failed"
)

// endpointNeverReached is the "closed or filtered port" rule: a real
// network endpoint (Port != 0) that errored without ever accepting a TCP
// connection is not recorded. A range scan probes dozens of ports per host and
// nearly all are closed, so recording them would flood the inventory.
func endpointNeverReached(ep scanner.DiscoveredEndpoint) bool {
	return ep.Error != "" && ep.Port != 0 && !ep.Reachable
}

// endpointIssuesJSON picks what lands in endpoints.issues: a port-less
// source's discovery error, an endpoint's own findings (NOT_TLS,
// TLS_HANDSHAKE_FAILED, DEPRECATED_TLS_VERSION), or cipheraudit's issues for
// an endpoint that completed a normal handshake.
func endpointIssuesJSON(ep scanner.DiscoveredEndpoint, audited string) string {
	switch {
	case ep.Error != "" && ep.Port == 0:
		return discoveryErrorIssuesJSON(ep.Error)
	case len(ep.Findings) > 0:
		b, err := json.Marshal(ep.Findings)
		if err != nil {
			return "[]"
		}
		return string(b)
	default:
		return audited
	}
}

// endpointCertsObserved reports whether a scan learned enough about an
// endpoint's certificates for an unobserved mapping to count as gone. Plain
// text on a TLS port means the certificate really is no longer served. A
// failed handshake or a legacy-only server we could not read a certificate
// from proves nothing about the certificate, so its mappings are left alone
// (a transient failure must not mark a healthy certificate gone).
func endpointCertsObserved(ep scanner.DiscoveredEndpoint) bool {
	if scanner.HasFinding(ep.Findings, scanner.FindingNotTLS) {
		return true
	}
	if ep.Error != "" {
		return false
	}
	return len(ep.Certs) > 0 || len(ep.Findings) == 0
}

// scanJobOutcome maps a finished scan and its persist outcome onto the
// scan_jobs row: the status, and a message that explains it.
func scanJobOutcome(result *scanner.ScanResult, out upsertOutcome, persistErr error) (status, msg string) {
	if persistErr != nil {
		return scanStatusFailed, truncateScanError(persistErr)
	}
	status = scanStatusCompleted
	switch result.Status {
	case "", scanStatusCompleted:
	case scanStatusCompletedWithErrors:
		status = scanStatusCompletedWithErrors
		msg = reachableFailureSummary(result)
	default:
		status = scanStatusFailed
		msg = unreachableSummary(result)
	}
	if skip := summarizeUpsertSkips(out); skip != "" {
		if msg != "" {
			msg += "; "
		}
		msg += skip
	}
	if msg == "" {
		return status, ""
	}
	return status, truncateScanError(errors.New(msg))
}

// endpointAddr renders host:port, or just the host for a port-less source.
func endpointAddr(ep scanner.DiscoveredEndpoint) string {
	if ep.Port == 0 {
		return ep.Host
	}
	return net.JoinHostPort(ep.Host, fmt.Sprint(ep.Port))
}

// portRank orders a host's ports so the one an operator actually asked about
// leads: 443 first, then ascending. A targeted scan of a bare host probes the
// whole catalogue concurrently, so "first error seen" named whichever of
// 5986/465/... happened to finish first.
func portRank(port int) int {
	if port == 443 {
		return 0
	}
	return port
}

func sortEndpoints(eps []scanner.DiscoveredEndpoint) {
	slices.SortFunc(eps, func(a, b scanner.DiscoveredEndpoint) int {
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return portRank(a.Port) - portRank(b.Port)
	})
}

// unreachableSummary explains a scan that reached nothing, naming one
// deterministic endpoint (see portRank) rather than a random one.
func unreachableSummary(result *scanner.ScanResult) string {
	var failed []scanner.DiscoveredEndpoint
	for _, ep := range result.Endpoints {
		if ep.Error != "" {
			failed = append(failed, ep)
		}
	}
	if len(failed) == 0 {
		return "scan failed without a reported reason"
	}
	sortEndpoints(failed)
	first := failed[0]
	msg := first.Error
	if addr := endpointAddr(first); addr != "" {
		msg = addr + ": " + msg
	}
	if len(failed) > 1 {
		msg = fmt.Sprintf("nothing answered on %d probed ports; first: %s", len(failed), msg)
	}
	return msg
}

// reachableFailureSummary lists the endpoints that answered but could not be
// read (plain HTTP, a failed handshake) and how many ports were closed.
func reachableFailureSummary(result *scanner.ScanResult) string {
	var open []scanner.DiscoveredEndpoint
	for _, ep := range result.Endpoints {
		if ep.Error != "" && ep.Reachable {
			open = append(open, ep)
		}
	}
	sortEndpoints(open)
	const listed = 3
	parts := make([]string, 0, listed)
	for _, ep := range open {
		if len(parts) == listed {
			break
		}
		part := endpointAddr(ep)
		if len(ep.Findings) > 0 {
			part += " " + scanner.FindingCode(ep.Findings[0])
		}
		parts = append(parts, part)
	}
	msg := fmt.Sprintf("%d endpoint(s) answered but failed", len(open))
	if len(parts) > 0 {
		msg += " (" + strings.Join(parts, ", ")
		if len(open) > listed {
			msg += fmt.Sprintf(", +%d more", len(open)-listed)
		}
		msg += ")"
	}
	if result.Unreachable > 0 {
		msg += fmt.Sprintf("; %d closed or filtered port(s) not recorded", result.Unreachable)
	}
	return msg
}
