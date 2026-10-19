// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"kryptkeeper/internal/agentdiscovery"
	"kryptkeeper/internal/discovery/scanner"
	"kryptkeeper/internal/logging"
)

// Endpoint-scoped facts live on the certificate_endpoints link, not on the
// shared certificates row. One certificate can be served on several endpoints:
// it may match the name on one and not another, or ship with its intermediate
// here and without it there. Stored on the certificate, those verdicts flipped
// with whichever endpoint was scanned last. On the link they cannot.
//
// The link carries: endpoint_flags (JSON array of scanner.EndpointFlags),
// endpoint_risk_score (the summed weight of those flags, so the risky rule can
// add it to the certificate's own score in SQL), and chain_complete /
// chain_trusted (NULL = never judged for this endpoint).

// linkState is one certificate_endpoints row's endpoint-scoped facts.
type linkState struct {
	Flags    []string
	Score    int
	Complete sql.NullBool
	Trusted  sql.NullBool
}

// chainFlagSet are the flags a chain classification owns; HOSTNAME_MISMATCH is
// owned by the TLS handshake itself.
var chainFlagSet = []string{scanner.FlagIncompleteChain, scanner.FlagUntrustedRoot}

// linkStateFromScan derives the link facts a scan observed for cert, merged
// over existing (nil when the link is new). The hostname verdict is judged by
// the scanner for the very name this endpoint was reached at, so every
// sighting is authoritative for it. The chain verdict is authoritative only
// when the chain was classified: a sighting that carries none (WinRM, mesh, a
// scan whose trust anchors were unavailable) changes nothing it did not
// observe, so it cannot erase a verdict an earlier scan of this endpoint
// established.
func linkStateFromScan(cert scanner.DiscoveredCert, existing *linkState) linkState {
	_, scanFlags, _ := scanner.SplitEndpointFlags(cert.RiskFlags)
	classified := cert.TrustClass != ""

	var prev linkState
	if existing != nil {
		prev = *existing
	}
	var flags []string
	for _, f := range prev.Flags {
		if slices.Contains(chainFlagSet, f) && !classified {
			flags = append(flags, f)
		}
	}
	for _, f := range scanFlags {
		if (!slices.Contains(chainFlagSet, f) || classified) && !slices.Contains(flags, f) {
			flags = append(flags, f)
		}
	}

	out := linkState{Flags: flags, Complete: prev.Complete, Trusted: prev.Trusted}
	if classified {
		out.Complete = sql.NullBool{Bool: cert.ChainComplete, Valid: cert.ChainCompleteKnown}
		out.Trusted = sql.NullBool{Bool: cert.ChainTrusted, Valid: true}
	}
	for _, f := range flags {
		out.Score += scanner.EndpointFlagScore(f)
	}
	return out
}

// loadLinkState reads the link's current endpoint facts; nil when absent.
// query takes (fingerprint, endpointID) in the dialect's placeholder style.
func loadLinkState(ctx context.Context, tx *sql.Tx, query, fingerprint, endpointID string) (*linkState, error) {
	var flagsText string
	var st linkState
	err := tx.QueryRowContext(ctx, query, fingerprint, endpointID).Scan(&flagsText, &st.Complete, &st.Trusted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read link state %s/%s: %w", fingerprint, endpointID, err)
	}
	st.Flags = parseRiskFlagsText(flagsText)
	return &st, nil
}

// linkArgs renders a linkState as the trailing arguments of the link upsert:
// endpoint_flags, endpoint_risk_score, chain_complete, chain_trusted.
func linkArgs(st linkState, postgres bool) []any {
	flags := st.Flags
	if flags == nil {
		flags = []string{}
	}
	b, _ := json.Marshal(flags) // []string always marshals
	nullable := func(v sql.NullBool) any {
		if !v.Valid {
			return nil
		}
		return boolArg(v.Bool, postgres)
	}
	return []any{string(b), st.Score, nullable(st.Complete), nullable(st.Trusted)}
}

const (
	selectLinkStateSQLite   = `SELECT COALESCE(endpoint_flags, '[]'), chain_complete, chain_trusted FROM certificate_endpoints WHERE certificate_fingerprint = ? AND endpoint_id = ?`
	selectLinkStatePostgres = `SELECT COALESCE(endpoint_flags, '[]'), chain_complete, chain_trusted FROM certificate_endpoints WHERE certificate_fingerprint = $1 AND endpoint_id = $2`

	upsertLinkSQLite = `
INSERT INTO certificate_endpoints (certificate_fingerprint, endpoint_id, first_seen, last_seen, currently_active, endpoint_flags, endpoint_risk_score, chain_complete, chain_trusted, source_path)
VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
ON CONFLICT (certificate_fingerprint, endpoint_id) DO UPDATE SET
    last_seen = excluded.last_seen, currently_active = 1,
    endpoint_flags = excluded.endpoint_flags, endpoint_risk_score = excluded.endpoint_risk_score,
    chain_complete = excluded.chain_complete, chain_trusted = excluded.chain_trusted,
    source_path = COALESCE(excluded.source_path, certificate_endpoints.source_path)
`
	upsertLinkPostgres = `
INSERT INTO certificate_endpoints (certificate_fingerprint, endpoint_id, first_seen, last_seen, currently_active, endpoint_flags, endpoint_risk_score, chain_complete, chain_trusted, source_path)
VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8, $9)
ON CONFLICT (certificate_fingerprint, endpoint_id) DO UPDATE SET
    last_seen = excluded.last_seen, currently_active = true,
    endpoint_flags = excluded.endpoint_flags, endpoint_risk_score = excluded.endpoint_risk_score,
    chain_complete = excluded.chain_complete, chain_trusted = excluded.chain_trusted,
    source_path = COALESCE(excluded.source_path, certificate_endpoints.source_path)
`
)

// upsertCertificateLink writes one (certificate, endpoint) mapping and its
// endpoint-scoped facts. now is the dialect's timestamp argument.
func upsertCertificateLink(ctx context.Context, tx *sql.Tx, postgres bool, cert scanner.DiscoveredCert, endpointID string, now any) error {
	selectSQL, upsertSQL := selectLinkStateSQLite, upsertLinkSQLite
	if postgres {
		selectSQL, upsertSQL = selectLinkStatePostgres, upsertLinkPostgres
	}
	existing, err := loadLinkState(ctx, tx, selectSQL, cert.Fingerprint, endpointID)
	if err != nil {
		return err
	}
	args := append([]any{cert.Fingerprint, endpointID, now, now}, linkArgs(linkStateFromScan(cert, existing), postgres)...)
	// A network re-scan has no path: COALESCE in the upsert keeps what an SSH
	// scan recorded.
	args = append(args, nullString(cert.SourcePath))
	if _, err := tx.ExecContext(ctx, upsertSQL, args...); err != nil {
		return fmt.Errorf("upsert certificate_endpoints %s/%s: %w", cert.Fingerprint, endpointID, err)
	}
	return nil
}

// mergeLinkFlags returns the certificate's own flags (with any endpoint-scoped
// flag a pre-link-era row still carries stripped) followed by the link's.
func mergeLinkFlags(certFlags, linkFlags []string) []string {
	own, _, _ := scanner.SplitEndpointFlags(certFlags)
	for _, f := range linkFlags {
		if !slices.Contains(own, f) {
			own = append(own, f)
		}
	}
	return own
}

// Listener correlation (W34-07). A host scan knows which process holds a port;
// the network scan knows what answered on it. The two meet on host:port, and
// the listener row is the only evidence heavy enough to make a fingerprint
// high confidence. The join is an exact string match on the scanned host
// (ip_address or hostname) with no DNS: a target registered by name does not
// match an endpoint scanned by IP, and the listener row is simply not applied.

// withoutListenerRows returns ev minus its listener rows.
func withoutListenerRows(ev []scanner.Evidence) []scanner.Evidence {
	out := make([]scanner.Evidence, 0, len(ev))
	for _, e := range ev {
		if e.Signal != scanner.SignalListener {
			out = append(out, e)
		}
	}
	return out
}

// listenerRows returns the listener rows of ev.
func listenerRows(ev []scanner.Evidence) []scanner.Evidence {
	var out []scanner.Evidence
	for _, e := range ev {
		if e.Signal == scanner.SignalListener {
			out = append(out, e)
		}
	}
	return out
}

// singleRowQuerier is the QueryRowContext both *sql.DB and *sql.Tx offer; the carry
// runs inside the upsert transaction, where a second connection would stall a
// single-connection SQLite pool.
type singleRowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// carryListenerEvidence keeps what an earlier host scan learned about this
// endpoint across a network rescan, whose own evidence has no listener rows.
// Without it every rescan would demote a high-confidence fingerprint until the
// next SSH scan.
func carryListenerEvidence(ctx context.Context, db singleRowQuerier, postgres bool, tenant string, ep scanner.DiscoveredEndpoint) scanner.DiscoveredEndpoint {
	if ep.Fingerprint == nil {
		return ep
	}
	q := `SELECT COALESCE(tech_evidence, '') FROM endpoints WHERE tenant = ? AND ip_address = ? AND port = ? AND sni_name = ?`
	if postgres {
		q = rebindPostgres(q)
	}
	var raw string
	if err := db.QueryRowContext(ctx, q, tenant, ep.Host, ep.Port, ep.Host).Scan(&raw); err != nil {
		return ep
	}
	carried := listenerRows(scanner.ParseEvidenceJSON(raw))
	if len(carried) == 0 {
		return ep
	}
	fp := scanner.Resolve(append(withoutListenerRows(ep.Fingerprint.Evidence), carried...))
	ep.Fingerprint = &fp
	if scanner.IsWebServerTech(fp.Tech) {
		ep.ServerTech = fp.Tech
	}
	return ep
}

// applyListenerEvidence merges a host scan's listener rows into the network
// endpoints on that host. Ports the sweep no longer sees lose their listener
// rows; endpoints are never created here, so a row the network scan wrote
// keeps its issues, protocol and posture untouched.
func applyListenerEvidence(ctx context.Context, db *sql.DB, postgres bool, tenant, host string, obs *scanner.HostObservations) error {
	if obs == nil || !obs.ListenersScanned {
		return nil
	}
	active := "1"
	if postgres {
		active = "true"
	}
	sel := `SELECT e.id, e.port, e.protocol, COALESCE(e.tech_evidence, ''),
       (SELECT COUNT(*) FROM certificate_endpoints ce WHERE ce.endpoint_id = e.id AND ce.currently_active = ` + active + `)
FROM endpoints e WHERE e.tenant = ? AND (e.ip_address = ? OR e.hostname = ?) AND e.port > 0`
	upd := `UPDATE endpoints SET tech = ?, tech_confidence = ?, platform = ?, tls_stack = ?, tech_evidence = ?,
       server_tech = COALESCE(?, server_tech), recommended_install_mode = COALESCE(?, recommended_install_mode)
WHERE id = ?`
	if postgres {
		sel, upd = rebindPostgres(sel), rebindPostgres(upd)
	}

	type row struct {
		id, protocol, raw string
		port, certs       int
	}
	rows, err := db.QueryContext(ctx, sel, tenant, host, host)
	if err != nil {
		return fmt.Errorf("list endpoints of %s: %w", host, err)
	}
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.port, &r.protocol, &r.raw, &r.certs); err != nil {
			rows.Close()
			return err
		}
		found = append(found, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	byPort := map[int][]scanner.Evidence{}
	for _, pe := range obs.Listeners {
		byPort[pe.Port] = append(byPort[pe.Port], pe.Evidence)
	}
	for _, r := range found {
		prev := scanner.ParseEvidenceJSON(r.raw)
		next := append(withoutListenerRows(prev), byPort[r.port]...)
		if len(listenerRows(prev)) == 0 && len(byPort[r.port]) == 0 {
			continue
		}
		fp := scanner.Resolve(next)
		var serverTech, mode any
		if scanner.IsWebServerTech(fp.Tech) {
			serverTech = fp.Tech
		}
		if r.certs > 0 {
			if m := scanner.RecommendedInstallMode(fp, r.protocol); m != "" {
				mode = m
			}
		}
		if _, err := db.ExecContext(ctx, upd, fp.Tech, fp.Confidence, fp.Platform, fp.TLSStack,
			nullString(scanner.EvidenceJSON(fp.Evidence)), serverTech, mode, r.id); err != nil {
			return fmt.Errorf("apply listener evidence %s:%d: %w", host, r.port, err)
		}
	}
	return nil
}

// listenerPortEvidence turns a sweep into the rows the join applies: one per
// (port, technology), so a master and its workers vote once. A plain java
// process names no product but still votes for the java platform.
func listenerPortEvidence(listeners []agentdiscovery.Listener) []scanner.PortEvidence {
	type key struct {
		port int
		tech string
	}
	seen := map[key]bool{}
	var out []scanner.PortEvidence
	for _, l := range listeners {
		tech, platform := l.Tech, ""
		if tech == "" {
			if l.Comm != "java" {
				continue
			}
			platform = scanner.PlatformJava
		}
		k := key{l.Port, tech}
		if seen[k] {
			continue
		}
		seen[k] = true
		value := strings.TrimSpace(l.Comm + " " + l.Exe)
		out = append(out, scanner.PortEvidence{Port: l.Port, Evidence: scanner.ListenerEvidence(value, tech, platform, !l.UIDKnown())})
	}
	return out
}

// applyHostObservations applies what host-side scans in results learned about
// the rest of the estate. It runs after the endpoint rows are committed and
// never fails the scan: a join that cannot be written is logged and the
// network-scan result stands.
func applyHostObservations(ctx context.Context, db *sql.DB, postgres bool, results []scanner.DiscoveredEndpoint) {
	tenant := discoveryStampTenant(ctx)
	for _, ep := range results {
		if ep.HostObs == nil {
			continue
		}
		if err := applyListenerEvidence(ctx, db, postgres, tenant, ep.Host, ep.HostObs); err != nil {
			logging.Warnf("host observations %s: %v", ep.Host, err)
		}
		if err := persistHostFiles(ctx, db, postgres, tenant, ep.Host, ep.HostObs); err != nil {
			logging.Warnf("host files %s: %v", ep.Host, err)
		}
		recordTargetScanState(ctx, db, postgres, ep.HostObs)
	}
}
