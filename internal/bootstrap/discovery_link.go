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

	"kryptkeeper/internal/discovery/scanner"
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
INSERT INTO certificate_endpoints (certificate_fingerprint, endpoint_id, first_seen, last_seen, currently_active, endpoint_flags, endpoint_risk_score, chain_complete, chain_trusted)
VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
ON CONFLICT (certificate_fingerprint, endpoint_id) DO UPDATE SET
    last_seen = excluded.last_seen, currently_active = 1,
    endpoint_flags = excluded.endpoint_flags, endpoint_risk_score = excluded.endpoint_risk_score,
    chain_complete = excluded.chain_complete, chain_trusted = excluded.chain_trusted
`
	upsertLinkPostgres = `
INSERT INTO certificate_endpoints (certificate_fingerprint, endpoint_id, first_seen, last_seen, currently_active, endpoint_flags, endpoint_risk_score, chain_complete, chain_trusted)
VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8)
ON CONFLICT (certificate_fingerprint, endpoint_id) DO UPDATE SET
    last_seen = excluded.last_seen, currently_active = true,
    endpoint_flags = excluded.endpoint_flags, endpoint_risk_score = excluded.endpoint_risk_score,
    chain_complete = excluded.chain_complete, chain_trusted = excluded.chain_trusted
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
