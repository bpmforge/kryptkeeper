// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// defaultDiscoveryRefreshEvery bounds how often a read re-queries the
// certificates table for rows other writers added or changed. Short enough
// that a peer replica's issuance or a scan's results show up as soon as the
// operator reloads, long enough that a busy list endpoint costs at most one
// cheap query per interval.
const defaultDiscoveryRefreshEvery = 2 * time.Second

// peerClockSkewLookback widens each incremental read below the watermark.
// The watermark is the newest updated_at seen, but a peer replica stamps its
// rows with its own clock (and the sqlite/Postgres defaults use the DB's), so
// a row can land with an updated_at slightly older than one already merged.
// Merging is idempotent, so re-reading a window is cheap insurance.
const peerClockSkewLookback = 30 * time.Second

// discoveryEpoch is the watermark before any row has been seen. It is a valid
// timestamp for both the sqlite text comparison and Postgres timestamptz,
// which an empty string would not be.
const discoveryEpoch = "1970-01-01T00:00:00Z"

func isDiscoverySource(source string) bool {
	return strings.HasPrefix(source, "discovery")
}

// parseRowTime reads an updated_at as stored: RFC 3339 with or without
// fractional seconds (app-written vs the sqlite default / Postgres
// timestamptz), or sqlite's CURRENT_TIMESTAMP shape.
func parseRowTime(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// refreshFromTable merges certificates that other writers added or changed in
// the shared table after this provider hydrated. The inventory used to be
// loaded once in the constructor, so anything written afterwards stayed
// invisible until the next restart. Two kinds of writer exist: discovery
// (scans, agents, WinRM, mesh) and, with more than one hub replica on one
// database, every peer replica's issue / renew / revoke / ownership edit. A
// peer's certificate was missing from this replica's list, from expiry and
// renewal-reminder runs, and from lookups by fingerprint.
//
// Design: pull rather than push. Writers run through their own stores (from
// env, ~20 zero-arg call sites), so a lazy updated_at watermark covers every
// writer without threading a callback through each constructor or adding a
// global.
//
// Which copy wins is decided per row by mergeLocked.
func (p *caCertificateProvider) refreshFromTable() {
	if p.db == nil || p.hydrateErr != nil {
		return
	}
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if p.discoveryRefreshEvery > 0 && time.Since(p.lastTableRefresh) < p.discoveryRefreshEvery {
		return
	}
	p.lastTableRefresh = time.Now()

	since := discoveryEpoch
	if !p.tableWatermark.IsZero() {
		since = p.tableWatermark.Add(-peerClockSkewLookback).UTC().Format(time.RFC3339)
	}
	// >= (not >): rows written in the same instant as the watermark must not
	// be skipped; re-merging an identical row is idempotent.
	loaded, err := p.queryChangedCerts(since)
	if err != nil {
		logging.Warnf("certificate provider: table refresh failed (serving the last good inventory): %v", err)
		return
	}
	if len(loaded) == 0 {
		return
	}
	p.mergeRows(loaded)
	p.noteTableWatermark(loaded)
}

// ensureCertLoaded is the read-through for a fingerprint this replica has not
// merged yet. Behind a load balancer a certificate issued on one replica is
// fetched, downloaded, revoked or renewed on another within milliseconds, far
// inside the refresh throttle, and answering 404 for a certificate that is
// durably recorded would be wrong. It runs a throttled refresh first so a
// known certificate is also current before a mutation is judged against it.
func (p *caCertificateProvider) ensureCertLoaded(fingerprint string) {
	if p.db == nil || p.hydrateErr != nil {
		return
	}
	p.refreshFromTable()
	p.mu.RLock()
	_, ok := p.certs[fingerprint]
	p.mu.RUnlock()
	if ok {
		return
	}
	placeholder := "?"
	if p.postgres {
		placeholder = "$1"
	}
	loaded, err := p.queryCerts(" WHERE fingerprint_sha256 = "+placeholder, fingerprint)
	if err != nil {
		logging.Warnf("certificate provider: read-through for %s failed: %v", fingerprint, err)
		return
	}
	p.mergeRows(loaded)
}

// mergeRows applies loaded rows to memory and re-flags key reuse for the ones
// that changed it.
func (p *caCertificateProvider) mergeRows(loaded []*storedCert) {
	var merged []string
	p.mu.Lock()
	for _, sc := range loaded {
		if p.mergeLocked(sc) {
			merged = append(merged, sc.item.FingerprintSHA256)
		}
	}
	p.mu.Unlock()
	for _, fp := range merged {
		p.flagKeyReuse(fp)
	}
}

// mergeLocked adds or replaces one in-memory certificate from a table row and
// reports whether it did. The indexes stay consistent because it goes through
// addLocked.
func (p *caCertificateProvider) mergeLocked(sc *storedCert) bool {
	fp := sc.item.FingerprintSHA256
	existing, ok := p.certs[fp]
	if ok {
		if !rowSupersedes(&existing.item, &sc.item) {
			return false
		}
		// ETag is a per-replica counter, not row state, so a replaced copy
		// needs a fresh one for If-None-Match to notice the change.
		sc.item.ETag = max(existing.item.ETag, 1) + 1
	}
	p.addLocked(fp, sc)
	return true
}

// rowSupersedes decides whether a table row replaces the in-memory copy.
//   - A discovery-sourced row that does not itself say managed never replaces
//     a managed certificate: a rescan must not demote or promote one. The
//     incoming row's source decides this, not the existing state alone.
//   - A revocation is terminal: a revoked row always replaces an unrevoked
//     copy, because revoke stamps updated_at at one-second resolution (and a
//     peer's clock may lag) so the timestamp alone could hide it.
//   - Otherwise the strictly newer updated_at wins; on a tie the local copy
//     stays, which also makes a replica's echo of its own write a no-op.
func rowSupersedes(existing, incoming *CertificateItem) bool {
	if isDiscoverySource(incoming.Source) && existing.ManagementState == "managed" && incoming.ManagementState != "managed" {
		return false
	}
	if incoming.RevokedAt != nil && existing.RevokedAt == nil {
		return true
	}
	in, inOK := parseRowTime(incoming.UpdatedAt)
	if !inOK {
		return false
	}
	ex, exOK := parseRowTime(existing.UpdatedAt)
	if !exOK {
		return true
	}
	return in.After(ex)
}

// noteTableWatermark advances the watermark to the newest updated_at among
// loaded, whatever wrote the row. Safe to call without refreshMu only from the
// constructor, before the provider is shared.
func (p *caCertificateProvider) noteTableWatermark(loaded []*storedCert) {
	for _, sc := range loaded {
		if t, ok := parseRowTime(sc.item.UpdatedAt); ok && t.After(p.tableWatermark) {
			p.tableWatermark = t
		}
	}
}

// refreshLoadBatch bounds the IN-list of one full-row fetch.
const refreshLoadBatch = 500

// queryChangedCerts returns the full rows updated at or after since that the
// in-memory inventory does not already hold in an equal or newer state.
//
// The window reaches peerClockSkewLookback below the watermark, so after a
// bulk write (an import, a restore, a clone) it covers most of the table and
// every 2 s refresh used to re-read, base64-decode and x509-parse every row
// just for mergeLocked to discard them: ~9 us a row, ~1 s per refresh at 100k
// certificates, all of it under refreshMu and so blocking every list and
// search caller (W30-25), and gigabytes of short-lived garbage (W30-26).
// A narrow (fingerprint, updated_at, revoked) scan decides cheaply which rows
// could win rowSupersedes; only those are fetched in full.
func (p *caCertificateProvider) queryChangedCerts(since string) ([]*storedCert, error) {
	q := `SELECT fingerprint_sha256, updated_at, revoked_at IS NOT NULL FROM certificates WHERE updated_at >= ?`
	notChainCA := " AND COALESCE(is_ca,0) = 0"
	if p.postgres {
		q = `SELECT fingerprint_sha256, updated_at, revoked_at IS NOT NULL FROM certificates WHERE updated_at >= $1`
		notChainCA = " AND NOT COALESCE(is_ca, FALSE)"
	}
	rows, err := p.db.Query(q+notChainCA, since)
	if err != nil {
		return nil, err
	}
	// Drain the narrow scan before touching p.mu. The sqlite pools are
	// MaxOpenConns=1, so an open cursor owns the only connection; UpdateEstate
	// and UpdateOwnership hold p.mu.Lock across their db.Exec, so waiting for
	// p.mu.RLock with the cursor open is a lock-order deadlock (conn -> mu here,
	// mu -> conn there) that wedges every writer until the process restarts.
	type changedRow struct {
		fp        string
		updatedAt string
		revoked   bool
	}
	var scanned []changedRow
	for rows.Next() {
		var r changedRow
		if err := rows.Scan(&r.fp, &r.updatedAt, &r.revoked); err != nil {
			_ = rows.Close()
			return nil, err
		}
		scanned = append(scanned, r)
	}
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}

	var want []string
	p.mu.RLock()
	for _, r := range scanned {
		existing, ok := p.certs[r.fp]
		if !ok || p.rowMayReplace(&existing.item, r.updatedAt, r.revoked) {
			want = append(want, r.fp)
		}
	}
	p.mu.RUnlock()

	var loaded []*storedCert
	for start := 0; start < len(want); start += refreshLoadBatch {
		batch := want[start:min(start+refreshLoadBatch, len(want))]
		marks := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, fp := range batch {
			marks[i] = "?"
			if p.postgres {
				marks[i] = "$" + strconv.Itoa(i+1)
			}
			args[i] = fp
		}
		part, err := p.queryCerts(" WHERE fingerprint_sha256 IN ("+strings.Join(marks, ",")+")", args...)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, part...)
	}
	return loaded, nil
}

// rowMayReplace is the cheap pre-filter for rowSupersedes: false only when
// rowSupersedes would also reject the full row (same or older updated_at and
// no new revocation). It mirrors rowSupersedes' revocation and timestamp
// rules exactly (an unparseable incoming timestamp is rejected there too);
// the managed-vs-discovery rule only rejects more, so it is left to
// rowSupersedes on the full row.
func (p *caCertificateProvider) rowMayReplace(existing *CertificateItem, updatedAt string, revoked bool) bool {
	if revoked && existing.RevokedAt == nil {
		return true
	}
	in, inOK := parseRowTime(updatedAt)
	if !inOK {
		return false
	}
	ex, exOK := parseRowTime(existing.UpdatedAt)
	return !exOK || in.After(ex)
}
