// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"log"
	"strings"
	"time"
)

// defaultDiscoveryRefreshEvery bounds how often a read re-queries the
// certificates table for discovery-written rows. Short enough that a scan's
// results show up as soon as the operator reloads, long enough that a busy
// list endpoint costs at most one cheap query per interval.
const defaultDiscoveryRefreshEvery = 2 * time.Second

// discoveryEpoch is the watermark before any discovery row has been seen. It
// is a valid timestamp for both the sqlite text comparison and Postgres
// timestamptz, which an empty string would not be.
const discoveryEpoch = "1970-01-01T00:00:00Z"

func isDiscoverySource(source string) bool {
	return strings.HasPrefix(source, "discovery")
}

// refreshDiscovered merges certificates that discovery wrote to the shared
// table after this provider hydrated. The inventory used to be loaded once in
// the constructor, so a scan's certificates stayed invisible until the next
// restart even though the dashboard (which reads the table) counted them.
//
// Design: pull rather than push. Discovery runs through its own store (from
// env, ~20 zero-arg call sites) and other writers (agents, WinRM, mesh) feed
// the same table, so a lazy updated_at watermark covers every discovery source
// without threading a callback through every constructor or adding a global.
//
// Only unmanaged/external discovery rows are merged. A managed row is owned by
// this provider's own write-through cache and must never be replaced by a
// table read, so the managed state is also what keeps discovery from ever
// promoting or demoting a certificate in memory.
func (p *caCertificateProvider) refreshDiscovered() {
	if p.db == nil || p.hydrateErr != nil {
		return
	}
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if p.discoveryRefreshEvery > 0 && time.Since(p.lastDiscoveryRefresh) < p.discoveryRefreshEvery {
		return
	}
	p.lastDiscoveryRefresh = time.Now()

	watermark := p.discoveryWatermark
	if watermark == "" {
		watermark = discoveryEpoch
	}
	placeholder := "?"
	if p.postgres {
		placeholder = "$1"
	}
	// >= (not >): rows written in the same instant as the watermark must not
	// be skipped; re-merging an identical row is idempotent.
	loaded, err := p.queryCerts(
		" WHERE source LIKE 'discovery%' AND management_state <> 'managed' AND updated_at >= "+placeholder,
		watermark)
	if err != nil {
		log.Printf("certificate provider: discovery refresh failed (serving the last good inventory): %v", err)
		return
	}
	if len(loaded) == 0 {
		return
	}

	p.mu.Lock()
	for _, sc := range loaded {
		fp := sc.item.FingerprintSHA256
		if existing, ok := p.certs[fp]; ok {
			if existing.item.ManagementState == "managed" {
				continue
			}
			sc.item.ETag = existing.item.ETag
		}
		p.addLocked(fp, sc)
	}
	p.mu.Unlock()
	for _, sc := range loaded {
		p.flagKeyReuse(sc.item.FingerprintSHA256)
	}
	p.noteDiscoveryWatermark(loaded)
}

// noteDiscoveryWatermark advances the watermark to the newest discovery row
// among loaded. Safe to call without refreshMu only from the constructor,
// before the provider is shared.
func (p *caCertificateProvider) noteDiscoveryWatermark(loaded []*storedCert) {
	for _, sc := range loaded {
		if isDiscoverySource(sc.item.Source) && sc.item.UpdatedAt > p.discoveryWatermark {
			p.discoveryWatermark = sc.item.UpdatedAt
		}
	}
}
