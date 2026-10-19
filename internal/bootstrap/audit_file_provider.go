// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/logging"
)

// fileAuditSyncInterval bounds how long an appended record may sit in the
// page cache before it is fsynced. Every audited request appends, so a sync
// per record would put one fsync (a full flush on macOS) on every API call.
// Each record is handed to the kernel with a single write(2) before
// AppendEntry returns, so a hub crash loses nothing; only an OS crash or power
// loss can lose the last interval's records. The trailing write is covered by
// a one-shot timer, so an idle hub is fully synced within one interval.
const fileAuditSyncInterval = 250 * time.Millisecond

// fileAuditProvider stores the audit trail as JSON Lines: one AuditEntry per
// line, oldest first, append-only. The file is never truncated or rewritten
// after the one-time legacy migration; a damaged line is skipped on read and
// reported, never a reason to discard the rest.
type fileAuditProvider struct {
	filePath     string
	syncInterval time.Duration

	mu          sync.Mutex // guards f, nextID, dirty, syncTimer, needNewline
	f           *os.File
	nextID      int64
	dirty       bool
	syncTimer   *time.Timer
	needNewline bool // a previous write may have left a torn tail

	corruptLines atomic.Int64 // corrupt lines seen (cumulative)
}

// NewFileAuditProviderFromEnv opens the file audit store named by
// APP_AUDIT_FILE (default ./var/bootstrap-audit.json). It fails when the store
// cannot be opened, migrated or written, so the hub can refuse to start
// instead of running without an audit trail.
func NewFileAuditProviderFromEnv() (AuditProvider, error) {
	path := resolveStateFilePath(os.Getenv, "APP_AUDIT_FILE", "bootstrap-audit.json")
	return openFileAuditProvider(path, fileAuditSyncInterval)
}

func openFileAuditProvider(path string, syncInterval time.Duration) (*fileAuditProvider, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("audit file %q: create directory: %w", path, err)
	}
	if err := migrateLegacyAuditFile(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit file %q: open for append: %w", path, err)
	}
	p := &fileAuditProvider{filePath: path, syncInterval: syncInterval, f: f}
	maxID, endsClean, err := scanAuditFile(path, func(AuditEntry) {}, &p.corruptLines)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit file %q: read: %w", path, err)
	}
	p.nextID = maxID + 1
	p.needNewline = !endsClean
	if n := p.corruptLines.Load(); n > 0 {
		logging.Infof("audit file %q: %d unreadable line(s) skipped; the remaining records are intact", path, n)
	}
	return p, nil
}

// migrateLegacyAuditFile converts the pre-0.9 format (one JSON array, newest
// first) to JSON Lines, oldest first. The converted copy is fsynced before it
// replaces the original by rename, and the original bytes are kept as
// <path>.bak. Anything that is not a JSON array is left alone.
func migrateLegacyAuditFile(path string) error {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit file %q: read: %w", path, err)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil
	}
	var legacy []AuditEntry
	if err := json.Unmarshal(trimmed, &legacy); err != nil {
		return fmt.Errorf("audit file %q is in the legacy JSON-array format but cannot be parsed (%v); refusing to start rather than discard it: move it aside and restart to begin a new trail", path, err)
	}
	var out bytes.Buffer
	for i := len(legacy) - 1; i >= 0; i-- { // legacy files are newest first
		line, err := json.Marshal(legacy[i])
		if err != nil {
			return fmt.Errorf("audit file %q: migrate entry: %w", path, err)
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	bak := path + ".bak"
	if _, err := os.Stat(bak); err == nil {
		bak = fmt.Sprintf("%s.%d.bak", path, time.Now().UnixNano())
	}
	if err := writeFileSynced(bak, body); err != nil {
		return fmt.Errorf("audit file %q: write backup: %w", path, err)
	}
	tmp := path + ".migrating"
	if err := writeFileSynced(tmp, out.Bytes()); err != nil {
		return fmt.Errorf("audit file %q: write migrated copy: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("audit file %q: replace with migrated copy: %w", path, err)
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		if serr := d.Sync(); serr != nil {
			logging.Warnf("audit file %q: directory sync after migration failed: %v", path, serr)
		}
		_ = d.Close()
	}
	logging.Infof("audit file %q: migrated %d legacy records to JSON Lines (original kept as %q)", path, len(legacy), bak)
	return nil
}

func writeFileSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// scanAuditFile streams the file line by line. A terminated line that does not
// parse is counted in corrupt and skipped. A final line with no newline is an
// append in flight (or a torn tail): it is used if it parses and otherwise
// ignored without counting. It returns the highest ID seen and whether the
// file ends on a line boundary.
func scanAuditFile(path string, fn func(AuditEntry), corrupt *atomic.Int64) (maxID int64, endsClean bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, true, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	endsClean = true
	for {
		line, rerr := r.ReadBytes('\n')
		terminated := rerr == nil
		if len(line) > 0 {
			endsClean = terminated
			if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
				var e AuditEntry
				if jerr := json.Unmarshal(trimmed, &e); jerr != nil {
					if terminated {
						corrupt.Add(1)
					}
				} else {
					if e.ID > maxID {
						maxID = e.ID
					}
					fn(e)
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return maxID, endsClean, nil
			}
			return maxID, endsClean, rerr
		}
	}
}

func (p *fileAuditProvider) ListEntries(_ context.Context, query AuditListQuery) (AuditListResult, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	order := query.Order
	if order == "" {
		order = "desc"
	}

	var filtered []AuditEntry
	var corrupt atomic.Int64
	_, _, err := scanAuditFile(p.filePath, func(entry AuditEntry) {
		if query.Action != "" && entry.Action != query.Action {
			return
		}
		if query.ActionPrefix != "" && entry.Action != query.ActionPrefix && !strings.HasPrefix(entry.Action, query.ActionPrefix+".") {
			return
		}
		if query.ActorType != "" && entry.ActorType != query.ActorType {
			return
		}
		if query.ActorID != "" && entry.ActorID != query.ActorID {
			return
		}
		if query.ResourceType != "" && entry.ResourceType != query.ResourceType {
			return
		}
		if query.ResourceID != "" && entry.ResourceID != query.ResourceID {
			return
		}
		if query.TraceID != "" && entry.TraceID != query.TraceID {
			return
		}
		if query.Tenant != "" && auditEntryTenantOrDefault(entry.Tenant) != query.Tenant {
			return
		}
		if query.Outcome != "" && entry.Outcome != query.Outcome {
			return
		}
		if query.After != "" && entry.Timestamp <= query.After {
			return
		}
		if query.Before != "" && entry.Timestamp >= query.Before {
			return
		}
		filtered = append(filtered, entry)
	}, &corrupt)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Unreadable is not the same as empty: callers (retry backoff,
		// custody reports) must be able to tell.
		return AuditListResult{}, fmt.Errorf("audit file %q unreadable: %w", p.filePath, err)
	}
	if n := corrupt.Load(); n > 0 {
		p.corruptLines.Add(n)
		logging.Infof("audit file %q: skipped %d unreadable line(s) while listing", p.filePath, n)
	}
	if filtered == nil {
		filtered = []AuditEntry{}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Timestamp == filtered[j].Timestamp {
			if order == "asc" {
				return filtered[i].ID < filtered[j].ID
			}
			return filtered[i].ID > filtered[j].ID
		}
		if order == "asc" {
			return filtered[i].Timestamp < filtered[j].Timestamp
		}
		return filtered[i].Timestamp > filtered[j].Timestamp
	})

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return AuditListResult{Entries: filtered[offset:end], Total: total, Limit: limit}, nil
}

func (p *fileAuditProvider) AppendEntry(_ context.Context, entry AuditEntry) error {
	if strings.TrimSpace(entry.Timestamp) == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.f == nil {
		return errors.New("audit file closed")
	}
	if entry.ID <= 0 {
		entry.ID = p.nextID
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if p.needNewline {
		encoded = append([]byte{'\n'}, encoded...)
	}
	encoded = append(encoded, '\n')
	n, err := p.f.Write(encoded)
	if err != nil {
		if n > 0 {
			p.needNewline = true // do not glue the next record onto a torn tail
		}
		return fmt.Errorf("audit file append: %w", err)
	}
	p.needNewline = false
	if entry.ID >= p.nextID {
		p.nextID = entry.ID + 1
	}
	if p.syncInterval <= 0 {
		if err := p.f.Sync(); err != nil {
			return fmt.Errorf("audit file sync: %w", err)
		}
		return nil
	}
	p.dirty = true
	if p.syncTimer == nil {
		p.syncTimer = time.AfterFunc(p.syncInterval, p.syncNow)
	}
	return nil
}

func (p *fileAuditProvider) syncNow() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.syncTimer = nil
	if !p.dirty || p.f == nil {
		return
	}
	p.dirty = false
	if err := p.f.Sync(); err != nil {
		logging.Warnf("audit file %q: sync failed: %v", p.filePath, err)
	}
}

// Close flushes and closes the file. Appends after Close fail.
func (p *fileAuditProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.syncTimer != nil {
		p.syncTimer.Stop()
		p.syncTimer = nil
	}
	if p.f == nil {
		return nil
	}
	err := p.f.Sync()
	if cerr := p.f.Close(); err == nil {
		err = cerr
	}
	p.f = nil
	return err
}
