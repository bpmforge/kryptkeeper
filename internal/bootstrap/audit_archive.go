// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/audittrust"
)

// W22-07: audit retention. Rows older than AUDIT_RETENTION_DAYS are written
// to a signed, hash-chained archive file; the archive's Merkle checkpoint is
// recorded in audit_archives BEFORE any row is deleted; the delete runs in
// one transaction that relaxes the append-only trigger only for that
// transaction. The whole job is a pending action, so a second admin must
// approve it: deleting evidence is exactly the change one person must not
// be able to make alone.
//
// Transparency-log consequence (decision taken from the spec's default):
// the live Merkle tree (buildAuditMerkleLog) is derived from ALL remaining
// rows oldest-first, so removing a prefix renumbers every later leaf and
// invalidates consistency proofs against checkpoints published before the
// archive. The tree therefore restarts over the remaining rows; the signed
// archive checkpoint (audit_archives and the audit.archive row) anchors the
// archived prefix. Offline-verifier support for the boundary is a follow-up.

// ActionAuditArchive is the pending-action type of an archive run.
const ActionAuditArchive = "audit_archive"

const (
	defaultAuditRetentionDays = 2555 // ~7 years
	auditArchiveBatch         = 5000
)

// AuditRetentionDays is the retention window in days from
// AUDIT_RETENTION_DAYS. Unset, non-numeric or non-positive values fall back
// to the default: an unparseable retention must never mean "keep nothing".
func AuditRetentionDays() int {
	raw := strings.TrimSpace(os.Getenv("AUDIT_RETENTION_DAYS"))
	if raw == "" {
		return defaultAuditRetentionDays
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		logging.Infof("audit retention: AUDIT_RETENTION_DAYS=%q is not a positive integer; using %d", raw, defaultAuditRetentionDays)
		return defaultAuditRetentionDays
	}
	return n
}

var errArchiveTooRecent = errors.New("rows inside the retention window cannot be archived")

// AuditArchiveManager runs the archive job. It operates on the audit_log of
// the database it is given, so it must only be built when the audit trail
// lives in that database.
type AuditArchiveManager struct {
	db       *sql.DB
	postgres bool
	dir      string
	actions  PendingActionStore
	audit    AuditProvider
	now      func() time.Time
	signKey  func() (ed25519.PrivateKey, error)

	// beforeDelete is a test seam called after the checkpoint is recorded
	// and before the delete transaction opens.
	beforeDelete func()

	mu sync.Mutex // one archive run at a time
}

// NewAuditArchiveManager returns nil without a database. dir defaults to
// AUDIT_ARCHIVE_DIR, then <KRYPTKEEPER_DATA_DIR>/audit-archive.
func NewAuditArchiveManager(db *sql.DB, postgres bool, actions PendingActionStore, audit AuditProvider) *AuditArchiveManager {
	if db == nil {
		return nil
	}
	dir := strings.TrimSpace(os.Getenv("AUDIT_ARCHIVE_DIR"))
	if dir == "" {
		base := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DATA_DIR"))
		if base == "" {
			base = "./var" // same default as sqliteDSNFromEnv
		}
		dir = filepath.Join(base, "audit-archive")
	}
	return &AuditArchiveManager{
		db: db, postgres: postgres, dir: dir, actions: actions, audit: audit,
		now: time.Now, signKey: auditTransparencySigningKey,
	}
}

const auditArchivesSchema = `
CREATE TABLE IF NOT EXISTS audit_archives (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    before_ts   TEXT NOT NULL,
    row_count   INTEGER NOT NULL,
    first_id    BIGINT NOT NULL,
    last_id     BIGINT NOT NULL,
    merkle_root TEXT NOT NULL,
    signature   TEXT NOT NULL,
    chain_head  TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    approver    TEXT NOT NULL,
    action_id   TEXT NOT NULL
)`

// EnsureSchema creates audit_archives when migrations have not (the audit
// store self-heals its own tables the same way).
func (m *AuditArchiveManager) EnsureSchema(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, auditArchivesSchema)
	return err
}

// q rewrites ? placeholders to $n for Postgres.
func (m *AuditArchiveManager) q(query string) string {
	if !m.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (m *AuditArchiveManager) retentionCutoff() time.Time {
	return m.now().UTC().Add(-time.Duration(AuditRetentionDays()) * 24 * time.Hour)
}

// checkBefore refuses a cutoff that would reach into the retention window.
func (m *AuditArchiveManager) checkBefore(before time.Time) error {
	if before.After(m.retentionCutoff()) {
		return fmt.Errorf("%w: AUDIT_RETENTION_DAYS=%d, latest allowed cutoff is %s",
			errArchiveTooRecent, AuditRetentionDays(), m.retentionCutoff().Format(time.RFC3339))
	}
	return nil
}

// Propose files the archive run for a second admin's approval.
func (m *AuditArchiveManager) Propose(ctx context.Context, pd AuthPrincipal, before time.Time) (PendingAction, error) {
	before = before.UTC().Truncate(time.Second)
	if err := m.checkBefore(before); err != nil {
		return PendingAction{}, err
	}
	if m.actions == nil {
		return PendingAction{}, errors.New("the approval queue is unavailable, so an archive run cannot be proposed")
	}
	params, _ := json.Marshal(map[string]string{"before": before.Format(time.RFC3339)})
	return m.actions.Create(ctx, PendingAction{
		ActionType: ActionAuditArchive, Params: params, ProposedBy: pd.ID, Tenant: pd.Tenant,
		Rationale: fmt.Sprintf("archive and delete audit rows older than %s (retention %d days)", before.Format(time.RFC3339), AuditRetentionDays()),
	})
}

// auditEntrySelect is the column list of the ListEntries queries, so the
// archived JSON carries exactly the fields the live log exposes.
func (m *AuditArchiveManager) auditEntrySelect() string {
	return `SELECT id, timestamp, action, actor_type, actor_id, resource_type, resource_id,
       COALESCE(trace_id, ''), outcome,
       COALESCE(source_ip, ''), COALESCE(user_agent, ''), COALESCE(session_id, ''), COALESCE(change_summary, ''),
       COALESCE(tenant, '')
FROM audit_log`
}

// scanBatch reads up to auditArchiveBatch rows older than before, after the
// (ts, id) cursor, in timestamp order. cursorTS is the raw column value
// (string on SQLite, time.Time on Postgres) so the keyset comparison is
// exact. Keyset rather than OFFSET: stable and linear over millions of rows.
func (m *AuditArchiveManager) scanBatch(ctx context.Context, before any, haveCursor bool, cursorTS any, cursorID int64) (entries []AuditEntry, lastTS any, err error) {
	query := m.auditEntrySelect() + ` WHERE timestamp < ?`
	args := []any{before}
	if haveCursor {
		query += ` AND (timestamp > ? OR (timestamp = ? AND id > ?))`
		args = append(args, cursorTS, cursorTS, cursorID)
	}
	query += fmt.Sprintf(` ORDER BY timestamp, id LIMIT %d`, auditArchiveBatch)
	rows, err := m.db.QueryContext(ctx, m.q(query), args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		var ts any
		if m.postgres {
			var t time.Time
			err = rows.Scan(&e.ID, &t, &e.Action, &e.ActorType, &e.ActorID, &e.ResourceType, &e.ResourceID,
				&e.TraceID, &e.Outcome, &e.SourceIP, &e.UserAgent, &e.SessionID, &e.ChangeSummary, &e.Tenant)
			e.Timestamp, ts = t.UTC().Format(time.RFC3339), t
		} else {
			var s string
			err = rows.Scan(&e.ID, &s, &e.Action, &e.ActorType, &e.ActorID, &e.ResourceType, &e.ResourceID,
				&e.TraceID, &e.Outcome, &e.SourceIP, &e.UserAgent, &e.SessionID, &e.ChangeSummary, &e.Tenant)
			e.Timestamp, ts = s, s
		}
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, e)
		lastTS = ts
	}
	return entries, lastTS, rows.Err()
}

func (m *AuditArchiveManager) beforeParam(before time.Time) any {
	if m.postgres {
		return before
	}
	return before.Format(time.RFC3339)
}

// ExecuteArchive is the ActionExecutor for ActionAuditArchive. The queue has
// already refused self-approval; archiving additionally needs a pki-admin
// approver, and with multi-tenancy on an unscoped super-admin, because the
// log it rewrites is instance-global.
func (m *AuditArchiveManager) ExecuteArchive(ctx context.Context, action PendingAction, approver AuthPrincipal) (result json.RawMessage, err error) {
	if !isAdminRole(approver.Role) {
		return nil, errors.New("archiving the audit log needs a pki-admin approver")
	}
	if !tenantBypass(approver) {
		return nil, errors.New("archiving the audit log is instance-wide: a platform super-admin must approve it when multi-tenancy is on")
	}
	var p struct {
		Before string `json:"before"`
	}
	if err := json.Unmarshal(action.Params, &p); err != nil {
		return nil, fmt.Errorf("bad params: %w", err)
	}
	before, err := time.Parse(time.RFC3339, p.Before)
	if err != nil {
		return nil, fmt.Errorf("bad before timestamp: %w", err)
	}
	before = before.UTC()
	// Re-checked at approval time: the window or the clock may have moved
	// since the proposal.
	if err := m.checkBefore(before); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var archiveID, rootB64 string
	rows := 0
	defer func() {
		// Written AFTER the delete so this row is not itself archived.
		outcome, detail := AuditOutcomeSuccess, fmt.Sprintf("rows=%d archive=%s root=%s", rows, archiveID, rootB64)
		if err != nil {
			outcome, detail = AuditOutcomeFailure, "before="+p.Before+" error="+truncateForLog(err.Error())
		}
		m.appendAudit(ctx, approver, outcome, archiveID, detail)
	}()

	priv, err := m.signKey()
	if err != nil {
		return nil, fmt.Errorf("archive signing key: %w", err)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, fmt.Errorf("archive dir: %w", err)
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	archiveID = hex.EncodeToString(idBytes)
	final := filepath.Join(m.dir, "audit-archive-"+action.ID+".jsonl")
	tmp := final + ".tmp"

	prev, err := m.previousChainHead(ctx)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("archive file: %w", err)
	}
	keepTmp := false
	defer func() {
		if !keepTmp {
			_ = f.Close()      // already closed on the success path; double close is harmless here
			_ = os.Remove(tmp) // never leave a half-written archive behind
		}
	}()
	w := audittrust.NewArchiveWriter(f, audittrust.ArchiveHeader{
		CreatedAt: m.now().UTC().Format(time.RFC3339), BeforeTS: before.Format(time.RFC3339), PrevHash: prev,
	}, audittrust.CanonicalLeaf, priv)

	var (
		haveCursor bool
		cursorTS   any
		cursorID   int64
	)
	for {
		batch, lastTS, err := m.scanBatch(ctx, m.beforeParam(before), haveCursor, cursorTS, cursorID)
		if err != nil {
			return nil, fmt.Errorf("read audit rows: %w", err)
		}
		for _, e := range batch {
			raw, _ := json.Marshal(e) // fixed-shape struct: cannot fail
			if err := w.Write(raw); err != nil {
				return nil, fmt.Errorf("write archive: %w", err)
			}
		}
		if len(batch) < auditArchiveBatch {
			break
		}
		haveCursor, cursorTS, cursorID = true, lastTS, batch[len(batch)-1].ID
	}
	trailer, err := w.Close()
	if err != nil {
		if errors.Is(err, audittrust.ErrArchiveEmpty) {
			return nil, errors.New("no audit rows older than the cutoff: nothing to archive")
		}
		return nil, fmt.Errorf("finish archive: %w", err)
	}
	rows, rootB64 = trailer.Count, trailer.Checkpoint.RootB64
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync archive: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close archive: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, fmt.Errorf("publish archive: %w", err)
	}
	keepTmp = true
	syncDir(m.dir)
	fileSum, err := fileSHA256(final)
	if err != nil {
		return nil, err
	}

	// The invariant of the whole job: the signed checkpoint is durable
	// before the first row is deleted. A crash after this point leaves an
	// archive and a record, never a deletion without evidence.
	if _, err := m.db.ExecContext(ctx, m.q(`INSERT INTO audit_archives
		(id, created_at, before_ts, row_count, first_id, last_id, merkle_root, signature, chain_head, file_path, file_sha256, approver, action_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		archiveID, m.now().UTC().Format(time.RFC3339), before.Format(time.RFC3339), trailer.Count, trailer.FirstID, trailer.LastID,
		trailer.Checkpoint.RootB64, trailer.Checkpoint.Signature, trailer.ChainHead, final, fileSum, approver.ID, action.ID); err != nil {
		return nil, fmt.Errorf("record archive checkpoint: %w", err)
	}
	if m.beforeDelete != nil {
		m.beforeDelete()
	}
	if err := m.deleteArchived(ctx, before, trailer); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"archive_id": archiveID, "rows": trailer.Count, "file": final, "merkle_root": trailer.Checkpoint.RootB64})
}

// deleteArchived removes exactly the archived rows in one transaction with
// the append-only guard relaxed for that transaction only. The affected-row
// count must equal the archived count, otherwise the delete rolls back: a
// mismatch means the table changed under the job.
func (m *AuditArchiveManager) deleteArchived(ctx context.Context, before time.Time, t audittrust.ArchiveTrailer) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	if m.postgres {
		// The trigger function only honours this setting for rows covered
		// by an audit_archives row (migration 000087), and SET LOCAL ends
		// with the transaction.
		if _, err := tx.ExecContext(ctx, `SET LOCAL kryptkeeper.audit_archive = 'on'`); err != nil {
			return fmt.Errorf("relax audit trigger: %w", err)
		}
	} else if _, err := tx.ExecContext(ctx, `DROP TRIGGER IF EXISTS trg_audit_log_no_delete`); err != nil {
		return fmt.Errorf("relax audit trigger: %w", err)
	}
	res, err := tx.ExecContext(ctx, m.q(`DELETE FROM audit_log WHERE timestamp < ? AND id >= ? AND id <= ?`),
		m.beforeParam(before), t.FirstID, t.LastID)
	if err != nil {
		return fmt.Errorf("delete archived rows: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if int(n) != t.Count {
		return fmt.Errorf("delete removed %d rows but %d were archived; rolled back", n, t.Count)
	}
	if !m.postgres {
		if _, err := tx.ExecContext(ctx, sqliteAuditNoDeleteTriggerSQL); err != nil {
			return fmt.Errorf("restore audit trigger: %w", err)
		}
	}
	return tx.Commit()
}

func (m *AuditArchiveManager) previousChainHead(ctx context.Context) (string, error) {
	var head string
	err := m.db.QueryRowContext(ctx, `SELECT chain_head FROM audit_archives ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return head, err
}

func (m *AuditArchiveManager) appendAudit(ctx context.Context, approver AuthPrincipal, outcome AuditOutcome, archiveID, detail string) {
	if m.audit == nil {
		return
	}
	// The row must land even if the approving request was cancelled.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditAppendTimeout)
	defer cancel()
	actorType := "user"
	if approver.ID == "bootstrap" {
		actorType = "system"
	}
	resID := archiveID
	if resID == "" {
		resID = "audit"
	}
	if err := m.audit.AppendEntry(actx, AuditEntry{
		Timestamp: m.now().UTC().Format(time.RFC3339), Action: "audit.archive",
		ActorType: actorType, ActorID: approver.ID, ResourceType: "audit_log", ResourceID: resID,
		Outcome: outcome, ChangeSummary: detail, Tenant: DefaultTenant,
	}); err != nil {
		logging.Warnf("audit archive: could not record audit.archive: %v", err)
	}
}

// Restore re-inserts the rows of an archive file. The file is fully verified
// (hash chain, signature, checkpoint) and its checkpoint root compared with
// the one stored in audit_archives BEFORE anything is inserted; a mismatch
// means the file is not the one this hub wrote. Rows keep their original
// ids; ids already present are skipped. INSERT is always allowed by the
// append-only trigger, so restoring needs no relaxation.
func (m *AuditArchiveManager) Restore(ctx context.Context, path string) (restored int, err error) {
	priv, err := m.signKey()
	if err != nil {
		return 0, fmt.Errorf("archive signing key: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	open := func() (*os.File, error) { return os.Open(path) }
	f, err := open()
	if err != nil {
		return 0, err
	}
	_, trailer, verr := audittrust.ScanArchive(f, pub, audittrust.CanonicalLeaf, nil)
	_ = f.Close()
	if verr != nil {
		return 0, fmt.Errorf("archive failed verification: %w", verr)
	}
	var storedRoot string
	err = m.db.QueryRowContext(ctx, m.q(`SELECT merkle_root FROM audit_archives WHERE chain_head = ?`), trailer.ChainHead).Scan(&storedRoot)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("this archive is not recorded in audit_archives")
	}
	if err != nil {
		return 0, err
	}
	if storedRoot != trailer.Checkpoint.RootB64 {
		return 0, errors.New("archive checkpoint does not match the one recorded when it was written")
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	insert := `INSERT INTO audit_log(id, timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome,
		source_ip, user_agent, session_id, change_summary, tenant)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`
	if m.postgres {
		insert = strings.Replace(insert, "VALUES", "OVERRIDING SYSTEM VALUE VALUES", 1)
	}
	insert = m.q(insert)

	f, err = open()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	_, _, err = audittrust.ScanArchive(f, pub, audittrust.CanonicalLeaf, func(raw json.RawMessage) error {
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		var ts any = e.Timestamp
		if m.postgres {
			parsed, perr := time.Parse(time.RFC3339, e.Timestamp)
			if perr != nil {
				return perr
			}
			ts = parsed
		}
		res, err := tx.ExecContext(ctx, insert, e.ID, ts, e.Action, e.ActorType, e.ActorID, e.ResourceType, e.ResourceID,
			nullableString(e.TraceID), e.Outcome, nullableString(e.SourceIP), nullableString(e.UserAgent),
			nullableString(e.SessionID), nullableString(e.ChangeSummary), auditEntryTenantOrDefault(e.Tenant))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			restored++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return restored, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// syncDir makes the rename durable; best effort (not supported everywhere).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()  // best-effort durability of the rename
		_ = d.Close() // read-only handle
	}
}

// RegisterAuditArchiveHandlers mounts POST /api/v1/audit/archive, which
// only PROPOSES a run; execution happens when a second admin approves the
// pending action. A nil manager (audit trail not in the hub database)
// answers 503.
func RegisterAuditArchiveHandlers(mux *http.ServeMux, auth *Authenticator, m *AuditArchiveManager, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/audit/archive", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "audit.archive_propose", "audit_log", "audit", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "audit.archive_propose", "audit_log", "audit", AuditOutcomeDenied)
			writeForbidden(w, "archiving the audit log needs the pki-admin role")
			return
		}
		// The log is instance-global: a tenant admin must not be able to
		// schedule its deletion.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "audit.archive_propose", "audit_log", "audit") {
			return
		}
		if m == nil {
			writeServiceUnavailable(w, "audit archiving is unavailable: the audit trail is not in the hub database")
			return
		}
		var body struct {
			Before string `json:"before"`
		}
		if r.ContentLength != 0 {
			if !decodeJSONBodyOrReject(w, r, &body, 4<<10, "body must be JSON like {\"before\":\"<RFC3339>\"}") {
				return
			}
		}
		before := m.retentionCutoff()
		if strings.TrimSpace(body.Before) != "" {
			if before, err = time.Parse(time.RFC3339, strings.TrimSpace(body.Before)); err != nil {
				writeBadRequest(w, "before must be an RFC 3339 timestamp")
				return
			}
		}
		action, err := m.Propose(r.Context(), pd, before)
		if err != nil {
			if errors.Is(err, errArchiveTooRecent) {
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "audit.archive_propose", "audit_log", "audit", AuditOutcomeFailure)
			logging.Infof("audit archive propose: %v", err)
			writeServiceUnavailable(w, "could not file the archive proposal")
			return
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "audit.archive_propose", "audit_log", action.ID, AuditOutcomeProposed,
			"before="+before.UTC().Format(time.RFC3339))
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"data": action})
	})
}
