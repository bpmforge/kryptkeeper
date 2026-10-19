// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// W22-35: access recertification campaigns. Opening a campaign freezes the
// W22-34 report; reviewers keep / revoke / modify each principal; closing
// writes a deterministic CSV whose SHA-256 goes into the audit log.
//
// The second-reviewer rule for approver-capable users is self-contained here
// rather than built on W22-10's quorum: that quorum is keyed to a
// PendingAction (an executor, a proposer, an expiry), none of which a
// campaign decision has, so reusing it would mean inventing a fake pending
// action per entry.

const (
	campaignOpen    = "open"
	campaignClosing = "closing" // decisions are frozen while the export hash is computed
	campaignClosed  = "closed"

	// campaignGlobalTenant stamps a campaign opened by an unscoped
	// super-admin: its snapshot spans tenants, so only bypass principals may
	// read or act on it.
	campaignGlobalTenant = "*"

	maxCampaignBody = 8 << 10
)

// AccessReviewDecision is one reviewer decision on one snapshot entry.
type AccessReviewDecision struct {
	CampaignID     string
	EntryID        string
	Decision       string // keep | revoke | modify
	NewRole        string
	Note           string
	DecidedBy      string // canonicalHuman of the first reviewer
	DecidedAt      string
	SecondReviewer string
	Executed       bool
}

// AccessReviewEntry is a snapshot principal plus its decision state.
type AccessReviewEntry struct {
	AccessReviewPrincipal
	EntryID        string `json:"entry_id"`
	Decision       string `json:"decision,omitempty"`
	NewRole        string `json:"new_role,omitempty"`
	Note           string `json:"note,omitempty"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	SecondReviewer string `json:"second_reviewer,omitempty"`
	Executed       bool   `json:"executed"`
	// DecisionStatus: undecided | pending_second | decided.
	DecisionStatus string `json:"decision_status"`
}

// AccessReviewCampaign is the API shape of a campaign.
type AccessReviewCampaign struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Status       string              `json:"status"`
	Tenant       string              `json:"tenant"`
	PeriodStart  string              `json:"period_start"`
	PeriodEnd    string              `json:"period_end"`
	OpenedBy     string              `json:"opened_by"`
	OpenedAt     string              `json:"opened_at"`
	ClosedBy     string              `json:"closed_by,omitempty"`
	ClosedAt     string              `json:"closed_at,omitempty"`
	ReportSHA256 string              `json:"report_sha256,omitempty"`
	Entries      []AccessReviewEntry `json:"entries,omitempty"`
}

type campaignSnapshot struct {
	GeneratedAt string                  `json:"generated_at"`
	DormantDays int                     `json:"dormant_days"`
	Principals  []AccessReviewPrincipal `json:"principals"`
}

// storedCampaign is a campaign row with its decoded snapshot and decisions.
type storedCampaign struct {
	AccessReviewCampaign
	Snapshot  campaignSnapshot
	Decisions map[string]AccessReviewDecision
}

func (c storedCampaign) entryID(p AccessReviewPrincipal) string { return p.Kind + ":" + p.ID }

// entries joins the frozen snapshot with the decisions, in entry-id order.
func (c storedCampaign) entries() []AccessReviewEntry {
	out := make([]AccessReviewEntry, 0, len(c.Snapshot.Principals))
	for _, p := range c.Snapshot.Principals {
		e := AccessReviewEntry{AccessReviewPrincipal: p, EntryID: c.entryID(p), DecisionStatus: "undecided"}
		if d, ok := c.Decisions[e.EntryID]; ok {
			e.Decision, e.NewRole, e.Note = d.Decision, d.NewRole, d.Note
			e.DecidedBy, e.DecidedAt, e.SecondReviewer, e.Executed = d.DecidedBy, d.DecidedAt, d.SecondReviewer, d.Executed
			switch {
			case d.Executed:
				e.DecisionStatus = "decided"
			case awaitsSecondReviewer(p, d):
				e.DecisionStatus = "pending_second"
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EntryID < out[j].EntryID })
	return out
}

// awaitsSecondReviewer: a first revoke of an approver-capable user is held
// until a different human repeats it.
func awaitsSecondReviewer(p AccessReviewPrincipal, d AccessReviewDecision) bool {
	return !d.Executed && d.Decision == "revoke" && p.Kind == "user" && p.ApproverCapable
}

func (c storedCampaign) view(withEntries bool) AccessReviewCampaign {
	v := c.AccessReviewCampaign
	if withEntries {
		v.Entries = c.entries()
	}
	return v
}

// accessReviewStore persists campaigns. Decision writes are conditional on the
// campaign still being open so a decision can never land after the export hash
// was taken.
type accessReviewStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, c storedCampaign) error
	Get(ctx context.Context, id string) (storedCampaign, bool, error)
	List(ctx context.Context) ([]storedCampaign, error)
	// InsertDecision reports false when a decision already exists or the
	// campaign is not open.
	InsertDecision(ctx context.Context, d AccessReviewDecision) (bool, error)
	// UpdateDecision swaps prev for next only if the stored row still equals
	// prev (compare-and-set) and the campaign is open.
	UpdateDecision(ctx context.Context, prev, next AccessReviewDecision) (bool, error)
	DeleteDecision(ctx context.Context, campaignID, entryID string) error
	// Transition moves status from -> to; false when the campaign was not in from.
	Transition(ctx context.Context, id, from, to string) (bool, error)
	Finish(ctx context.Context, id, closedBy, closedAt, sha string) (bool, error)
}

// ---- memory store ----------------------------------------------------------

type memAccessReviewStore struct {
	mu        sync.Mutex
	campaigns map[string]storedCampaign
}

func newMemAccessReviewStore() *memAccessReviewStore {
	return &memAccessReviewStore{campaigns: map[string]storedCampaign{}}
}

func (m *memAccessReviewStore) EnsureSchema(context.Context) error { return nil }

func (m *memAccessReviewStore) Create(_ context.Context, c storedCampaign) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.campaigns[c.ID]; dup {
		return fmt.Errorf("campaign %s exists", c.ID)
	}
	c.Decisions = map[string]AccessReviewDecision{}
	m.campaigns[c.ID] = c
	return nil
}

func (m *memAccessReviewStore) copyOf(c storedCampaign) storedCampaign {
	d := make(map[string]AccessReviewDecision, len(c.Decisions))
	for k, v := range c.Decisions {
		d[k] = v
	}
	c.Decisions = d
	return c
}

func (m *memAccessReviewStore) Get(_ context.Context, id string) (storedCampaign, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return storedCampaign{}, false, nil
	}
	return m.copyOf(c), true, nil
}

func (m *memAccessReviewStore) List(context.Context) ([]storedCampaign, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]storedCampaign, 0, len(m.campaigns))
	for _, c := range m.campaigns {
		out = append(out, m.copyOf(c))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OpenedAt > out[j].OpenedAt || (out[i].OpenedAt == out[j].OpenedAt && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (m *memAccessReviewStore) InsertDecision(_ context.Context, d AccessReviewDecision) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[d.CampaignID]
	if !ok || c.Status != campaignOpen {
		return false, nil
	}
	if _, exists := c.Decisions[d.EntryID]; exists {
		return false, nil
	}
	c.Decisions[d.EntryID] = d
	return true, nil
}

func (m *memAccessReviewStore) UpdateDecision(_ context.Context, prev, next AccessReviewDecision) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[prev.CampaignID]
	if !ok || c.Status != campaignOpen || c.Decisions[prev.EntryID] != prev {
		return false, nil
	}
	c.Decisions[prev.EntryID] = next
	return true, nil
}

func (m *memAccessReviewStore) DeleteDecision(_ context.Context, campaignID, entryID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.campaigns[campaignID]; ok && c.Status == campaignOpen {
		delete(c.Decisions, entryID)
	}
	return nil
}

func (m *memAccessReviewStore) Transition(_ context.Context, id, from, to string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok || c.Status != from {
		return false, nil
	}
	c.Status = to
	m.campaigns[id] = c
	return true, nil
}

func (m *memAccessReviewStore) Finish(_ context.Context, id, closedBy, closedAt, sha string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok || c.Status != campaignClosing {
		return false, nil
	}
	c.Status, c.ClosedBy, c.ClosedAt, c.ReportSHA256 = campaignClosed, closedBy, closedAt, sha
	m.campaigns[id] = c
	return true, nil
}

// ---- database store --------------------------------------------------------

var accessReviewSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS access_review_campaigns (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, period_start TEXT NOT NULL, period_end TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', opened_by TEXT NOT NULL, opened_at TEXT NOT NULL,
  closed_by TEXT NOT NULL DEFAULT '', closed_at TEXT NOT NULL DEFAULT '',
  report_sha256 TEXT NOT NULL DEFAULT '', snapshot_json TEXT NOT NULL, tenant TEXT NOT NULL DEFAULT 'default')`,
	`CREATE TABLE IF NOT EXISTS access_review_decisions (
  campaign_id TEXT NOT NULL, entry_id TEXT NOT NULL, decision TEXT NOT NULL,
  new_role TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
  decided_by TEXT NOT NULL, decided_at TEXT NOT NULL,
  second_reviewer TEXT NOT NULL DEFAULT '', executed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (campaign_id, entry_id))`,
}

// dbAccessReviewStore serves sqlite and postgres; ph is the placeholder style.
type dbAccessReviewStore struct {
	db *sql.DB
	ph func(int) string
}

func (s *dbAccessReviewStore) EnsureSchema(ctx context.Context) error {
	return execSchemaStatements(ctx, s.db, accessReviewSchemaStatements)
}

func (s *dbAccessReviewStore) Create(ctx context.Context, c storedCampaign) error {
	snap, err := json.Marshal(c.Snapshot)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO access_review_campaigns (id, name, period_start, period_end, status, opened_by, opened_at, snapshot_json, tenant)
		 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9)),
		c.ID, c.Name, c.PeriodStart, c.PeriodEnd, c.Status, c.OpenedBy, c.OpenedAt, string(snap), c.Tenant)
	return err
}

const accessReviewCampaignCols = `id, name, period_start, period_end, status, opened_by, opened_at, closed_by, closed_at, report_sha256, snapshot_json, tenant`

func scanCampaign(row interface{ Scan(...any) error }) (storedCampaign, error) {
	var c storedCampaign
	var snap string
	if err := row.Scan(&c.ID, &c.Name, &c.PeriodStart, &c.PeriodEnd, &c.Status, &c.OpenedBy, &c.OpenedAt, &c.ClosedBy, &c.ClosedAt, &c.ReportSHA256, &snap, &c.Tenant); err != nil {
		return storedCampaign{}, err
	}
	if err := json.Unmarshal([]byte(snap), &c.Snapshot); err != nil {
		return storedCampaign{}, fmt.Errorf("campaign %s snapshot: %w", c.ID, err)
	}
	c.Decisions = map[string]AccessReviewDecision{}
	return c, nil
}

func (s *dbAccessReviewStore) Get(ctx context.Context, id string) (storedCampaign, bool, error) {
	c, err := scanCampaign(s.db.QueryRowContext(ctx, `SELECT `+accessReviewCampaignCols+` FROM access_review_campaigns WHERE id = `+s.ph(1), id))
	if err == sql.ErrNoRows {
		return storedCampaign{}, false, nil
	}
	if err != nil {
		return storedCampaign{}, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT entry_id, decision, new_role, note, decided_by, decided_at, second_reviewer, executed
		FROM access_review_decisions WHERE campaign_id = `+s.ph(1), id)
	if err != nil {
		return storedCampaign{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		d := AccessReviewDecision{CampaignID: id}
		var executed int
		if err := rows.Scan(&d.EntryID, &d.Decision, &d.NewRole, &d.Note, &d.DecidedBy, &d.DecidedAt, &d.SecondReviewer, &executed); err != nil {
			return storedCampaign{}, false, err
		}
		d.Executed = executed != 0
		c.Decisions[d.EntryID] = d
	}
	return c, true, rows.Err()
}

func (s *dbAccessReviewStore) List(ctx context.Context) ([]storedCampaign, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accessReviewCampaignCols+` FROM access_review_campaigns ORDER BY opened_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedCampaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// lockOpen takes the campaign row's write lock (a no-op UPDATE) and reports
// whether it is still open; the decision write in the same transaction is then
// serialised against Transition/Finish on both engines.
func (s *dbAccessReviewStore) lockOpen(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	res, err := tx.ExecContext(ctx, `UPDATE access_review_campaigns SET status = status WHERE id = `+s.ph(1)+` AND status = `+s.ph(2), id, campaignOpen)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *dbAccessReviewStore) InsertDecision(ctx context.Context, d AccessReviewDecision) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := s.lockOpen(ctx, tx, d.CampaignID); err != nil || !ok {
		return false, err
	}
	res, err := tx.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO access_review_decisions (campaign_id, entry_id, decision, new_role, note, decided_by, decided_at, second_reviewer, executed)
		 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (campaign_id, entry_id) DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9)),
		d.CampaignID, d.EntryID, d.Decision, d.NewRole, d.Note, d.DecidedBy, d.DecidedAt, d.SecondReviewer, boolToInt(d.Executed))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	return true, tx.Commit()
}

func (s *dbAccessReviewStore) UpdateDecision(ctx context.Context, prev, next AccessReviewDecision) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := s.lockOpen(ctx, tx, prev.CampaignID); err != nil || !ok {
		return false, err
	}
	res, err := tx.ExecContext(ctx, fmt.Sprintf(
		`UPDATE access_review_decisions SET decision=%s, new_role=%s, note=%s, decided_by=%s, decided_at=%s, second_reviewer=%s, executed=%s
		 WHERE campaign_id=%s AND entry_id=%s AND decision=%s AND decided_by=%s AND second_reviewer=%s AND executed=%s`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12), s.ph(13)),
		next.Decision, next.NewRole, next.Note, next.DecidedBy, next.DecidedAt, next.SecondReviewer, boolToInt(next.Executed),
		prev.CampaignID, prev.EntryID, prev.Decision, prev.DecidedBy, prev.SecondReviewer, boolToInt(prev.Executed))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	return true, tx.Commit()
}

func (s *dbAccessReviewStore) DeleteDecision(ctx context.Context, campaignID, entryID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_review_decisions WHERE campaign_id = `+s.ph(1)+` AND entry_id = `+s.ph(2)+
		` AND EXISTS (SELECT 1 FROM access_review_campaigns WHERE id = `+s.ph(1)+` AND status = 'open')`, campaignID, entryID)
	return err
}

func (s *dbAccessReviewStore) Transition(ctx context.Context, id, from, to string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE access_review_campaigns SET status = `+s.ph(1)+` WHERE id = `+s.ph(2)+` AND status = `+s.ph(3), to, id, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *dbAccessReviewStore) Finish(ctx context.Context, id, closedBy, closedAt, sha string) (bool, error) {
	res, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`UPDATE access_review_campaigns SET status=%s, closed_by=%s, closed_at=%s, report_sha256=%s WHERE id=%s AND status=%s`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6)),
		campaignClosed, closedBy, closedAt, sha, id, campaignClosing)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// lazyAccessReviewStore answers errStoreUnavailable until the configured
// database opens (D-290-A, S-10): campaign decisions and the finish SHA are
// compliance evidence and must not live only in a process's memory.
type lazyAccessReviewStore struct{ *lazyStore[accessReviewStore] }

func (l lazyAccessReviewStore) EnsureSchema(context.Context) error { return nil }

func (l lazyAccessReviewStore) Create(ctx context.Context, c storedCampaign) error {
	s, err := l.get()
	if err != nil {
		return err
	}
	return s.Create(ctx, c)
}

func (l lazyAccessReviewStore) Get(ctx context.Context, id string) (storedCampaign, bool, error) {
	s, err := l.get()
	if err != nil {
		return storedCampaign{}, false, err
	}
	return s.Get(ctx, id)
}

func (l lazyAccessReviewStore) List(ctx context.Context) ([]storedCampaign, error) {
	s, err := l.get()
	if err != nil {
		return nil, err
	}
	return s.List(ctx)
}

func (l lazyAccessReviewStore) InsertDecision(ctx context.Context, d AccessReviewDecision) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.InsertDecision(ctx, d)
}

func (l lazyAccessReviewStore) UpdateDecision(ctx context.Context, prev, next AccessReviewDecision) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.UpdateDecision(ctx, prev, next)
}

func (l lazyAccessReviewStore) DeleteDecision(ctx context.Context, campaignID, entryID string) error {
	s, err := l.get()
	if err != nil {
		return err
	}
	return s.DeleteDecision(ctx, campaignID, entryID)
}

func (l lazyAccessReviewStore) Transition(ctx context.Context, id, from, to string) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.Transition(ctx, id, from, to)
}

func (l lazyAccessReviewStore) Finish(ctx context.Context, id, closedBy, closedAt, sha string) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.Finish(ctx, id, closedBy, closedAt, sha)
}

// newAccessReviewStoreFromEnv returns the DB-backed store behind a gate that
// fails closed while the database is down; memory only when
// APP_ACCESS_REVIEW_PROVIDER=memory names it.
func newAccessReviewStoreFromEnv() accessReviewStore {
	if memoryProviderRequested("APP_ACCESS_REVIEW_PROVIDER", "access review campaigns") {
		return newMemAccessReviewStore()
	}
	return lazyAccessReviewStore{newLazyStore("access-review", openAccessReviewStore, nil)}
}

func openAccessReviewStore() (accessReviewStore, error) {
	state := newDBProviderState[accessReviewStore](
		"access-review",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_ACCESS_REVIEW_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_ACCESS_REVIEW_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_ACCESS_REVIEW_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) accessReviewStore { return &dbAccessReviewStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) accessReviewStore { return &dbAccessReviewStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr == nil && state.store != nil {
		if err := state.store.EnsureSchema(context.Background()); err == nil {
			return state.store, nil
		} else {
			if db, ok := state.store.(*dbAccessReviewStore); ok {
				releaseFailedOpenDB("access-review", db.db)
			}
			state.openErr = err
		}
	}
	if state.openErr == nil {
		state.openErr = errStoreUnavailable
	}
	return nil, dbProviderUnavailable("access-review", state.openErr) // logs the cause; callers see only errStoreUnavailable
}

// ---- CSV -------------------------------------------------------------------

var accessReviewCSVHeader = []string{"kind", "id", "name", "role", "tenant", "source", "status", "last_activity_at", "dormant", "approver_capable", "decision", "new_role", "decided_by", "decided_at", "second_reviewer", "executed"}

// renderAccessReviewCSV is a pure function of the stored campaign: no
// generation timestamp, so re-rendering after close is byte-identical to the
// bytes that were hashed.
func renderAccessReviewCSV(c storedCampaign) ([]byte, error) {
	entries := c.entries()
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{e.Kind, e.ID, e.Name, e.Role, e.Tenant, e.Source, e.Status, e.LastActivityAt,
			fmt.Sprint(e.Dormant), fmt.Sprint(e.ApproverCapable), e.Decision, e.NewRole, e.DecidedBy, e.DecidedAt, e.SecondReviewer, fmt.Sprint(e.Executed)})
	}
	var buf bytes.Buffer
	if err := writeCSV(&buf, accessReviewCSVHeader, rows); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- handlers --------------------------------------------------------------

type accessReviewCampaignAPI struct {
	auth  *Authenticator
	users UserProvider
	roles *CustomRoleStore
	store accessReviewStore
	audit AuditProvider
	now   func() time.Time
}

const accessReviewCampaignsPath = "/api/v1/admin/access-review/campaigns"

func registerAccessReviewCampaignHandlers(mux *http.ServeMux, auth *Authenticator, users UserProvider, roles *CustomRoleStore, store accessReviewStore, audit AuditProvider) {
	auth.requireStore(store)
	registerAccessReviewCampaignHandlersAt(gateRoutes(mux, store), &accessReviewCampaignAPI{auth: auth, users: users, roles: roles, store: store, audit: audit, now: time.Now})
}

func registerAccessReviewCampaignHandlersAt(mux routeRegistrar, h *accessReviewCampaignAPI) {
	mux.HandleFunc("/api/v1/admin/access-review/campaigns", h.collection)
	mux.HandleFunc("/api/v1/admin/access-review/campaigns/", h.item)
}

func campaignVisible(pd AuthPrincipal, tenant string) bool {
	if tenantBypass(pd) {
		return true
	}
	if tenant == campaignGlobalTenant {
		return false
	}
	return stampedTenantVisible(pd, tenant)
}

func newCampaignID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "arc-" + hex.EncodeToString(b), nil
}

// authenticate resolves the caller and applies the permission class: reads
// need audit.read, writes need an administrator (the /admin/** write gate
// enforces the same, repeated here so the handler is safe on its own).
func (h *accessReviewCampaignAPI) authenticate(w http.ResponseWriter, r *http.Request, action, resource string, write bool) (AuthPrincipal, bool) {
	pd, err := h.auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, h.audit, "", action, "access-review", resource, AuditOutcomeDenied)
		writeUnauthorized(w)
		return AuthPrincipal{}, false
	}
	if write {
		if _, admin := principalPermissions(pd, h.roles); !admin {
			emitAuditEvent(r, h.audit, pd.ID, action, "access-review", resource, AuditOutcomeDenied)
			writeForbidden(w, "administrator role required")
			return AuthPrincipal{}, false
		}
		return pd, true
	}
	if !requireReadPermission(w, r, h.audit, pd, h.roles, "audit.read", action, "access-review", resource) {
		return AuthPrincipal{}, false
	}
	return pd, true
}

func (h *accessReviewCampaignAPI) collection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pd, ok := h.authenticate(w, r, "access_review.list", "campaigns", false)
		if !ok {
			return
		}
		all, err := h.store.List(r.Context())
		if err != nil {
			writeServiceUnavailable(w, "access review campaigns unavailable")
			return
		}
		items := make([]AccessReviewCampaign, 0, len(all))
		for _, c := range all {
			if campaignVisible(pd, c.Tenant) {
				items = append(items, c.view(false))
			}
		}
		writeJSONData(w, map[string]any{"items": items})
	case http.MethodPost:
		h.open(w, r)
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (h *accessReviewCampaignAPI) open(w http.ResponseWriter, r *http.Request) {
	pd, ok := h.authenticate(w, r, "access_review.open", "campaigns", true)
	if !ok {
		return
	}
	var req struct {
		Name       string `json:"name"`
		PeriodDays int    `json:"period_days"`
	}
	if !decodeJSONBodyOrReject(w, r, &req, maxCampaignBody, "invalid request body") {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 200 {
		emitAuditEvent(r, h.audit, pd.ID, "access_review.open", "access-review", "campaigns", AuditOutcomeFailure)
		writeBadRequest(w, "name is required (1..200 characters)")
		return
	}
	if req.PeriodDays == 0 {
		req.PeriodDays = defaultAccessReviewPeriodDays
	}
	if req.PeriodDays < 1 || req.PeriodDays > 3660 {
		emitAuditEvent(r, h.audit, pd.ID, "access_review.open", "access-review", "campaigns", AuditOutcomeFailure)
		writeBadRequest(w, "period_days must be between 1 and 3660")
		return
	}
	now := h.now().UTC()
	dormantDays := intFromEnvOrDefault(envAccessReviewDormantDays, defaultAccessReviewDormantDays)
	if dormantDays < 1 {
		dormantDays = defaultAccessReviewDormantDays
	}
	report, err := BuildAccessReport(r.Context(), accessReviewDeps{auth: h.auth, users: h.users, roles: h.roles, audit: h.audit},
		pd, now.AddDate(0, 0, -req.PeriodDays), now, now, dormantDays)
	if err != nil {
		emitAuditEvent(r, h.audit, pd.ID, "access_review.open", "access-review", "campaigns", AuditOutcomeFailure)
		writeServiceUnavailable(w, "access review data unavailable")
		return
	}
	id, err := newCampaignID()
	if err != nil {
		writeServiceUnavailable(w, "could not allocate a campaign id")
		return
	}
	tenant := pd.Tenant
	if tenantBypass(pd) {
		tenant = campaignGlobalTenant
	}
	if tenant == "" {
		tenant = DefaultTenant
	}
	c := storedCampaign{
		AccessReviewCampaign: AccessReviewCampaign{
			ID: id, Name: req.Name, Status: campaignOpen, Tenant: tenant,
			PeriodStart: report.PeriodStart, PeriodEnd: report.PeriodEnd,
			OpenedBy: pd.ID, OpenedAt: now.Format(time.RFC3339),
		},
		Snapshot: campaignSnapshot{GeneratedAt: report.GeneratedAt, DormantDays: dormantDays, Principals: report.Principals},
	}
	if err := h.store.Create(r.Context(), c); err != nil {
		emitAuditEvent(r, h.audit, pd.ID, "access_review.open", "access-review", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "could not store the campaign")
		return
	}
	c.Decisions = map[string]AccessReviewDecision{}
	emitAuditEventDetail(r, h.audit, pd.ID, "access_review.open", "access-review", id, AuditOutcomeSuccess, fmt.Sprintf("entries=%d;tenant=%s", len(c.Snapshot.Principals), tenant))
	writeJSONStatus(w, http.StatusCreated, map[string]any{"data": c.view(true)})
}

// item routes /campaigns/{id}[/decisions|/close|/export].
func (h *accessReviewCampaignAPI) item(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, accessReviewCampaignsPath+"/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" || strings.Contains(sub, "/") {
		http.NotFound(w, r)
		return
	}
	switch sub {
	case "":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, ok := h.authenticate(w, r, "access_review.get", id, false)
		if !ok {
			return
		}
		if c, ok := h.load(w, r, pd, "access_review.get", id); ok {
			writeJSONData(w, c.view(true))
		}
	case "export":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.export(w, r, id)
	case "decisions":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		h.decide(w, r, id)
	case "close":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		h.closeCampaign(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// load fetches a campaign the caller may see; another tenant's campaign is
// indistinguishable from a missing one.
func (h *accessReviewCampaignAPI) load(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action, id string) (storedCampaign, bool) {
	c, found, err := h.store.Get(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, h.audit, pd.ID, action, "access-review", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "access review campaigns unavailable")
		return storedCampaign{}, false
	}
	if !found || !campaignVisible(pd, c.Tenant) {
		emitAuditEvent(r, h.audit, pd.ID, action, "access-review", id, AuditOutcomeFailure)
		writeNotFound(w, "campaign not found")
		return storedCampaign{}, false
	}
	return c, true
}

func (h *accessReviewCampaignAPI) export(w http.ResponseWriter, r *http.Request, id string) {
	pd, ok := h.authenticate(w, r, "access_review.export", id, false)
	if !ok {
		return
	}
	if f := r.URL.Query().Get("format"); f != "" && f != "csv" {
		writeBadRequest(w, "format must be csv (PDF export is not available yet)")
		return
	}
	c, ok := h.load(w, r, pd, "access_review.export", id)
	if !ok {
		return
	}
	body, err := renderAccessReviewCSV(c)
	if err != nil {
		writeServiceUnavailable(w, "csv render failed")
		return
	}
	emitAuditEventDetail(r, h.audit, pd.ID, "access_review.export", "access-review", id, AuditOutcomeSuccess, "format=csv;status="+c.Status)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="access-review-%s.csv"`, id))
	_, _ = w.Write(body)
}

func (h *accessReviewCampaignAPI) closeCampaign(w http.ResponseWriter, r *http.Request, id string) {
	pd, ok := h.authenticate(w, r, "access_review.close", id, true)
	if !ok {
		return
	}
	var req struct {
		AllowUndecided bool `json:"allow_undecided"`
	}
	if r.ContentLength != 0 && !decodeJSONBodyOrReject(w, r, &req, maxCampaignBody, "invalid request body") {
		return
	}
	c, ok := h.load(w, r, pd, "access_review.close", id)
	if !ok {
		return
	}
	if c.Status == campaignClosed {
		writeConflict(w, "campaign is closed")
		return
	}
	// Freeze decisions first: with the campaign out of "open" no decision can
	// land between hashing and the status flip. A crashed earlier close left
	// "closing" behind; resuming it is safe because the hash is deterministic.
	if c.Status == campaignOpen {
		if won, err := h.store.Transition(r.Context(), id, campaignOpen, campaignClosing); err != nil || !won {
			if err != nil {
				writeServiceUnavailable(w, "access review campaigns unavailable")
				return
			}
			writeConflict(w, "campaign is being closed")
			return
		}
	}
	frozen, found, err := h.store.Get(r.Context(), id)
	if err != nil || !found {
		writeServiceUnavailable(w, "access review campaigns unavailable")
		return
	}
	undecided := 0
	for _, e := range frozen.entries() {
		if e.DecisionStatus != "decided" {
			undecided++
		}
	}
	if undecided > 0 && !req.AllowUndecided {
		h.reopen(r.Context(), id)
		writeConflict(w, fmt.Sprintf("%d entries undecided", undecided))
		return
	}
	body, err := renderAccessReviewCSV(frozen)
	if err != nil {
		h.reopen(r.Context(), id)
		writeServiceUnavailable(w, "csv render failed")
		return
	}
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	closedAt := h.now().UTC().Format(time.RFC3339)
	done, err := h.store.Finish(r.Context(), id, pd.ID, closedAt, hexSum)
	if err != nil {
		writeServiceUnavailable(w, "could not close the campaign")
		return
	}
	if !done {
		writeConflict(w, "campaign is closed")
		return
	}
	emitAuditEventDetail(r, h.audit, pd.ID, "access_review.close", "access-review", id, AuditOutcomeSuccess,
		fmt.Sprintf("sha256=%s;format=csv;entries=%d", hexSum, len(frozen.Snapshot.Principals)))
	frozen.Status, frozen.ClosedBy, frozen.ClosedAt, frozen.ReportSHA256 = campaignClosed, pd.ID, closedAt, hexSum
	writeJSONData(w, frozen.view(true))
}

type campaignDecisionRequest struct {
	EntryID  string `json:"entry_id"`
	Decision string `json:"decision"`
	NewRole  string `json:"new_role"`
	Note     string `json:"note"`
}

func (h *accessReviewCampaignAPI) decide(w http.ResponseWriter, r *http.Request, id string) {
	pd, ok := h.authenticate(w, r, "access_review.decide", id, true)
	if !ok {
		return
	}
	var req campaignDecisionRequest
	if !decodeJSONBodyOrReject(w, r, &req, maxCampaignBody, "invalid request body") {
		return
	}
	c, ok := h.load(w, r, pd, "access_review.decide", id)
	if !ok {
		return
	}
	if c.Status != campaignOpen {
		writeConflict(w, "campaign is closed")
		return
	}
	// Role, source and kind come from the frozen snapshot only; nothing the
	// client sends about the principal is trusted.
	var entry *AccessReviewEntry
	for _, e := range c.entries() {
		if e.EntryID == req.EntryID {
			e := e
			entry = &e
			break
		}
	}
	if entry == nil || !tenantVisible(pd, entry.Tenant) {
		emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeFailure, "entry not found")
		writeNotFound(w, "entry not found")
		return
	}
	req.NewRole = strings.TrimSpace(req.NewRole)
	switch req.Decision {
	case "keep", "revoke":
	case "modify":
		if req.NewRole == "" {
			emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeFailure, "invalid decision")
			writeBadRequest(w, "new_role is required for modify")
			return
		}
	default:
		emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeFailure, "invalid decision")
		writeBadRequest(w, "decision must be keep, revoke or modify")
		return
	}
	if len(req.Note) > 1000 {
		emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeFailure, "invalid note")
		writeBadRequest(w, "note is too long (max 1000 characters)")
		return
	}
	if req.Decision != "keep" && entry.Source == "scim" {
		emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeDenied, "entry="+req.EntryID+";scim read-only")
		writeConflict(w, "scim-managed users are read-only here; change them in the IdP")
		return
	}
	if req.Decision == "modify" && entry.Kind == "api_key" {
		writeBadRequest(w, "keys cannot change role; revoke and mint a new key")
		return
	}

	human := h.auth.canonicalHuman(pd)
	next := AccessReviewDecision{CampaignID: id, EntryID: req.EntryID, Decision: req.Decision, NewRole: req.NewRole, Note: req.Note, DecidedBy: human, DecidedAt: h.now().UTC().Format(time.RFC3339)}
	prev, hasPrev := c.Decisions[req.EntryID]

	// Second reviewer completing a held revoke of an approver-capable user.
	if hasPrev && awaitsSecondReviewer(entry.AccessReviewPrincipal, prev) && req.Decision == "revoke" {
		if h.auth.isBootstrapHuman(pd) {
			emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeDenied, "entry="+req.EntryID+";second reviewer is bootstrap")
			writeForbidden(w, msgBootstrapCannotApprove)
			return
		}
		if human == prev.DecidedBy {
			emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeDenied, "entry="+req.EntryID+";same reviewer")
			writeForbidden(w, msgSelfApproval)
			return
		}
		done := prev
		done.SecondReviewer, done.Executed = human, true
		claimed, err := h.store.UpdateDecision(r.Context(), prev, done)
		if err != nil {
			writeServiceUnavailable(w, "access review campaigns unavailable")
			return
		}
		if !claimed {
			writeConflict(w, "entry was decided concurrently; reload the campaign")
			return
		}
		if status, msg := h.execute(r, pd, id, *entry, done); status != 0 {
			h.revert(r.Context(), done, prev) // let a reviewer retry
			h.fail(w, status, msg)
			return
		}
		h.respondDecision(w, r, pd, id, req.EntryID, http.StatusOK, "second="+human)
		return
	}
	if hasPrev && prev.Executed {
		writeConflict(w, "entry already decided")
		return
	}

	// First-reviewer path. A held revoke is stored un-executed and answered 202.
	hold := awaitsSecondReviewer(entry.AccessReviewPrincipal, next)
	next.Executed = req.Decision == "keep"
	var wrote bool
	var err error
	if hasPrev {
		// Replaces a held (or crashed, un-executed) decision. Only the claim
		// that read it can win.
		wrote, err = h.store.UpdateDecision(r.Context(), prev, next)
	} else {
		wrote, err = h.store.InsertDecision(r.Context(), next)
	}
	if err != nil {
		writeServiceUnavailable(w, "access review campaigns unavailable")
		return
	}
	if !wrote {
		writeConflict(w, "entry was decided concurrently; reload the campaign")
		return
	}
	if hold {
		h.respondDecision(w, r, pd, id, req.EntryID, http.StatusAccepted, "pending_second")
		return
	}
	if req.Decision != "keep" {
		claim := next
		if status, msg := h.execute(r, pd, id, *entry, next); status != 0 {
			if hasPrev {
				h.revert(r.Context(), claim, prev)
			} else {
				h.discard(r.Context(), id, req.EntryID)
			}
			h.fail(w, status, msg)
			return
		}
		done := next
		done.Executed = true
		if ok, err := h.store.UpdateDecision(r.Context(), next, done); err != nil || !ok {
			// The side effect already happened; surface that the record lags
			// instead of retrying a revoke.
			logging.Errorf("access review %s entry %s executed but not recorded: ok=%v err=%v", id, req.EntryID, ok, err)
		}
	}
	h.respondDecision(w, r, pd, id, req.EntryID, http.StatusOK, "")
}

// execute performs the side effect of a decision with the same calls the
// admin handlers make (no loop back over HTTP). It returns a non-zero status
// and message on failure.
func (h *accessReviewCampaignAPI) execute(r *http.Request, pd AuthPrincipal, campaignID string, e AccessReviewEntry, d AccessReviewDecision) (int, string) {
	detail := "access_review=" + campaignID
	switch {
	case e.Kind == "api_key" && d.Decision == "revoke":
		found, persistErr := h.auth.RevokeAPIKey(e.ID)
		switch {
		case !found:
			emitAuditEventDetail(r, h.audit, pd.ID, "api-key.delete", "api-key", e.ID, AuditOutcomeFailure, detail)
			return http.StatusNotFound, "api key not found"
		case persistErr != nil:
			emitAuditEventDetail(r, h.audit, pd.ID, "api-key.delete", "api-key", e.ID, AuditOutcomeFailure, detail)
			return http.StatusServiceUnavailable, "api key is revoked for this process but the revocation is not durable yet; repeat the decision"
		}
		emitAuditEventDetail(r, h.audit, pd.ID, "api-key.delete", "api-key", e.ID, AuditOutcomeSuccess, detail)
	case e.Kind == "user" && (d.Decision == "revoke" || d.Decision == "modify"):
		live, found, err := lookupPrincipalUser(r.Context(), h.users, e.ID)
		if err != nil {
			return http.StatusServiceUnavailable, "users unavailable"
		}
		// Live checks: the snapshot may be stale, and the same grant rules as
		// PATCH /users/{id} apply to whoever acts now.
		if !found || !tenantVisible(pd, userTenant(live)) {
			return http.StatusNotFound, "user not found"
		}
		if ref := checkTargetRole(pd, h.roles, live.Role); ref != nil {
			emitAuditEventDetail(r, h.audit, pd.ID, "users.update", "user", e.ID, AuditOutcomeDenied, ref.detail)
			return ref.status, ref.msg
		}
		role, status := "", "deactivated" // the only status literal that deactivates
		if d.Decision == "modify" {
			if ref := checkRoleGrant(pd, h.roles, d.NewRole); ref != nil {
				emitAuditEventDetail(r, h.audit, pd.ID, "users.update", "user", e.ID, AuditOutcomeDenied, ref.detail)
				return ref.status, ref.msg
			}
			role, status = d.NewRole, ""
		}
		if _, err := h.users.UpdateUser(r.Context(), e.ID, role, status); err != nil {
			emitAuditEventDetail(r, h.audit, pd.ID, "users.update", "user", e.ID, AuditOutcomeFailure, detail)
			return http.StatusNotFound, "user not found"
		}
		emitAuditEventDetail(r, h.audit, pd.ID, "users.update", "user", e.ID, AuditOutcomeSuccess, detail)
	}
	return 0, ""
}

func (h *accessReviewCampaignAPI) fail(w http.ResponseWriter, status int, msg string) {
	switch status {
	case http.StatusNotFound:
		writeNotFound(w, msg)
	case http.StatusForbidden:
		writeForbidden(w, msg)
	case http.StatusBadRequest:
		writeBadRequest(w, msg)
	default:
		writeServiceUnavailable(w, msg)
	}
}

func (h *accessReviewCampaignAPI) respondDecision(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, id, entryID string, status int, note string) {
	c, found, err := h.store.Get(r.Context(), id)
	if err != nil || !found {
		writeServiceUnavailable(w, "access review campaigns unavailable")
		return
	}
	var out *AccessReviewEntry
	for _, e := range c.entries() {
		if e.EntryID == entryID {
			e := e
			out = &e
		}
	}
	detail := "entry=" + entryID
	if out != nil {
		detail += ";decision=" + out.Decision + ";status=" + out.DecisionStatus
	}
	if note != "" {
		detail += ";" + note
	}
	emitAuditEventDetail(r, h.audit, pd.ID, "access_review.decide", "access-review", id, AuditOutcomeSuccess, detail)
	writeJSONStatus(w, status, map[string]any{"data": out})
}

// reopen, revert and discard undo a claim after a refused close or a failed
// side effect. A failure here only leaves the entry held for a manual retry,
// so it is logged rather than surfaced over the response already chosen.
func (h *accessReviewCampaignAPI) reopen(ctx context.Context, id string) {
	if _, err := h.store.Transition(ctx, id, campaignClosing, campaignOpen); err != nil {
		logging.Errorf("access review %s: could not reopen after refused close: %v", id, err)
	}
}

func (h *accessReviewCampaignAPI) revert(ctx context.Context, from, to AccessReviewDecision) {
	if _, err := h.store.UpdateDecision(ctx, from, to); err != nil {
		logging.Errorf("access review %s entry %s: could not roll back a failed decision: %v", from.CampaignID, from.EntryID, err)
	}
}

func (h *accessReviewCampaignAPI) discard(ctx context.Context, campaignID, entryID string) {
	if err := h.store.DeleteDecision(ctx, campaignID, entryID); err != nil {
		logging.Errorf("access review %s entry %s: could not discard a failed decision: %v", campaignID, entryID, err)
	}
}
