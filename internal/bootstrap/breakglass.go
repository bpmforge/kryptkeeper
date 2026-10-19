// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/logging"
)

// W22-37: break-glass. Two distinct holders of the break-glass role open a
// time-boxed override window; every use of it raises an alert and opens an
// after-action review task that an administrator who was not involved must
// complete. Nothing here changes who may approve: the bootstrap token stays
// non-approving and proposer != approver is enforced by the callers that
// consume the window (W22-38), not relaxed by it.

const (
	breakGlassRole          = "break-glass"
	breakGlassTTL           = 4 * time.Hour
	breakGlassConfirmWindow = 15 * time.Minute
	breakGlassReviewDue     = 24 * time.Hour

	breakGlassLocalLoginScope = "local-login"
	maxBreakGlassBody         = 4 << 10
	maxBreakGlassReason       = 500
	maxBreakGlassNotes        = 2000
)

const (
	bgPending   = "pending"
	bgActive    = "active"
	bgExpired   = "expired"
	bgOpen      = "open"
	bgCompleted = "completed"
)

var (
	errBreakGlassNotActive  = errors.New("break-glass is not active")
	errBreakGlassNotHolder  = errors.New("only active holders of the break-glass role may do this")
	errBreakGlassSameHuman  = errors.New(msgSelfApproval)
	errBreakGlassLapsed     = errors.New("the activation request lapsed; request again")
	errBreakGlassBootstrap  = errors.New(msgBootstrapCannotApprove)
	errBreakGlassNamedOnly  = errors.New("break-glass needs a named interactive session, not an API key")
	errBreakGlassBusy       = errors.New("a break-glass activation is already pending or active")
	errBreakGlassNotFound   = errors.New("not found")
	errBreakGlassNotPending = errors.New("the activation is not pending")
	errBreakGlassReviewDone = errors.New("the review is already completed")
	errBreakGlassInvolved   = errors.New("the reviewer took part in this break-glass use")
	errBreakGlassBadInput   = errors.New("bad request")
)

// BreakGlassActivation is one two-person override window.
type BreakGlassActivation struct {
	ID          string `json:"id"`
	Reason      string `json:"reason"`
	Status      string `json:"status"` // pending | active | expired
	RequestedBy string `json:"requested_by"`
	ConfirmedBy string `json:"confirmed_by,omitempty"`
	RequestedAt string `json:"requested_at"`
	ActivatedAt string `json:"activated_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// BreakGlassReview is the 24 h after-action task opened by the first use of a
// scope (an activation, or the local-login path).
type BreakGlassReview struct {
	ID           string   `json:"id"`
	ActivationID string   `json:"activation_id"` // the scope: "act-<id>" or "local-login"
	Status       string   `json:"status"`        // open | completed
	OpenedAt     string   `json:"opened_at"`
	DueAt        string   `json:"due_at"`
	CompletedBy  string   `json:"completed_by,omitempty"`
	CompletedAt  string   `json:"completed_at,omitempty"`
	Outcome      string   `json:"outcome,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	UseCount     int      `json:"use_count"`
	Actors       []string `json:"actors"`
	Overdue      bool     `json:"overdue"`
}

// BreakGlassAlert is what the alert hook receives; Event is "breakglass.used".
type BreakGlassAlert struct{ Event, ActivationID, ReviewID, Detail string }

// BreakGlass is the manager. Field names are read by W22-38 (same package).
type BreakGlass struct {
	store breakGlassStore
	users UserProvider
	auth  *Authenticator
	audit AuditProvider
	now   func() time.Time
	alert func(BreakGlassAlert)
	// roles, when set, additionally requires the break-glass role to be a
	// global (non-tenant-owned) custom role, so a tenant admin cannot mint a
	// look-alike role and stand up their own holders.
	roles *CustomRoleStore
}

func NewBreakGlass(store breakGlassStore, users UserProvider, auth *Authenticator, audit AuditProvider, now func() time.Time, alert func(BreakGlassAlert)) *BreakGlass {
	if now == nil {
		now = time.Now
	}
	if alert == nil {
		alert = defaultBreakGlassAlert
	}
	return &BreakGlass{store: store, users: users, auth: auth, audit: audit, now: now, alert: alert}
}

// defaultBreakGlassAlert logs loudly; the audit row it accompanies is what the
// SIEM forwarder ships. Fan-out to chat/email is a follow-up (W30-04).
func defaultBreakGlassAlert(a BreakGlassAlert) {
	logging.Infof("ALERT %s activation=%q review=%q %q", a.Event, a.ActivationID, a.ReviewID, a.Detail)
}

// activeBreakGlassPtr lets the W22-38 handlers reach the instance mounted by
// registerBreakGlassHandlers, the same way activeTenantStore is shared.
var activeBreakGlassPtr atomic.Pointer[BreakGlass]

func setActiveBreakGlass(b *BreakGlass) { activeBreakGlassPtr.Store(b) }
func activeBreakGlass() *BreakGlass     { return activeBreakGlassPtr.Load() }

// breakGlassRouteHooks lets later tickets mount routes that need the manager.
// Hooks must be appended (init), never assigned.
var breakGlassRouteHooks []func(mux *http.ServeMux, b *BreakGlass, auth *Authenticator)

func (b *BreakGlass) stamp() string { return b.now().UTC().Format(time.RFC3339) }

// IsHolder reports whether pd is an interactive session of an active user who
// currently holds the break-glass role. The bootstrap token and API keys never
// qualify: activation is a named-person act.
func (b *BreakGlass) IsHolder(ctx context.Context, pd AuthPrincipal) error {
	if b.auth.isBootstrapHuman(pd) {
		return errBreakGlassBootstrap
	}
	if pd.AuthType == AuthTypeAPIKey {
		return errBreakGlassNamedOnly
	}
	if pd.Role != breakGlassRole {
		return errBreakGlassNotHolder
	}
	u, found, err := lookupPrincipalUser(ctx, b.users, pd.ID)
	if err != nil {
		return fmt.Errorf("users unavailable: %w", err)
	}
	// The live record decides: a demoted or deactivated user with a still-valid
	// token is no longer a holder.
	if !found || u.Status != "active" || u.Role != breakGlassRole {
		return errBreakGlassNotHolder
	}
	if b.roles != nil {
		role, ok, err := b.roles.GetRole(breakGlassRole)
		if err != nil {
			return fmt.Errorf("roles unavailable: %w", err)
		}
		if ok && role.TenantID != "" {
			return errBreakGlassNotHolder
		}
	}
	return nil
}

func newBreakGlassID(prefix string) (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

// Request opens a pending activation for a second holder to confirm.
func (b *BreakGlass) Request(ctx context.Context, pd AuthPrincipal, reason string) (BreakGlassActivation, error) {
	if err := b.IsHolder(ctx, pd); err != nil {
		return BreakGlassActivation{}, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxBreakGlassReason {
		return BreakGlassActivation{}, fmt.Errorf("%w: reason is required (1..%d characters)", errBreakGlassBadInput, maxBreakGlassReason)
	}
	id, err := newBreakGlassID("bga-")
	if err != nil {
		return BreakGlassActivation{}, err
	}
	a := BreakGlassActivation{ID: id, Reason: reason, Status: bgPending, RequestedBy: b.auth.canonicalHuman(pd), RequestedAt: b.stamp()}
	created, err := b.store.CreateActivationIfFree(ctx, a, b.now())
	if err != nil {
		return BreakGlassActivation{}, err
	}
	if !created {
		return BreakGlassActivation{}, errBreakGlassBusy
	}
	return a, nil
}

// Confirm activates a pending request; the confirmer must be a different
// holder, and the flip is a compare-and-set on status='pending'.
func (b *BreakGlass) Confirm(ctx context.Context, pd AuthPrincipal, id string) (BreakGlassActivation, error) {
	if err := b.IsHolder(ctx, pd); err != nil {
		return BreakGlassActivation{}, err
	}
	a, found, err := b.store.GetActivation(ctx, id)
	if err != nil {
		return BreakGlassActivation{}, err
	}
	if !found {
		return BreakGlassActivation{}, errBreakGlassNotFound
	}
	if a.Status != bgPending {
		return BreakGlassActivation{}, errBreakGlassNotPending
	}
	now := b.now()
	if requested, perr := time.Parse(time.RFC3339, a.RequestedAt); perr != nil || now.Sub(requested) > breakGlassConfirmWindow {
		if _, err := b.store.SetActivationStatus(ctx, id, bgPending, bgExpired); err != nil {
			return BreakGlassActivation{}, err
		}
		return BreakGlassActivation{}, errBreakGlassLapsed
	}
	if human := b.auth.canonicalHuman(pd); human == a.RequestedBy || pd.ID == a.RequestedBy {
		return BreakGlassActivation{}, errBreakGlassSameHuman
	}
	activated, expires := now.UTC().Format(time.RFC3339), now.UTC().Add(breakGlassTTL).Format(time.RFC3339)
	won, err := b.store.ConfirmActivation(ctx, id, b.auth.canonicalHuman(pd), activated, expires)
	if err != nil {
		return BreakGlassActivation{}, err
	}
	if !won {
		return BreakGlassActivation{}, errBreakGlassNotPending
	}
	a.Status, a.ConfirmedBy, a.ActivatedAt, a.ExpiresAt = bgActive, b.auth.canonicalHuman(pd), activated, expires
	return a, nil
}

// Active returns the live window, lazily persisting its expiry.
func (b *BreakGlass) Active(ctx context.Context) (BreakGlassActivation, bool) {
	a, found, err := b.store.CurrentActive(ctx)
	if err != nil || !found {
		return BreakGlassActivation{}, false
	}
	expires, perr := time.Parse(time.RFC3339, a.ExpiresAt)
	if perr != nil || !b.now().Before(expires) {
		if _, err := b.store.SetActivationStatus(ctx, a.ID, bgActive, bgExpired); err != nil {
			logging.Errorf("break-glass: could not persist expiry of %s: %v", a.ID, err)
		}
		return BreakGlassActivation{}, false
	}
	return a, true
}

// RecordUse records a use of the live override window.
func (b *BreakGlass) RecordUse(ctx context.Context, r *http.Request, actor, usage, detail string) (BreakGlassReview, error) {
	act, ok := b.Active(ctx)
	if !ok {
		return BreakGlassReview{}, errBreakGlassNotActive
	}
	return b.recordUse(ctx, r, "act-"+act.ID, actor, usage, detail, true)
}

// recordUse audits the use, alerts synchronously (so the alert is not
// delayed behind anything), then opens the scope's review on first use or
// extends it. The local-login path passes requireWindow=false: it exists for
// when no two holders can be reached, so it alerts and is reviewed all the
// same.
func (b *BreakGlass) recordUse(ctx context.Context, r *http.Request, scope, actor, usage, detail string, requireWindow bool) (BreakGlassReview, error) {
	if requireWindow {
		if _, ok := b.Active(ctx); !ok {
			return BreakGlassReview{}, errBreakGlassNotActive
		}
	}
	resource := strings.TrimPrefix(scope, "act-")
	emitAuditEventDetail(r, b.audit, actor, "breakglass.used", "breakglass", resource, AuditOutcomeSuccess, usage+": "+detail)

	rid, err := newBreakGlassID("bgr-")
	if err != nil {
		return BreakGlassReview{}, err
	}
	now := b.now()
	review, _, err := b.store.UseReview(ctx, BreakGlassReview{
		ID: rid, ActivationID: scope, Status: bgOpen, OpenedAt: now.UTC().Format(time.RFC3339),
		DueAt: now.UTC().Add(breakGlassReviewDue).Format(time.RFC3339),
	}, actor)
	reviewID := review.ID
	b.alert(BreakGlassAlert{Event: "breakglass.used", ActivationID: resource, ReviewID: reviewID, Detail: usage + ": " + detail})
	if err != nil {
		return BreakGlassReview{}, err
	}
	return review, nil
}

// CompleteReview closes an after-action review. The reviewer must be an
// administrator (never the bootstrap token) who neither held nor used the
// override being reviewed.
func (b *BreakGlass) CompleteReview(ctx context.Context, pd AuthPrincipal, id, outcome, notes string) (BreakGlassReview, error) {
	if b.auth.isBootstrapHuman(pd) {
		return BreakGlassReview{}, errBreakGlassBootstrap
	}
	if !isAdminRole(pd.Role) {
		return BreakGlassReview{}, errBreakGlassNotHolder
	}
	if outcome != "justified" && outcome != "unjustified" {
		return BreakGlassReview{}, fmt.Errorf("%w: outcome must be justified or unjustified", errBreakGlassBadInput)
	}
	notes = strings.TrimSpace(notes)
	if len(notes) > maxBreakGlassNotes {
		return BreakGlassReview{}, fmt.Errorf("%w: notes are too long", errBreakGlassBadInput)
	}
	rv, found, err := b.store.GetReview(ctx, id)
	if err != nil {
		return BreakGlassReview{}, err
	}
	if !found {
		return BreakGlassReview{}, errBreakGlassNotFound
	}
	if rv.Status == bgCompleted {
		return BreakGlassReview{}, errBreakGlassReviewDone
	}
	involved := map[string]bool{}
	for _, a := range rv.Actors {
		involved[a] = true
	}
	if strings.HasPrefix(rv.ActivationID, "act-") {
		if act, ok, err := b.store.GetActivation(ctx, strings.TrimPrefix(rv.ActivationID, "act-")); err == nil && ok {
			involved[act.RequestedBy], involved[act.ConfirmedBy] = true, true
		}
	}
	if involved[b.auth.canonicalHuman(pd)] || involved[pd.ID] {
		return BreakGlassReview{}, errBreakGlassInvolved
	}
	done, err := b.store.CompleteReview(ctx, id, b.auth.canonicalHuman(pd), b.stamp(), outcome, notes)
	if err != nil {
		return BreakGlassReview{}, err
	}
	if !done {
		return BreakGlassReview{}, errBreakGlassReviewDone
	}
	rv, _, _ = b.store.GetReview(ctx, id)
	return b.withOverdue(rv), nil
}

func (b *BreakGlass) withOverdue(rv BreakGlassReview) BreakGlassReview {
	if due, err := time.Parse(time.RFC3339, rv.DueAt); err == nil {
		rv.Overdue = rv.Status == bgOpen && b.now().After(due)
	}
	return rv
}

// Reviews lists reviews, optionally by status ("open", "completed" or "").
func (b *BreakGlass) Reviews(ctx context.Context, status string) ([]BreakGlassReview, error) {
	all, err := b.store.ListReviews(ctx, status)
	if err != nil {
		return nil, err
	}
	for i := range all {
		all[i] = b.withOverdue(all[i])
	}
	return all, nil
}

// ---- store -----------------------------------------------------------------

type breakGlassStore interface {
	EnsureSchema(ctx context.Context) error
	// CreateActivationIfFree inserts a pending activation unless another is
	// pending (and not lapsed) or active (and not expired) at now.
	CreateActivationIfFree(ctx context.Context, a BreakGlassActivation, now time.Time) (bool, error)
	GetActivation(ctx context.Context, id string) (BreakGlassActivation, bool, error)
	// ConfirmActivation is a compare-and-set on status='pending'.
	ConfirmActivation(ctx context.Context, id, confirmedBy, activatedAt, expiresAt string) (bool, error)
	SetActivationStatus(ctx context.Context, id, from, to string) (bool, error)
	CurrentActive(ctx context.Context) (BreakGlassActivation, bool, error)
	// UseReview opens review.ActivationID's review (created=true) or bumps the
	// open one's use_count and actors, returning the stored row.
	UseReview(ctx context.Context, review BreakGlassReview, actor string) (stored BreakGlassReview, created bool, err error)
	GetReview(ctx context.Context, id string) (BreakGlassReview, bool, error)
	ListReviews(ctx context.Context, status string) ([]BreakGlassReview, error)
	// CompleteReview is a compare-and-set on status='open'.
	CompleteReview(ctx context.Context, id, by, at, outcome, notes string) (bool, error)
}

func addActor(actors []string, actor string) []string {
	for _, a := range actors {
		if a == actor {
			return actors
		}
	}
	return append(actors, actor)
}

// breakGlassBusy mirrors the SQL busy predicate for the memory store.
func breakGlassBusy(a BreakGlassActivation, now time.Time) bool {
	switch a.Status {
	case bgPending:
		t, err := time.Parse(time.RFC3339, a.RequestedAt)
		return err == nil && now.Sub(t) <= breakGlassConfirmWindow
	case bgActive:
		t, err := time.Parse(time.RFC3339, a.ExpiresAt)
		return err == nil && now.Before(t)
	}
	return false
}

type memBreakGlassStore struct {
	mu          sync.Mutex
	activations map[string]BreakGlassActivation
	reviews     map[string]BreakGlassReview
}

func newMemBreakGlassStore() *memBreakGlassStore {
	return &memBreakGlassStore{activations: map[string]BreakGlassActivation{}, reviews: map[string]BreakGlassReview{}}
}

func (m *memBreakGlassStore) EnsureSchema(context.Context) error { return nil }

func (m *memBreakGlassStore) CreateActivationIfFree(_ context.Context, a BreakGlassActivation, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.activations {
		if breakGlassBusy(x, now) {
			return false, nil
		}
	}
	m.activations[a.ID] = a
	return true, nil
}

func (m *memBreakGlassStore) GetActivation(_ context.Context, id string) (BreakGlassActivation, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.activations[id]
	return a, ok, nil
}

func (m *memBreakGlassStore) ConfirmActivation(_ context.Context, id, confirmedBy, activatedAt, expiresAt string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.activations[id]
	if !ok || a.Status != bgPending {
		return false, nil
	}
	a.Status, a.ConfirmedBy, a.ActivatedAt, a.ExpiresAt = bgActive, confirmedBy, activatedAt, expiresAt
	m.activations[id] = a
	return true, nil
}

func (m *memBreakGlassStore) SetActivationStatus(_ context.Context, id, from, to string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.activations[id]
	if !ok || a.Status != from {
		return false, nil
	}
	a.Status = to
	m.activations[id] = a
	return true, nil
}

func (m *memBreakGlassStore) CurrentActive(context.Context) (BreakGlassActivation, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best BreakGlassActivation
	found := false
	for _, a := range m.activations {
		if a.Status == bgActive && (!found || a.ActivatedAt > best.ActivatedAt) {
			best, found = a, true
		}
	}
	return best, found, nil
}

func (m *memBreakGlassStore) UseReview(_ context.Context, review BreakGlassReview, actor string) (BreakGlassReview, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, rv := range m.reviews {
		if rv.ActivationID == review.ActivationID && rv.Status == bgOpen {
			rv.UseCount++
			rv.Actors = addActor(append([]string(nil), rv.Actors...), actor)
			m.reviews[id] = rv
			return rv, false, nil
		}
	}
	review.UseCount, review.Actors = 1, []string{actor}
	m.reviews[review.ID] = review
	return review, true, nil
}

func (m *memBreakGlassStore) GetReview(_ context.Context, id string) (BreakGlassReview, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rv, ok := m.reviews[id]
	return rv, ok, nil
}

func (m *memBreakGlassStore) ListReviews(_ context.Context, status string) ([]BreakGlassReview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []BreakGlassReview
	for _, rv := range m.reviews {
		if status == "" || rv.Status == status {
			out = append(out, rv)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OpenedAt < out[j].OpenedAt || (out[i].OpenedAt == out[j].OpenedAt && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (m *memBreakGlassStore) CompleteReview(_ context.Context, id, by, at, outcome, notes string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rv, ok := m.reviews[id]
	if !ok || rv.Status != bgOpen {
		return false, nil
	}
	rv.Status, rv.CompletedBy, rv.CompletedAt, rv.Outcome, rv.Notes = bgCompleted, by, at, outcome, notes
	m.reviews[id] = rv
	return true, nil
}

var breakGlassSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS breakglass_activations (
  id TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
  requested_by TEXT NOT NULL DEFAULT '', confirmed_by TEXT NOT NULL DEFAULT '',
  requested_at TEXT NOT NULL DEFAULT '', activated_at TEXT NOT NULL DEFAULT '', expires_at TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE IF NOT EXISTS breakglass_reviews (
  id TEXT PRIMARY KEY, activation_id TEXT NOT NULL, status TEXT NOT NULL,
  opened_at TEXT NOT NULL DEFAULT '', due_at TEXT NOT NULL DEFAULT '',
  completed_by TEXT NOT NULL DEFAULT '', completed_at TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
  use_count INTEGER NOT NULL DEFAULT 0, actors TEXT NOT NULL DEFAULT '[]')`,
	`CREATE UNIQUE INDEX IF NOT EXISTS breakglass_reviews_one_open_per_scope ON breakglass_reviews (activation_id) WHERE status = 'open'`,
}

// dbBreakGlassStore serves sqlite and postgres; ph is the placeholder style.
type dbBreakGlassStore struct {
	db *sql.DB
	ph func(int) string
}

func (s *dbBreakGlassStore) EnsureSchema(ctx context.Context) error {
	return execSchemaStatements(ctx, s.db, breakGlassSchemaStatements)
}

const breakGlassActivationCols = `id, reason, status, requested_by, confirmed_by, requested_at, activated_at, expires_at`

func scanActivation(row interface{ Scan(...any) error }) (BreakGlassActivation, error) {
	var a BreakGlassActivation
	err := row.Scan(&a.ID, &a.Reason, &a.Status, &a.RequestedBy, &a.ConfirmedBy, &a.RequestedAt, &a.ActivatedAt, &a.ExpiresAt)
	return a, err
}

func (s *dbBreakGlassStore) CreateActivationIfFree(ctx context.Context, a BreakGlassActivation, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	// RFC 3339 UTC strings of one precision order lexicographically.
	cutoff := now.UTC().Add(-breakGlassConfirmWindow).Format(time.RFC3339)
	var busy int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM breakglass_activations
		WHERE (status = 'pending' AND requested_at >= `+s.ph(1)+`) OR (status = 'active' AND expires_at > `+s.ph(2)+`)`,
		cutoff, now.UTC().Format(time.RFC3339)).Scan(&busy); err != nil {
		return false, err
	}
	if busy > 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO breakglass_activations (`+breakGlassActivationCols+`) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8)),
		a.ID, a.Reason, a.Status, a.RequestedBy, a.ConfirmedBy, a.RequestedAt, a.ActivatedAt, a.ExpiresAt); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *dbBreakGlassStore) GetActivation(ctx context.Context, id string) (BreakGlassActivation, bool, error) {
	a, err := scanActivation(s.db.QueryRowContext(ctx, `SELECT `+breakGlassActivationCols+` FROM breakglass_activations WHERE id = `+s.ph(1), id))
	if err == sql.ErrNoRows {
		return BreakGlassActivation{}, false, nil
	}
	return a, err == nil, err
}

func (s *dbBreakGlassStore) ConfirmActivation(ctx context.Context, id, confirmedBy, activatedAt, expiresAt string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE breakglass_activations SET status = 'active', confirmed_by = `+s.ph(1)+`, activated_at = `+s.ph(2)+`, expires_at = `+s.ph(3)+
		` WHERE id = `+s.ph(4)+` AND status = 'pending'`, confirmedBy, activatedAt, expiresAt, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *dbBreakGlassStore) SetActivationStatus(ctx context.Context, id, from, to string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE breakglass_activations SET status = `+s.ph(1)+` WHERE id = `+s.ph(2)+` AND status = `+s.ph(3), to, id, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *dbBreakGlassStore) CurrentActive(ctx context.Context) (BreakGlassActivation, bool, error) {
	a, err := scanActivation(s.db.QueryRowContext(ctx, `SELECT `+breakGlassActivationCols+` FROM breakglass_activations WHERE status = 'active' ORDER BY activated_at DESC LIMIT 1`))
	if err == sql.ErrNoRows {
		return BreakGlassActivation{}, false, nil
	}
	return a, err == nil, err
}

const breakGlassReviewCols = `id, activation_id, status, opened_at, due_at, completed_by, completed_at, outcome, notes, use_count, actors`

func scanReview(row interface{ Scan(...any) error }) (BreakGlassReview, error) {
	var rv BreakGlassReview
	var actors string
	if err := row.Scan(&rv.ID, &rv.ActivationID, &rv.Status, &rv.OpenedAt, &rv.DueAt, &rv.CompletedBy, &rv.CompletedAt, &rv.Outcome, &rv.Notes, &rv.UseCount, &actors); err != nil {
		return BreakGlassReview{}, err
	}
	if err := json.Unmarshal([]byte(actors), &rv.Actors); err != nil {
		rv.Actors = nil
	}
	return rv, nil
}

func (s *dbBreakGlassStore) UseReview(ctx context.Context, review BreakGlassReview, actor string) (BreakGlassReview, bool, error) {
	// Two attempts: a concurrent first use can win the INSERT between our
	// SELECT and INSERT (the partial unique index refuses ours); the second
	// pass then finds and bumps theirs.
	for attempt := 0; attempt < 3; attempt++ {
		rv, created, err := s.useReviewOnce(ctx, review, actor)
		if err != nil {
			return BreakGlassReview{}, false, err
		}
		if rv.ID != "" {
			return rv, created, nil
		}
	}
	return BreakGlassReview{}, false, fmt.Errorf("break-glass review for %s kept racing", review.ActivationID)
}

func (s *dbBreakGlassStore) useReviewOnce(ctx context.Context, review BreakGlassReview, actor string) (BreakGlassReview, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BreakGlassReview{}, false, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	existing, err := scanReview(tx.QueryRowContext(ctx, `SELECT `+breakGlassReviewCols+` FROM breakglass_reviews WHERE activation_id = `+s.ph(1)+` AND status = 'open'`, review.ActivationID))
	switch {
	case err == nil:
		existing.UseCount++
		existing.Actors = addActor(existing.Actors, actor)
		raw, _ := json.Marshal(existing.Actors)
		if _, err := tx.ExecContext(ctx, `UPDATE breakglass_reviews SET use_count = `+s.ph(1)+`, actors = `+s.ph(2)+` WHERE id = `+s.ph(3), existing.UseCount, string(raw), existing.ID); err != nil {
			return BreakGlassReview{}, false, err
		}
		return existing, false, tx.Commit()
	case err != sql.ErrNoRows:
		return BreakGlassReview{}, false, err
	}
	review.UseCount, review.Actors = 1, []string{actor}
	raw, _ := json.Marshal(review.Actors)
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO breakglass_reviews (`+breakGlassReviewCols+`) VALUES (%s,%s,%s,%s,%s,'','','','',%s,%s) ON CONFLICT DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7)),
		review.ID, review.ActivationID, review.Status, review.OpenedAt, review.DueAt, review.UseCount, string(raw))
	if err != nil {
		return BreakGlassReview{}, false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return BreakGlassReview{}, false, nil // lost the race; caller retries
	}
	return review, true, tx.Commit()
}

func (s *dbBreakGlassStore) GetReview(ctx context.Context, id string) (BreakGlassReview, bool, error) {
	rv, err := scanReview(s.db.QueryRowContext(ctx, `SELECT `+breakGlassReviewCols+` FROM breakglass_reviews WHERE id = `+s.ph(1), id))
	if err == sql.ErrNoRows {
		return BreakGlassReview{}, false, nil
	}
	return rv, err == nil, err
}

func (s *dbBreakGlassStore) ListReviews(ctx context.Context, status string) ([]BreakGlassReview, error) {
	q, args := `SELECT `+breakGlassReviewCols+` FROM breakglass_reviews`, []any{}
	if status != "" {
		q += ` WHERE status = ` + s.ph(1)
		args = append(args, status)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY opened_at, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassReview
	for rows.Next() {
		rv, err := scanReview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, rows.Err()
}

func (s *dbBreakGlassStore) CompleteReview(ctx context.Context, id, by, at, outcome, notes string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE breakglass_reviews SET status = 'completed', completed_by = `+s.ph(1)+`, completed_at = `+s.ph(2)+`, outcome = `+s.ph(3)+`, notes = `+s.ph(4)+
		` WHERE id = `+s.ph(5)+` AND status = 'open'`, by, at, outcome, notes, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// lazyBreakGlassStore answers errStoreUnavailable until the configured
// database opens (D-290-A, S-04). Break-glass never falls back to memory:
// CreateActivationIfFree is a per-process singleton, so replicas would each
// grant their own elevation, and a restart would lose the review obligation.
// The "stays available in an outage" rationale does not hold: an outage that
// blocks this store also takes down the stores the elevation acts on.
type lazyBreakGlassStore struct{ *lazyStore[breakGlassStore] }

func (l lazyBreakGlassStore) EnsureSchema(context.Context) error { return nil }

func (l lazyBreakGlassStore) CreateActivationIfFree(ctx context.Context, a BreakGlassActivation, now time.Time) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.CreateActivationIfFree(ctx, a, now)
}

func (l lazyBreakGlassStore) GetActivation(ctx context.Context, id string) (BreakGlassActivation, bool, error) {
	s, err := l.get()
	if err != nil {
		return BreakGlassActivation{}, false, err
	}
	return s.GetActivation(ctx, id)
}

func (l lazyBreakGlassStore) ConfirmActivation(ctx context.Context, id, confirmedBy, activatedAt, expiresAt string) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.ConfirmActivation(ctx, id, confirmedBy, activatedAt, expiresAt)
}

func (l lazyBreakGlassStore) SetActivationStatus(ctx context.Context, id, from, to string) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.SetActivationStatus(ctx, id, from, to)
}

func (l lazyBreakGlassStore) CurrentActive(ctx context.Context) (BreakGlassActivation, bool, error) {
	s, err := l.get()
	if err != nil {
		return BreakGlassActivation{}, false, err
	}
	return s.CurrentActive(ctx)
}

func (l lazyBreakGlassStore) UseReview(ctx context.Context, review BreakGlassReview, actor string) (BreakGlassReview, bool, error) {
	s, err := l.get()
	if err != nil {
		return BreakGlassReview{}, false, err
	}
	return s.UseReview(ctx, review, actor)
}

func (l lazyBreakGlassStore) GetReview(ctx context.Context, id string) (BreakGlassReview, bool, error) {
	s, err := l.get()
	if err != nil {
		return BreakGlassReview{}, false, err
	}
	return s.GetReview(ctx, id)
}

func (l lazyBreakGlassStore) ListReviews(ctx context.Context, status string) ([]BreakGlassReview, error) {
	s, err := l.get()
	if err != nil {
		return nil, err
	}
	return s.ListReviews(ctx, status)
}

func (l lazyBreakGlassStore) CompleteReview(ctx context.Context, id, by, at, outcome, notes string) (bool, error) {
	s, err := l.get()
	if err != nil {
		return false, err
	}
	return s.CompleteReview(ctx, id, by, at, outcome, notes)
}

// newBreakGlassStoreFromEnv returns the DB-backed store behind a gate that
// fails closed while the database is down; memory only when
// APP_BREAKGLASS_PROVIDER=memory names it.
func newBreakGlassStoreFromEnv() breakGlassStore {
	if memoryProviderRequested("APP_BREAKGLASS_PROVIDER", "break-glass") {
		return newMemBreakGlassStore()
	}
	return lazyBreakGlassStore{newLazyStore("breakglass", openBreakGlassStore, nil)}
}

func openBreakGlassStore() (breakGlassStore, error) {
	state := newDBProviderState[breakGlassStore](
		"breakglass",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_BREAKGLASS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_BREAKGLASS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_BREAKGLASS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) breakGlassStore { return &dbBreakGlassStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) breakGlassStore { return &dbBreakGlassStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr == nil && state.store != nil {
		if err := state.store.EnsureSchema(context.Background()); err == nil {
			return state.store, nil
		} else {
			if db, ok := state.store.(*dbBreakGlassStore); ok {
				releaseFailedOpenDB("breakglass", db.db)
			}
			state.openErr = err
		}
	}
	if state.openErr == nil {
		state.openErr = errStoreUnavailable
	}
	return nil, dbProviderUnavailable("breakglass", state.openErr) // logs the cause; callers see only errStoreUnavailable
}

// ---- handlers --------------------------------------------------------------

const breakGlassBase = "/api/v1/auth/breakglass"

// registerBreakGlassHandlers builds the manager, publishes it for W22-38, mounts
// the routes and then runs every registered route hook. Routes sit under
// /api/v1/auth/ (permSelf in the write gate) because holders are not admins and
// would be refused by /admin/**; each handler enforces its own checks.
func registerBreakGlassHandlers(mux *http.ServeMux, auth *Authenticator, users UserProvider, audit AuditProvider) {
	store := newBreakGlassStoreFromEnv()
	auth.requireStore(store)
	b := NewBreakGlass(store, users, auth, audit, time.Now, defaultBreakGlassAlert)
	b.roles = accessReviewRoles(auth)
	mountBreakGlass(gateRoutes(mux, store), b, auth)
	setActiveBreakGlass(b)
	for _, hook := range breakGlassRouteHooks {
		hook(mux, b, auth)
	}
}

func mountBreakGlass(mux routeRegistrar, b *BreakGlass, auth *Authenticator) {
	h := &breakGlassAPI{b: b, auth: auth}
	mux.HandleFunc("/api/v1/auth/breakglass/activations", h.activations)
	mux.HandleFunc("/api/v1/auth/breakglass/activations/", h.confirm)
	mux.HandleFunc("/api/v1/auth/breakglass/status", h.status)
	mux.HandleFunc("/api/v1/auth/breakglass/reviews", h.reviews)
	mux.HandleFunc("/api/v1/auth/breakglass/reviews/", h.completeReview)
}

type breakGlassAPI struct {
	b    *BreakGlass
	auth *Authenticator
}

func (h *breakGlassAPI) authenticate(w http.ResponseWriter, r *http.Request, action, resource string) (AuthPrincipal, bool) {
	pd, err := h.auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, h.b.audit, "", action, "breakglass", resource, AuditOutcomeDenied)
		writeUnauthorized(w)
		return AuthPrincipal{}, false
	}
	return pd, true
}

// fail maps a manager error to a response and audits the refusal.
func (h *breakGlassAPI) fail(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action, resource string, err error) {
	outcome := AuditOutcomeDenied
	switch {
	case errors.Is(err, errBreakGlassBootstrap):
		writeForbidden(w, msgBootstrapCannotApprove)
	case errors.Is(err, errBreakGlassSameHuman):
		writeForbidden(w, msgSelfApproval)
	case errors.Is(err, errBreakGlassNotHolder), errors.Is(err, errBreakGlassNamedOnly), errors.Is(err, errBreakGlassInvolved):
		writeForbidden(w, err.Error())
	case errors.Is(err, errBreakGlassLapsed):
		writeJSONStatus(w, http.StatusGone, map[string]any{"error": map[string]string{"code": "gone", "message": err.Error()}})
	case errors.Is(err, errBreakGlassBusy), errors.Is(err, errBreakGlassNotPending), errors.Is(err, errBreakGlassReviewDone):
		outcome = AuditOutcomeFailure
		writeConflict(w, err.Error())
	case errors.Is(err, errBreakGlassNotFound):
		outcome = AuditOutcomeFailure
		writeNotFound(w, "not found")
	case errors.Is(err, errBreakGlassBadInput):
		outcome = AuditOutcomeFailure
		writeBadRequest(w, strings.TrimPrefix(err.Error(), errBreakGlassBadInput.Error()+": "))
	default:
		outcome = AuditOutcomeFailure
		logging.Errorf("break-glass %s: %v", action, err)
		writeServiceUnavailable(w, "break-glass unavailable")
	}
	emitAuditEventDetail(r, h.b.audit, pd.ID, action, "breakglass", resource, outcome, err.Error())
}

func (h *breakGlassAPI) activations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	pd, ok := h.authenticate(w, r, "breakglass.request", "activation")
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeJSONBodyOrReject(w, r, &req, maxBreakGlassBody, "invalid request body") {
		return
	}
	a, err := h.b.Request(r.Context(), pd, req.Reason)
	if err != nil {
		h.fail(w, r, pd, "breakglass.request", "activation", err)
		return
	}
	emitAuditEventDetail(r, h.b.audit, pd.ID, "breakglass.request", "breakglass", a.ID, AuditOutcomeSuccess, "reason="+a.Reason)
	writeJSONStatus(w, http.StatusCreated, map[string]any{"data": a})
}

func (h *breakGlassAPI) confirm(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, breakGlassBase+"/activations/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" || sub != "confirm" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	pd, ok := h.authenticate(w, r, "breakglass.activate", id)
	if !ok {
		return
	}
	a, err := h.b.Confirm(r.Context(), pd, id)
	if err != nil {
		h.fail(w, r, pd, "breakglass.activate", id, err)
		return
	}
	emitAuditEventDetail(r, h.b.audit, pd.ID, "breakglass.activate", "breakglass", a.ID, AuditOutcomeSuccess,
		fmt.Sprintf("holders=%s,%s;expires_at=%s", a.RequestedBy, a.ConfirmedBy, a.ExpiresAt))
	writeJSONData(w, a)
}

// mayView: a holder, or an administrator. With multi-tenancy on, an
// administrator must be an unscoped super-admin: the window and its reviews
// are instance-wide, not a tenant's data.
func (h *breakGlassAPI) mayView(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action string) bool {
	if h.b.IsHolder(r.Context(), pd) == nil {
		return true
	}
	if _, admin := principalPermissions(pd, h.b.roles); !admin {
		emitAuditEvent(r, h.b.audit, pd.ID, action, "breakglass", "status", AuditOutcomeDenied)
		writeForbidden(w, "break-glass holders and administrators only")
		return false
	}
	return !denyNonSuperAdminGlobal(w, r, h.b.audit, pd, action, "breakglass", "status")
}

func (h *breakGlassAPI) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	pd, ok := h.authenticate(w, r, "breakglass.status", "status")
	if !ok || !h.mayView(w, r, pd, "breakglass.status") {
		return
	}
	out := map[string]any{"active": false}
	if a, active := h.b.Active(r.Context()); active {
		out["active"], out["activation"] = true, a
	}
	open, err := h.b.Reviews(r.Context(), bgOpen)
	if err != nil {
		writeServiceUnavailable(w, "break-glass unavailable")
		return
	}
	out["open_reviews"] = len(open)
	writeJSONData(w, out)
}

func (h *breakGlassAPI) reviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	pd, ok := h.authenticate(w, r, "breakglass.reviews", "reviews")
	if !ok || !h.mayView(w, r, pd, "breakglass.reviews") {
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != bgOpen && status != bgCompleted {
		writeBadRequest(w, "status must be open or completed")
		return
	}
	list, err := h.b.Reviews(r.Context(), status)
	if err != nil {
		writeServiceUnavailable(w, "break-glass unavailable")
		return
	}
	if list == nil {
		list = []BreakGlassReview{}
	}
	writeJSONData(w, map[string]any{"items": list})
}

func (h *breakGlassAPI) completeReview(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, breakGlassBase+"/reviews/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" || sub != "complete" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	pd, ok := h.authenticate(w, r, "breakglass.review", id)
	if !ok {
		return
	}
	if denyNonSuperAdminGlobal(w, r, h.b.audit, pd, "breakglass.review", "breakglass", id) {
		return
	}
	var req struct {
		Outcome string `json:"outcome"`
		Notes   string `json:"notes"`
	}
	if !decodeJSONBodyOrReject(w, r, &req, maxBreakGlassBody, "invalid request body") {
		return
	}
	rv, err := h.b.CompleteReview(r.Context(), pd, id, req.Outcome, req.Notes)
	if err != nil {
		h.fail(w, r, pd, "breakglass.review", id, err)
		return
	}
	emitAuditEventDetail(r, h.b.audit, pd.ID, "breakglass.review", "breakglass", rv.ID, AuditOutcomeSuccess, "outcome="+rv.Outcome+";scope="+rv.ActivationID)
	writeJSONData(w, rv)
}
