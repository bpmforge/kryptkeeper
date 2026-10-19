// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	drainBatch = 100
	// reconcileBatch bounds one reconcile pass (newest created tickets first).
	reconcileBatch = 500
	// DefaultReconcileInterval is how often Run checks that created tickets
	// still exist (W32-10 gives no figure; hourly keeps ITSM API load low).
	DefaultReconcileInterval = time.Hour
	maxErrorText             = 300
)

// ConnectorSource builds the Connector for a connection id. Errors (missing
// credential, kind without a factory) are retried like an outage: the row
// stays queued rather than being lost.
type ConnectorSource func(ctx context.Context, connectionID string) (Connector, error)

// Config wires a Service. Audit and Alert may be nil.
type Config struct {
	Store *Store
	Conns ConnectorSource
	Now   func() time.Time
	Audit func(ctx context.Context, rec AuditRecord)
	Alert func(ctx context.Context, class, detail string)
	// ReconcileInterval is how often Run reconciles created tickets; zero
	// means DefaultReconcileInterval.
	ReconcileInterval time.Duration
}

// Service is the connector-agnostic ITSM core.
type Service struct {
	store *Store
	conns ConnectorSource
	now   func() time.Time
	audit func(ctx context.Context, rec AuditRecord)
	alert func(ctx context.Context, class, detail string)

	reconcileEvery time.Duration
	lastReconcile  time.Time // zero until the first pass; only Run touches it

	mu          sync.Mutex
	unreachable map[string]bool // connection id -> last attempt failed temporarily
}

// NewService returns a Service; Now defaults to time.Now.
func NewService(c Config) *Service {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	every := c.ReconcileInterval
	if every <= 0 {
		every = DefaultReconcileInterval
	}
	return &Service{store: c.Store, conns: c.Conns, now: now, audit: c.Audit, alert: c.Alert, reconcileEvery: every, unreachable: map[string]bool{}}
}

// TestConnection checks that connectionID's connector can reach its ITSM with
// the stored credential, using one read-only Find. The returned error is
// classified (ErrTemporary / ErrPermanent / other) and may carry upstream
// text: callers must map it to a generic message, never echo it.
func (s *Service) TestConnection(ctx context.Context, connectionID string) error {
	if s.conns == nil {
		return errors.New("itsm: connector source not configured")
	}
	conn, err := s.conns(ctx, connectionID)
	if err != nil {
		return err
	}
	_, err = conn.Find(ctx, "kk-connection-test")
	return err
}

// Store exposes the underlying store for the connection and event APIs.
func (s *Service) Store() *Store { return s.store }

// Connector builds the connector of a connection (W32-12 polls approvals through it).
func (s *Service) Connector(ctx context.Context, connectionID string) (Connector, error) {
	return s.conns(ctx, connectionID)
}

func (s *Service) record(ctx context.Context, rec AuditRecord) {
	if s.audit != nil {
		s.audit(ctx, rec)
	}
}

func (s *Service) raise(ctx context.Context, class, detail string) {
	if s.alert != nil {
		s.alert(ctx, class, detail)
	}
}

// Submit enqueues ev for connectionID and returns without calling the ITSM.
// The same ev.ID submitted again, however often, leaves one row. An event
// whose class the connection does not subscribe to is dropped silently.
func (s *Service) Submit(ctx context.Context, connectionID string, ev Event) error {
	if strings.TrimSpace(ev.ID) == "" {
		return errors.New("itsm: event id is required")
	}
	conn, err := s.store.GetConnection(ctx, connectionID)
	if err != nil {
		return fmt.Errorf("itsm: connection %q: %w", connectionID, err)
	}
	if !conn.Enabled {
		return fmt.Errorf("itsm: connection %q is disabled", connectionID)
	}
	ticketType, subscribed := conn.TicketTypeFor(ev.Class)
	if !subscribed {
		return nil
	}
	if ev.TicketType == "" {
		ev.TicketType = ticketType
	}
	if ev.Tenant == "" {
		ev.Tenant = conn.Tenant
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = s.store.InsertEvent(ctx, EventRow{
		EventID: ev.ID, ConnectionID: connectionID, Class: ev.Class, Fingerprint: ev.Fingerprint,
		Payload: string(payload), Tenant: ev.Tenant,
	}, s.now())
	return err
}

// Drain processes every due pending row once and reports how many reached
// `created`. Per-row failures are recorded on the row; the returned error is
// only for storage failures.
func (s *Service) Drain(ctx context.Context) (done int, err error) {
	rows, err := s.store.DueEvents(ctx, s.now(), drainBatch)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		ok, err := s.process(ctx, row)
		if err != nil {
			return done, err
		}
		if ok {
			done++
		}
	}
	return done, nil
}

func (s *Service) process(ctx context.Context, row EventRow) (created bool, err error) {
	var ev Event
	if err := json.Unmarshal([]byte(row.Payload), &ev); err != nil {
		return false, s.fail(ctx, row, fmt.Errorf("%w: unreadable payload", ErrPermanent))
	}
	conn, err := s.conns(ctx, row.ConnectionID)
	if err != nil {
		return false, s.retryLater(ctx, row, err)
	}
	// Find before Create: a ticket made just before a crash lost the row
	// update is adopted instead of duplicated.
	ref, err := conn.Find(ctx, row.EventID)
	if err == nil && ref == nil {
		var made TicketRef
		made, err = conn.Create(ctx, ev)
		ref = &made
	}
	if err != nil {
		if errors.Is(err, ErrPermanent) {
			return false, s.fail(ctx, row, err)
		}
		return false, s.retryLater(ctx, row, err)
	}
	s.markReachable(row.ConnectionID)
	row.Status, row.TicketKey, row.TicketURL = StatusCreated, ref.Key, ref.URL
	row.Attempts, row.LastError = 0, ""
	if err := s.store.SaveEvent(ctx, row, s.now()); err != nil {
		return false, err
	}
	s.record(ctx, AuditRecord{Action: ActionTicketCreate, ResourceID: row.EventID, Outcome: OutcomeSuccess, Tenant: row.Tenant, ChangeSummary: "ticket=" + ref.Key})
	return true, nil
}

func (s *Service) retryLater(ctx context.Context, row EventRow, cause error) error {
	row.Attempts++
	row.NextAttemptAt = s.now().Add(BackoffDelay(row.Attempts))
	row.LastError = truncate(cause.Error())
	if err := s.store.SaveEvent(ctx, row, s.now()); err != nil {
		return err
	}
	s.mu.Lock()
	first := !s.unreachable[row.ConnectionID]
	s.unreachable[row.ConnectionID] = true
	s.mu.Unlock()
	if first {
		s.raise(ctx, AlertUnreachable, row.ConnectionID)
	}
	return nil
}

func (s *Service) markReachable(connectionID string) {
	s.mu.Lock()
	delete(s.unreachable, connectionID)
	s.mu.Unlock()
}

func (s *Service) fail(ctx context.Context, row EventRow, cause error) error {
	row.Status, row.LastError = StatusFailed, truncate(cause.Error())
	if err := s.store.SaveEvent(ctx, row, s.now()); err != nil {
		return err
	}
	s.record(ctx, AuditRecord{Action: ActionTicketCreate, ResourceID: row.EventID, Outcome: OutcomeFailure, Tenant: row.Tenant, ChangeSummary: row.LastError})
	return nil
}

func truncate(s string) string {
	if len(s) > maxErrorText {
		return s[:maxErrorText]
	}
	return s
}

// Reconcile checks a `created` row's ticket still exists. A ticket deleted
// externally is recreated once and flagged; deleted again, it is reported
// (audit + alert) and left alone.
func (s *Service) Reconcile(ctx context.Context, eventID string) error {
	row, err := s.store.GetEvent(ctx, eventID)
	if err != nil {
		return err
	}
	if _, err = s.reconcile(ctx, row); errors.Is(err, errGone) {
		return nil
	}
	return err
}

// reconcile returns the up-to-date row, or errGone when the ticket was
// deleted a second time.
func (s *Service) reconcile(ctx context.Context, row EventRow) (EventRow, error) {
	if row.Status != StatusCreated {
		return row, nil
	}
	conn, err := s.conns(ctx, row.ConnectionID)
	if err != nil {
		return row, err
	}
	exists, err := conn.Exists(ctx, TicketRef{Key: row.TicketKey, URL: row.TicketURL})
	if err != nil || exists {
		return row, err
	}
	if row.Recreated {
		// Report once per ticket: the marker in last_error survives restarts
		// (no schema change) and stops the hourly reconcile re-alerting.
		if row.LastError != deletedAgainMarker {
			row.LastError = deletedAgainMarker
			if err := s.store.SaveEvent(ctx, row, s.now()); err != nil {
				return row, err
			}
			s.record(ctx, AuditRecord{Action: ActionTicketCreate, ResourceID: row.EventID, Outcome: OutcomeFailure, Tenant: row.Tenant, ChangeSummary: deletedAgainMarker})
			s.raise(ctx, AlertTicketDeletedAgain, row.EventID)
		}
		return row, errGone
	}
	var ev Event
	if err := json.Unmarshal([]byte(row.Payload), &ev); err != nil {
		return row, err
	}
	ref, err := conn.Create(ctx, ev)
	if err != nil {
		return row, err
	}
	row.TicketKey, row.TicketURL, row.Recreated = ref.Key, ref.URL, true
	if err := s.store.SaveEvent(ctx, row, s.now()); err != nil {
		return row, err
	}
	s.record(ctx, AuditRecord{Action: ActionTicketCreate, ResourceID: row.EventID, Outcome: OutcomeSuccess, Tenant: row.Tenant, ChangeSummary: "recreated_after_external_delete ticket=" + ref.Key})
	return row, nil
}

// ReconcileAll reconciles every `created` ticket (newest first, bounded) and
// reports how many it checked. One failing ticket (ITSM outage, missing
// credential) does not stop the others; the errors are joined.
func (s *Service) ReconcileAll(ctx context.Context) (n int, err error) {
	rows, err := s.store.ListEvents(ctx, StatusCreated, reconcileBatch)
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, row := range rows {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		n++
		if _, err := s.reconcile(ctx, row); err != nil && !errors.Is(err, errGone) {
			errs = append(errs, fmt.Errorf("event %s: %w", row.EventID, err))
		}
	}
	return n, errors.Join(errs...)
}

// reconcileIfDue runs ReconcileAll once per reconcile interval. The first call
// only starts the clock: a freshly started hub drains before it reconciles.
func (s *Service) reconcileIfDue(ctx context.Context) (n int, err error) {
	now := s.now()
	if s.lastReconcile.IsZero() {
		s.lastReconcile = now
		return 0, nil
	}
	if now.Sub(s.lastReconcile) < s.reconcileEvery {
		return 0, nil
	}
	s.lastReconcile = now
	return s.ReconcileAll(ctx)
}

// deletedAgainMarker is stored in a created row's last_error once its
// recreated ticket was found deleted a second time (and reported).
const deletedAgainMarker = "deleted_externally_again"

// errGone marks a ticket deleted a second time; Reconcile reports it as nil
// (the audit row and alert are the report) while resolve skips the row.
var errGone = errors.New("itsm: ticket deleted externally again")

// ResolveByFingerprint closes the ticket of every `created` row carrying
// fingerprint (after a Reconcile) and marks the row resolved. It reports how
// many rows were resolved; failures on one row do not stop the others.
func (s *Service) ResolveByFingerprint(ctx context.Context, fingerprint, comment string) (n int, err error) {
	if fingerprint == "" {
		return 0, errors.New("itsm: fingerprint is required")
	}
	rows, err := s.store.CreatedByFingerprint(ctx, fingerprint)
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, row := range rows {
		row, err := s.reconcile(ctx, row)
		if errors.Is(err, errGone) {
			continue
		}
		if err == nil {
			err = s.resolveRow(ctx, row, comment)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("event %s: %w", row.EventID, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (s *Service) resolveRow(ctx context.Context, row EventRow, comment string) error {
	conn, err := s.conns(ctx, row.ConnectionID)
	if err != nil {
		return err
	}
	if err := conn.Resolve(ctx, TicketRef{Key: row.TicketKey, URL: row.TicketURL}, comment); err != nil {
		s.record(ctx, AuditRecord{Action: ActionTicketResolve, ResourceID: row.EventID, Outcome: OutcomeFailure, Tenant: row.Tenant, ChangeSummary: truncate(err.Error())})
		return err
	}
	row.Status = StatusResolved
	if err := s.store.SaveEvent(ctx, row, s.now()); err != nil {
		return err
	}
	s.record(ctx, AuditRecord{Action: ActionTicketResolve, ResourceID: row.EventID, Outcome: OutcomeSuccess, Tenant: row.Tenant, ChangeSummary: "ticket=" + row.TicketKey})
	return nil
}

// Run drains every interval, and reconciles created tickets once per
// reconcile interval, until ctx is done.
func (s *Service) Run(ctx context.Context, interval time.Duration, logf func(format string, args ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Drain(ctx); err != nil && logf != nil {
				logf("itsm: drain: %v", err)
			}
			if _, err := s.reconcileIfDue(ctx); err != nil && logf != nil {
				logf("itsm: reconcile: %v", err)
			}
		}
	}
}
