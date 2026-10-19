// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/connectors"
)

// W27-24: domain control validation (DCV) lifetime tracking. A CA may reuse a
// prior validation only for a limited period that CA/Browser Forum ballots
// step down over time, so the period is a date-keyed table, not a constant.

// DCVReuseStep is one row of the reuse schedule: from Effective on, a
// validation may be reused for Days.
type DCVReuseStep struct {
	Effective time.Time
	Days      int
}

// DCVSchedule is sorted ascending by Effective.
type DCVSchedule []DCVReuseStep

// DefaultDCVSchedule is the CA/B Forum BR 3.2.2.4 reuse schedule (398 days,
// then 200/100/10 from the dates the ballot fixes). The schedule is
// operator-overridable (KRYPTKEEPER_DCV_REUSE_SCHEDULE) because the dates
// must be re-checked against the current Baseline Requirements text.
func DefaultDCVSchedule() DCVSchedule {
	d := func(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 0, 0, 0, 0, time.UTC) }
	return DCVSchedule{
		{Effective: d(1970, 1, 1), Days: 398},
		{Effective: d(2026, 3, 15), Days: 200},
		{Effective: d(2027, 3, 15), Days: 100},
		{Effective: d(2029, 3, 15), Days: 10},
	}
}

// PeriodAt is the reuse period in force at t: the last step whose Effective
// is not after t, or the first step when t precedes the table.
func (s DCVSchedule) PeriodAt(t time.Time) int {
	if len(s) == 0 {
		return 0
	}
	days := s[0].Days
	for _, step := range s {
		if step.Effective.After(t) {
			break
		}
		days = step.Days
	}
	return days
}

// effectiveDays is min(period fixed when the validation happened, period in
// force now): a later step-down shortens validations already on file.
func (s DCVSchedule) effectiveDays(validatedAt, now time.Time) int {
	stored, current := s.PeriodAt(validatedAt), s.PeriodAt(now)
	if current < stored {
		return current
	}
	return stored
}

// remainingExact is the fractional days left, possibly negative.
func (s DCVSchedule) remainingExact(validatedAt, now time.Time) (days float64, effective int) {
	effective = s.effectiveDays(validatedAt, now)
	end := validatedAt.UTC().Add(time.Duration(effective) * 24 * time.Hour)
	return end.Sub(now.UTC()).Hours() / 24, effective
}

// DaysRemaining is whole days (floored, never negative) until the validation
// made at validatedAt can no longer be reused.
func (s DCVSchedule) DaysRemaining(validatedAt, now time.Time) int {
	exact, _ := s.remainingExact(validatedAt, now)
	if exact <= 0 {
		return 0
	}
	return int(exact)
}

// LoadDCVScheduleFromEnv reads KRYPTKEEPER_DCV_REUSE_SCHEDULE, a JSON array
// like [{"effective":"2026-03-15","days":200}]. Empty means the default.
func LoadDCVScheduleFromEnv() (DCVSchedule, error) {
	raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DCV_REUSE_SCHEDULE"))
	if raw == "" {
		return DefaultDCVSchedule(), nil
	}
	var in []struct {
		Effective string `json:"effective"`
		Days      int    `json:"days"`
	}
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("KRYPTKEEPER_DCV_REUSE_SCHEDULE: %w", err)
	}
	if len(in) == 0 {
		return nil, errors.New("KRYPTKEEPER_DCV_REUSE_SCHEDULE: at least one step is required")
	}
	out := make(DCVSchedule, 0, len(in))
	for _, row := range in {
		eff, err := time.Parse("2006-01-02", row.Effective)
		if err != nil {
			return nil, fmt.Errorf("KRYPTKEEPER_DCV_REUSE_SCHEDULE: effective %q: %w", row.Effective, err)
		}
		if row.Days <= 0 {
			return nil, fmt.Errorf("KRYPTKEEPER_DCV_REUSE_SCHEDULE: days for %s must be positive", row.Effective)
		}
		out = append(out, DCVReuseStep{Effective: eff.UTC(), Days: row.Days})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Effective.Before(out[j].Effective) })
	return out, nil
}

type DCVValidation struct {
	Domain      string
	ConnectorID string
	Tenant      string
	ValidatedAt time.Time
	ExpiresAt   time.Time
	ReuseDays   int
	WarnedAt    *time.Time
}

type DCVStore interface {
	EnsureSchema(ctx context.Context) error
	Upsert(ctx context.Context, v DCVValidation) error
	List(ctx context.Context) ([]DCVValidation, error)
	MarkWarned(ctx context.Context, domain, connectorID string, at time.Time) error
}

const dcvSchema = `
CREATE TABLE IF NOT EXISTS dcv_validations (
    domain       TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    tenant       TEXT NOT NULL DEFAULT 'default',
    validated_at TEXT NOT NULL,
    reuse_days   INTEGER NOT NULL,
    expires_at   TEXT NOT NULL,
    warned_at    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (domain, connector_id)
);
CREATE INDEX IF NOT EXISTS idx_dcv_validations_tenant ON dcv_validations(tenant);`

type dbDCVStore struct {
	db       *sql.DB
	postgres bool
}

func newDCVStore(db *sql.DB, postgres bool) DCVStore { return &dbDCVStore{db: db, postgres: postgres} }

func (s *dbDCVStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *dbDCVStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, dcvSchema)
	return err
}

// Upsert leaves warned_at alone: WarnScan compares it with validated_at, so a
// re-validation re-arms the warning without clearing history.
func (s *dbDCVStore) Upsert(ctx context.Context, v DCVValidation) error {
	if v.Tenant == "" {
		v.Tenant = DefaultTenant
	}
	q := fmt.Sprintf(`INSERT INTO dcv_validations (domain, connector_id, tenant, validated_at, reuse_days, expires_at)
		VALUES (%s, %s, %s, %s, %s, %s)
		ON CONFLICT (domain, connector_id) DO UPDATE SET
		  tenant = excluded.tenant, validated_at = excluded.validated_at,
		  reuse_days = excluded.reuse_days, expires_at = excluded.expires_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6))
	_, err := s.db.ExecContext(ctx, q, v.Domain, v.ConnectorID, v.Tenant,
		v.ValidatedAt.UTC().Format(time.RFC3339), v.ReuseDays, v.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func (s *dbDCVStore) List(ctx context.Context) ([]DCVValidation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain, connector_id, tenant, validated_at, reuse_days, expires_at, warned_at
		FROM dcv_validations ORDER BY domain, connector_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DCVValidation{}
	for rows.Next() {
		var v DCVValidation
		var validated, expires, warned string
		if err := rows.Scan(&v.Domain, &v.ConnectorID, &v.Tenant, &validated, &v.ReuseDays, &expires, &warned); err != nil {
			return nil, err
		}
		if v.ValidatedAt, err = time.Parse(time.RFC3339, validated); err != nil {
			return nil, fmt.Errorf("dcv_validations %s: validated_at: %w", v.Domain, err)
		}
		if v.ExpiresAt, err = time.Parse(time.RFC3339, expires); err != nil {
			return nil, fmt.Errorf("dcv_validations %s: expires_at: %w", v.Domain, err)
		}
		if warned != "" {
			if w, err := time.Parse(time.RFC3339, warned); err == nil {
				v.WarnedAt = &w
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *dbDCVStore) MarkWarned(ctx context.Context, domain, connectorID string, at time.Time) error {
	q := fmt.Sprintf(`UPDATE dcv_validations SET warned_at = %s WHERE domain = %s AND connector_id = %s`, s.ph(1), s.ph(2), s.ph(3))
	_, err := s.db.ExecContext(ctx, q, at.UTC().Format(time.RFC3339), domain, connectorID)
	return err
}

func newDCVStoreFromEnv() DCVStore {
	state := newDBProviderState[DCVStore](
		"dcv",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_DCV_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_DCV_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_DCV_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) DCVStore { return newDCVStore(db, false) },
		func(db *sql.DB) DCVStore { return newDCVStore(db, true) },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("dcv", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("dcv", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

type DCVTracker struct {
	store DCVStore
	sched DCVSchedule
	audit AuditProvider
	now   func() time.Time
}

func NewDCVTracker(store DCVStore, sched DCVSchedule, audit AuditProvider) *DCVTracker {
	return &DCVTracker{store: store, sched: sched, audit: audit, now: time.Now}
}

// withAudit returns a copy bound to an audit provider, so the process-wide
// tracker is never mutated after construction.
func (t *DCVTracker) withAudit(a AuditProvider) *DCVTracker {
	cp := *t
	cp.audit = a
	return &cp
}

var (
	dcvSharedOnce    sync.Once
	dcvSharedTracker *DCVTracker
)

// sharedDCVTracker is the process-wide tracker, opened on first use so
// handler registration never touches the DB. BuildConnectorRegistry runs per
// renewal, so every registry's ACME connectors record into the same store.
// Nil means the DCV store is unavailable; callers then skip tracking.
func sharedDCVTracker() *DCVTracker {
	dcvSharedOnce.Do(func() {
		store := newDCVStoreFromEnv()
		if store == nil {
			return
		}
		sched, err := LoadDCVScheduleFromEnv()
		if err != nil {
			logging.Infof("dcv tracker: %v; using the default reuse schedule", err)
			sched = DefaultDCVSchedule()
		}
		dcvSharedTracker = NewDCVTracker(store, sched, nil)
	})
	return dcvSharedTracker
}

// Record stamps each domain validated now. The decorator cannot tell a fresh
// challenge from a CA-reused authorization, so a successful issuance counts
// as a validation (slightly optimistic; the CA still decides).
func (t *DCVTracker) Record(ctx context.Context, connectorID, tenant string, domains []string) error {
	now := t.now().UTC()
	period := t.sched.PeriodAt(now)
	var errs []error
	for _, d := range domains {
		errs = append(errs, t.store.Upsert(ctx, DCVValidation{
			Domain: d, ConnectorID: connectorID, Tenant: tenant, ValidatedAt: now,
			ReuseDays: period, ExpiresAt: now.Add(time.Duration(period) * 24 * time.Hour),
		}))
	}
	return errors.Join(errs...)
}

func (t *DCVTracker) validAt(v DCVValidation, now time.Time) bool {
	exact, _ := t.sched.remainingExact(v.ValidatedAt, now)
	return exact > 0
}

func (t *DCVTracker) Valid(ctx context.Context, domain, connectorID string) bool {
	rows, err := t.store.List(ctx)
	if err != nil {
		return false
	}
	now := t.now().UTC()
	for _, v := range rows {
		if v.Domain == domain && v.ConnectorID == connectorID {
			return t.validAt(v, now)
		}
	}
	return false
}

// PlanRevalidation splits domains into those whose recorded validation is
// still reusable and those that need a fresh challenge. Informational: the CA
// decides, and the ACME connector already skips authorizations it reports valid.
func (t *DCVTracker) PlanRevalidation(ctx context.Context, connectorID string, domains []string) (reuse, revalidate []string) {
	rows, err := t.store.List(ctx)
	if err != nil {
		rows = nil // unreadable store: plan a full revalidation rather than reuse blindly
	}
	now := t.now().UTC()
	valid := map[string]bool{}
	for _, v := range rows {
		if v.ConnectorID == connectorID && t.validAt(v, now) {
			valid[v.Domain] = true
		}
	}
	for _, d := range domains {
		if valid[d] {
			reuse = append(reuse, d)
		} else {
			revalidate = append(revalidate, d)
		}
	}
	sort.Strings(reuse)
	sort.Strings(revalidate)
	return reuse, revalidate
}

// shouldWarn is the 20% rule: 0 < remaining <= 20% of the effective period.
func (t *DCVTracker) shouldWarn(v DCVValidation, now time.Time) bool {
	exact, eff := t.sched.remainingExact(v.ValidatedAt, now)
	return exact > 0 && exact*5 <= float64(eff)
}

// WarnScan appends one dcv.expiry_warning audit event per validation as it
// enters the final 20% of its reuse period; re-validating re-arms it.
func (t *DCVTracker) WarnScan(ctx context.Context) (warned int, err error) {
	rows, err := t.store.List(ctx)
	if err != nil {
		return 0, err
	}
	now := t.now().UTC()
	var errs []error
	for _, v := range rows {
		if !t.shouldWarn(v, now) {
			continue
		}
		if v.WarnedAt != nil && !v.WarnedAt.Before(v.ValidatedAt) {
			continue
		}
		if t.audit != nil {
			summary := fmt.Sprintf("connector=%s days_remaining=%d reuse_days=%d",
				v.ConnectorID, t.sched.DaysRemaining(v.ValidatedAt, now), t.sched.effectiveDays(v.ValidatedAt, now))
			if aerr := t.audit.AppendEntry(ctx, AuditEntry{
				Timestamp: now.Format(time.RFC3339), Action: "dcv.expiry_warning", ActorType: "system",
				ActorID: "dcv-tracker", ResourceType: "domain", ResourceID: v.Domain,
				Outcome: AuditOutcomeSuccess, ChangeSummary: summary, Tenant: v.Tenant,
			}); aerr != nil {
				errs = append(errs, aerr)
				continue // not marked warned: the next scan retries
			}
		}
		if merr := t.store.MarkWarned(ctx, v.Domain, v.ConnectorID, now); merr != nil {
			errs = append(errs, merr)
			continue
		}
		warned++
	}
	return warned, errors.Join(errs...)
}

type dcvTrackedConnector struct {
	connectors.IssuerConnector
	tenant  string
	tracker *DCVTracker
}

// wrapWithDCVTracking records validations after each successful Issue. A nil
// tracker returns c unchanged.
func wrapWithDCVTracking(c connectors.IssuerConnector, tenant string, t *DCVTracker) connectors.IssuerConnector {
	if t == nil {
		return c
	}
	return &dcvTrackedConnector{IssuerConnector: c, tenant: tenant, tracker: t}
}

func (d *dcvTrackedConnector) Issue(ctx context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	res, err := d.IssuerConnector.Issue(ctx, req)
	if err != nil {
		return res, err
	}
	if domains := csrDomains(req.CSRPEM); len(domains) > 0 {
		if rerr := d.tracker.Record(ctx, d.ID(), d.tenant, domains); rerr != nil {
			logging.Infof("dcv tracker: connector %s: recording validations: %v", d.ID(), rerr)
		}
	}
	return res, nil
}

// csrDomains is the CN plus DNS SANs, lower-cased and deduped; wildcards are
// kept as written.
func csrDomains(csrPEM string) []string {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	add(csr.Subject.CommonName)
	for _, n := range csr.DNSNames {
		add(n)
	}
	return out
}

func dcvWarnInterval() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("KRYPTKEEPER_DCV_WARN_INTERVAL"))); err == nil && d >= time.Second {
		return d
	}
	return 6 * time.Hour
}

// startDCVWarnLoop ticks WarnScan for the life of the process. The tracker is
// fetched per tick so registration stays free of DB access.
func startDCVWarnLoop(interval time.Duration, get func() *DCVTracker, audit AuditProvider) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			t := get()
			if t == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			if _, err := t.withAudit(audit).WarnScan(ctx); err != nil {
				logging.Infof("dcv tracker: warn scan: %v", err)
			}
			cancel()
		}
	}()
}

type dcvListEntry struct {
	Domain        string `json:"domain"`
	ConnectorID   string `json:"connector_id"`
	ValidatedAt   string `json:"validated_at"`
	ExpiresAt     string `json:"expires_at"`
	ReuseDays     int    `json:"reuse_days"`
	DaysRemaining int    `json:"days_remaining"`
	Warn          bool   `json:"warn"`
}

// registerDCVHandlers mounts GET /api/v1/connectors/dcv-validations. The
// exact pattern outranks the /api/v1/connectors/ subtree.
func registerDCVHandlers(mux *http.ServeMux, auth *Authenticator, get func() *DCVTracker, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/connectors/dcv-validations", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		tracker := get()
		if tracker == nil {
			writeServiceUnavailable(w, "dcv store not configured")
			return
		}
		rows, err := tracker.store.List(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "dcv.list", "domain", "dcv-validations", AuditOutcomeFailure)
			writeServiceUnavailable(w, "dcv list failed")
			return
		}
		now := tracker.now().UTC()
		data := make([]dcvListEntry, 0, len(rows))
		for _, v := range rows {
			if !stampedTenantVisible(pd, v.Tenant) {
				continue
			}
			data = append(data, dcvListEntry{
				Domain: v.Domain, ConnectorID: v.ConnectorID,
				ValidatedAt: v.ValidatedAt.UTC().Format(time.RFC3339), ExpiresAt: v.ExpiresAt.UTC().Format(time.RFC3339),
				ReuseDays: v.ReuseDays, DaysRemaining: tracker.sched.DaysRemaining(v.ValidatedAt, now),
				Warn: tracker.shouldWarn(v, now),
			})
		}
		type scheduleRow struct {
			Effective string `json:"effective"`
			Days      int    `json:"days"`
		}
		schedule := make([]scheduleRow, 0, len(tracker.sched))
		for _, s := range tracker.sched {
			schedule = append(schedule, scheduleRow{Effective: s.Effective.Format("2006-01-02"), Days: s.Days})
		}
		emitAuditEvent(r, auditProvider, pd.ID, "dcv.list", "domain", "dcv-validations", AuditOutcomeSuccess)
		writeJSONStatus(w, http.StatusOK, struct {
			Data             []dcvListEntry `json:"data"`
			Schedule         []scheduleRow  `json:"schedule"`
			CurrentReuseDays int            `json:"current_reuse_days"`
		}{Data: data, Schedule: schedule, CurrentReuseDays: tracker.sched.PeriodAt(now)})
	})
}
