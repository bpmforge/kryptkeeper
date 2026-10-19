// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// W24-04: GET/PUT /api/v1/discovery/schedules — per-target scan interval
// plus last/next run. The key travels in the PUT body because CIDR keys
// contain "/".

const (
	minScheduleIntervalSeconds = 60
	maxScheduleIntervalSeconds = 2592000 // 30 days
	scheduleIntervalRangeMsg   = "interval_seconds must be between 60 and 2592000, or null to use the global interval"
)

type discoveryScheduleRow struct {
	Key                      string  `json:"key"`
	ScanType                 string  `json:"scan_type"`
	Target                   string  `json:"target"`
	Source                   string  `json:"source"` // env | managed
	Name                     string  `json:"name,omitempty"`
	IntervalSeconds          *int64  `json:"interval_seconds"`
	EffectiveIntervalSeconds *int64  `json:"effective_interval_seconds"`
	LastRun                  *string `json:"last_run"`
	NextRun                  *string `json:"next_run"`
	Running                  bool    `json:"running"`
	RunningJobID             string  `json:"running_job_id"`
}

// buildDiscoverySchedulePlan lists the schedulable targets visible to the
// principal, in a stable order, before any run state is attached.
func buildDiscoverySchedulePlan(ctx context.Context, principal AuthPrincipal, targets ManagedTargetStore) []discoveryScheduleRow {
	var rows []discoveryScheduleRow
	for _, t := range envDiscoveryTargets() {
		rows = append(rows, discoveryScheduleRow{Key: t, ScanType: "targeted", Target: t, Source: "env"})
	}
	if targets != nil {
		list, err := targets.List(ctx)
		if err == nil {
			for _, t := range filterManagedTargetsByTenant(principal, list) {
				if scanType, ok := scheduledManagedScanType(t); ok {
					rows = append(rows, discoveryScheduleRow{Key: t.ID, ScanType: scanType, Target: t.ID, Source: "managed", Name: t.Name})
				}
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Source < rows[j].Source })
	return rows
}

func fillDiscoveryScheduleRow(ctx context.Context, row *discoveryScheduleRow, st discoverySchedule, global time.Duration, haveGlobal bool, provider DiscoveryProvider, now time.Time) {
	var effective time.Duration
	switch {
	case st.Interval != nil:
		secs := int64(st.Interval.Seconds())
		row.IntervalSeconds = &secs
		effective = *st.Interval
	case haveGlobal:
		effective = global
	}
	if effective > 0 {
		secs := int64(effective.Seconds())
		row.EffectiveIntervalSeconds = &secs
	}
	if !st.LastRunAt.IsZero() {
		s := st.LastRunAt.UTC().Format(time.RFC3339)
		row.LastRun = &s
	}
	if effective > 0 {
		next := now.UTC()
		if !st.LastRunAt.IsZero() {
			next = st.LastRunAt.Add(effective).UTC()
		}
		s := next.Format(time.RFC3339)
		row.NextRun = &s
	}
	if provider != nil {
		if job, running, err := findRunningScanJob(ctx, provider, row.ScanType, row.Target); err == nil && running {
			row.Running, row.RunningJobID = true, job.ID
		}
	}
}

func registerDiscoveryScheduleHandlers(mux *http.ServeMux, auth *Authenticator, provider DiscoveryProvider, schedules discoveryScheduleStore, targets ManagedTargetStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/discovery/schedules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleDiscoverySchedulesList(w, r, auth, provider, schedules, targets, auditProvider)
		case http.MethodPut:
			handleDiscoverySchedulePut(w, r, auth, provider, schedules, targets, auditProvider)
		default:
			writeMethodNotAllowed(w, "GET, PUT")
		}
	})
}

func discoveryScheduleRows(ctx context.Context, principal AuthPrincipal, provider DiscoveryProvider, schedules discoveryScheduleStore, targets ManagedTargetStore) ([]discoveryScheduleRow, error) {
	state, err := schedules.List(ctx)
	if err != nil {
		return nil, err
	}
	global, haveGlobal := globalDiscoveryIntervalQuiet()
	now := time.Now()
	rows := buildDiscoverySchedulePlan(ctx, principal, targets)
	for i := range rows {
		fillDiscoveryScheduleRow(ctx, &rows[i], state[rows[i].Key], global, haveGlobal, provider, now)
	}
	return rows, nil
}

func handleDiscoverySchedulesList(w http.ResponseWriter, r *http.Request, auth *Authenticator, provider DiscoveryProvider, schedules discoveryScheduleStore, targets ManagedTargetStore, auditProvider AuditProvider) {
	principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, "", "discovery.schedules.list", "discovery", "schedules", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if !canReadOperationalSummaries(principal) {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedules.list", "discovery", "schedules", AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	if schedules == nil {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedules.list", "discovery", "schedules", AuditOutcomeFailure)
		writeServiceUnavailable(w, "discovery schedules unavailable")
		return
	}
	rows, err := discoveryScheduleRows(r.Context(), principal, provider, schedules, targets)
	if err != nil {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedules.list", "discovery", "schedules", AuditOutcomeFailure)
		writeServiceUnavailable(w, "discovery schedules unavailable")
		return
	}
	emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedules.list", "discovery", "schedules", AuditOutcomeSuccess)
	if rows == nil {
		rows = []discoveryScheduleRow{}
	}
	writeJSONData(w, rows)
}

func handleDiscoverySchedulePut(w http.ResponseWriter, r *http.Request, auth *Authenticator, provider DiscoveryProvider, schedules discoveryScheduleStore, targets ManagedTargetStore, auditProvider AuditProvider) {
	principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, "", "discovery.schedule.update", "discovery", "schedules", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if !canManageDiscovery(principal) {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", "schedules", AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	var body struct {
		Key             string          `json:"key"`
		IntervalSeconds json.RawMessage `json:"interval_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Key == "" || body.IntervalSeconds == nil {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", "schedules", AuditOutcomeFailure)
		writeBadRequest(w, "body must be {\"key\": string, \"interval_seconds\": number|null}")
		return
	}
	var interval *time.Duration
	if !bytes.Equal(bytes.TrimSpace(body.IntervalSeconds), []byte("null")) {
		var secs int64
		if err := json.Unmarshal(body.IntervalSeconds, &secs); err != nil || secs < minScheduleIntervalSeconds || secs > maxScheduleIntervalSeconds {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", body.Key, AuditOutcomeFailure)
			writeBadRequest(w, scheduleIntervalRangeMsg)
			return
		}
		d := time.Duration(secs) * time.Second
		interval = &d
	}
	if schedules == nil {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", body.Key, AuditOutcomeFailure)
		writeServiceUnavailable(w, "discovery schedules unavailable")
		return
	}
	// The key must be a known row; unknown and other-tenant keys look the same.
	var known *discoveryScheduleRow
	plan := buildDiscoverySchedulePlan(r.Context(), principal, targets)
	for i := range plan {
		if plan[i].Key == body.Key {
			known = &plan[i]
			break
		}
	}
	if known == nil {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", body.Key, AuditOutcomeFailure)
		writeNotFound(w, "not found")
		return
	}
	if err := schedules.SetInterval(r.Context(), known.Key, known.ScanType, known.Target, interval); err != nil {
		emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", body.Key, AuditOutcomeFailure)
		writeServiceUnavailable(w, "discovery schedules unavailable")
		return
	}
	emitAuditEvent(r, auditProvider, principal.ID, "discovery.schedule.update", "discovery", body.Key, AuditOutcomeSuccess)
	state, err := schedules.List(r.Context())
	if err != nil {
		writeServiceUnavailable(w, "discovery schedules unavailable")
		return
	}
	global, haveGlobal := globalDiscoveryIntervalQuiet()
	fillDiscoveryScheduleRow(r.Context(), known, state[known.Key], global, haveGlobal, provider, time.Now())
	writeJSONData(w, known)
}
