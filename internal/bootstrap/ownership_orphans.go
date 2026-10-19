// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W22-26: orphan owner detection. A certificate whose owner_email belongs to a
// deactivated account (SCIM deprovision, admin deactivate) has no one to renew
// or answer for it. The scanner finds those, alerts once per departed owner,
// and the reassign endpoint moves every one of the owner's certificates to a
// new owner in a single call.

const haLockOwnershipOrphan = "ownership-orphan-scanner"

// defaultOrphanSweep must stay <= 5 minutes so detection lands inside the
// 15-minute acceptance window even after one skipped tick.
const defaultOrphanSweep = 5 * time.Minute

const (
	orphanActorID      = "ownership-orphan-scanner"
	orphanSubjectClass = "ownership.orphan"
	maxOrphanBodyBytes = 64 << 10
)

type orphanedOwner struct {
	UserID     string `json:"user_id"`
	OwnerEmail string `json:"owner_email"`
	CertCount  int    `json:"cert_count"`
}

func normalizeOwnerEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// orphanGroup is one departed owner with the certificates still pointing at it.
type orphanGroup struct {
	userID string
	email  string
	certs  []CertificateItem
}

func certIsRevoked(c CertificateItem) bool {
	return (c.RevokedAt != nil && *c.RevokedAt != "") || strings.EqualFold(c.RenewalStatus, string(RenewalStatusRevoked))
}

// collectOrphans groups non-revoked certificates by deactivated owner. visible
// filters certificates before they are grouped, so a tenant caller's counts
// (and the very existence of an orphan row) never reflect another tenant's
// inventory. An email shared with an active account is never an orphan: the
// certificates still have a live person behind them.
func collectOrphans(ctx context.Context, users UserProvider, certs CertificateProvider, visible func(CertificateItem) bool) ([]orphanGroup, error) {
	if users == nil {
		return nil, nil // no user store wired: nobody can be deactivated
	}
	list, err := users.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	gone := map[string]string{} // normalised email -> user ID
	live := map[string]bool{}
	for _, u := range list {
		e := normalizeOwnerEmail(u.Email)
		if e == "" {
			continue
		}
		if isDeprovisionedStatus(u.Status) {
			if _, dup := gone[e]; !dup {
				gone[e] = u.ID
			}
		} else {
			live[e] = true
		}
	}
	for e := range live {
		delete(gone, e)
	}
	if len(gone) == 0 {
		return nil, nil
	}

	byEmail := map[string]*orphanGroup{}
	err = ForEachCertificate(ctx, certs, CertificateListQuery{}, func(c CertificateItem) error {
		e := normalizeOwnerEmail(c.OwnerEmail)
		id, ok := gone[e]
		if !ok || certIsRevoked(c) || (visible != nil && !visible(c)) {
			return nil
		}
		g := byEmail[e]
		if g == nil {
			g = &orphanGroup{userID: id, email: e}
			byEmail[e] = g
		}
		g.certs = append(g.certs, c)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk certificates: %w", err)
	}
	out := make([]orphanGroup, 0, len(byEmail))
	for _, g := range byEmail {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].email < out[j].email })
	return out, nil
}

// findOrphanedOwners lists deactivated users that still own >=1 non-revoked
// certificate, across the whole inventory (scanner view, no tenant filter).
func findOrphanedOwners(ctx context.Context, users UserProvider, certs CertificateProvider) ([]orphanedOwner, error) {
	groups, err := collectOrphans(ctx, users, certs, nil)
	if err != nil {
		return nil, err
	}
	return orphansFromGroups(groups), nil
}

func orphansFromGroups(groups []orphanGroup) []orphanedOwner {
	out := make([]orphanedOwner, 0, len(groups))
	for _, g := range groups {
		out = append(out, orphanedOwner{UserID: g.userID, OwnerEmail: g.email, CertCount: len(g.certs)})
	}
	return out
}

// OrphanScanner periodically looks for orphaned owners and alerts once each.
type OrphanScanner struct {
	certs    CertificateProvider
	users    UserProvider
	audit    AuditProvider
	channel  delivery.Channel
	target   string
	interval time.Duration

	haCoordinator *HACoordinator

	mu   sync.Mutex
	seen map[string]bool // user ID -> already alerted

	stop chan struct{}
	once sync.Once
}

// NewOrphanScannerFromEnv builds the scanner (KRYPTKEEPER_OWNERSHIP_ORPHAN_SWEEP_MINUTES,
// default 5, capped at 5 so the 15-minute detection promise holds). channel
// may be nil: the audit row is written regardless.
func NewOrphanScannerFromEnv(certs CertificateProvider, users UserProvider, audit AuditProvider, ch delivery.Channel, target string) *OrphanScanner {
	interval := defaultOrphanSweep
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_OWNERSHIP_ORPHAN_SWEEP_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && time.Duration(n)*time.Minute < interval {
			interval = time.Duration(n) * time.Minute
		}
	}
	return &OrphanScanner{
		certs: certs, users: users, audit: audit, channel: ch, target: target,
		interval:      interval,
		haCoordinator: newHACoordinatorFromEnvLogged(),
		seen:          map[string]bool{},
		stop:          make(chan struct{}),
	}
}

func (s *OrphanScanner) Start() {
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.tick(context.Background(), time.Now())
			}
		}
	}()
}

func (s *OrphanScanner) Stop() { s.once.Do(func() { close(s.stop) }) }

func (s *OrphanScanner) tick(ctx context.Context, now time.Time) {
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockOwnershipOrphan, 2*s.interval)
		if err != nil {
			logging.Warnf("ownership orphan scanner: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}
	// A user-store or inventory outage skips the tick; it must never page
	// "everyone is fine" or panic.
	orphans, err := findOrphanedOwners(ctx, s.users, s.certs)
	if err != nil {
		logging.Warnf("ownership orphan scanner: sweep failed, skipping this tick: %v", err)
		return
	}

	// The latch holds only users still orphaned, so clearing the last cert
	// re-arms the alert for a later re-orphan.
	s.mu.Lock()
	current := map[string]bool{}
	var fresh []orphanedOwner
	for _, o := range orphans {
		current[o.UserID] = true
		if !s.seen[o.UserID] {
			fresh = append(fresh, o)
		}
	}
	s.seen = current
	s.mu.Unlock()

	for _, o := range fresh {
		s.raise(ctx, o, now)
	}
}

func (s *OrphanScanner) raise(ctx context.Context, o orphanedOwner, now time.Time) {
	if s.audit != nil {
		summary, _ := json.Marshal(map[string]any{"owner_email": o.OwnerEmail, "cert_count": o.CertCount})
		if err := s.audit.AppendEntry(ctx, AuditEntry{
			Timestamp: now.UTC().Format(time.RFC3339), Action: "ownership.orphan_detected",
			ActorType: "system", ActorID: orphanActorID,
			ResourceType: "user", ResourceID: o.UserID,
			Outcome: AuditOutcomeSuccess, ChangeSummary: string(summary),
		}); err != nil {
			logging.Warnf("ownership orphan scanner: audit append failed for %s: %v", o.UserID, err)
		}
	}
	if s.channel == nil {
		return
	}
	// delivery.Event has no event-type field, so the class travels as the
	// Subject prefix (W22-26 default pending the UC-I01 event catalog).
	ev := delivery.Event{
		ID:       "ownership-orphan-" + o.UserID,
		Channel:  s.channel.Name(),
		Target:   s.target,
		Subject:  orphanSubjectClass + ": " + o.OwnerEmail,
		Message:  fmt.Sprintf("%s was deactivated but still owns %d certificate(s). Reassign them with POST /api/v1/ownership/reassign.", o.OwnerEmail, o.CertCount),
		Priority: "high", CreatedAt: now,
	}
	if err := s.channel.Send(ctx, ev); err != nil {
		logging.Warnf("ownership orphan scanner: notify failed for %s: %v", o.UserID, err)
	}
}

type reassignRequest struct {
	FromEmail string `json:"from_email"`
	ToTeam    string `json:"to_team"`
	ToEmail   string `json:"to_email"`
}

// orphanVisible is the per-certificate tenant gate. Like cmdbCertVisible it
// fails closed when tenancy is on but no tenant store is wired, because the
// reassign path is a bulk write.
func orphanVisible(ctx context.Context, pd AuthPrincipal) func(CertificateItem) bool {
	return func(c CertificateItem) bool { return cmdbCertVisible(ctx, pd, c) }
}

// RegisterOwnershipOrphanHandlers mounts GET /api/v1/ownership/orphans and
// POST /api/v1/ownership/reassign. Both require a certificate admin and see
// only certificates visible to the caller's tenant.
func RegisterOwnershipOrphanHandlers(mux *http.ServeMux, auth *Authenticator, certs CertificateProvider, users UserProvider, audit AuditProvider) {
	mux.HandleFunc("/api/v1/ownership/orphans", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", "ownership.orphans_list", "ownership", "orphans", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !isCertificateAdmin(pd) {
			emitAuditEvent(r, audit, pd.ID, "ownership.orphans_list", "ownership", "orphans", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		groups, err := collectOrphans(r.Context(), users, certs, orphanVisible(r.Context(), pd))
		if err != nil {
			logging.Warnf("ownership orphans unavailable: %v", err)
			writeServiceUnavailable(w, "ownership data unavailable")
			return
		}
		writeJSONData(w, orphansFromGroups(groups))
	})

	mux.HandleFunc("/api/v1/ownership/reassign", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", "ownership.reassign", "ownership", "reassign", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !isCertificateAdmin(pd) {
			emitAuditEvent(r, audit, pd.ID, "ownership.reassign", "ownership", "reassign", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		var req reassignRequest
		if !decodeJSONBodyOrReject(w, r, &req, maxOrphanBodyBytes, "invalid request body") {
			emitAuditEvent(r, audit, pd.ID, "ownership.reassign", "ownership", "reassign", AuditOutcomeFailure)
			return
		}
		from := normalizeOwnerEmail(req.FromEmail)
		team := strings.TrimSpace(req.ToTeam)
		toEmail := strings.TrimSpace(req.ToEmail)
		if team == "" {
			emitAuditEvent(r, audit, pd.ID, "ownership.reassign", "ownership", "reassign", AuditOutcomeFailure)
			writeBadRequest(w, "to_team is required")
			return
		}
		groups, err := collectOrphans(r.Context(), users, certs, orphanVisible(r.Context(), pd))
		if err != nil {
			logging.Warnf("ownership reassign unavailable: %v", err)
			writeServiceUnavailable(w, "ownership data unavailable")
			return
		}
		// Only groups built from certificates the caller may see are searched,
		// so a foreign tenant's orphan is indistinguishable from none at all.
		var target *orphanGroup
		for i := range groups {
			if groups[i].email == from {
				target = &groups[i]
				break
			}
		}
		if target == nil {
			emitAuditEvent(r, audit, pd.ID, "ownership.reassign", "ownership", from, AuditOutcomeFailure)
			writeBadRequest(w, "from_email is not an orphaned owner")
			return
		}

		// Matches were collected before any write: UpdateOwnership takes the
		// provider lock a ForEachCertificate pass must not hold.
		moved, failed := 0, 0
		for _, c := range target.certs {
			// ServiceName is carried over because UpdateOwnership overwrites it.
			_, err := certs.UpdateOwnership(r.Context(), c.FingerprintSHA256, CertificateOwnershipRequest{
				OwnerTeam: team, OwnerEmail: toEmail, ServiceName: c.ServiceName,
				Source: OwnershipSourceManual,
			})
			if err != nil {
				logging.Infof("ownership reassign: %s not updated: %v", c.FingerprintSHA256, err)
				failed++
				continue
			}
			moved++
			detail, _ := json.Marshal(map[string]any{
				"from": map[string]string{"owner_email": c.OwnerEmail, "owner_team": c.OwnerTeam},
				"to":   map[string]string{"owner_email": toEmail, "owner_team": team},
			})
			emitAuditEventDetail(r, audit, pd.ID, "certificate.ownership_update", "certificate", c.FingerprintSHA256, AuditOutcomeSuccess, string(detail))
		}
		summary, _ := json.Marshal(map[string]any{"from_email": from, "to_team": team, "reassigned": moved, "failed": failed})
		outcome := AuditOutcomeSuccess
		if failed > 0 {
			outcome = AuditOutcomeFailure
		}
		emitAuditEventDetail(r, audit, pd.ID, "ownership.reassign", "user", target.userID, outcome, string(summary))
		writeJSONData(w, map[string]int{"reassigned": moved})
	})
}
