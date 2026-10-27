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
	"sort"
	"strings"
	"time"

	"kryptkeeper/internal/blastradius"
	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/trustpush"
)

// W40-03 (D-318, D-319): trust bundles. A bundle is a set of CA certificates
// the hub asks selected agents to add to (or remove from) their OS trust
// stores, so a private-CA rollover can land the new root everywhere before the
// old one goes. Adding a root to a trust store is one of the most powerful
// things the hub can do to a host, so creating a bundle is a Critical action:
// it exists only after a second human approves it in the pending-actions
// queue, and an agent applies it only if its own configuration opts in.

// ActionTrustBundlePush is the approval-queue action type that creates a
// bundle. validActionType deliberately does not list it: the generic POST
// /pending-actions must not be a second way to push a root.
const ActionTrustBundlePush = "trust_bundle.push"

const (
	trustBundleBodyMax   = 320 << 10
	trustBundleNameMax   = 120
	trustBundleDetailMax = 1000
)

// TrustSelector names the agents a bundle targets. Agents carry no tenant or
// label (D-203), so the selectors are the ones that exist: explicit ids, an
// agent platform, or all. They combine as a union.
type TrustSelector struct {
	AgentIDs   []string `json:"agent_ids,omitempty"`
	AgentTypes []string `json:"agent_types,omitempty"`
	All        bool     `json:"all,omitempty"`
}

// TrustBundleCert describes one certificate of a bundle for display.
type TrustBundleCert struct {
	SHA256   string `json:"sha256"`
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	Root     bool   `json:"root"`
}

// TrustBundle is an approved bundle.
type TrustBundle struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Action     string            `json:"action"`
	Certs      []TrustBundleCert `json:"certs"`
	Selector   TrustSelector     `json:"selector"`
	AgentIDs   []string          `json:"agent_ids"`
	CreatedBy  string            `json:"created_by"`
	ApprovedBy string            `json:"approved_by"`
	ActionID   string            `json:"action_id"`
	CreatedAt  string            `json:"created_at"`
	// CertPEM is the normalised bundle sent to agents; omitted from list output.
	CertPEM string `json:"-"`
}

// TrustBundleResult is one agent's outcome for one bundle.
type TrustBundleResult struct {
	BundleID   string `json:"bundle_id"`
	AgentID    string `json:"agent_id"`
	Outcome    string `json:"outcome"`
	Detail     string `json:"detail,omitempty"`
	ReportedAt string `json:"reported_at"`
}

// TrustBundleStore persists bundles and their per-agent results.
type TrustBundleStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, b TrustBundle) (TrustBundle, error)
	Get(ctx context.Context, id string) (TrustBundle, bool, error)
	List(ctx context.Context, limit int) ([]TrustBundle, error)
	SaveResult(ctx context.Context, r TrustBundleResult) error
	Results(ctx context.Context, bundleID string) ([]TrustBundleResult, error)
	// PendingForAgent returns the bundles that target agentID and have no
	// applied result yet (a refused or failed one is offered again), oldest
	// first, minus bundles wholly superseded by a newer one for the same certs.
	PendingForAgent(ctx context.Context, agentID string) ([]TrustBundle, error)
}

// Mirrors migrations 000371 and 000372; idempotent for the per-store
// EnsureSchema convention.
const trustBundleSchema = `
CREATE TABLE IF NOT EXISTS trust_bundles (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, action TEXT NOT NULL,
    cert_pem TEXT NOT NULL, certs_json TEXT NOT NULL, selector_json TEXT NOT NULL,
    agent_ids_json TEXT NOT NULL, created_by TEXT NOT NULL, approved_by TEXT NOT NULL,
    action_id TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_trust_bundles_created ON trust_bundles(created_at);
CREATE TABLE IF NOT EXISTS trust_bundle_results (
    bundle_id TEXT NOT NULL, agent_id TEXT NOT NULL, outcome TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '', reported_at TEXT NOT NULL,
    PRIMARY KEY (bundle_id, agent_id));
CREATE INDEX IF NOT EXISTS idx_trust_bundle_results_agent ON trust_bundle_results(agent_id);`

type dbTrustBundleStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *dbTrustBundleStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, trustBundleSchema)
	return err
}

func (s *dbTrustBundleStore) Create(ctx context.Context, b TrustBundle) (TrustBundle, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return TrustBundle{}, err
	}
	b.ID = "tb-" + hex.EncodeToString(raw)
	b.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	certs, _ := json.Marshal(b.Certs)       // plain structs: cannot fail
	selector, _ := json.Marshal(b.Selector) // plain struct: cannot fail
	agents, _ := json.Marshal(b.AgentIDs)   // []string: cannot fail
	q := fmt.Sprintf(`INSERT INTO trust_bundles
		(id, name, action, cert_pem, certs_json, selector_json, agent_ids_json, created_by, approved_by, action_id, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11))
	if _, err := s.db.ExecContext(ctx, q, b.ID, b.Name, b.Action, b.CertPEM, string(certs), string(selector),
		string(agents), b.CreatedBy, b.ApprovedBy, b.ActionID, b.CreatedAt); err != nil {
		return TrustBundle{}, err
	}
	return b, nil
}

const trustBundleSelect = `SELECT id, name, action, cert_pem, certs_json, selector_json, agent_ids_json,
	created_by, approved_by, action_id, created_at FROM trust_bundles`

func (s *dbTrustBundleStore) query(ctx context.Context, where string, limit int, args ...any) ([]TrustBundle, error) {
	rows, err := s.db.QueryContext(ctx, trustBundleSelect+where+fmt.Sprintf(" ORDER BY created_at DESC, id ASC LIMIT %d", limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustBundle
	for rows.Next() {
		var b TrustBundle
		var certs, selector, agents string
		if err := rows.Scan(&b.ID, &b.Name, &b.Action, &b.CertPEM, &certs, &selector, &agents,
			&b.CreatedBy, &b.ApprovedBy, &b.ActionID, &b.CreatedAt); err != nil {
			return nil, err
		}
		if err := errors.Join(json.Unmarshal([]byte(certs), &b.Certs), json.Unmarshal([]byte(selector), &b.Selector),
			json.Unmarshal([]byte(agents), &b.AgentIDs)); err != nil {
			return nil, fmt.Errorf("trust bundle %s: corrupt row: %w", b.ID, err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *dbTrustBundleStore) Get(ctx context.Context, id string) (TrustBundle, bool, error) {
	list, err := s.query(ctx, " WHERE id = "+s.ph(1), 1, id)
	if err != nil || len(list) == 0 {
		return TrustBundle{}, false, err
	}
	return list[0], true, nil
}

func (s *dbTrustBundleStore) List(ctx context.Context, limit int) ([]TrustBundle, error) {
	return s.query(ctx, "", limit)
}

func (s *dbTrustBundleStore) SaveResult(ctx context.Context, r TrustBundleResult) error {
	r.ReportedAt = time.Now().UTC().Format(time.RFC3339)
	q := fmt.Sprintf(`INSERT INTO trust_bundle_results (bundle_id, agent_id, outcome, detail, reported_at)
		VALUES (%s, %s, %s, %s, %s)
		ON CONFLICT (bundle_id, agent_id) DO UPDATE SET outcome = excluded.outcome, detail = excluded.detail, reported_at = excluded.reported_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5))
	_, err := s.db.ExecContext(ctx, q, r.BundleID, r.AgentID, r.Outcome, r.Detail, r.ReportedAt)
	return err
}

func (s *dbTrustBundleStore) Results(ctx context.Context, bundleID string) ([]TrustBundleResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT bundle_id, agent_id, outcome, detail, reported_at
		FROM trust_bundle_results WHERE bundle_id = `+s.ph(1)+` ORDER BY agent_id`, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustBundleResult
	for rows.Next() {
		var r TrustBundleResult
		if err := rows.Scan(&r.BundleID, &r.AgentID, &r.Outcome, &r.Detail, &r.ReportedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *dbTrustBundleStore) PendingForAgent(ctx context.Context, agentID string) ([]TrustBundle, error) {
	// The fleet is small and bundles are rare; filtering the newest 200 in Go
	// avoids a JSON-array predicate that differs between the two engines.
	all, err := s.query(ctx, "", 200)
	if err != nil {
		return nil, err
	}
	// Walk newest -> oldest. A bundle is superseded for this agent when every
	// one of its certs appears in a NEWER bundle targeting the agent (whatever
	// that bundle's result): applying the older one afterwards would undo the
	// newer intent (an old ADD re-adding a root a later REMOVE took out, or a
	// failed old ADD retried after the REMOVE succeeded). The remaining pending
	// bundles are returned OLDEST first so the latest intent is applied last.
	newer := map[string]bool{}
	var out []TrustBundle
	for _, b := range all {
		if !containsString(b.AgentIDs, agentID) {
			continue
		}
		var outcome string
		qerr := s.db.QueryRowContext(ctx, `SELECT outcome FROM trust_bundle_results WHERE bundle_id = `+s.ph(1)+
			` AND agent_id = `+s.ph(2), b.ID, agentID).Scan(&outcome)
		if qerr != nil && !errors.Is(qerr, sql.ErrNoRows) {
			return nil, qerr
		}
		superseded := len(b.Certs) > 0
		for _, c := range b.Certs {
			if !newer[c.SHA256] {
				superseded = false
			}
		}
		for _, c := range b.Certs {
			newer[c.SHA256] = true
		}
		if outcome != trustpush.OutcomeApplied && !superseded {
			out = append(out, b)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// NewTrustBundleStoreFromEnv opens the shared DB and ensures the schema.
// Returns nil if the DB is unavailable (callers answer 503).
func NewTrustBundleStoreFromEnv() TrustBundleStore {
	state := newDBProviderState[*dbTrustBundleStore](
		"trust-bundles",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbTrustBundleStore { return &dbTrustBundleStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) *dbTrustBundleStore { return &dbTrustBundleStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("trust-bundles", state.openErr) // logs the outage itself
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("trust-bundles", err) // logs the outage itself
		return nil
	}
	return state.store
}

// trustBundleParams is the pending action's payload: exactly what the approver
// is shown, and what the executor creates. AgentIDs is the target snapshot at
// proposal, so an agent registered after the approver looked is never included.
type trustBundleParams struct {
	Name     string        `json:"name"`
	Action   string        `json:"action"`
	CertPEM  string        `json:"cert_pem"`
	Selector TrustSelector `json:"selector"`
	AgentIDs []string      `json:"agent_ids"`
	Warnings []string      `json:"warnings,omitempty"`
}

func trustBundleCerts(cas []trustpush.CA) ([]TrustBundleCert, string) {
	certs := make([]TrustBundleCert, 0, len(cas))
	var pem strings.Builder
	for _, c := range cas {
		certs = append(certs, TrustBundleCert{
			SHA256: c.SHA256, Subject: c.Cert.Subject.String(), Issuer: c.Cert.Issuer.String(),
			NotAfter: c.Cert.NotAfter.UTC().Format(time.RFC3339), Root: c.IsRoot(),
		})
		pem.Write(c.PEM())
	}
	return certs, pem.String()
}

// resolveTrustTargets turns a selector into the ids it matches among agents.
// An unknown explicit id is an error rather than a silent skip: the approver
// must see exactly the hosts the proposer meant.
func resolveTrustTargets(sel TrustSelector, agents []AgentInfo) ([]string, error) {
	if !sel.All && len(sel.AgentIDs) == 0 && len(sel.AgentTypes) == 0 {
		return nil, errors.New("selector is empty: name agent_ids, agent_types or all")
	}
	known := map[string]AgentInfo{}
	for _, a := range agents {
		known[a.ID] = a
	}
	picked := map[string]bool{}
	for _, id := range sel.AgentIDs {
		if _, ok := known[id]; !ok {
			return nil, fmt.Errorf("unknown agent %q", id)
		}
		picked[id] = true
	}
	types := map[string]bool{}
	for _, t := range sel.AgentTypes {
		switch AgentType(t) {
		case AgentTypeLinux, AgentTypeMac, AgentTypeWindows:
			types[t] = true
		default:
			return nil, fmt.Errorf("unknown agent type %q (linux, mac, windows)", t)
		}
	}
	for _, a := range agents {
		if sel.All || types[string(a.Type)] {
			picked[a.ID] = true
		}
	}
	out := make([]string, 0, len(picked))
	for id := range picked {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("selector matches no registered agent")
	}
	return out, nil
}

// removalWarnings names, for each certificate a removal bundle would drop, the
// live hub-issued certificates that chain to it (reusing the blast-radius
// graph, W17-05). A host that stops trusting a root stops trusting everything
// that root issued, so the approver must see that before saying yes.
func removalWarnings(ctx context.Context, cas []trustpush.CA, certs CertificateProvider, caProv CAProvider, now time.Time) []string {
	if certs == nil || caProv == nil {
		return nil
	}
	list, err := caProv.ListCAs(ctx, CAListQuery{Limit: 1000})
	if err != nil {
		logging.Infof("trust bundle: blast radius skipped, CA list failed: %v", err)
		return nil
	}
	byFP := map[string]CAListItem{}
	for _, c := range list.Items {
		byFP[strings.ToLower(strings.ReplaceAll(c.CertificateFingerprintSHA256, ":", ""))] = c
	}
	var matched []CAListItem
	for _, c := range cas {
		if hub, ok := byFP[c.SHA256]; ok {
			matched = append(matched, hub)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	items, err := blastRadiusInventory(ctx, certs)
	if err != nil {
		logging.Infof("trust bundle: blast radius skipped, inventory failed: %v", err)
		return nil
	}
	live := items[:0:0]
	for _, it := range items {
		if it.RevokedAt != nil {
			continue
		}
		if t, perr := time.Parse(time.RFC3339, it.ValidUntil); perr == nil && t.Before(now) {
			continue
		}
		live = append(live, it)
	}
	graph := buildBlastRadiusGraphWithCAs(live, list.Items)
	var warnings []string
	for _, hub := range matched {
		impact := graph.SimulateRetireCA(hub.ID)
		if n := len(impact.AffectedByKind[blastradius.KindCert]); n > 0 {
			warnings = append(warnings, fmt.Sprintf("removing the root of hub CA %q (%s) distrusts %d live managed certificate(s) it issued (%s severity)",
				hub.Name, hub.ID, n, impact.Severity))
		}
	}
	return warnings
}

// ProposeTrustBundle validates a bundle request and queues it for approval; it
// never creates the bundle itself.
func ProposeTrustBundle(ctx context.Context, pending PendingActionStore, pd AuthPrincipal, p trustBundleParams, rationale string) (PendingAction, error) {
	if pending == nil {
		return PendingAction{}, errors.New("approval queue unavailable")
	}
	params, err := json.Marshal(p)
	if err != nil {
		return PendingAction{}, err
	}
	summary := fmt.Sprintf("trust bundle %q: %s %d CA certificate(s) on %d agent(s)", p.Name, p.Action, strings.Count(p.CertPEM, "BEGIN CERTIFICATE"), len(p.AgentIDs))
	if len(p.Warnings) > 0 {
		summary += ". WARNING: " + strings.Join(p.Warnings, "; ")
	}
	if r := strings.TrimSpace(rationale); r != "" {
		summary += ". " + r
	}
	return pending.Create(ctx, PendingAction{
		ActionType: ActionTrustBundlePush, Params: params, ProposedBy: pd.ID,
		Rationale: summary, Status: "pending", Tenant: pd.Tenant,
	})
}

// newTrustBundleExecutor creates an approved bundle. The queue already
// enforced approver role, no-self-approval and quorum; this re-validates the
// certificates (a row written outside the handler must not slip a leaf or an
// expired root through) and drops targets that no longer exist.
func newTrustBundleExecutor(store TrustBundleStore, agents AgentStore, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		if store == nil || agents == nil {
			return nil, errors.New("trust bundle store unavailable")
		}
		// The propose route is instance-wide (agents carry no tenant, D-203), but
		// the queue only scopes an action to the proposer's tenant, so a tenant
		// admin could otherwise approve a fleet-wide push they may not propose.
		if !tenantBypass(approver) {
			return nil, errors.New("instance-wide setting: platform super-admin required when multi-tenancy is on")
		}
		var p trustBundleParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid trust bundle params: %w", err)
		}
		act := trustpush.Action(p.Action)
		if !act.Valid() {
			return nil, fmt.Errorf("unknown action %q", p.Action)
		}
		cas, err := trustpush.ParseCAs(p.CertPEM, time.Now(), act == trustpush.ActionAdd)
		if err != nil {
			return nil, err
		}
		exists := map[string]bool{}
		for _, a := range agents.list() {
			exists[a.ID] = true
		}
		var targets []string
		for _, id := range p.AgentIDs {
			if exists[id] {
				targets = append(targets, id)
			}
		}
		if len(targets) == 0 {
			return nil, errors.New("none of the targeted agents still exists")
		}
		certs, pem := trustBundleCerts(cas)
		created, err := store.Create(ctx, TrustBundle{
			Name: p.Name, Action: p.Action, Certs: certs, CertPEM: pem, Selector: p.Selector, AgentIDs: targets,
			CreatedBy: action.ProposedBy, ApprovedBy: approver.ID, ActionID: action.ID,
		})
		if err != nil {
			return nil, err
		}
		if audit != nil {
			fps := make([]string, 0, len(certs))
			for _, c := range certs {
				fps = append(fps, c.SHA256)
			}
			if aerr := audit.AppendEntry(ctx, AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "trust_bundle.create",
				ActorType: "user", ActorID: approver.ID, ResourceType: "trust_bundle", ResourceID: created.ID,
				Outcome: AuditOutcomeSuccess, Tenant: DefaultTenant,
				ChangeSummary: fmt.Sprintf("action=%s name=%q agents=%d certs=%s proposed_by=%s approved_by=%s",
					p.Action, p.Name, len(targets), strings.Join(fps, ","), action.ProposedBy, approver.ID),
			}); aerr != nil {
				logging.Infof("ERROR trust bundle %s created but the audit append failed: %v", created.ID, aerr)
			}
		}
		return json.Marshal(map[string]any{"bundle_id": created.ID, "targets": len(targets)})
	}
}
