// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// AgentType is the OS/context of a satellite agent.
type AgentType string

const (
	AgentTypeLinux   AgentType = "linux"
	AgentTypeMac     AgentType = "mac"
	AgentTypeWindows AgentType = "windows"
)

// AgentStatus reflects whether the agent has recently phoned home.
type AgentStatus string

const (
	AgentStatusActive  AgentStatus = "active"
	AgentStatusStale   AgentStatus = "stale"
	AgentStatusOffline AgentStatus = "offline"
)

// AgentInfo is the public view of a registered satellite agent.
type AgentInfo struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Type           AgentType   `json:"type"`
	RegisteredAt   time.Time   `json:"registered_at"`
	LastSeen       *time.Time  `json:"last_seen,omitempty"`
	Status         AgentStatus `json:"status"`
	InventoryCount int         `json:"inventory_count"`
	// Version is the agent build the agent last reported via X-Agent-Version;
	// empty for agents that never reported one.
	Version string `json:"version"`
	// HostReport is the latest host pass (W34-09): privilege mode, unreadable
	// paths and file posture. Nil until the agent has pushed inventory.
	HostReport *AgentHostReport `json:"host_report,omitempty"`
}

// AgentDiscoveredCert is a certificate reported by an agent during inventory push.
type AgentDiscoveredCert struct {
	Fingerprint   string    `json:"fingerprint"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Source        string    `json:"source"`
	AutoRenewable bool      `json:"auto_renewable"`
	// DNSNames is the cert's SAN DNS list, as reported by the agent (W19-13).
	// Omitted by pre-W19-13 agents; renewalIdentifiers falls back to parsing
	// Subject's CN for those.
	DNSNames []string `json:"dns_names,omitempty"`
}

// AgentEndpoint is an installable TLS endpoint reported by an agent during
// inventory push — the v1.3 install contract (where a renewed cert is written
// and where it's verified).
type AgentEndpoint struct {
	ServerType string `json:"server_type"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
}

// AgentRenewalTask is a task the hub assigns to an agent.
//
// It has no CA/ACME-directory URL field (W19-26 removed the dead CAURL --
// declared, stored at agent_store_db.go, but never assigned by the hub or
// read by cmd/kryptkeeper-agent/internal/agentclient). The agent derives its
// ACME directory from its own KRYPTKEEPER_HUB_URL env var
// (acme_renewer.go: r.HubURL + "/acme/directory"), so the hub never needs to
// tell it where the CA is.
type AgentRenewalTask struct {
	TaskID      string    `json:"task_id"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Action      string    `json:"action"` // "renew" | "install"
	NotAfter    time.Time `json:"not_after"`
	// CreatedAt is when the hub queued this task (W19-26) -- surfaced via
	// GET /api/v1/agents/{id}/tasks so an operator has durable evidence of
	// task lifecycle beyond the audit log (UAT W19-04).
	CreatedAt time.Time `json:"created_at,omitempty"`

	// Install hints (v1.3 autopilot). Populated when the hub matches the cert
	// to a reported endpoint; empty for renew-only tasks.
	ServerType     string `json:"server_type,omitempty"`
	CertPath       string `json:"cert_path,omitempty"`
	KeyPath        string `json:"key_path,omitempty"`
	ReloadMethod   string `json:"reload_method,omitempty"`
	VerifyHostPort string `json:"verify_host_port,omitempty"`

	// Identifiers is the DNS SAN/CN list the agent's ACME renewer must use as
	// the order's identifiers (W19-13) -- never Subject, which is a full RDN
	// string (e.g. "CN=localhost") that can't satisfy HTTP-01. Populated by
	// renewalIdentifiers from the discovered cert's SANs, falling back to a
	// parsed CN. A cert whose CN isn't a valid hostname yields no
	// identifiers, and matchRenewalTasks skips queuing a task for it rather
	// than assigning an order that could never validate (see matchRenewalTasks).
	Identifiers []string `json:"identifiers,omitempty"`
}

// AgentRenewalResult is the install/verify outcome an agent reports back after
// acting on a renewal task — the v1.3 W2 close-the-loop signal.
type AgentRenewalResult struct {
	TaskID            string `json:"task_id"`
	Fingerprint       string `json:"fingerprint"`
	Outcome           string `json:"outcome"`
	ServedFingerprint string `json:"served_fingerprint,omitempty"`
	RolledBack        bool   `json:"rolled_back"`
	Detail            string `json:"detail,omitempty"`
	ReportedAt        string `json:"reported_at"`
}

type agentRecord struct {
	info      AgentInfo
	token     string
	inventory []AgentDiscoveredCert
	endpoints []AgentEndpoint
	tasks     []AgentRenewalTask
	results   []AgentRenewalResult
}

func (r *agentRecord) computedStatus() AgentStatus {
	return computeAgentStatus(r.info.LastSeen)
}

const (
	// agentStaleAfter is how long an agent may stay silent before it shows
	// "stale"; agentOfflineAfter before "offline". The 5-minute stale cutoff is
	// the UC-C05 acceptance threshold (stale within 5 minutes of stopping).
	agentStaleAfter   = 5 * time.Minute
	agentOfflineAfter = 30 * time.Minute

	// maxAgentVersionLen bounds the self-reported X-Agent-Version value.
	maxAgentVersionLen = 64

	// minAgentPruneAfter is the floor for KRYPTKEEPER_AGENT_PRUNE_AFTER: a
	// shorter window would delete agents that are merely between slow polls.
	minAgentPruneAfter = time.Hour
)

// ErrAgentNotFound is returned by AgentStore.remove for an unknown agent id.
var ErrAgentNotFound = errors.New("agent not found")

// computeAgentStatusAt derives agent status from its last-seen time as of now
// (a parameter so tests can drive it with a fake clock).
func computeAgentStatusAt(lastSeen *time.Time, now time.Time) AgentStatus {
	if lastSeen == nil {
		return AgentStatusOffline
	}
	age := now.Sub(*lastSeen)
	switch {
	case age < agentStaleAfter:
		return AgentStatusActive
	case age < agentOfflineAfter:
		return AgentStatusStale
	default:
		return AgentStatusOffline
	}
}

// computeAgentStatus derives agent status from its last-seen time. Shared by the
// in-memory and DB-backed stores.
func computeAgentStatus(lastSeen *time.Time) AgentStatus {
	return computeAgentStatusAt(lastSeen, time.Now())
}

// agentPruneAfterFromEnv reads KRYPTKEEPER_AGENT_PRUNE_AFTER (a Go duration).
// Unset, unparsable, or non-positive means pruning is off (0); values under
// minAgentPruneAfter are raised to it.
func agentPruneAfterFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_AGENT_PRUNE_AFTER"))
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0
	}
	if d < minAgentPruneAfter {
		logging.Infof("KRYPTKEEPER_AGENT_PRUNE_AFTER=%s is below the %s minimum; using %s", raw, minAgentPruneAfter, minAgentPruneAfter)
		return minAgentPruneAfter
	}
	return d
}

// sanitizeAgentVersion trims and bounds a self-reported agent version.
func sanitizeAgentVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxAgentVersionLen {
		v = strings.ToValidUTF8(v[:maxAgentVersionLen], "")
	}
	return v
}

// AgentStore is the registry of satellite agents. It has an in-memory
// implementation (memAgentStore, the default) and a DB-backed one
// (dbAgentStore) for restart-safe persistence. Methods are unexported — only
// internal/bootstrap implements this.
type AgentStore interface {
	register(name string, agentType AgentType) (id, token string, err error)
	heartbeat(agentID, token string) error
	submitInventory(agentID, token string, certs []AgentDiscoveredCert, endpoints []AgentEndpoint) error
	getTasks(agentID, token string) ([]AgentRenewalTask, error)
	submitRenewalResult(agentID, token string, result AgentRenewalResult) error
	endpointsFor(agentID string) []AgentEndpoint
	// tasksFor returns an agent's currently-queued tasks without an agent
	// token -- the admin-facing counterpart to getTasks (which the agent
	// itself calls, token-authenticated). Used by GET
	// /api/v1/agents/{id}/tasks (W19-26), same shape as endpointsFor.
	tasksFor(agentID string) []AgentRenewalTask
	resultsFor(agentID string) []AgentRenewalResult
	allResults() []AgentResultEntry
	endpointCount() (int, error)
	agentCounts() (total, active int)
	list() []AgentInfo
	// sweepRenewals re-evaluates every registered agent's last-known
	// inventory against the renewal threshold as of now, independent of
	// whether the agent has pushed fresh inventory since it was last
	// evaluated, and returns the number of tasks newly assigned. See
	// renewal_agent_driver.go for the gap this closes.
	sweepRenewals(now time.Time) int
	// setVersion records the version an authenticated agent reported. No-op
	// for an unknown id or an empty version.
	setVersion(agentID, version string)
	// setHostReport records an authenticated agent's latest host pass.
	setHostReport(agentID string, report AgentHostReport)
	// remove deletes an agent and all of its inventory/endpoints/tasks/results,
	// revoking its token. ErrAgentNotFound if absent.
	remove(agentID string) error
	// pruneSilent removes agents whose newest sign of life (last_seen, or
	// registered_at if never seen) is before cutoff, returning the removed ids.
	pruneSilent(cutoff time.Time) []string

	// registerWithID is register with a caller-chosen id (from newAgentID), so
	// an enrollment token can record the agent it enrols before the row exists.
	registerWithID(id, name string, agentType AgentType) (token string, err error)

	// W29-06 per-agent enrollment tokens: hashed at rest, single-use, expiring;
	// W33-24 adds the minting tenant and the redeeming agent id.
	mintEnrollmentToken(label, createdBy, tenant string, ttl time.Duration, now time.Time) (tok AgentEnrollmentToken, secret string, err error)
	// redeemEnrollmentToken consumes secret atomically and records agentID as
	// the redeeming agent in the same step; any failure is
	// ErrEnrollmentTokenInvalid (unknown, expired, revoked and used are indistinguishable).
	redeemEnrollmentToken(secret, agentID string, now time.Time) (tokenID string, err error)
	listEnrollmentTokens() []AgentEnrollmentToken
	// revokeEnrollmentToken: absent id is ErrAgentNotFound; already redeemed
	// or revoked is ErrEnrollmentTokenInvalid.
	revokeEnrollmentToken(id string, now time.Time) error
}

// renewalThresholdDaysFromEnv reads RENEWAL_THRESHOLD_DAYS (default 30).
func renewalThresholdDaysFromEnv() int {
	threshold := 30
	if raw := strings.TrimSpace(os.Getenv("RENEWAL_THRESHOLD_DAYS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			threshold = n
		}
	}
	return threshold
}

// memAgentStore is the in-memory registry of satellite agents.
type memAgentStore struct {
	mu      sync.RWMutex
	records map[string]*agentRecord
	enroll  map[string]*memEnrollToken

	// renewalThresholdDays controls how soon before expiry a cert is tasked for
	// autopilot renewal (RENEWAL_THRESHOLD_DAYS, default 30).
	renewalThresholdDays int
}

// NewAgentStore returns an in-memory agent store (the default; used by tests).
// Production wiring uses NewAgentStoreFromEnv for DB-backed persistence.
func NewAgentStore() AgentStore {
	return &memAgentStore{
		records:              make(map[string]*agentRecord),
		enroll:               make(map[string]*memEnrollToken),
		renewalThresholdDays: renewalThresholdDaysFromEnv(),
	}
}

func newAgentID() (string, error) {
	id, err := generateToken(8)
	if err != nil {
		return "", fmt.Errorf("generate agent id: %w", err)
	}
	return id, nil
}

func (s *memAgentStore) register(name string, agentType AgentType) (id, token string, err error) {
	if id, err = newAgentID(); err != nil {
		return "", "", err
	}
	token, err = s.registerWithID(id, name, agentType)
	return id, token, err
}

func (s *memAgentStore) registerWithID(id, name string, agentType AgentType) (token string, err error) {
	token, err = generateToken(32)
	if err != nil {
		return "", fmt.Errorf("generate agent token: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[id] = &agentRecord{
		info: AgentInfo{
			ID:           id,
			Name:         name,
			Type:         agentType,
			RegisteredAt: time.Now().UTC(),
			Status:       AgentStatusOffline,
		},
		token: token,
		tasks: []AgentRenewalTask{},
	}
	return token, nil
}

func (s *memAgentStore) setVersion(agentID, version string) {
	if version == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.records[agentID]; ok {
		r.info.Version = version
	}
}

func (s *memAgentStore) setHostReport(agentID string, report AgentHostReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.records[agentID]; ok {
		r.info.HostReport = &report
	}
}

func (s *memAgentStore) remove(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[agentID]; !ok {
		return ErrAgentNotFound
	}
	delete(s.records, agentID)
	return nil
}

func (s *memAgentStore) pruneSilent(cutoff time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []string
	for id, r := range s.records {
		newest := r.info.RegisteredAt
		if r.info.LastSeen != nil && r.info.LastSeen.After(newest) {
			newest = *r.info.LastSeen
		}
		if newest.Before(cutoff) {
			delete(s.records, id)
			removed = append(removed, id)
		}
	}
	return removed
}

func (s *memAgentStore) heartbeat(agentID, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[agentID]
	if !ok || r.token != token {
		return ErrAgentUnauthorized
	}
	now := time.Now().UTC()
	r.info.LastSeen = &now
	return nil
}

func (s *memAgentStore) submitInventory(agentID, token string, certs []AgentDiscoveredCert, endpoints []AgentEndpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[agentID]
	if !ok || r.token != token {
		return ErrAgentUnauthorized
	}
	r.inventory = certs
	r.endpoints = endpoints
	r.info.InventoryCount = len(certs)
	now := time.Now().UTC()
	r.info.LastSeen = &now
	s.assignTasksLocked(r, now)
	return nil
}

// assignTasksLocked appends newly-matched renewal tasks to the agent record.
// The caller must hold s.mu.
func (s *memAgentStore) assignTasksLocked(r *agentRecord, now time.Time) {
	r.tasks = append(r.tasks, matchRenewalTasks(
		r.inventory, r.endpoints, r.tasks, r.results,
		s.renewalThresholdDays, now, newRenewalTaskID,
	)...)
}

// sweepRenewals re-evaluates every registered agent's already-stored
// inventory against the renewal threshold as of now. Reuses
// assignTasksLocked (itself a thin wrapper over matchRenewalTasks) for each
// agent — no separate assignment logic. See renewal_agent_driver.go for the
// gap this closes.
func (s *memAgentStore) sweepRenewals(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	added := 0
	for _, r := range s.records {
		before := len(r.tasks)
		s.assignTasksLocked(r, now)
		added += len(r.tasks) - before
	}
	return added
}

// newRenewalTaskID generates a task identifier ("task-" + random hex).
func newRenewalTaskID() string {
	id, err := generateToken(8)
	if err != nil {
		return ""
	}
	return "task-" + id
}

// matchRenewalTasks is the shared, backend-agnostic assignment logic: it returns
// the install-hinted tasks to ADD for expiring auto-renewable certs that match a
// reported endpoint (by cert file path). It is idempotent — it never returns a
// task for a fingerprint already pending, and skips fingerprints already
// verified. Used by both the in-memory and DB-backed stores.
func matchRenewalTasks(
	inventory []AgentDiscoveredCert,
	endpoints []AgentEndpoint,
	existingTasks []AgentRenewalTask,
	results []AgentRenewalResult,
	thresholdDays int,
	now time.Time,
	newID func() string,
) []AgentRenewalTask {
	threshold := now.AddDate(0, 0, thresholdDays)

	tasked := make(map[string]bool)
	for _, t := range existingTasks {
		tasked[t.Fingerprint] = true
	}
	verified := make(map[string]bool)
	for _, res := range results {
		if res.Outcome == "installed_verified" || res.Outcome == "installed" {
			verified[res.Fingerprint] = true
		}
	}
	epByCertPath := make(map[string]AgentEndpoint, len(endpoints))
	for _, e := range endpoints {
		epByCertPath[e.CertPath] = e
	}

	var added []AgentRenewalTask
	for _, c := range inventory {
		if !c.AutoRenewable || c.Fingerprint == "" {
			continue
		}
		if c.NotAfter.IsZero() || c.NotAfter.After(threshold) {
			continue // not approaching expiry yet
		}
		if tasked[c.Fingerprint] || verified[c.Fingerprint] {
			continue
		}
		ep, ok := epByCertPath[c.Source]
		if !ok {
			continue // no installable endpoint for this cert
		}
		identifiers := renewalIdentifiers(c)
		if len(identifiers) == 0 {
			// W19-13: no SAN and no CN that parses as a hostname (e.g. a CN
			// of "My Service") means there is no identifier an ACME order
			// could ever validate. submitRenewalResult clears a task on
			// failure so the next inventory cycle would re-task it --
			// queuing this would be a permanent retry loop against the ACME
			// server for a cert that can never renew. Skip rather than
			// queue; there is no "unrenewable" flag to set that an old
			// agent would honor anyway.
			continue
		}
		id := newID()
		if id == "" {
			continue
		}
		added = append(added, AgentRenewalTask{
			TaskID:         id,
			Fingerprint:    c.Fingerprint,
			Subject:        c.Subject,
			Action:         "renew",
			NotAfter:       c.NotAfter,
			CreatedAt:      now,
			ServerType:     ep.ServerType,
			CertPath:       ep.CertPath,
			KeyPath:        ep.KeyPath,
			VerifyHostPort: ep.verifyHostPort(),
			Identifiers:    identifiers,
		})
		tasked[c.Fingerprint] = true
	}
	return added
}

// renewalIdentifiers returns the DNS identifiers an ACME order for c's
// renewal should use: c's reported SAN DNS names first (deduplicated,
// invalid entries dropped), then c.Subject's CN if it parses as a
// syntactically valid hostname and isn't already present. Never returns the
// raw Subject RDN string as an identifier (W19-13; UAT W19-04 observed the
// hub queuing "CN=localhost" verbatim, which can't satisfy HTTP-01).
func renewalIdentifiers(c AgentDiscoveredCert) []string {
	seen := make(map[string]bool, len(c.DNSNames)+1)
	var ids []string
	for _, d := range c.DNSNames {
		d = strings.TrimSpace(d)
		if d == "" || seen[strings.ToLower(d)] || !isValidHostname(d) {
			continue
		}
		seen[strings.ToLower(d)] = true
		ids = append(ids, d)
	}
	if cn, ok := parseCNHostname(c.Subject); ok && !seen[strings.ToLower(cn)] {
		ids = append(ids, cn)
	}
	return ids
}

// parseCNHostname extracts the CN attribute value from an RDN string in the
// form pkix.Name.String() produces (e.g. "CN=localhost,O=Example") and
// reports whether it is a syntactically valid hostname. Used only as a
// fallback when a cert reports no SANs, or as a compatibility path for a
// pre-W19-13 agent that only ever reported Subject.
func parseCNHostname(subject string) (string, bool) {
	for _, part := range splitRDN(subject) {
		if v, ok := strings.CutPrefix(part, "CN="); ok {
			v = strings.TrimSpace(v)
			return v, isValidHostname(v)
		}
	}
	return "", false
}

// splitRDN splits a pkix.Name.String() RDN sequence on unescaped commas
// (RFC 2253 backslash-escapes a literal comma inside an attribute value).
func splitRDN(s string) []string {
	var parts []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts
}

// isValidHostname reports whether h is a syntactically valid DNS hostname
// suitable for an ACME identifier -- single-label names like "localhost" are
// accepted (that is the actual live case: UAT W19-04's fixture cert had
// CN=localhost), but an IP literal or anything with invalid label
// characters is not.
func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
	}
	return true
}

// verifyHostPort returns the host:port to TLS-dial when confirming an install.
// Falls back to localhost and 443, matching agentclient.Endpoint.VerifyHostPort.
func (e AgentEndpoint) verifyHostPort() string {
	host := e.ServerName
	if host == "" || host == "_" || strings.HasPrefix(host, "*") {
		host = "localhost"
	}
	port := e.ListenPort
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// endpointsFor returns the installable endpoints last reported by an agent.
func (s *memAgentStore) endpointsFor(agentID string) []AgentEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[agentID]
	if !ok {
		return nil
	}
	out := make([]AgentEndpoint, len(r.endpoints))
	copy(out, r.endpoints)
	return out
}

// tasksFor returns the currently-queued tasks for an agent, no token required
// (admin path -- see AgentStore.tasksFor doc comment).
func (s *memAgentStore) tasksFor(agentID string) []AgentRenewalTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[agentID]
	if !ok {
		return nil
	}
	out := make([]AgentRenewalTask, len(r.tasks))
	copy(out, r.tasks)
	return out
}

// maxAgentResults caps the per-agent renewal-result history to bound memory.
const maxAgentResults = 100

// submitRenewalResult records an install/verify outcome reported by an agent.
func (s *memAgentStore) submitRenewalResult(agentID, token string, result AgentRenewalResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[agentID]
	if !ok || r.token != token {
		return ErrAgentUnauthorized
	}
	r.results = append(r.results, result)
	if len(r.results) > maxAgentResults {
		r.results = r.results[len(r.results)-maxAgentResults:]
	}
	// Clear the completed task. A failure (rolled back) leaves no task, so the
	// next inventory cycle re-tasks it if the cert is still expiring — i.e.
	// failures auto-retry; successes won't re-match (the cert is renewed).
	r.tasks = removeTask(r.tasks, result.TaskID, result.Fingerprint)
	now := time.Now().UTC()
	r.info.LastSeen = &now
	return nil
}

// removeTask drops the task matching taskID (or fingerprint when taskID empty).
func removeTask(tasks []AgentRenewalTask, taskID, fingerprint string) []AgentRenewalTask {
	out := tasks[:0]
	for _, t := range tasks {
		match := (taskID != "" && t.TaskID == taskID) ||
			(taskID == "" && fingerprint != "" && t.Fingerprint == fingerprint)
		if match {
			continue
		}
		out = append(out, t)
	}
	return out
}

// resultsFor returns the renewal-result history reported by an agent.
func (s *memAgentStore) resultsFor(agentID string) []AgentRenewalResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[agentID]
	if !ok {
		return nil
	}
	out := make([]AgentRenewalResult, len(r.results))
	copy(out, r.results)
	return out
}

// AgentTaskResult is one row of the merged queued-task/reported-result view
// GET /api/v1/agents/{id}/tasks returns (W19-26): today the audit log is the
// only durable evidence of what an agent was asked to do and what happened,
// so this exposes the same data resultsFor already tracked internally.
// Status discriminates the two source rows this is built from -- a currently
// queued AgentRenewalTask (Action/Identifiers/CreatedAt populated, no
// outcome yet) or a completed AgentRenewalResult (Outcome/Detail/CompletedAt
// populated; Action/Identifiers are not recorded per-result so are empty).
type AgentTaskResult struct {
	TaskID      string    `json:"task_id"`
	Fingerprint string    `json:"fingerprint"`
	Action      string    `json:"action,omitempty"`
	Identifiers []string  `json:"identifiers,omitempty"`
	Status      string    `json:"status"` // "queued" | "completed"
	Outcome     string    `json:"outcome,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// mergeAgentTaskResults combines an agent's currently-queued tasks and its
// reported result history into one chronological-ish view: completed results
// (oldest first, as resultsFor already orders them) followed by whatever is
// still queued. A pure function so it's testable without a store.
func mergeAgentTaskResults(tasks []AgentRenewalTask, results []AgentRenewalResult) []AgentTaskResult {
	out := make([]AgentTaskResult, 0, len(tasks)+len(results))
	for _, res := range results {
		out = append(out, AgentTaskResult{
			TaskID:      res.TaskID,
			Fingerprint: res.Fingerprint,
			Status:      "completed",
			Outcome:     res.Outcome,
			Detail:      res.Detail,
			CompletedAt: parseTimeOrZero(res.ReportedAt),
		})
	}
	for _, t := range tasks {
		out = append(out, AgentTaskResult{
			TaskID:      t.TaskID,
			Fingerprint: t.Fingerprint,
			Action:      t.Action,
			Identifiers: t.Identifiers,
			Status:      "queued",
			CreatedAt:   t.CreatedAt,
		})
	}
	return out
}

// AgentResultEntry pairs a renewal result with the agent that reported it.
type AgentResultEntry struct {
	AgentID string
	Result  AgentRenewalResult
}

// allResults returns every renewal result across all agents (for SLO aggregation).
func (s *memAgentStore) allResults() []AgentResultEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []AgentResultEntry
	for id, r := range s.records {
		for _, res := range r.results {
			out = append(out, AgentResultEntry{AgentID: id, Result: res})
		}
	}
	return out
}

// endpointCount returns the total installable endpoints reported across agents.
func (s *memAgentStore) endpointCount() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, r := range s.records {
		n += len(r.endpoints)
	}
	return n, nil
}

// agentCounts returns the total and active (recently-seen) agent counts.
func (s *memAgentStore) agentCounts() (total, active int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.records {
		total++
		if r.computedStatus() == AgentStatusActive {
			active++
		}
	}
	return total, active
}

func (s *memAgentStore) getTasks(agentID, token string) ([]AgentRenewalTask, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[agentID]
	if !ok || r.token != token {
		return nil, ErrAgentUnauthorized
	}
	out := make([]AgentRenewalTask, len(r.tasks))
	copy(out, r.tasks)
	return out, nil
}

func (s *memAgentStore) list() []AgentInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentInfo, 0, len(s.records))
	for _, r := range s.records {
		info := r.info
		info.Status = r.computedStatus()
		out = append(out, info)
	}
	return out
}

// ErrAgentUnauthorized is returned when an agent token is invalid or unknown.
var ErrAgentUnauthorized = fmt.Errorf("invalid agent id or token")

func generateToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// agentRegisterLimitPerMinute caps unauthenticated register attempts per
// client IP (W33-24; token guessing is infeasible at 256 bits, this bounds noise).
const agentRegisterLimitPerMinute = 30

// registerAgentHandlers wires all /api/v1/agent* routes.
func registerAgentHandlers(mux routeRegistrar, auth *Authenticator, store AgentStore, auditProvider AuditProvider) {
	// W5-07: enrollment is gated — closed by default, secret-based, or
	// (migration only) explicitly open. Resolved once at registration.
	enrollmentGate := NewAgentEnrollmentGateFromEnv()
	// announcedRunning dedupes the install "running" event: an agent polls
	// GET /agent/tasks repeatedly while a task stays queued.
	var announcedRunning sync.Map

	// POST /api/v1/agent/register — no JWT, but enrollment evidence
	// (W5-07) is required; anonymous self-registration is refused.
	mux.HandleFunc("POST /api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string    `json:"name"`
			Type AgentType `json:"type"`
			// EnrollmentSecret and EnrollmentToken are consumed by the gate /
			// store — never stored, never logged, never audited.
			EnrollmentSecret string `json:"enrollment_secret"`
			EnrollmentToken  string `json:"enrollment_token"`
		}
		if !auth.allowRateLimit("agent-register:"+clientIP(r), agentRegisterLimitPerMinute, time.Minute, time.Now()) {
			emitAuditEvent(r, auditProvider, "", "agent.register", "agent", "-", AuditOutcomeDenied)
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAgentSmallBodyBytes, "invalid JSON") {
			return
		}
		secret := req.EnrollmentSecret
		if secret == "" {
			secret = r.Header.Get("X-Enrollment-Secret")
		}
		enrollToken := req.EnrollmentToken
		if enrollToken == "" {
			enrollToken = r.Header.Get("X-Enrollment-Token")
		}
		// Evidence order: token (wins), then configured secret / open flag.
		if enrollToken == "" {
			if err := enrollmentGate.Check(AgentEnrollmentEvidence{Secret: secret}); err != nil {
				emitAuditEvent(r, auditProvider, "", "agent.register", "agent", req.Name, AuditOutcomeDenied)
				// The gate's own text names enrollment env vars and tells a probe
				// whether secrets are configured or registration is closed; that is
				// operator information, so it goes to the log, not the caller.
				logging.Warnf("agent register refused for %q: %v", req.Name, err)
				if secret == "" {
					writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "enrollment credential required")
					return
				}
				writeForbidden(w, "enrollment refused")
				return
			}
		}
		if req.Name == "" {
			emitAuditEvent(r, auditProvider, "", "agent.register", "agent", "-", AuditOutcomeFailure)
			writeBadRequest(w, "name is required")
			return
		}
		if req.Type == "" {
			req.Type = AgentTypeLinux
		}
		id, err := newAgentID()
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "agent.register", "agent", req.Name, AuditOutcomeFailure)
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		via := `{"via":"secret"}`
		if enrollToken != "" {
			// The id is fixed before the redeem so the token row records the
			// agent it enrolled in the same conditional UPDATE (W33-24 attach).
			tokenID, err := store.redeemEnrollmentToken(enrollToken, id, time.Now())
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "agent.register", "agent", req.Name, AuditOutcomeDenied)
				writeForbidden(w, "enrollment refused")
				return
			}
			via = fmt.Sprintf(`{"enrollment_token_id":%q}`, tokenID)
		}
		token, err := store.registerWithID(id, req.Name, req.Type)
		if err != nil {
			// A redeemed token is burned on a register failure (documented).
			emitAuditEventDetail(r, auditProvider, "", "agent.register", "agent", req.Name, AuditOutcomeFailure, via)
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		emitAuditEventDetail(r, auditProvider, "agent:"+id, "agent.register", "agent", id, AuditOutcomeSuccess, via)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": id,
			"token":    token,
		})
	})

	// POST /api/v1/agent/heartbeat — agent liveness ping
	mux.HandleFunc("POST /api/v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		agentID, token, ok := agentCredentials(r)
		if !ok {
			emitAuditEvent(r, auditProvider, "", "agent.heartbeat", "agent", "-", AuditOutcomeDenied)
			writeBadRequest(w, "missing X-Agent-ID or X-Agent-Token")
			return
		}
		if err := store.heartbeat(agentID, token); err != nil {
			emitAuditEvent(r, auditProvider, "agent:"+agentID, "agent.heartbeat", "agent", agentID, AuditOutcomeDenied)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		store.setVersion(agentID, sanitizeAgentVersion(r.Header.Get("X-Agent-Version")))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// POST /api/v1/agent/inventory — agent pushes discovered certs
	mux.HandleFunc("POST /api/v1/agent/inventory", func(w http.ResponseWriter, r *http.Request) {
		agentID, token, ok := agentCredentials(r)
		if !ok {
			emitAuditEvent(r, auditProvider, "", "agent.inventory", "agent", "-", AuditOutcomeDenied)
			writeBadRequest(w, "missing X-Agent-ID or X-Agent-Token")
			return
		}
		var req struct {
			Certs     []AgentDiscoveredCert `json:"certs"`
			Endpoints []AgentEndpoint       `json:"endpoints"`
			agentHostPush
		}
		if !decodeJSONBodyOrReject(w, r, &req, maxAgentInventoryBodyBytes, "invalid JSON") {
			return
		}
		before := taskIDSet(store.tasksFor(agentID))
		if err := store.submitInventory(agentID, token, req.Certs, req.Endpoints); err != nil {
			emitAuditEvent(r, auditProvider, "agent:"+agentID, "agent.inventory", "agent", agentID, AuditOutcomeDenied)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		store.setVersion(agentID, sanitizeAgentVersion(r.Header.Get("X-Agent-Version")))
		store.setHostReport(agentID, buildAgentHostReport(req.agentHostPush, time.Now()))
		for _, t := range store.tasksFor(agentID) {
			if _, existed := before[t.TaskID]; !existed && isInstallTask(t) {
				publishOperationEvent(DefaultTenant, EventKindInstall, t.TaskID, "queued", nil, "")
			}
		}
		emitAuditEvent(r, auditProvider, "agent:"+agentID, "agent.inventory", "agent", agentID, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(req.Certs)})
	})

	// POST /api/v1/agent/renewal-result — agent reports install/verify outcome
	mux.HandleFunc("POST /api/v1/agent/renewal-result", func(w http.ResponseWriter, r *http.Request) {
		agentID, token, ok := agentCredentials(r)
		if !ok {
			emitAuditEvent(r, auditProvider, "", "agent.renewal_result", "agent", "-", AuditOutcomeDenied)
			writeBadRequest(w, "missing X-Agent-ID or X-Agent-Token")
			return
		}
		var result AgentRenewalResult
		if !decodeJSONBodyOrReject(w, r, &result, maxAgentResultBodyBytes, "invalid JSON") {
			return
		}
		if result.ReportedAt == "" {
			result.ReportedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if err := store.submitRenewalResult(agentID, token, result); err != nil {
			emitAuditEvent(r, auditProvider, "agent:"+agentID, "agent.renewal_result", "agent", agentID, AuditOutcomeDenied)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		// Audit outcome: anything that rolled back or failed is a failure.
		outcome := AuditOutcomeSuccess
		if result.RolledBack || (result.Outcome != "" &&
			result.Outcome != "installed_verified" && result.Outcome != "installed") {
			outcome = AuditOutcomeFailure
		}
		emitAuditEvent(r, auditProvider, "agent:"+agentID, "agent.renewal_result", "certificate", result.Fingerprint, outcome)
		if outcome == AuditOutcomeSuccess {
			publishOperationEvent(DefaultTenant, EventKindInstall, result.TaskID, "completed", nil, "installed")
		} else {
			publishOperationEvent(DefaultTenant, EventKindInstall, result.TaskID, "failed", nil, "install failed")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
	})

	// GET /api/v1/agent/tasks — agent polls for pending renewal tasks
	mux.HandleFunc("GET /api/v1/agent/tasks", func(w http.ResponseWriter, r *http.Request) {
		agentID, token, ok := agentCredentials(r)
		if !ok {
			writeBadRequest(w, "missing X-Agent-ID or X-Agent-Token")
			return
		}
		tasks, err := store.getTasks(agentID, token)
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		for _, t := range tasks {
			if isInstallTask(t) {
				if _, seen := announcedRunning.LoadOrStore(t.TaskID, struct{}{}); !seen {
					publishOperationEvent(DefaultTenant, EventKindInstall, t.TaskID, "running", nil, "")
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks})
	})

	// GET /api/v1/agents — admin list (requires bearer JWT)
	mux.HandleFunc("GET /api/v1/agents", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		// D-203: agents carry no tenant column, so the fleet view is global.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "agent.list", "agent", "-") {
			return
		}
		// Prune is lazy (no background loop owns the agent store) and opt-in.
		if d := agentPruneAfterFromEnv(); d > 0 {
			for _, id := range store.pruneSilent(time.Now().Add(-d)) {
				emitAuditEvent(r, auditProvider, "system", "agent.prune", "agent", id, AuditOutcomeSuccess)
			}
		}
		agents := store.list()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": agents})
	})

	// GET /api/v1/agents/{id}/tasks — admin view of one agent's queued tasks
	// and reported results (W19-26). Trailing-slash catch-all + manual
	// sub-path parsing, matching this codebase's convention for sub-resource
	// routes (see handlers_certificates.go) rather than a Go 1.22 {id}
	// pattern, which nothing else here uses. Authorized the same way as the
	// list endpoint above. Agents carry no tenant column (see agent_store_db.go),
	// so under multi-tenancy both are global-admin-only (D-203).
	mux.HandleFunc("GET /api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		// D-203: agents carry no tenant column, so the fleet view is global.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "agent.tasks", "agent", strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")) {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
		id, sub, ok := strings.Cut(rest, "/")
		if !ok || sub != "tasks" || id == "" {
			http.NotFound(w, r)
			return
		}
		if !agentExists(store, id) {
			writeNotFound(w, "agent not found")
			return
		}
		result := mergeAgentTaskResults(store.tasksFor(id), store.resultsFor(id))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": result})
	})

	registerAgentRemoveHandler(mux, auth, store, auditProvider)
	registerAgentEnrollmentTokenHandlers(mux, auth, store, auditProvider)
}

// DELETE /api/v1/agents/{id} removes an agent and revokes its credential: the
// token lives in the agent's row, so the agent's next call gets 401. Admin
// only; hand-parsed like the GET sub-route above.
func registerAgentRemoveHandler(mux routeRegistrar, auth *Authenticator, store AgentStore, auditProvider AuditProvider) {
	mux.HandleFunc("DELETE /api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "agent.remove", "agent", id, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		// D-203: a tenant-scoped pki-admin must not delete another tenant's agents.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "agent.remove", "agent", id) {
			return
		}
		if err := store.remove(id); err != nil {
			if errors.Is(err, ErrAgentNotFound) {
				emitAuditEvent(r, auditProvider, pd.ID, "agent.remove", "agent", id, AuditOutcomeFailure)
				writeNotFound(w, "agent not found")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "agent.remove", "agent", id, AuditOutcomeFailure)
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "agent.remove", "agent", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}

// agentExists reports whether agentID is registered. list() is the only
// store method that already returns full AgentInfo; small fleets (the
// expected agent-store scale) make an O(n) scan cheaper than adding a
// dedicated get-by-id method to AgentStore for this one 404 check.
func agentExists(store AgentStore, agentID string) bool {
	for _, a := range store.list() {
		if a.ID == agentID {
			return true
		}
	}
	return false
}

// agentCredentials extracts X-Agent-ID and X-Agent-Token from request headers.
func agentCredentials(r *http.Request) (agentID, token string, ok bool) {
	agentID = r.Header.Get("X-Agent-ID")
	token = r.Header.Get("X-Agent-Token")
	return agentID, token, agentID != "" && token != ""
}

func taskIDSet(tasks []AgentRenewalTask) map[string]struct{} {
	ids := make(map[string]struct{}, len(tasks))
	for _, t := range tasks {
		ids[t.TaskID] = struct{}{}
	}
	return ids
}

// isInstallTask reports whether a task installs the renewed cert. The hub
// queues every task as Action "renew" carrying the matched endpoint's
// install hints (matchRenewalTasks), so the hints, not the Action string,
// are what mark a task as an install operation.
func isInstallTask(t AgentRenewalTask) bool {
	return t.Action == "install" || t.CertPath != ""
}
