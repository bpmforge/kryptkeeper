// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/logging"
)

// W15-02: per-key custody evidence — backend, rotation history, and
// access events — from data the platform already holds. The
// regulatory driver is documented key custody; the append-only audit
// trail is the single source of custody truth (nothing reconstructable
// from the audit log is a bug, per the laws).

// PQCCustodyStatement is the single auditor-facing statement of PQC key
// custody (ADR D-086, W31-19). ui/src/pages/Keys.tsx carries the same literal;
// TestPQCCustodyStatementMatchesKeysPage fails if the two drift.
const PQCCustodyStatement = "ML-DSA and hybrid keys are generated and held in the software keystore only (Argon2id + AES-256-GCM). HSM, KMS and Vault backends refuse them with a citation of docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md (D-086). Hardware-backed PQC key custody is not provided."

// KeyCustodyEntry is one key's custody facts.
type KeyCustodyEntry struct {
	KeyID          string            `json:"key_id"`
	Algorithm      string            `json:"algorithm"`
	Backend        string            `json:"backend"`
	CreatedAt      string            `json:"created_at,omitempty"`
	Deleted        bool              `json:"deleted,omitempty"`
	Imported       bool              `json:"imported,omitempty"`
	RotationCount  int               `json:"rotation_count"`
	LastRotatedAt  string            `json:"last_rotated_at,omitempty"`
	AccessCount    int               `json:"access_count"`
	LastAccessedAt string            `json:"last_accessed_at,omitempty"`
	Events         []KeyCustodyEvent `json:"events"`
}

// KeyCustodyReport is the whole-keystore custody evidence.
type KeyCustodyReport struct {
	GeneratedAt       string            `json:"generated_at"`
	Backend           string            `json:"backend"`
	DualControlEscrow bool              `json:"dual_control_escrow"`
	Keys              []KeyCustodyEntry `json:"keys"`
	// EventCounts always carries all five custody actions, recomputed from the
	// keys visible to the caller so a tenant never sees foreign totals.
	EventCounts map[string]int `json:"event_counts"`
	// Truncated is set when the audit trail exceeded the read limit.
	Truncated bool `json:"truncated,omitempty"`
	// Targets lists the effective key-handling mode of every target visible
	// to the caller (W23-46).
	Targets []TargetKeyModeEntry `json:"targets"`
	// PQCCustody states that ML-DSA/hybrid keys are software-keystore-only.
	PQCCustody string `json:"pqc_custody_statement"`
}

// keystoreBackendLabel maps the concrete store type to the custody
// boundary auditors ask about.
func keystoreBackendLabel(store keystore.Store) string {
	// Match by type NAME rather than concrete type: PKCS11Store is
	// build-tag-gated (//go:build pkcs11) and absent from the default
	// build, so a typed case would not compile.
	name := fmt.Sprintf("%T", store)
	switch {
	case strings.Contains(name, "SoftwareStore"):
		return "software"
	case strings.Contains(name, "PKCS11Store"):
		return "pkcs11-hsm"
	case strings.Contains(name, "VaultStore"):
		return "vault-transit"
	case strings.Contains(name, "CloudKMSStore"):
		return "cloud-kms"
	default:
		return name
	}
}

// keyUseActions are the audit actions that count as ACCESS to key
// material (a signing/get/export operation).
var keyUseActions = map[string]bool{"key.op": true, "key.get": true, "key.export": true}

// Custody event actions reported per key (W28-16).
const (
	custodyExport        = "key.export"
	custodyEscrow        = "key.escrow"
	custodyEscrowRecover = "key.escrow_recover"
	custodyRotate        = "key.rotate"
	custodyDelete        = "key.delete"
)

var custodyActions = []string{custodyExport, custodyEscrow, custodyEscrowRecover, custodyRotate, custodyDelete}

// grantActionAudit maps grant-type approvals to the audit action written when
// the grant is redeemed.
var grantActionAudit = map[string]string{
	keyActionExport:        custodyExport,
	keyActionEscrow:        custodyEscrow,
	keyActionEscrowRecover: custodyEscrowRecover,
}

// KeyCustodyEvent is one export/escrow/rotate/delete with the three roles an
// auditor asks about. Approver is "" only when dual control was off.
type KeyCustodyEvent struct {
	Action      string `json:"action"`
	OccurredAt  string `json:"occurred_at"`
	Requester   string `json:"requester"`
	Approver    string `json:"approver"`
	Redeemer    string `json:"redeemer"`
	DualControl bool   `json:"dual_control"`
	ApprovalID  string `json:"approval_id,omitempty"`
}

// custodyData is everything derived from one audit pass plus the approvals queue.
type custodyData struct {
	events     map[string][]KeyCustodyEvent
	imported   map[string]bool
	rotations  map[string]int
	lastRotate map[string]string
	accesses   map[string]int
	lastAccess map[string]string
	truncated  bool
}

func parseRFC3339(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func collectKeyCustody(ctx context.Context, audit AuditProvider, approvals PendingActionStore) (custodyData, error) {
	d := custodyData{
		events:     map[string][]KeyCustodyEvent{},
		imported:   map[string]bool{},
		rotations:  map[string]int{},
		lastRotate: map[string]string{},
		accesses:   map[string]int{},
		lastAccess: map[string]string{},
	}
	var rows []AuditEntry
	if audit != nil {
		res, err := audit.ListEntries(ctx, AuditListQuery{ResourceType: "key", Limit: 10000, Order: "asc"})
		if err != nil {
			return d, err
		}
		rows = res.Entries
		if res.Total > len(res.Entries) {
			logging.Infof("key-custody: audit trail truncated (%d of %d entries)", len(res.Entries), res.Total)
			d.truncated = true
		}
	}

	// Approved key actions per (type, key id), oldest decision first.
	type pending struct {
		a    PendingAction
		at   time.Time
		used bool
	}
	approved := map[string][]*pending{}
	var direct []KeyCustodyEvent // delete/rotate events from approvals
	directKeys := []string{}
	if approvals != nil {
		list, err := approvals.List(ctx, "approved")
		if err != nil {
			return d, err
		}
		for _, a := range list {
			if !isKeyAction(a.ActionType) {
				continue
			}
			var p keyActionParams
			if json.Unmarshal(a.Params, &p) != nil || p.KeyID == "" {
				continue
			}
			switch a.ActionType {
			case keyActionDelete, keyActionRotate:
				act := custodyDelete
				if a.ActionType == keyActionRotate {
					act = custodyRotate
				}
				// Executed at approval time, by the approver's request.
				direct = append(direct, KeyCustodyEvent{Action: act, OccurredAt: a.DecidedAt, Requester: a.ProposedBy,
					Approver: a.ApprovedBy, Redeemer: a.ApprovedBy, DualControl: true, ApprovalID: a.ID})
				directKeys = append(directKeys, p.KeyID)
			default:
				if _, ok := grantActionAudit[a.ActionType]; !ok {
					continue
				}
				at, ok := parseRFC3339(a.DecidedAt)
				if !ok {
					continue
				}
				k := a.ActionType + "|" + p.KeyID
				approved[k] = append(approved[k], &pending{a: a, at: at})
			}
		}
		for _, v := range approved {
			sort.SliceStable(v, func(i, j int) bool { return v[i].at.Before(v[j].at) })
		}
	}
	for i, ev := range direct {
		d.events[directKeys[i]] = append(d.events[directKeys[i]], ev)
	}

	auditToType := map[string]string{}
	for t, a := range grantActionAudit {
		auditToType[a] = t
	}
	for _, e := range rows {
		id := e.ResourceID
		if keyUseActions[e.Action] {
			d.accesses[id]++
			d.lastAccess[id] = e.Timestamp
		}
		if e.Outcome != AuditOutcomeSuccess {
			continue
		}
		if e.Action == "key.import" {
			d.imported[id] = true
			continue
		}
		switch e.Action {
		case custodyDelete, custodyRotate:
			d.events[id] = append(d.events[id], KeyCustodyEvent{Action: e.Action, OccurredAt: e.Timestamp,
				Requester: e.ActorID, Redeemer: e.ActorID})
		case custodyExport, custodyEscrow, custodyEscrowRecover:
			ev := KeyCustodyEvent{Action: e.Action, OccurredAt: e.Timestamp, Requester: e.ActorID, Redeemer: e.ActorID}
			if rt, ok := parseRFC3339(e.Timestamp); ok {
				for _, p := range approved[auditToType[e.Action]+"|"+id] {
					if !p.used && !p.at.After(rt) {
						p.used = true
						ev.Requester, ev.Approver, ev.DualControl, ev.ApprovalID = p.a.ProposedBy, p.a.ApprovedBy, true, p.a.ID
						break
					}
				}
			}
			d.events[id] = append(d.events[id], ev)
		}
	}
	for id, evs := range d.events {
		sort.SliceStable(evs, func(i, j int) bool {
			ti, oki := parseRFC3339(evs[i].OccurredAt)
			tj, okj := parseRFC3339(evs[j].OccurredAt)
			if oki && okj {
				return ti.Before(tj)
			}
			return evs[i].OccurredAt < evs[j].OccurredAt
		})
		for _, ev := range evs {
			if ev.Action == custodyRotate {
				d.rotations[id]++
				d.lastRotate[id] = ev.OccurredAt
			}
		}
	}
	return d, nil
}

func countCustodyEvents(keys []KeyCustodyEntry) map[string]int {
	c := make(map[string]int, len(custodyActions))
	for _, a := range custodyActions {
		c[a] = 0
	}
	for _, k := range keys {
		for _, ev := range k.Events {
			c[ev.Action]++
		}
	}
	return c
}

// buildKeyCustodyReport assembles the report from the keystore and the
// append-only audit trail.
func buildKeyCustodyReport(ctx context.Context, store keystore.Store, auditProvider AuditProvider) (KeyCustodyReport, error) {
	return buildKeyCustodyReportWithApprovals(ctx, store, auditProvider, nil)
}

func buildKeyCustodyReportWithApprovals(ctx context.Context, store keystore.Store, auditProvider AuditProvider, approvals PendingActionStore) (KeyCustodyReport, error) {
	metas, err := store.List()
	if err != nil {
		return KeyCustodyReport{}, err
	}
	backend := keystoreBackendLabel(store)
	report := KeyCustodyReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Backend:           backend,
		DualControlEscrow: strings.TrimSpace(os.Getenv("APP_KEY_ESCROW_CUSTODIANS")) != "",
		Keys:              []KeyCustodyEntry{},
		Targets:           []TargetKeyModeEntry{},
		PQCCustody:        PQCCustodyStatement,
	}
	d, err := collectKeyCustody(ctx, auditProvider, approvals)
	if err != nil {
		return KeyCustodyReport{}, err
	}
	report.Truncated = d.truncated

	live := map[string]bool{}
	for _, m := range metas {
		live[m.ID] = true
		evs := d.events[m.ID]
		if evs == nil {
			evs = []KeyCustodyEvent{}
		}
		report.Keys = append(report.Keys, KeyCustodyEntry{
			KeyID:          m.ID,
			Algorithm:      string(m.Algorithm),
			Backend:        backend,
			CreatedAt:      m.CreatedAt,
			Imported:       d.imported[m.ID],
			RotationCount:  d.rotations[m.ID],
			LastRotatedAt:  d.lastRotate[m.ID],
			AccessCount:    d.accesses[m.ID],
			LastAccessedAt: d.lastAccess[m.ID],
			Events:         evs,
		})
	}
	// Deleted keys keep a tombstone so their custody history survives.
	var gone []string
	for id := range d.events {
		if !live[id] {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		report.Keys = append(report.Keys, KeyCustodyEntry{
			KeyID: id, Backend: backend, Deleted: true, Imported: d.imported[id],
			RotationCount: d.rotations[id], LastRotatedAt: d.lastRotate[id],
			AccessCount: d.accesses[id], LastAccessedAt: d.lastAccess[id],
			Events: d.events[id],
		})
	}
	report.EventCounts = countCustodyEvents(report.Keys)
	return report, nil
}

// registerKeyCustodyHandler mounts the custody evidence endpoint.
func registerKeyCustodyHandler(mux *http.ServeMux, auth *Authenticator, store keystore.Store, targets ManagedTargetStore, auditProvider AuditProvider, approvals ...PendingActionStore) {
	var approvalStore PendingActionStore
	if len(approvals) > 0 {
		approvalStore = approvals[0]
	}
	mux.HandleFunc("/api/v1/reports/key-custody", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.key_custody", "report", "key-custody", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "report.key_custody", "report", "key-custody", AuditOutcomeDenied)
			writeForbidden(w, "your role is not authorized to read key-custody evidence")
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "key-custody evidence requires a keystore (none configured)")
			return
		}
		report, err := buildKeyCustodyReportWithApprovals(r.Context(), store, auditProvider, approvalStore)
		if err != nil {
			writeServiceUnavailable(w, "key-custody report failed")
			return
		}
		if !tenantBypass(pd) {
			kept := report.Keys[:0:0]
			for _, k := range report.Keys {
				if keyVisibleToTenant(r.Context(), activeTenantStore, pd, k.KeyID) {
					kept = append(kept, k)
				}
			}
			report.Keys = kept
			report.EventCounts = countCustodyEvents(kept)
		}
		if targets != nil {
			items, terr := targets.List(r.Context())
			if terr != nil {
				writeServiceUnavailable(w, "key-custody report failed")
				return
			}
			report.Targets = targetKeyModeEntries(filterManagedTargetsByTenant(pd, items))
		}
		emitAuditEvent(r, auditProvider, pd.ID, "report.key_custody", "report", "key-custody", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Data KeyCustodyReport `json:"data"`
		}{Data: report})
	})
}
