// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"kryptkeeper/internal/logging"
)

// W28-11: manual-attestation controls. Some controls cannot be read off the
// certificate inventory (a human reviews CA access, cipher policy, the key
// management practice statement). The pack lists them with the named
// attester and date, or "pending" when nobody has attested. They are
// appended after the summary tally so they never move pass/warn/fail.

const (
	manualControlType    = "manual"
	attestStatusAttested = "attested"
	attestStatusPending  = "pending"
	// attestationValidity bounds how long an attestation counts: a year-old
	// review is not evidence of the current state.
	attestationValidity = 365 * 24 * time.Hour

	attestNameMax = 100
	attestNoteMax = 500

	attestTimeLayout = "2006-01-02T15:04:05.000000000Z"
)

type ManualControl struct{ ID, FrameworkKey, FrameworkLabel, Title string }

// FrameworkLabel must equal frameworkDisplayName(FrameworkKey).
var manualControlCatalog = []ManualControl{
	{"SOC2-MAN-CC6.1", "soc2", "SOC 2", "Privileged access to certificate authorities reviewed"},
	{"PCI-MAN-12.3.3", "pci", "PCI DSS 4.0.1", "Cryptographic cipher suites and protocols reviewed"},
	{"NIST-MAN-800-57-KMP", "nist", "NIST SP 800-57", "Key management policy and practice statement reviewed"},
}

// Attestation is one recorded human attestation; rows are append-only.
type Attestation struct {
	ID                  string `json:"id"`
	ControlID           string `json:"control_id"`
	AttesterName        string `json:"attester_name"`
	AttestedByPrincipal string `json:"attested_by"`
	Note                string `json:"note"`
	AttestedAt          string `json:"attested_at"`
}

type ComplianceAttestationStore interface {
	EnsureSchema(ctx context.Context) error
	// Record appends an attestation, assigning its ID and AttestedAt.
	Record(ctx context.Context, a Attestation) (Attestation, error)
	// Latest returns the newest attestation per control ID.
	Latest(ctx context.Context) (map[string]Attestation, error)
}

const complianceAttestationSchema = `
CREATE TABLE IF NOT EXISTS compliance_attestations (
    id TEXT PRIMARY KEY, control_id TEXT NOT NULL, attester_name TEXT NOT NULL,
    attested_by TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', attested_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_compliance_attestations_control ON compliance_attestations(control_id, attested_at);`

type dbComplianceAttestationStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *dbComplianceAttestationStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, complianceAttestationSchema)
	return err
}

func (s *dbComplianceAttestationStore) Close() error { return s.db.Close() }

func (s *dbComplianceAttestationStore) Record(ctx context.Context, a Attestation) (Attestation, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return Attestation{}, err
	}
	a.ID = "att-" + hex.EncodeToString(b)
	a.AttestedAt = time.Now().UTC().Format(attestTimeLayout)
	q := fmt.Sprintf(`INSERT INTO compliance_attestations
		(id, control_id, attester_name, attested_by, note, attested_at)
		VALUES (%s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6))
	if _, err := s.db.ExecContext(ctx, q, a.ID, a.ControlID, a.AttesterName,
		a.AttestedByPrincipal, a.Note, a.AttestedAt); err != nil {
		return Attestation{}, err
	}
	return a, nil
}

func (s *dbComplianceAttestationStore) Latest(ctx context.Context) (map[string]Attestation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, control_id, attester_name, attested_by, note, attested_at
		FROM compliance_attestations ORDER BY attested_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Attestation{}
	for rows.Next() {
		var a Attestation
		if err := rows.Scan(&a.ID, &a.ControlID, &a.AttesterName, &a.AttestedByPrincipal, &a.Note, &a.AttestedAt); err != nil {
			return nil, err
		}
		out[a.ControlID] = a // ascending order: the last row per control is the newest
	}
	return out, rows.Err()
}

// NewComplianceAttestationStoreFromEnv opens the shared DB and ensures the
// schema. Returns nil if the DB is unavailable (callers tolerate nil).
func NewComplianceAttestationStoreFromEnv() ComplianceAttestationStore {
	state := newDBProviderState[*dbComplianceAttestationStore](
		"compliance-attestation",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbComplianceAttestationStore {
			return &dbComplianceAttestationStore{db: db, ph: sqlitePlaceholder}
		},
		func(db *sql.DB) *dbComplianceAttestationStore {
			return &dbComplianceAttestationStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("compliance-attestation", state.openErr) // logs the outage itself
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("compliance-attestation", err) // logs the outage itself
		return nil
	}
	return state.store
}

// closeAttestationStore releases a store opened for one-shot use.
func closeAttestationStore(st ComplianceAttestationStore) {
	if c, ok := st.(io.Closer); ok {
		_ = c.Close()
	}
}

// applyManualControls appends the manual controls for rep.Framework. A store
// that is nil or errors degrades to pending: the report must still render,
// and an attestation we cannot read is not one we can claim.
func applyManualControls(ctx context.Context, st ComplianceAttestationStore, rep *ComplianceEvidenceReport, now time.Time) {
	var latest map[string]Attestation
	if st != nil {
		var err error
		if latest, err = st.Latest(ctx); err != nil {
			logging.Infof("compliance attestations unavailable, manual controls read pending: %v", err)
			latest = nil
		}
	}
	for _, m := range manualControlCatalog {
		if rep.Framework != "all" && rep.Framework != m.FrameworkKey {
			continue
		}
		c := ComplianceControl{ID: m.ID, Framework: m.FrameworkLabel, Title: m.Title, Type: manualControlType, Artifacts: []ControlArtifact{}}
		a, ok := latest[m.ID]
		at, perr := time.Parse(time.RFC3339, a.AttestedAt)
		if ok && perr == nil && !at.After(now.Add(time.Minute)) && now.Sub(at) <= attestationValidity {
			c.Status = attestStatusAttested
			c.Attester = a.AttesterName
			c.AttestedAt = a.AttestedAt
			c.Evidence = fmt.Sprintf("Attested by %s on %s.", a.AttesterName, at.UTC().Format("2006-01-02"))
		} else {
			c.Status = attestStatusPending
			c.Evidence = "Pending attestation: no current attester on record."
			c.Remediation = "A named administrator must attest this control."
		}
		rep.Controls = append(rep.Controls, c)
	}
}

func manualControlKnown(id string) bool {
	for _, m := range manualControlCatalog {
		if m.ID == id {
			return true
		}
	}
	return false
}

// RegisterComplianceAttestationHandlers mounts GET/POST
// /api/v1/reports/compliance-attestations. It is deliberately outside
// /reports/evidence/**, which the write gate maps to notification.manage.
func RegisterComplianceAttestationHandlers(mux *http.ServeMux, auth *Authenticator, st ComplianceAttestationStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/compliance-attestations", func(w http.ResponseWriter, r *http.Request) {
		const resType = "compliance-control"
		switch r.Method {
		case http.MethodGet:
			pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "evidence.attest_list", resType, "-", AuditOutcomeDenied)
				writeUnauthorized(w)
				return
			}
			if denyAggregateReportForTenantScoped(w, pd) {
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest_list", resType, "-", AuditOutcomeDenied)
				return
			}
			if !requireReadPermission(w, r, auditProvider, pd, nil, "report.read", "evidence.attest_list", resType, "") {
				return
			}
			if st == nil {
				writeServiceUnavailable(w, "attestation store unavailable")
				return
			}
			latest, err := st.Latest(r.Context())
			if err != nil {
				logging.Infof("compliance attestations: list: %v", err)
				writeServiceUnavailable(w, "list failed")
				return
			}
			list := make([]Attestation, 0, len(latest))
			for _, m := range manualControlCatalog {
				if a, ok := latest[m.ID]; ok {
					list = append(list, a)
				}
			}
			writeAttestData(w, http.StatusOK, list)
		case http.MethodPost:
			pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
			if err != nil {
				emitAuditEvent(r, auditProvider, "", "evidence.attest", resType, "-", AuditOutcomeDenied)
				writeUnauthorized(w)
				return
			}
			if denyAggregateReportForTenantScoped(w, pd) {
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest", resType, "-", AuditOutcomeDenied)
				return
			}
			if _, admin := principalPermissions(pd, nil); !admin {
				emitAuditEventDetail(r, auditProvider, pd.ID, "evidence.attest", resType, "-", AuditOutcomeDenied,
					"role="+truncateForLog(pd.Role)+" needs=admin")
				writeForbidden(w, "only an administrator can attest a control")
				return
			}
			var req struct {
				ControlID    string `json:"control_id"`
				AttesterName string `json:"attester_name"`
				Note         string `json:"note"`
			}
			if !decodeAttestBody(w, r, auditProvider, pd.ID, &req) {
				return
			}
			name := strings.TrimSpace(req.AttesterName)
			switch {
			case !manualControlKnown(req.ControlID):
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest", resType, "-", AuditOutcomeFailure)
				writeBadRequest(w, "control_id must name a manual control")
				return
			case name == "" || utf8.RuneCountInString(name) > attestNameMax:
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest", resType, req.ControlID, AuditOutcomeFailure)
				writeBadRequest(w, fmt.Sprintf("attester_name is required, 1-%d characters", attestNameMax))
				return
			case utf8.RuneCountInString(req.Note) > attestNoteMax:
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest", resType, req.ControlID, AuditOutcomeFailure)
				writeBadRequest(w, fmt.Sprintf("note must be at most %d characters", attestNoteMax))
				return
			}
			if st == nil {
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest", resType, req.ControlID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "attestation store unavailable")
				return
			}
			rec, err := st.Record(r.Context(), Attestation{
				ControlID: req.ControlID, AttesterName: name, AttestedByPrincipal: pd.ID, Note: req.Note,
			})
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "evidence.attest", resType, req.ControlID, AuditOutcomeFailure)
				logging.Infof("compliance attestations: record: %v", err)
				writeServiceUnavailable(w, "attest failed")
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "evidence.attest", resType, req.ControlID, AuditOutcomeSuccess, "attester="+name)
			writeAttestData(w, http.StatusCreated, rec)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})
}

// decodeAttestBody parses the POST body; a rejected body is audited like any
// other validation failure.
func decodeAttestBody(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, principal string, dst any) bool {
	if decodeJSONBodyOrReject(w, r, dst, 4096, "invalid request") {
		return true
	}
	emitAuditEvent(r, auditProvider, principal, "evidence.attest", "compliance-control", "-", AuditOutcomeFailure)
	return false
}

func writeAttestData(w http.ResponseWriter, status int, data any) {
	writeJSONStatus(w, status, map[string]any{"data": data})
}
