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
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// W7-02 (D-056/NFR-P2): identity FOR agents. A non-human identity (AI
// agent, service account, workflow) is PROPOSED by any authenticated
// principal, sits pending until a DIFFERENT principal with an approver
// role approves it, and only then yields a single-use join token bound
// to the NHI's SPIFFE ID — redeemed via the W7-01 workload-attestation
// endpoint for a short-lived SVID. Scopes are authorization data on the
// identity record, resolved by SPIFFE ID at request time; they are
// deliberately NOT baked into certificates, so revising a scope never
// requires reissuance.

// nhiKinds is the closed kind vocabulary.
var nhiKinds = map[string]bool{
	"ai_agent":        true,
	"service_account": true,
	"workflow":        true,
}

var nhiNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// NHIIdentity is one non-human identity and its issuance state.
type NHIIdentity struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	SPIFFEID  string   `json:"spiffe_id"`
	Scopes    []string `json:"scopes"`
	Status    string   `json:"status"` // pending | approved | rejected | revoked
	CreatedBy string   `json:"created_by"`
	DecidedBy string   `json:"decided_by,omitempty"`
	CreatedAt string   `json:"created_at"`
	DecidedAt string   `json:"decided_at,omitempty"`
}

// NHIStore persists non-human identities.
type NHIStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, n NHIIdentity) (NHIIdentity, error)
	List(ctx context.Context) ([]NHIIdentity, error)
	Get(ctx context.Context, id string) (NHIIdentity, bool, error)
	Decide(ctx context.Context, id, status, decidedBy string) error
}

// Mirrors migration 000035; idempotent so pre-migration deployments
// (per-store EnsureSchema convention) get the same shape.
const nhiSchema = `
CREATE TABLE IF NOT EXISTS nhi_identities (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
    spiffe_id TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    created_by TEXT NOT NULL, decided_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT '',
    UNIQUE (name, kind));`

type dbNHIStore struct {
	db *sql.DB
	ph func(n int) string
}

func newNHIID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "nhi-" + hex.EncodeToString(b), nil
}

func (s *dbNHIStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, nhiSchema)
	return err
}

func (s *dbNHIStore) Create(ctx context.Context, n NHIIdentity) (NHIIdentity, error) {
	id, err := newNHIID()
	if err != nil {
		return NHIIdentity{}, err
	}
	n.ID = id
	n.Status = "pending"
	n.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	scopes, err := json.Marshal(n.Scopes)
	if err != nil {
		return NHIIdentity{}, err
	}
	q := fmt.Sprintf(`INSERT INTO nhi_identities
		(id, name, kind, spiffe_id, scopes, status, created_by, created_at)
		VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7))
	if _, err := s.db.ExecContext(ctx, q, n.ID, n.Name, n.Kind, n.SPIFFEID,
		string(scopes), n.CreatedBy, n.CreatedAt); err != nil {
		return NHIIdentity{}, err
	}
	return n, nil
}

func (s *dbNHIStore) scanRows(rows *sql.Rows) ([]NHIIdentity, error) {
	var out []NHIIdentity
	for rows.Next() {
		var n NHIIdentity
		var scopes string
		if err := rows.Scan(&n.ID, &n.Name, &n.Kind, &n.SPIFFEID, &scopes,
			&n.Status, &n.CreatedBy, &n.DecidedBy, &n.CreatedAt, &n.DecidedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &n.Scopes); err != nil {
			n.Scopes = nil
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

const nhiSelect = `SELECT id, name, kind, spiffe_id, scopes, status,
	created_by, decided_by, created_at, decided_at FROM nhi_identities`

func (s *dbNHIStore) List(ctx context.Context) ([]NHIIdentity, error) {
	rows, err := s.db.QueryContext(ctx, nhiSelect+" ORDER BY created_at DESC, id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanRows(rows)
}

func (s *dbNHIStore) Get(ctx context.Context, id string) (NHIIdentity, bool, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(nhiSelect+" WHERE id = %s", s.ph(1)), id)
	if err != nil {
		return NHIIdentity{}, false, err
	}
	defer rows.Close()
	items, err := s.scanRows(rows)
	if err != nil || len(items) == 0 {
		return NHIIdentity{}, false, err
	}
	return items[0], true, nil
}

func (s *dbNHIStore) Decide(ctx context.Context, id, status, decidedBy string) error {
	q := fmt.Sprintf(`UPDATE nhi_identities SET status = %s, decided_by = %s, decided_at = %s
		WHERE id = %s`, s.ph(1), s.ph(2), s.ph(3), s.ph(4))
	res, err := s.db.ExecContext(ctx, q, status, decidedBy,
		time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("nhi identity %s not found", id)
	}
	return nil
}

// NewNHIStoreFromEnv opens the shared DB and ensures the schema.
// Returns nil if the DB is unavailable (callers tolerate nil).
func NewNHIStoreFromEnv() NHIStore {
	state := newDBProviderState[*dbNHIStore](
		"nhi-identity",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbNHIStore { return &dbNHIStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) *dbNHIStore { return &dbNHIStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("nhi-identity", state.openErr) // logs the outage itself
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("nhi-identity", err) // logs the outage itself
		return nil
	}
	return state.store
}

// validateNHIRequest applies filing-time policy: closed kind vocabulary,
// scopes drawn from the ONE permission vocabulary (shared with W6-08
// custom roles — a typo is refused, never minted), DNS-label-ish name.
func validateNHIRequest(name, kind string, scopes []string) error {
	if !nhiNameRE.MatchString(name) {
		return fmt.Errorf("nhi name must be a lowercase dns-label-like string (got %q)", name)
	}
	if !nhiKinds[kind] {
		return fmt.Errorf("nhi kind %q is not in the vocabulary (ai_agent, service_account, workflow)", kind)
	}
	if len(scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}
	for _, sc := range scopes {
		if !permissionVocabulary[sc] {
			return fmt.Errorf("scope %q is not in the permission vocabulary", sc)
		}
	}
	return nil
}

// registerNHIHandlers mounts the NHI issuance lifecycle. registry MUST
// be the same instance the workload-SVID endpoint consults, or approved
// identities would mint tokens nothing can redeem.
func registerNHIHandlers(mux *http.ServeMux, auth *Authenticator, store NHIStore, registry *WorkloadRegistry, auditProvider AuditProvider) {
	// POST (propose) / GET (list) — any authenticated principal may
	// propose; listing requires authentication only.
	mux.HandleFunc("/api/v1/nhi/identities", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "nhi identity store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			items, err := store.List(r.Context())
			if err != nil {
				writeServiceUnavailable(w, "nhi list failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Data []NHIIdentity `json:"data"`
			}{Data: items})
		case http.MethodPost:
			td := spiffeTrustDomain()
			if td == "" {
				writeServiceUnavailable(w, "SPIFFE_TRUST_DOMAIN not set (NHI identities are SPIFFE-addressed)")
				return
			}
			var req struct {
				Name   string   `json:"name"`
				Kind   string   `json:"kind"`
				Scopes []string `json:"scopes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "invalid JSON")
				return
			}
			if err := validateNHIRequest(req.Name, req.Kind, req.Scopes); err != nil {
				writeBadRequest(w, err.Error())
				return
			}
			spiffeID := fmt.Sprintf("spiffe://%s/nhi/%s/%s", td, req.Kind, req.Name)
			if _, err := validateSPIFFEID(spiffeID, td); err != nil {
				writeBadRequest(w, err.Error())
				return
			}
			created, err := store.Create(r.Context(), NHIIdentity{
				Name: req.Name, Kind: req.Kind, SPIFFEID: spiffeID,
				Scopes: req.Scopes, CreatedBy: pd.ID,
			})
			if err != nil {
				writeBadRequest(w, "nhi create failed: "+err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "nhi.propose", "nhi_identity", created.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data NHIIdentity `json:"data"`
			}{Data: created})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	// POST /api/v1/nhi/identities/{id}/(approve|reject|revoke)
	mux.HandleFunc("/api/v1/nhi/identities/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "nhi identity store unavailable")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/nhi/identities/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 {
			writeBadRequest(w, "expected /nhi/identities/{id}/{approve|reject|revoke}")
			return
		}
		id, verb := parts[0], parts[1]
		if !canApproveActions(pd.Role) {
			writeForbidden(w, "your role is not authorized to decide NHI identities")
			return
		}
		identity, found, err := store.Get(r.Context(), id)
		if err != nil || !found {
			writeNotFound(w, "nhi identity not found")
			return
		}
		switch verb {
		case "approve":
			// NFR-P2 / house law: the proposer must never be the
			// approver — refused structurally, not by convention.
			if msg := auth.approverRefusal(pd, identity.CreatedBy); msg != "" {
				emitAuditEvent(r, auditProvider, pd.ID, "nhi.approve", "nhi_identity", id, AuditOutcomeFailure)
				writeForbidden(w, "self-approval is not permitted: "+msg)
				return
			}
			if identity.Status != "pending" {
				writeBadRequest(w, "identity is not pending (status: "+identity.Status+")")
				return
			}
			entry, token, err := registry.Register(identity.SPIFFEID, pd.ID, 0, time.Now())
			if err != nil {
				writeServiceUnavailable(w, "join token mint failed: "+err.Error())
				return
			}
			if err := store.Decide(r.Context(), id, "approved", pd.ID); err != nil {
				writeServiceUnavailable(w, "nhi decide failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "nhi.approve", "nhi_identity", id, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Data struct {
					ID             string `json:"id"`
					SPIFFEID       string `json:"spiffe_id"`
					JoinToken      string `json:"join_token"`
					TokenExpiresAt string `json:"token_expires_at"`
				} `json:"data"`
			}{Data: struct {
				ID             string `json:"id"`
				SPIFFEID       string `json:"spiffe_id"`
				JoinToken      string `json:"join_token"`
				TokenExpiresAt string `json:"token_expires_at"`
			}{
				ID:             id,
				SPIFFEID:       identity.SPIFFEID,
				JoinToken:      token,
				TokenExpiresAt: entry.ExpiresAt.UTC().Format(time.RFC3339),
			}})
		case "reject", "revoke":
			target := map[string]string{"reject": "rejected", "revoke": "revoked"}[verb]
			if verb == "reject" && identity.Status != "pending" {
				writeBadRequest(w, "identity is not pending (status: "+identity.Status+")")
				return
			}
			if err := store.Decide(r.Context(), id, target, pd.ID); err != nil {
				writeServiceUnavailable(w, "nhi decide failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "nhi."+verb, "nhi_identity", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeBadRequest(w, "unknown verb "+verb)
		}
	})
}
