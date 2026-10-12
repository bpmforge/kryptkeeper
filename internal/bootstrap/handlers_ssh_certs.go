// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/sshkeys"
)

// W11-07: the SSH CA API. The CA key lives in the platform keystore under a
// well-known id — generated on first use, reused forever after; signing
// happens through the keystore's crypto.Signer, so key material never
// leaves its boundary. Issuance is direct + audited; approval gating joins
// when the issuance policy engine (W5-05) defines when it is required
// (spec decision 3).

const sshCAKeyID = "ssh-ca"

const sshCertificateSchema = `
CREATE TABLE IF NOT EXISTS ssh_certificates (
    serial               TEXT PRIMARY KEY,
    cert_type            TEXT NOT NULL CHECK (cert_type IN ('user', 'host')),
    key_id               TEXT NOT NULL,
    principals           TEXT NOT NULL DEFAULT '[]',
    valid_after          TEXT NOT NULL,
    valid_before         TEXT NOT NULL,
    subject_fingerprint  TEXT NOT NULL,
    authority_fingerprint TEXT NOT NULL,
    certificate_line     TEXT NOT NULL,
    tenant               TEXT NOT NULL DEFAULT 'default',
    created_at           TEXT NOT NULL,
    template_id          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_subject ON ssh_certificates(subject_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_tenant ON ssh_certificates(tenant);`

// SSHCertRecord is a stored issued SSH certificate.
type SSHCertRecord struct {
	Serial               string   `json:"serial"`
	CertType             string   `json:"cert_type"`
	KeyID                string   `json:"key_id"`
	Principals           []string `json:"principals"`
	ValidAfter           string   `json:"valid_after"`
	ValidBefore          string   `json:"valid_before"`
	SubjectFingerprint   string   `json:"subject_fingerprint"`
	AuthorityFingerprint string   `json:"authority_fingerprint"`
	CertificateLine      string   `json:"certificate_line"`
	Tenant               string   `json:"tenant"`
	CreatedAt            string   `json:"created_at"`
	// TemplateID is the certificate template whose SSH policy authorised the
	// issuance (A01S-4); empty on certificates issued before it was required.
	TemplateID string `json:"template_id,omitempty"`
}

type sshCertStore struct {
	db       *sql.DB
	postgres bool
}

func (s *sshCertStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *sshCertStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sshCertificateSchema)
	return err
}

func (s *sshCertStore) insert(ctx context.Context, rec SSHCertRecord) error {
	principals, _ := json.Marshal(rec.Principals)
	q := fmt.Sprintf(`INSERT INTO ssh_certificates
		(serial, cert_type, key_id, principals, valid_after, valid_before, subject_fingerprint, authority_fingerprint, certificate_line, tenant, created_at, template_id)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12))
	_, err := s.db.ExecContext(ctx, q,
		rec.Serial, rec.CertType, rec.KeyID, string(principals), rec.ValidAfter, rec.ValidBefore,
		rec.SubjectFingerprint, rec.AuthorityFingerprint, rec.CertificateLine, rec.Tenant, rec.CreatedAt, rec.TemplateID)
	return err
}

func (s *sshCertStore) list(ctx context.Context, subjectFingerprint string) ([]SSHCertRecord, error) {
	query := `SELECT serial, cert_type, key_id, principals, valid_after, valid_before,
		subject_fingerprint, authority_fingerprint, certificate_line, tenant, created_at, template_id
		FROM ssh_certificates`
	args := []any{}
	if subjectFingerprint != "" {
		query += fmt.Sprintf(" WHERE subject_fingerprint = %s", s.ph(1))
		args = append(args, subjectFingerprint)
	}
	query += " ORDER BY created_at DESC LIMIT 200"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SSHCertRecord{}
	for rows.Next() {
		var rec SSHCertRecord
		var principals string
		if err := rows.Scan(&rec.Serial, &rec.CertType, &rec.KeyID, &principals, &rec.ValidAfter, &rec.ValidBefore,
			&rec.SubjectFingerprint, &rec.AuthorityFingerprint, &rec.CertificateLine, &rec.Tenant, &rec.CreatedAt, &rec.TemplateID); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(principals), &rec.Principals) // corrupt row degrades to zero value, not a fatal
		out = append(out, rec)
	}
	return out, rows.Err()
}

// sshCAAuthority resolves (generating on first use) the keystore-held SSH CA
// signer. Guarded by a mutex: two concurrent first requests must not race
// two CA keys into existence.
type sshCAAuthority struct {
	keys keystore.Store
	mu   sync.Mutex
}

func (a *sshCAAuthority) signer() (ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys == nil {
		return nil, errors.New("ssh ca: no keystore configured (APP_CERTIFICATE_PROVIDER=ca required)")
	}
	if _, err := a.keys.Metadata(sshCAKeyID); err != nil {
		if _, err := a.keys.GenerateKey(sshCAKeyID, keystore.ECDSAP256); err != nil {
			return nil, fmt.Errorf("ssh ca: generate CA key: %w", err)
		}
	}
	cryptoSigner, err := a.keys.Signer(sshCAKeyID)
	if err != nil {
		return nil, fmt.Errorf("ssh ca: keystore signer: %w", err)
	}
	return ssh.NewSignerFromSigner(cryptoSigner)
}

type sshCertIssueRequest struct {
	TemplateID string   `json:"template_id"`
	PublicKey  string   `json:"public_key"`
	CertType   string   `json:"cert_type"`
	KeyID      string   `json:"key_id"`
	Principals []string `json:"principals"`
	TTLHours   float64  `json:"ttl_hours"`
}

// newSSHCertStoreFromEnv opens the store on the standard env-resolved DB —
// same pattern as every other DB-backed store in this package.
func newSSHCertStoreFromEnv() *sshCertStore {
	state := newDBProviderState[*sshCertStore](
		"ssh-certificate",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_SSH_CERTS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_SSH_CERTS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_SSH_CERTS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *sshCertStore { return &sshCertStore{db: db, postgres: false} },
		func(db *sql.DB) *sshCertStore { return &sshCertStore{db: db, postgres: true} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("ssh-certificate", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.ensureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("ssh-certificate", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// RegisterSSHCertHandlers mounts the SSH CA API: POST/GET
// /api/v1/ssh/certificates and GET /api/v1/ssh/ca. keys may be nil (no
// crypto engine) — issuance then 503s with the reason. Issuance is refused
// unless the request names a template whose SSH policy covers the cert type,
// principals and TTL (A01S-4).
func RegisterSSHCertHandlers(mux *http.ServeMux, auth *Authenticator, keys keystore.Store, templates TemplateProvider, auditProvider AuditProvider) {
	authority := &sshCAAuthority{keys: keys}
	store := newSSHCertStoreFromEnv()

	mux.HandleFunc("/api/v1/ssh/ca", func(w http.ResponseWriter, r *http.Request) {
		if _, err := auth.AuthenticatePrincipalDetails(r, time.Now()); err != nil {
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		signer, err := authority.signer()
		if err != nil {
			writeServiceUnavailable(w, err.Error())
			return
		}
		writeJSONStatus(w, http.StatusOK, map[string]string{
			"authority_line":        sshkeys.AuthorityLine(signer),
			"authority_fingerprint": ssh.FingerprintSHA256(signer.PublicKey()),
		})
	})

	mux.HandleFunc("/api/v1/ssh/certificates", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "ssh_certificate.issue", "ssh_certificate", "ssh-certificates", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if store == nil {
				writeServiceUnavailable(w, "ssh certificate store not configured")
				return
			}
			recs, err := store.list(r.Context(), strings.TrimSpace(r.URL.Query().Get("subject_fingerprint")))
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			writeJSONStatus(w, http.StatusOK, struct {
				Data []SSHCertRecord `json:"data"`
			}{Data: recs})
		case http.MethodPost:
			body := http.MaxBytesReader(w, r.Body, 64*1024)
			defer body.Close()
			raw, err := io.ReadAll(body)
			if err != nil {
				writeBadRequestJSON(w, "invalid request body")
				return
			}
			var req sshCertIssueRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				writeBadRequestJSON(w, "invalid request body")
				return
			}
			req.TemplateID = strings.TrimSpace(req.TemplateID)
			if req.TemplateID == "" {
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.KeyID, AuditOutcomeDenied)
				writeBadRequestJSON(w, "template_id is required: SSH certificates are issued against a template with an ssh_policy")
				return
			}
			if templates == nil {
				writeServiceUnavailable(w, "template provider not configured")
				return
			}
			tpl, found, terr := templates.GetTemplate(r.Context(), req.TemplateID)
			if terr != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.KeyID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "template lookup failed")
				return
			}
			if !found || !templateVisibleToTenant(r.Context(), activeTenantStore, pd, req.TemplateID) {
				// Same answer for missing and other-tenant templates: no existence oracle.
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.TemplateID+":"+req.KeyID, AuditOutcomeDenied)
				writeBadRequestJSON(w, "unknown template_id")
				return
			}
			if !tpl.Active || tpl.SSHPolicy == nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.TemplateID+":"+req.KeyID, AuditOutcomeDenied)
				writeBadRequestJSON(w, "template is inactive or has no ssh_policy; SSH certificates can only be issued from a template that configures one")
				return
			}
			if err := tpl.SSHPolicy.Validate(); err != nil {
				// A hand-edited template file can carry a policy the API would have refused.
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.TemplateID+":"+req.KeyID, AuditOutcomeDenied)
				writeBadRequestJSON(w, "template ssh_policy is invalid")
				return
			}
			ttl, err := tpl.SSHPolicy.Check(req.CertType, req.Principals, time.Duration(req.TTLHours*float64(time.Hour)))
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.TemplateID+":"+req.KeyID, AuditOutcomeDenied)
				writeBadRequestJSON(w, err.Error())
				return
			}
			signer, err := authority.signer()
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.KeyID, AuditOutcomeFailure)
				writeServiceUnavailable(w, err.Error())
				return
			}
			issued, err := sshkeys.IssueCert(signer, sshkeys.CertRequest{
				PublicKey:  req.PublicKey,
				CertType:   req.CertType,
				KeyID:      req.KeyID,
				Principals: req.Principals,
				TTL:        ttl,
			})
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.KeyID, AuditOutcomeFailure)
				writeBadRequestJSON(w, err.Error())
				return
			}

			rec := SSHCertRecord{
				Serial:               fmt.Sprintf("%d", issued.Serial),
				CertType:             issued.CertType,
				KeyID:                issued.KeyID,
				Principals:           issued.Principals,
				ValidAfter:           issued.ValidAfter.Format(time.RFC3339),
				ValidBefore:          issued.ValidBefore.Format(time.RFC3339),
				SubjectFingerprint:   issued.SubjectFingerprint,
				AuthorityFingerprint: issued.AuthorityFingerprint,
				CertificateLine:      issued.CertificateLine,
				Tenant:               DefaultTenant,
				CreatedAt:            time.Now().UTC().Format(time.RFC3339),
				TemplateID:           req.TemplateID,
			}
			if !tenantBypass(pd) {
				rec.Tenant = pd.Tenant
			}
			if store != nil {
				if err := store.insert(r.Context(), rec); err != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate", req.KeyID, AuditOutcomeFailure)
					writeServiceUnavailable(w, "issued but persisting the record failed: "+err.Error())
					return
				}
			}
			// The audit resource id carries template+serial+key_id — the record
			// is reconstructable from the audit log plus this table.
			emitAuditEvent(r, auditProvider, pd.ID, "ssh_certificate.issue", "ssh_certificate",
				rec.TemplateID+":"+rec.Serial+":"+rec.KeyID, AuditOutcomeSuccess)
			writeJSONStatus(w, http.StatusCreated, struct {
				Data SSHCertRecord `json:"data"`
			}{Data: rec})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})
}
