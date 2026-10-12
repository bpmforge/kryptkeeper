// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// DBStore implements Store backed by the certificate_authorities table.
// The table must have the cert_pem and key_id columns added by migration 000009.
type DBStore struct {
	db         *sql.DB
	isPostgres bool
}

// NewDBStore creates a CA Store backed by the given database.
// Set isPostgres=true when the database is PostgreSQL (uses $N placeholders).
func NewDBStore(db *sql.DB, isPostgres bool) *DBStore {
	return &DBStore{db: db, isPostgres: isPostgres}
}

func (s *DBStore) ph(n int) string {
	if s.isPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *DBStore) phs(count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = s.ph(i + 1)
	}
	return strings.Join(parts, ", ")
}

// caTypeForDB converts internal CA type to the DB check constraint values.
func caTypeForDB(t string) string {
	if t == "intermediate" {
		return "issuing"
	}
	return t
}

// caTypeFromDB converts DB type back to the internal representation.
func caTypeFromDB(t string) string {
	if t == "issuing" {
		return "intermediate"
	}
	return t
}

func (s *DBStore) Save(ca *CA) error {
	now := time.Now().UTC().Format(time.RFC3339)
	dbType := caTypeForDB(ca.Type)
	parentCAID := sql.NullString{String: ca.ParentCAID, Valid: ca.ParentCAID != ""}
	certPEM := sql.NullString{String: string(ca.CertPEM), Valid: len(ca.CertPEM) > 0}
	keyID := sql.NullString{String: ca.KeyID, Valid: ca.KeyID != ""}

	var query string
	if s.isPostgres {
		query = `
INSERT INTO certificate_authorities
    (id, name, display_name, type, key_storage_type, key_id, cert_pem, status,
     parent_ca_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    status       = EXCLUDED.status,
    cert_pem     = EXCLUDED.cert_pem,
    key_id       = EXCLUDED.key_id,
    updated_at   = EXCLUDED.updated_at`
	} else {
		query = `
INSERT OR REPLACE INTO certificate_authorities
    (id, name, display_name, type, key_storage_type, key_id, cert_pem, status,
     parent_ca_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}

	// W19-08: previously hardcoded "software" here regardless of which
	// keystore.Store backend actually generated the key -- an HSM-held
	// CA key was misreported as software custody in the persisted record.
	keyStorageType := ca.KeyStorageType
	if keyStorageType == "" {
		keyStorageType = "software"
	}
	_, err := s.db.Exec(query,
		ca.ID, ca.Name, ca.Name, dbType, keyStorageType, keyID, certPEM,
		ca.Status, parentCAID, now, now,
	)
	return err
}

func (s *DBStore) Load(id string) (*CA, error) {
	query := `
SELECT id, name, type, key_storage_type, key_id, cert_pem, status, parent_ca_id
FROM certificate_authorities
WHERE id = ` + s.ph(1)

	row := s.db.QueryRow(query, id)
	return scanCA(row)
}

func (s *DBStore) List() ([]*CA, error) {
	rows, err := s.db.Query(`
SELECT id, name, type, key_storage_type, key_id, cert_pem, status, parent_ca_id
FROM certificate_authorities
ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ca)
	}
	return result, rows.Err()
}

func (s *DBStore) UpdateStatus(id, status string) error {
	var query string
	if s.isPostgres {
		query = `UPDATE certificate_authorities SET status = $1, updated_at = $2 WHERE id = $3`
	} else {
		query = `UPDATE certificate_authorities SET status = ?, updated_at = ? WHERE id = ?`
	}
	res, err := s.db.Exec(query, status, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCANotFound
	}
	return nil
}

func (s *DBStore) RecordKeyRotation(r KeyRotation) error {
	rotatedAt := r.RotatedAt
	if rotatedAt.IsZero() {
		rotatedAt = time.Now().UTC()
	}
	query := `INSERT INTO ca_key_rotations (id, ca_id, old_key_id, new_key_id, new_cert_sn, method, rotated_at) VALUES (` + s.phs(7) + `)`
	_, err := s.db.Exec(query, r.ID, r.CAID, r.OldKeyID, r.NewKeyID, r.NewCertSN, r.Method, rotatedAt.Format(time.RFC3339))
	return err
}

func (s *DBStore) ListKeyRotations(caID string) ([]KeyRotation, error) {
	query := `
SELECT id, ca_id, old_key_id, new_key_id, new_cert_sn, method, rotated_at
FROM ca_key_rotations
WHERE ca_id = ` + s.ph(1) + `
ORDER BY rotated_at DESC`

	rows, err := s.db.Query(query, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []KeyRotation
	for rows.Next() {
		var r KeyRotation
		// Postgres's pgx driver returns an actual time.Time for a
		// TIMESTAMPTZ column when scanned; sqlite stores it as TEXT and
		// must be scanned as a string then parsed -- same split this
		// codebase already uses for audit_log's timestamp column
		// (audit_db_provider.go's sqlite vs postgres ListEntries).
		if s.isPostgres {
			var rotatedAt time.Time
			if err := rows.Scan(&r.ID, &r.CAID, &r.OldKeyID, &r.NewKeyID, &r.NewCertSN, &r.Method, &rotatedAt); err != nil {
				return nil, fmt.Errorf("scan ca_key_rotations row: %w", err)
			}
			r.RotatedAt = rotatedAt.UTC()
		} else {
			var rotatedAt string
			if err := rows.Scan(&r.ID, &r.CAID, &r.OldKeyID, &r.NewKeyID, &r.NewCertSN, &r.Method, &rotatedAt); err != nil {
				return nil, fmt.Errorf("scan ca_key_rotations row: %w", err)
			}
			if t, err := time.Parse(time.RFC3339, rotatedAt); err == nil {
				r.RotatedAt = t
			}
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// scanner abstracts *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanCA(row scanner) (*CA, error) {
	var id, name, dbType, status string
	var keyID, certPEMStr, parentCAID, keyStorageType sql.NullString

	if err := row.Scan(&id, &name, &dbType, &keyStorageType, &keyID, &certPEMStr, &status, &parentCAID); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrCANotFound
		}
		return nil, fmt.Errorf("scan CA row: %w", err)
	}

	ca := &CA{
		ID:             id,
		Name:           name,
		Type:           caTypeFromDB(dbType),
		KeyID:          keyID.String,
		Status:         status,
		ParentCAID:     parentCAID.String,
		KeyStorageType: keyStorageType.String,
	}

	if certPEMStr.Valid && certPEMStr.String != "" {
		ca.CertPEM = []byte(certPEMStr.String)
		block, _ := pem.Decode(ca.CertPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse stored cert for CA %s: %w", id, err)
			}
			ca.Certificate = cert
		}
	}

	return ca, nil
}
