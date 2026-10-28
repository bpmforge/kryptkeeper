// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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

// ErrSerialCollision reports that (issuing CA, serial) is already stored.
// The database enforces it with the unique index idx_cert_serial_ca
// (certificates.serial_number, certificates.ca_id).
var ErrSerialCollision = errors.New("ca: serial number already issued by this CA")

// IsSerialCollision reports a unique violation on idx_cert_serial_ca. It
// matches by text so no driver dependency is needed: sqlite reports
// "UNIQUE constraint failed: certificates.serial_number, certificates.ca_id",
// postgres `duplicate key value violates unique constraint "idx_cert_serial_ca"`.
func IsSerialCollision(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrSerialCollision) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "idx_cert_serial_ca") {
		return true
	}
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, "certificates.serial_number") &&
		strings.Contains(msg, "certificates.ca_id")
}

// SerialExists reports whether (caID, serial) is already stored.
func (s *DBStore) SerialExists(caID string, serial *big.Int) (bool, error) {
	if serial == nil {
		return false, errors.New("ca: nil serial")
	}
	var n int
	q := fmt.Sprintf(`SELECT COUNT(*) FROM certificates WHERE serial_number = %s AND ca_id = %s`, s.ph(1), s.ph(2))
	if err := s.db.QueryRow(q, serial.String(), caID).Scan(&n); err != nil {
		return false, fmt.Errorf("check serial: %w", err)
	}
	return n > 0, nil
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

// crlSelect reads crl_distribution_points back as JSON text on both engines
// (NULL stays NULL), so scanCA has one decoding path.
func (s *DBStore) crlSelect() string {
	if s.isPostgres {
		return "array_to_json(crl_distribution_points)::text"
	}
	return "crl_distribution_points"
}

func (s *DBStore) Save(ca *CA) error {
	now := time.Now().UTC().Format(time.RFC3339)
	dbType := caTypeForDB(ca.Type)
	parentCAID := sql.NullString{String: ca.ParentCAID, Valid: ca.ParentCAID != ""}
	certPEM := sql.NullString{String: string(ca.CertPEM), Valid: len(ca.CertPEM) > 0}
	keyID := sql.NullString{String: ca.KeyID, Valid: ca.KeyID != ""}
	csrPEM := sql.NullString{String: string(ca.CSRPEM), Valid: len(ca.CSRPEM) > 0}
	connectorID := sql.NullString{String: ca.ConnectorID, Valid: ca.ConnectorID != ""}
	trustPEM := sql.NullString{String: string(ca.ExternalTrustPEM), Valid: len(ca.ExternalTrustPEM) > 0}
	displayName := ca.DisplayName
	if displayName == "" {
		displayName = ca.Name
	}
	ocspURL := sql.NullString{String: ca.OCSPServiceURL, Valid: ca.OCSPServiceURL != ""}
	// Passed as JSON text and converted in SQL, so neither driver needs array
	// binding (TEXT[] on Postgres, plain TEXT on sqlite).
	crlJSON := sql.NullString{}
	if len(ca.CRLDistributionPoints) > 0 {
		b, err := json.Marshal(ca.CRLDistributionPoints)
		if err != nil {
			return fmt.Errorf("encode crl distribution points: %w", err)
		}
		crlJSON = sql.NullString{String: string(b), Valid: true}
	}

	var query string
	if s.isPostgres {
		query = `
INSERT INTO certificate_authorities
    (id, name, display_name, type, key_storage_type, key_id, cert_pem, status,
     parent_ca_id, created_at, updated_at, csr_pem, connector_id, external_trust_pem,
     crl_distribution_points, ocsp_service_url)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    (SELECT array_agg(x ORDER BY ord) FROM jsonb_array_elements_text($15::jsonb) WITH ORDINALITY AS t(x, ord)),
    $16)
ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    crl_distribution_points = EXCLUDED.crl_distribution_points,
    ocsp_service_url = EXCLUDED.ocsp_service_url,
    status       = EXCLUDED.status,
    cert_pem     = EXCLUDED.cert_pem,
    key_id       = EXCLUDED.key_id,
    csr_pem      = EXCLUDED.csr_pem,
    connector_id = EXCLUDED.connector_id,
    external_trust_pem = EXCLUDED.external_trust_pem,
    updated_at   = EXCLUDED.updated_at`
	} else {
		// A true upsert, not INSERT OR REPLACE: replace deletes and
		// re-inserts the row, which would rewrite key_storage_type (and
		// every column not listed here). key_storage_type is immutable.
		query = `
INSERT INTO certificate_authorities
    (id, name, display_name, type, key_storage_type, key_id, cert_pem, status,
     parent_ca_id, created_at, updated_at, csr_pem, connector_id, external_trust_pem,
     crl_distribution_points, ocsp_service_url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    display_name = excluded.display_name,
    crl_distribution_points = excluded.crl_distribution_points,
    ocsp_service_url = excluded.ocsp_service_url,
    status       = excluded.status,
    cert_pem     = excluded.cert_pem,
    key_id       = excluded.key_id,
    csr_pem      = excluded.csr_pem,
    connector_id = excluded.connector_id,
    external_trust_pem = excluded.external_trust_pem,
    updated_at   = excluded.updated_at`
	}

	// W19-08/W23-10: record which backend actually holds the key, in the
	// canonical vocabulary. The engine's env label ("cloudkms") would
	// otherwise violate the table CHECK.
	keyStorageType := NormalizeKeyStorageType(ca.KeyStorageType)
	if !validKeyStorageType(keyStorageType) {
		return fmt.Errorf("%w: %q", ErrUnknownKeyStorageType, ca.KeyStorageType)
	}
	_, err := s.db.Exec(query,
		ca.ID, ca.Name, displayName, dbType, keyStorageType, keyID, certPEM,
		ca.Status, parentCAID, now, now, csrPEM, connectorID, trustPEM,
		crlJSON, ocspURL,
	)
	return err
}

func (s *DBStore) Load(id string) (*CA, error) {
	query := `
SELECT id, name, type, key_storage_type, key_id, cert_pem, status, parent_ca_id, csr_pem, connector_id, external_trust_pem,
       display_name, ocsp_service_url, ` + s.crlSelect() + `
FROM certificate_authorities
WHERE id = ` + s.ph(1)

	row := s.db.QueryRow(query, id)
	return scanCA(row)
}

func (s *DBStore) List() ([]*CA, error) {
	rows, err := s.db.Query(`
SELECT id, name, type, key_storage_type, key_id, cert_pem, status, parent_ca_id, csr_pem, connector_id, external_trust_pem,
       display_name, ocsp_service_url, ` + s.crlSelect() + `
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

// Delete removes the CA row. A certificates row still referencing it fails on
// the foreign key and surfaces as an error; callers map that to a conflict.
func (s *DBStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM certificate_authorities WHERE id = `+s.ph(1), id)
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
	query := `INSERT INTO ca_key_rotations (id, ca_id, old_key_id, new_key_id, new_cert_sn, method, rotated_at, old_cert_pem) VALUES (` + s.phs(8) + `)`
	_, err := s.db.Exec(query, r.ID, r.CAID, r.OldKeyID, r.NewKeyID, r.NewCertSN, r.Method, rotatedAt.Format(time.RFC3339), string(r.OldCertPEM))
	return err
}

func (s *DBStore) ListKeyRotations(caID string) ([]KeyRotation, error) {
	query := `
SELECT id, ca_id, old_key_id, new_key_id, new_cert_sn, method, rotated_at, old_cert_pem
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
		var oldCertPEM string
		// Postgres's pgx driver returns an actual time.Time for a
		// TIMESTAMPTZ column when scanned; sqlite stores it as TEXT and
		// must be scanned as a string then parsed -- same split this
		// codebase already uses for audit_log's timestamp column
		// (audit_db_provider.go's sqlite vs postgres ListEntries).
		if s.isPostgres {
			var rotatedAt time.Time
			if err := rows.Scan(&r.ID, &r.CAID, &r.OldKeyID, &r.NewKeyID, &r.NewCertSN, &r.Method, &rotatedAt, &oldCertPEM); err != nil {
				return nil, fmt.Errorf("scan ca_key_rotations row: %w", err)
			}
			r.RotatedAt = rotatedAt.UTC()
		} else {
			var rotatedAt string
			if err := rows.Scan(&r.ID, &r.CAID, &r.OldKeyID, &r.NewKeyID, &r.NewCertSN, &r.Method, &rotatedAt, &oldCertPEM); err != nil {
				return nil, fmt.Errorf("scan ca_key_rotations row: %w", err)
			}
			if t, err := time.Parse(time.RFC3339, rotatedAt); err == nil {
				r.RotatedAt = t
			}
		}
		r.OldCertPEM = []byte(oldCertPEM)
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
	var keyID, certPEMStr, parentCAID, keyStorageType, csrPEMStr, connectorID, trustPEM sql.NullString
	var displayName, ocspURL, crlJSON sql.NullString

	if err := row.Scan(&id, &name, &dbType, &keyStorageType, &keyID, &certPEMStr, &status, &parentCAID, &csrPEMStr, &connectorID, &trustPEM, &displayName, &ocspURL, &crlJSON); err != nil {
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
		ConnectorID:    connectorID.String,
		DisplayName:    displayName.String,
		OCSPServiceURL: ocspURL.String,
	}
	if crlJSON.Valid && crlJSON.String != "" {
		if err := json.Unmarshal([]byte(crlJSON.String), &ca.CRLDistributionPoints); err != nil {
			return nil, fmt.Errorf("decode crl distribution points for CA %s: %w", id, err)
		}
	}
	if trustPEM.Valid && trustPEM.String != "" {
		ca.ExternalTrustPEM = []byte(trustPEM.String)
	}
	if csrPEMStr.Valid && csrPEMStr.String != "" {
		ca.CSRPEM = []byte(csrPEMStr.String)
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
