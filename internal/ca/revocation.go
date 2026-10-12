// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// RevokedEntry is a single revocation record from the store.
type RevokedEntry struct {
	Serial     *big.Int
	RevokedAt  time.Time
	ReasonCode int
}

// RevocationStore records and queries certificate revocations.
// Implementations must be safe for concurrent use.
type RevocationStore interface {
	// Revoke marks a certificate as revoked. meta is optional: a backend
	// that requires a pre-existing certificates row (DBRevocationStore) uses
	// it to create one on demand when serial+caID matches nothing, instead
	// of silently matching zero rows (W1-15/G-92) -- callers that already
	// know a row exists, and backends with no such requirement
	// (MemRevocationStore), may omit it. At most one CertMeta is
	// meaningful; extras are ignored.
	Revoke(serial *big.Int, caID string, reasonCode int, when time.Time, meta ...CertMeta) error
	// IsRevoked reports whether a certificate is revoked and, if so, the revocation
	// time and reason code.
	IsRevoked(serial *big.Int, caID string) (revoked bool, revokedAt time.Time, reasonCode int, err error)
	// ListRevoked returns all revoked certificates for the given CA.
	ListRevoked(caID string) ([]RevokedEntry, error)
}

// RevocationCacheInvalidator lets a RevocationStore.Revoke caller tell a live
// OCSP responder that a serial's cached response is stale and must be
// recomputed. Found live (W19-01): internal/ocsp.Responder caches each
// status response (good OR revoked) for its full validity window (24h by
// default) keyed by serial, and nothing ever called its own
// InvalidateCache -- both the ACME revoke path (internal/acme) and the
// certificate API revoke path (internal/bootstrap) revoked a real
// certificate through revStore.Revoke and OCSP kept answering "good" for
// the rest of the day, even though the comment at the API call site already
// claimed OCSP "reflect[s] it immediately". *ocsp.Responder implements this
// interface (InvalidateCache(serial *big.Int)) structurally; defined here
// rather than in internal/ocsp so acme and bootstrap can accept it as an
// optional dependency without importing internal/ocsp, matching the
// IssuedCertificateRecorder seam above.
type RevocationCacheInvalidator interface {
	InvalidateCache(serial *big.Int)
}

// CertMeta carries the certificate fields a RevocationStore needs to create
// a certificates row on the fly, for a caller whose certificate was never
// inserted into the table at issuance time -- e.g. ACME-issued certificates,
// which (unlike bootstrap.caCertificateProvider's dashboard/API path and its
// writeCertToDB call at issuance) have no row for DBRevocationStore.Revoke
// to update (W1-15/G-92).
//
// This covers every column bootstrap.caCertificateProvider.loadCertsFromDB
// scans into a non-nullable Go type (common_name, subject_alt_names,
// issuer_cn, key_size_bits, extended_key_usage, key_usage) -- a sparser row
// would make that scan fail and silently drop the certificate from the
// dashboard's list on the provider's next restart, out of write_scope to fix
// on the read side.
type CertMeta struct {
	FingerprintSHA256  string
	CommonName         string
	SubjectDN          string
	SubjectAltNames    []string
	IssuerDN           string
	IssuerCN           string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	KeySizeBits        int
	SignatureAlgorithm string
	ExtendedKeyUsage   []string
	KeyUsage           []string
	Source             string
	CertPEM            []byte
}

// MemRevocationStore is a thread-safe in-memory RevocationStore for tests.
type MemRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]RevokedEntry // key: serial.String()+":"+caID
}

func NewMemRevocationStore() *MemRevocationStore {
	return &MemRevocationStore{revoked: make(map[string]RevokedEntry)}
}

func revKey(serial *big.Int, caID string) string {
	return serial.String() + ":" + caID
}

func (s *MemRevocationStore) Revoke(serial *big.Int, caID string, reasonCode int, when time.Time, _ ...CertMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[revKey(serial, caID)] = RevokedEntry{Serial: new(big.Int).Set(serial), RevokedAt: when, ReasonCode: reasonCode}
	return nil
}

func (s *MemRevocationStore) IsRevoked(serial *big.Int, caID string) (bool, time.Time, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.revoked[revKey(serial, caID)]
	if !ok {
		return false, time.Time{}, 0, nil
	}
	return true, entry.RevokedAt, entry.ReasonCode, nil
}

func (s *MemRevocationStore) ListRevoked(caID string) ([]RevokedEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	suffix := ":" + caID
	var result []RevokedEntry
	for key, entry := range s.revoked {
		if len(key) > len(suffix) && key[len(key)-len(suffix):] == suffix {
			result = append(result, entry)
		}
	}
	return result, nil
}

// DBRevocationStore implements RevocationStore backed by the certificates table.
// It reads/writes certificates.revoked_at and certificates.revocation_reason
// using certificates.serial_number and certificates.ca_id for lookups.
type DBRevocationStore struct {
	db         *sql.DB
	isPostgres bool
}

// NewDBRevocationStore creates a RevocationStore backed by the given database.
func NewDBRevocationStore(db *sql.DB, isPostgres bool) *DBRevocationStore {
	return &DBRevocationStore{db: db, isPostgres: isPostgres}
}

func (s *DBRevocationStore) ph(n int) string {
	if s.isPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *DBRevocationStore) Revoke(serial *big.Int, caID string, reasonCode int, when time.Time, meta ...CertMeta) error {
	revokedAt := when.UTC().Format(time.RFC3339)
	var query string
	if s.isPostgres {
		query = `UPDATE certificates SET revoked_at = $1, revocation_reason = $2,
		          renewal_status = 'revoked', updated_at = $3
		         WHERE serial_number = $4 AND ca_id = $5`
	} else {
		query = `UPDATE certificates SET revoked_at = ?, revocation_reason = ?,
		          renewal_status = 'revoked', updated_at = ?
		         WHERE serial_number = ? AND ca_id = ?`
	}
	result, err := s.db.Exec(query, revokedAt, reasonCode, revokedAt, serial.String(), caID)
	if err != nil {
		return fmt.Errorf("revoke: update certificates: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke: rows affected: %w", err)
	}
	if affected > 0 {
		return nil
	}
	// No row means nothing to mark revoked. Previously this fell through as
	// a nil error (G-92): a zero-row UPDATE looks identical to a successful
	// one from sql.Exec's perspective alone, so IsRevoked silently kept
	// reporting not-revoked. If the caller supplied CertMeta (the ACME
	// revoke-cert path, whose certificates are never inserted at issuance),
	// create the row instead of erroring.
	if len(meta) == 0 {
		return fmt.Errorf("revoke: no certificates row for serial_number=%s ca_id=%s and no metadata supplied to create one", serial.String(), caID)
	}
	return s.insertRevokedCertificate(serial, caID, reasonCode, revokedAt, meta[0])
}

// insertRevokedCertificate creates a certificates row already marked
// revoked, for a caller (ACME revoke-cert, W1-15/G-92) whose certificate was
// never written to the table at issuance. Only reached after Revoke's own
// UPDATE already matched zero rows, so a fingerprint_sha256 (primary key)
// conflict here always means a row for a DIFFERENT serial_number/ca_id --
// silently doing nothing would reproduce the exact zero-rows-nil-error bug
// this ticket exists to fix, just one level down, so RowsAffected is checked
// the same way the UPDATE in Revoke is.
func (s *DBRevocationStore) insertRevokedCertificate(serial *big.Int, caID string, reasonCode int, revokedAt string, meta CertMeta) error {
	now := time.Now().UTC().Format(time.RFC3339)
	validFrom := meta.NotBefore.UTC().Format(time.RFC3339)
	validUntil := meta.NotAfter.UTC().Format(time.RFC3339)
	source := meta.Source
	if source == "" {
		source = "acme"
	}
	sanJSON, _ := json.Marshal(meta.SubjectAltNames)
	ekuJSON, _ := json.Marshal(meta.ExtendedKeyUsage)
	kuJSON, _ := json.Marshal(meta.KeyUsage)

	var query string
	if s.isPostgres {
		query = `INSERT INTO certificates
		    (fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
		     issuer_dn, issuer_cn, ca_id, valid_from, valid_until,
		     public_key_algorithm, key_size_bits, signature_algorithm,
		     extended_key_usage, key_usage, renewal_status, source,
		     raw_cert_b64, revoked_at, revocation_reason, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'revoked',$16,$17,$18,$19,$20,$21)
		ON CONFLICT (fingerprint_sha256) DO NOTHING`
	} else {
		query = `INSERT OR IGNORE INTO certificates
		    (fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
		     issuer_dn, issuer_cn, ca_id, valid_from, valid_until,
		     public_key_algorithm, key_size_bits, signature_algorithm,
		     extended_key_usage, key_usage, renewal_status, source,
		     raw_cert_b64, revoked_at, revocation_reason, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'revoked',?,?,?,?,?,?)`
	}
	result, err := s.db.Exec(query,
		meta.FingerprintSHA256, serial.String(), meta.SubjectDN, meta.CommonName, string(sanJSON),
		meta.IssuerDN, meta.IssuerCN, caID, validFrom, validUntil,
		meta.PublicKeyAlgorithm, meta.KeySizeBits, meta.SignatureAlgorithm,
		string(ekuJSON), string(kuJSON), source,
		string(meta.CertPEM), revokedAt, reasonCode, now, now,
	)
	if err != nil {
		return fmt.Errorf("revoke: insert certificates row: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke: insert rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("revoke: a certificates row for fingerprint=%s already exists under a different serial_number/ca_id than serial_number=%s ca_id=%s -- refusing to silently no-op", meta.FingerprintSHA256, serial.String(), caID)
	}
	return nil
}

func (s *DBRevocationStore) IsRevoked(serial *big.Int, caID string) (bool, time.Time, int, error) {
	var query string
	if s.isPostgres {
		query = `SELECT revoked_at, revocation_reason FROM certificates
		         WHERE serial_number = $1 AND ca_id = $2 AND revoked_at IS NOT NULL`
	} else {
		query = `SELECT revoked_at, revocation_reason FROM certificates
		         WHERE serial_number = ? AND ca_id = ? AND revoked_at IS NOT NULL`
	}

	var revokedAtStr string
	var reasonCode sql.NullInt64
	err := s.db.QueryRow(query, serial.String(), caID).Scan(&revokedAtStr, &reasonCode)
	if err == sql.ErrNoRows {
		return false, time.Time{}, 0, nil
	}
	if err != nil {
		return false, time.Time{}, 0, fmt.Errorf("IsRevoked query: %w", err)
	}

	revokedAt, err := time.Parse(time.RFC3339, revokedAtStr)
	if err != nil {
		return false, time.Time{}, 0, fmt.Errorf("parse revoked_at: %w", err)
	}
	return true, revokedAt, int(reasonCode.Int64), nil
}

func (s *DBRevocationStore) ListRevoked(caID string) ([]RevokedEntry, error) {
	var query string
	if s.isPostgres {
		query = `SELECT serial_number, revoked_at, revocation_reason FROM certificates
		         WHERE ca_id = $1 AND revoked_at IS NOT NULL`
	} else {
		query = `SELECT serial_number, revoked_at, revocation_reason FROM certificates
		         WHERE ca_id = ? AND revoked_at IS NOT NULL`
	}

	rows, err := s.db.Query(query, caID)
	if err != nil {
		return nil, fmt.Errorf("ListRevoked query: %w", err)
	}
	defer rows.Close()

	var result []RevokedEntry
	for rows.Next() {
		var serialStr, revokedAtStr string
		var reasonCode sql.NullInt64
		if err := rows.Scan(&serialStr, &revokedAtStr, &reasonCode); err != nil {
			return nil, fmt.Errorf("scan revoked row: %w", err)
		}
		serial := new(big.Int)
		if _, ok := serial.SetString(serialStr, 10); !ok {
			return nil, fmt.Errorf("parse serial %q: not a valid integer", serialStr)
		}
		revokedAt, err := time.Parse(time.RFC3339, revokedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse revoked_at %q: %w", revokedAtStr, err)
		}
		result = append(result, RevokedEntry{
			Serial:     serial,
			RevokedAt:  revokedAt,
			ReasonCode: int(reasonCode.Int64),
		})
	}
	return result, rows.Err()
}
