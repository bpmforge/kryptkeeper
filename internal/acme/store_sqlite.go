// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// SQLiteStore is a persistent ACME Store backed by SQLite (or Postgres with isPostgres=true).
// Call EnsureSchema once at startup to create the required tables.
type SQLiteStore struct {
	db         *sql.DB
	isPostgres bool
}

// NewSQLiteStore creates a persistent ACME store. Call EnsureSchema before first use.
func NewSQLiteStore(db *sql.DB, isPostgres bool) *SQLiteStore {
	return &SQLiteStore{db: db, isPostgres: isPostgres}
}

// EnsureSchema creates the ACME tables if they do not already exist.
func (s *SQLiteStore) EnsureSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS acme_accounts (
			id          TEXT PRIMARY KEY,
			contact     TEXT NOT NULL DEFAULT '[]',
			thumbprint  TEXT NOT NULL DEFAULT '',
			status      TEXT NOT NULL DEFAULT 'valid',
			created_at  TEXT NOT NULL,
			jwk         TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS acme_orders (
			id            TEXT PRIMARY KEY,
			account_id    TEXT NOT NULL DEFAULT '',
			status        TEXT NOT NULL DEFAULT 'pending',
			identifiers   TEXT NOT NULL DEFAULT '[]',
			authorizations TEXT NOT NULL DEFAULT '[]',
			finalize      TEXT NOT NULL DEFAULT '',
			certificate   TEXT NOT NULL DEFAULT '',
			not_before    TEXT,
			not_after     TEXT,
			expires       TEXT NOT NULL,
			created_at    TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS acme_authzs (
			id          TEXT PRIMARY KEY,
			account_id  TEXT NOT NULL DEFAULT '',
			identifier  TEXT NOT NULL DEFAULT '{}',
			status      TEXT NOT NULL DEFAULT 'pending',
			challenges  TEXT NOT NULL DEFAULT '[]',
			expires     TEXT NOT NULL,
			attested_key_thumbprint TEXT NOT NULL DEFAULT '',
			attestation_format      TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS acme_certs (
			id       TEXT PRIMARY KEY,
			pem_data TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS acme_eab_keys (
			kid        TEXT PRIMARY KEY,
			mac_key    TEXT NOT NULL,
			disabled   INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS acme_account_eab (
			account_id TEXT PRIMARY KEY,
			kid        TEXT NOT NULL,
			bound_at   TEXT NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("acme schema: %w", err)
		}
	}
	// acme_accounts predates migrations/{postgres,sqlite}/000040_acme_account_key
	// (G-90): a table created by a pre-W1-13 boot already exists in the
	// 5-column shape, so the CREATE TABLE IF NOT EXISTS above no-ops against
	// it and never widens it. Repair that table directly: best-effort because
	// on every OTHER boot (a genuinely fresh database, or one 000040 already
	// migrated) the column already exists and this duplicate-fails, which is
	// the expected, tolerated outcome -- any other error is real and fails
	// EnsureSchema, matching db.isAlreadySatisfiedDDLError's philosophy for
	// the identical ALTER-vs-EnsureSchema race elsewhere in this codebase.
	if err := ensureAccountJWKColumn(s.db); err != nil {
		return fmt.Errorf("acme schema: %w", err)
	}
	// W40-02: acme_authzs predates the device-attestation columns, and exists
	// only through this function (no migration creates it), so widening it
	// belongs here too.
	for _, col := range []string{"attested_key_thumbprint", "attestation_format"} {
		if err := ensureColumn(s.db, "acme_authzs", col, "TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("acme schema: %w", err)
		}
	}
	return nil
}

// ensureColumn adds a column, tolerating "already exists" (see
// ensureAccountJWKColumn for the driver messages).
func ensureColumn(db *sql.DB, table, column, decl string) error {
	_, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + decl)
	if err == nil {
		return nil
	}
	if msg := err.Error(); strings.Contains(msg, "duplicate column name") || strings.Contains(msg, "already exists") {
		return nil
	}
	return err
}

// ensureAccountJWKColumn adds acme_accounts.jwk to a table that already
// exists in the pre-G-90 shape. Confirmed empirically against this
// codebase's actual driver versions: sqlite (mattn/go-sqlite3) reports
// "duplicate column name: jwk"; Postgres reports "column \"jwk\" of
// relation \"acme_accounts\" already exists" -- the same two substrings
// internal/db.isAlreadySatisfiedDDLError already tolerates for this exact
// class of collision.
func ensureAccountJWKColumn(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE acme_accounts ADD COLUMN jwk TEXT`)
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "duplicate column name") || strings.Contains(msg, "already exists") {
		return nil
	}
	return err
}

func (s *SQLiteStore) ph(n int) string {
	if s.isPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// --- Account ---

func (s *SQLiteStore) SaveAccount(acct *Account) error {
	contact, _ := json.Marshal(acct.Contact)

	// jwk alongside thumbprint (not replacing it, G-90): the thumbprint is a
	// SHA-256 digest (RFC 7638) newAccount dedupes on, one-way by
	// construction, so it can never itself be turned back into a
	// verification key. A nil Key persists as SQL NULL, not an empty JWK.
	var jwkJSON sql.NullString
	if acct.Key != nil {
		jwk, err := publicKeyToJWK(acct.Key)
		if err != nil {
			return fmt.Errorf("acme: encode account key: %w", err)
		}
		raw, err := json.Marshal(jwk)
		if err != nil {
			return fmt.Errorf("acme: encode account key: %w", err)
		}
		jwkJSON = sql.NullString{String: string(raw), Valid: true}
	}

	var q string
	if s.isPostgres {
		q = `INSERT INTO acme_accounts (id,contact,thumbprint,status,created_at,jwk) VALUES ($1,$2,$3,$4,$5,$6)
		     ON CONFLICT (id) DO UPDATE SET contact=$2, thumbprint=$3, status=$4, jwk=$6`
	} else {
		q = `INSERT OR REPLACE INTO acme_accounts (id,contact,thumbprint,status,created_at,jwk) VALUES (?,?,?,?,?,?)`
	}
	_, err := s.db.Exec(q, acct.ID, string(contact), acct.KeyThumbprint, acct.Status,
		acct.CreatedAt.UTC().Format(time.RFC3339), jwkJSON)
	return err
}

func (s *SQLiteStore) LoadAccount(id string) (*Account, bool) {
	row := s.db.QueryRow(
		`SELECT id, contact, thumbprint, status, created_at, jwk FROM acme_accounts WHERE id = `+s.ph(1), id)
	return scanAccount(row)
}

func (s *SQLiteStore) ListAccounts() []*Account {
	rows, err := s.db.Query(`SELECT id, contact, thumbprint, status, created_at, jwk FROM acme_accounts`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		if a, ok := scanAccount(rows); ok {
			out = append(out, a)
		}
	}
	return out
}

type accountScanner interface {
	Scan(dest ...any) error
}

// scanAccount rebuilds an Account, including (G-90) a usable crypto.PublicKey
// from the persisted jwk column when present. A row with no jwk -- NULL
// (pre-G-90 row, degrading safely per acceptance criterion 4) or a value
// that fails to parse into a supported key -- leaves Key nil rather than
// erroring the whole scan: the caller (server.go's resolveAccountKey) already
// treats acct.Key == nil as unauthorized, so failing to reconstruct a key
// fails closed instead of surfacing as an unrelated load error.
func scanAccount(row accountScanner) (*Account, bool) {
	var id, contactJSON, thumbprint, status, createdAt string
	var jwkJSON sql.NullString
	if err := row.Scan(&id, &contactJSON, &thumbprint, &status, &createdAt, &jwkJSON); err != nil {
		return nil, false
	}
	var contact []string
	_ = json.Unmarshal([]byte(contactJSON), &contact) // corrupt row degrades to zero value, not a fatal
	t, _ := time.Parse(time.RFC3339, createdAt)

	acct := &Account{
		ID:            id,
		Contact:       contact,
		KeyThumbprint: thumbprint,
		Status:        status,
		CreatedAt:     t,
	}
	if jwkJSON.Valid && jwkJSON.String != "" {
		var jwk JSONWebKey
		if err := json.Unmarshal([]byte(jwkJSON.String), &jwk); err == nil {
			if pub, err := jwk.publicKey(); err == nil {
				acct.Key = pub
			}
		}
	}
	return acct, true
}

// publicKeyToJWK converts an ACME account's crypto.PublicKey into the RFC
// 7517 JSON Web Key that JSONWebKey.publicKey (jws.go) already knows how to
// parse back, covering exactly the three algorithms verifyJWSSignature
// accepts: ECDSA P-256 (ES256), RSA (RS256), Ed25519 (EdDSA). The dynamic
// types matched here are exactly what jwk.publicKey() returns, so a
// save/load round trip preserves the type verifyJWSSignature type-asserts
// on.
func publicKeyToJWK(pub crypto.PublicKey) (*JSONWebKey, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported EC curve for account key")
		}
		// Bytes is the fixed-length uncompressed point 0x04||X||Y, so the
		// coordinates keep their leading zero bytes and the RFC 7638
		// thumbprint the caller may separately derive stays stable.
		point, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("encode EC account key: %w", err)
		}
		size := (len(point) - 1) / 2
		x, y := point[1:1+size], point[1+size:]
		return &JSONWebKey{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
		}, nil
	case *rsa.PublicKey:
		return &JSONWebKey{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil
	case ed25519.PublicKey:
		return &JSONWebKey{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(key),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported account key type %T", pub)
	}
}

// --- Order ---

func (s *SQLiteStore) SaveOrder(order *Order) error {
	idents, _ := json.Marshal(order.Identifiers)
	authzs, _ := json.Marshal(order.Authorizations)

	var notBefore, notAfter sql.NullString
	if order.NotBefore != nil {
		notBefore = sql.NullString{String: order.NotBefore.UTC().Format(time.RFC3339), Valid: true}
	}
	if order.NotAfter != nil {
		notAfter = sql.NullString{String: order.NotAfter.UTC().Format(time.RFC3339), Valid: true}
	}

	var q string
	if s.isPostgres {
		q = `INSERT INTO acme_orders (id,account_id,status,identifiers,authorizations,finalize,certificate,not_before,not_after,expires,created_at)
		     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		     ON CONFLICT (id) DO UPDATE SET status=$3, certificate=$7`
	} else {
		q = `INSERT OR REPLACE INTO acme_orders (id,account_id,status,identifiers,authorizations,finalize,certificate,not_before,not_after,expires,created_at)
		     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	}
	_, err := s.db.Exec(q,
		order.ID, order.AccountID, order.Status,
		string(idents), string(authzs),
		order.Finalize, order.Certificate,
		notBefore, notAfter,
		order.Expires.UTC().Format(time.RFC3339),
		order.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) LoadOrder(id string) (*Order, bool) {
	row := s.db.QueryRow(
		`SELECT id,account_id,status,identifiers,authorizations,finalize,certificate,not_before,not_after,expires,created_at
		 FROM acme_orders WHERE id = `+s.ph(1), id)
	return scanOrder(row)
}

func (s *SQLiteStore) ListOrders() []*Order {
	rows, err := s.db.Query(
		`SELECT id,account_id,status,identifiers,authorizations,finalize,certificate,not_before,not_after,expires,created_at FROM acme_orders`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*Order
	for rows.Next() {
		if o, ok := scanOrder(rows); ok {
			out = append(out, o)
		}
	}
	return out
}

type orderScanner interface {
	Scan(dest ...any) error
}

func scanOrder(row orderScanner) (*Order, bool) {
	var (
		id, accountID, status, identsJSON, authzsJSON string
		finalize, certificate                         string
		notBefore, notAfter                           sql.NullString
		expires, createdAt                            string
	)
	if err := row.Scan(&id, &accountID, &status, &identsJSON, &authzsJSON,
		&finalize, &certificate, &notBefore, &notAfter, &expires, &createdAt); err != nil {
		return nil, false
	}
	var idents []Identifier
	var authzs []string
	_ = json.Unmarshal([]byte(identsJSON), &idents) // corrupt row degrades to zero value, not a fatal
	_ = json.Unmarshal([]byte(authzsJSON), &authzs) // corrupt row degrades to zero value, not a fatal
	exp, _ := time.Parse(time.RFC3339, expires)
	created, _ := time.Parse(time.RFC3339, createdAt)

	o := &Order{
		ID:             id,
		AccountID:      accountID,
		Status:         status,
		Identifiers:    idents,
		Authorizations: authzs,
		Finalize:       finalize,
		Certificate:    certificate,
		Expires:        exp,
		CreatedAt:      created,
	}
	if notBefore.Valid {
		t, _ := time.Parse(time.RFC3339, notBefore.String)
		o.NotBefore = &t
	}
	if notAfter.Valid {
		t, _ := time.Parse(time.RFC3339, notAfter.String)
		o.NotAfter = &t
	}
	return o, true
}

// --- Authorization ---

func (s *SQLiteStore) SaveAuthz(authz *Authorization) error {
	ident, _ := json.Marshal(authz.Identifier)
	challenges, _ := json.Marshal(authz.Challenges)

	var q string
	if s.isPostgres {
		q = `INSERT INTO acme_authzs (id,account_id,identifier,status,challenges,expires,attested_key_thumbprint,attestation_format)
		     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		     ON CONFLICT (id) DO UPDATE SET status=$4, challenges=$5, attested_key_thumbprint=$7, attestation_format=$8`
	} else {
		q = `INSERT OR REPLACE INTO acme_authzs (id,account_id,identifier,status,challenges,expires,attested_key_thumbprint,attestation_format)
		     VALUES (?,?,?,?,?,?,?,?)`
	}
	_, err := s.db.Exec(q,
		authz.ID, authz.AccountID, string(ident), authz.Status,
		string(challenges), authz.Expires.UTC().Format(time.RFC3339),
		authz.AttestedKeyThumbprint, authz.AttestationFormat,
	)
	return err
}

func (s *SQLiteStore) LoadAuthz(id string) (*Authorization, bool) {
	row := s.db.QueryRow(
		`SELECT id,account_id,identifier,status,challenges,expires,attested_key_thumbprint,attestation_format FROM acme_authzs WHERE id = `+s.ph(1), id)
	return scanAuthz(row)
}

type authzScanner interface {
	Scan(dest ...any) error
}

func scanAuthz(row authzScanner) (*Authorization, bool) {
	var id, accountID, identJSON, status, challengesJSON, expires, thumb, format string
	if err := row.Scan(&id, &accountID, &identJSON, &status, &challengesJSON, &expires, &thumb, &format); err != nil {
		return nil, false
	}
	var ident Identifier
	var challenges []Challenge
	_ = json.Unmarshal([]byte(identJSON), &ident)           // corrupt row degrades to zero value, not a fatal
	_ = json.Unmarshal([]byte(challengesJSON), &challenges) // corrupt row degrades to zero value, not a fatal
	exp, _ := time.Parse(time.RFC3339, expires)
	return &Authorization{
		ID:         id,
		AccountID:  accountID,
		Identifier: ident,
		Status:     status,
		Challenges: challenges,
		Expires:    exp,

		AttestedKeyThumbprint: thumb,
		AttestationFormat:     format,
	}, true
}

// --- Certificate ---

func (s *SQLiteStore) SaveCert(id string, pemBytes []byte) error {
	var q string
	if s.isPostgres {
		q = `INSERT INTO acme_certs (id,pem_data) VALUES ($1,$2) ON CONFLICT (id) DO UPDATE SET pem_data=$2`
	} else {
		q = `INSERT OR REPLACE INTO acme_certs (id,pem_data) VALUES (?,?)`
	}
	_, err := s.db.Exec(q, id, string(pemBytes))
	return err
}

func (s *SQLiteStore) LoadCert(id string) ([]byte, bool) {
	var pem string
	err := s.db.QueryRow(`SELECT pem_data FROM acme_certs WHERE id = `+s.ph(1), id).Scan(&pem)
	if err != nil {
		return nil, false
	}
	return []byte(pem), true
}

// --- External Account Binding (W4-04) ---

func (s *SQLiteStore) SaveEABKey(key *EABKey) error {
	var q string
	if s.isPostgres {
		q = `INSERT INTO acme_eab_keys (kid,mac_key,disabled,created_at) VALUES ($1,$2,$3,$4)
		     ON CONFLICT (kid) DO UPDATE SET mac_key=$2, disabled=$3`
	} else {
		q = `INSERT OR REPLACE INTO acme_eab_keys (kid,mac_key,disabled,created_at) VALUES (?,?,?,?)`
	}
	// disabled is stored as 0/1 (not a Go bool) because EnsureSchema declares the
	// column INTEGER on both engines; Postgres has no implicit bool->integer cast.
	disabled := 0
	if key.Disabled {
		disabled = 1
	}
	_, err := s.db.Exec(q,
		key.KID, base64.RawURLEncoding.EncodeToString(key.MACKey), disabled,
		key.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) LoadEABKey(kid string) (*EABKey, bool) {
	var macKeyB64, createdAt string
	var disabled int
	err := s.db.QueryRow(
		`SELECT mac_key, disabled, created_at FROM acme_eab_keys WHERE kid = `+s.ph(1), kid,
	).Scan(&macKeyB64, &disabled, &createdAt)
	if err != nil {
		return nil, false
	}
	macKey, err := base64.RawURLEncoding.DecodeString(macKeyB64)
	if err != nil {
		return nil, false
	}
	created, _ := time.Parse(time.RFC3339, createdAt)
	return &EABKey{KID: kid, MACKey: macKey, Disabled: disabled != 0, CreatedAt: created}, true
}

func (s *SQLiteStore) BindAccountEAB(accountID, kid string) error {
	var q string
	if s.isPostgres {
		q = `INSERT INTO acme_account_eab (account_id,kid,bound_at) VALUES ($1,$2,$3)
		     ON CONFLICT (account_id) DO UPDATE SET kid=$2, bound_at=$3`
	} else {
		q = `INSERT OR REPLACE INTO acme_account_eab (account_id,kid,bound_at) VALUES (?,?,?)`
	}
	_, err := s.db.Exec(q, accountID, kid, time.Now().UTC().Format(time.RFC3339))
	return err
}

// Ensure the interface is satisfied at compile time.
var _ Store = (*SQLiteStore)(nil)
