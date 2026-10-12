// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

var errOutboundCredentialNotFound = errors.New("outbound credential not found")
var errOutboundCredentialInvalidType = errors.New("invalid credential_type")

// Fixed enum, mirrors the CHECK constraint (L-03: implement the whole set).
const (
	CredentialTypeSSHKey   = "ssh_key"
	CredentialTypeAPIToken = "api_token"
	CredentialTypeCloudIAM = "cloud_iam"
	// W18-01: WinRM authenticates with a username and password (optionally
	// an NTLM domain). Windows targets could not resolve a credential at
	// all before this — the vocabulary was SSH- and token-shaped only.
	CredentialTypeWindowsPassword = "windows_password"
)

var validCredentialTypes = map[string]bool{
	CredentialTypeSSHKey:          true,
	CredentialTypeAPIToken:        true,
	CredentialTypeCloudIAM:        true,
	CredentialTypeWindowsPassword: true,
}

// Encryption constants -- same values as internal/keystore/software.go's
// unexported constants of the same name. Redeclared here rather than
// imported: they're private to that package, and this store's envelope
// format is deliberately different (see sealEnvelope's doc comment), so
// sharing code across the package boundary would buy nothing.
const (
	argon2Time    = 2
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
	nonceLen      = 12
)

// OutboundCredentialMeta is everything the API layer (whenever one is
// built) is allowed to see -- no plaintext, no envelope.
type OutboundCredentialMeta struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CredentialType string `json:"credential_type"`
	Tenant         string `json:"tenant"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// OutboundCredentialStore persists outbound credentials (SSH keys, API
// tokens, cloud IAM refs) encrypted at rest, referenced by id from a
// managed_target's CredentialRef (W5-09). There is no Update/rotate method
// -- see the doc comment on Resolve and docs/board/specs/W5-10.md's "Known
// traps" for why that's a deliberate, disclosed gap, not an oversight.
type OutboundCredentialStore interface {
	EnsureSchema(ctx context.Context) error
	// Create encrypts plaintext and persists it. plaintext's shape is
	// opaque to the store (an SSH PEM, a raw token string, a cloud-IAM
	// JSON blob) -- callers marshal/unmarshal their own payload shape.
	Create(ctx context.Context, id, name, credentialType, tenant string, plaintext []byte) (OutboundCredentialMeta, error)
	// Get returns metadata ONLY -- never the envelope or plaintext. This
	// is the method an eventual HTTP handler would call.
	Get(ctx context.Context, id string) (OutboundCredentialMeta, error)
	List(ctx context.Context) ([]OutboundCredentialMeta, error)
	Delete(ctx context.Context, id string) error
	// Resolve decrypts and returns the plaintext. NOT for HTTP handlers --
	// only for internal Go callers that need real key material (e.g. a
	// future SSH executor). Callers MUST NOT serialize the result back
	// over any API response, log it, or include it in an audit event --
	// treat it exactly as radioactively as a private key.
	Resolve(ctx context.Context, id string) ([]byte, error)
}

func validateCredentialType(credentialType string) error {
	if !validCredentialTypes[credentialType] {
		return errOutboundCredentialInvalidType
	}
	return nil
}

// sealEnvelope encrypts plaintext with Argon2id-derived AES-256-GCM using a
// fresh salt and nonce, and returns base64(salt(16) || nonce(12) ||
// ciphertext). A fresh salt AND fresh nonce on every call is the property
// that makes this safe -- a shared nonce across two envelopes encrypted
// under the same derived key breaks AES-GCM's confidentiality guarantee
// outright. Deliberately not the PEM/hex-header envelope
// internal/keystore/software.go's encryptAndPersist uses -- that format
// exists for PEM-tooling compatibility on files; this writes to a DB TEXT
// column with no such audience, so one self-contained blob is enough.
func sealEnvelope(passphrase, plaintext []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	raw := append(append(append([]byte{}, salt...), nonce...), ciphertext...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// openEnvelope decrypts an envelope produced by sealEnvelope. The envelope
// is DB-sourced data this function did not create -- it may be truncated,
// corrupted, or the product of a bad migration -- so it is bounds-checked
// before any slicing happens, rather than trusting its shape the way
// sealEnvelope's own callers can trust output they just produced.
func openEnvelope(passphrase []byte, envelope string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	if len(raw) < saltLen+nonceLen {
		return nil, fmt.Errorf("envelope too short: got %d bytes, need at least %d", len(raw), saltLen+nonceLen)
	}

	salt := raw[:saltLen]
	nonce := raw[saltLen : saltLen+nonceLen]
	ciphertext := raw[saltLen+nonceLen:]

	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt envelope: %w", err)
	}
	return plaintext, nil
}

// outboundCredentialSchema mirrors migration 000029_outbound_credentials --
// see G-33: a migration existing is not sufficient, every DB-backed store
// in this codebase must self-heal its own schema since migrations are
// never actually run against a live deployment.
const outboundCredentialSchema = `
CREATE TABLE IF NOT EXISTS outbound_credentials (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('ssh_key', 'api_token', 'cloud_iam', 'windows_password')),
    tenant          TEXT NOT NULL DEFAULT 'default',
    envelope        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbound_credentials_tenant ON outbound_credentials(tenant);`

// --- SQLite implementation ---

type sqliteOutboundCredentialStore struct {
	db         *sql.DB
	passphrase []byte
}

func (s *sqliteOutboundCredentialStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, outboundCredentialSchema)
	return err
}

func (s *sqliteOutboundCredentialStore) Create(ctx context.Context, id, name, credentialType, tenant string, plaintext []byte) (OutboundCredentialMeta, error) {
	return createOutboundCredential(ctx, s.db, s.passphrase, "?, ?, ?, ?, ?, ?, ?", id, name, credentialType, tenant, plaintext)
}

func (s *sqliteOutboundCredentialStore) Get(ctx context.Context, id string) (OutboundCredentialMeta, error) {
	return scanOutboundCredentialMeta(s.db.QueryRowContext(ctx, `
		SELECT id, name, credential_type, tenant, created_at, updated_at
		FROM outbound_credentials WHERE id = ?`, id))
}

func (s *sqliteOutboundCredentialStore) List(ctx context.Context) ([]OutboundCredentialMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, credential_type, tenant, created_at, updated_at
		FROM outbound_credentials ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanOutboundCredentialMetaRows(rows)
}

func (s *sqliteOutboundCredentialStore) Delete(ctx context.Context, id string) error {
	return deleteOutboundCredentialRow(ctx, s.db, "DELETE FROM outbound_credentials WHERE id = ?", id)
}

func (s *sqliteOutboundCredentialStore) Resolve(ctx context.Context, id string) ([]byte, error) {
	return resolveOutboundCredential(ctx, s.db, s.passphrase, "SELECT envelope FROM outbound_credentials WHERE id = ?", id)
}

// --- Postgres implementation ---

type postgresOutboundCredentialStore struct {
	db         *sql.DB
	passphrase []byte
}

func (s *postgresOutboundCredentialStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, outboundCredentialSchema)
	return err
}

func (s *postgresOutboundCredentialStore) Create(ctx context.Context, id, name, credentialType, tenant string, plaintext []byte) (OutboundCredentialMeta, error) {
	return createOutboundCredential(ctx, s.db, s.passphrase, "$1, $2, $3, $4, $5, $6, $7", id, name, credentialType, tenant, plaintext)
}

func (s *postgresOutboundCredentialStore) Get(ctx context.Context, id string) (OutboundCredentialMeta, error) {
	return scanOutboundCredentialMeta(s.db.QueryRowContext(ctx, `
		SELECT id, name, credential_type, tenant, created_at, updated_at
		FROM outbound_credentials WHERE id = $1`, id))
}

func (s *postgresOutboundCredentialStore) List(ctx context.Context) ([]OutboundCredentialMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, credential_type, tenant, created_at, updated_at
		FROM outbound_credentials ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanOutboundCredentialMetaRows(rows)
}

func (s *postgresOutboundCredentialStore) Delete(ctx context.Context, id string) error {
	return deleteOutboundCredentialRow(ctx, s.db, "DELETE FROM outbound_credentials WHERE id = $1", id)
}

func (s *postgresOutboundCredentialStore) Resolve(ctx context.Context, id string) ([]byte, error) {
	return resolveOutboundCredential(ctx, s.db, s.passphrase, "SELECT envelope FROM outbound_credentials WHERE id = $1", id)
}

// --- shared helpers ---

func createOutboundCredential(ctx context.Context, db *sql.DB, passphrase []byte, valuesPlaceholders string, id, name, credentialType, tenant string, plaintext []byte) (OutboundCredentialMeta, error) {
	if err := validateCredentialType(credentialType); err != nil {
		return OutboundCredentialMeta{}, err
	}
	envelope, err := sealEnvelope(passphrase, plaintext)
	if err != nil {
		return OutboundCredentialMeta{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	query := fmt.Sprintf(`
		INSERT INTO outbound_credentials (id, name, credential_type, tenant, envelope, created_at, updated_at)
		VALUES (%s)`, valuesPlaceholders)
	if _, err := db.ExecContext(ctx, query, id, name, credentialType, tenant, envelope, now, now); err != nil {
		return OutboundCredentialMeta{}, err
	}
	return OutboundCredentialMeta{
		ID: id, Name: name, CredentialType: credentialType, Tenant: tenant,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func scanOutboundCredentialMeta(row *sql.Row) (OutboundCredentialMeta, error) {
	var m OutboundCredentialMeta
	err := row.Scan(&m.ID, &m.Name, &m.CredentialType, &m.Tenant, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OutboundCredentialMeta{}, errOutboundCredentialNotFound
	}
	if err != nil {
		return OutboundCredentialMeta{}, err
	}
	return m, nil
}

func scanOutboundCredentialMetaRows(rows *sql.Rows) ([]OutboundCredentialMeta, error) {
	defer rows.Close()
	items := []OutboundCredentialMeta{}
	for rows.Next() {
		var m OutboundCredentialMeta
		if err := rows.Scan(&m.ID, &m.Name, &m.CredentialType, &m.Tenant, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

func deleteOutboundCredentialRow(ctx context.Context, db *sql.DB, query, id string) error {
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errOutboundCredentialNotFound
	}
	return nil
}

func resolveOutboundCredential(ctx context.Context, db *sql.DB, passphrase []byte, query, id string) ([]byte, error) {
	var envelope string
	err := db.QueryRowContext(ctx, query, id).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errOutboundCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	return openEnvelope(passphrase, envelope)
}

// outboundCredentialPassphraseFromEnv resolves the passphrase this store
// encrypts with: APP_CREDENTIAL_STORE_PASSPHRASE, falling back to
// KRYPTKEEPER_KEYSTORE_PASSPHRASE if unset (mirrors the multi-var-fallback
// convention resolvePostgresDSNFromEnv already uses). Deliberately NOT
// gated on APP_CERTIFICATE_PROVIDER=ca the way the keystore passphrase is
// (cmd/kryptkeeper/main.go) -- outbound credentials for agentless targets
// are a real feature independent of whether the CA engine is active.
//
// WARNING: when APP_CREDENTIAL_STORE_PASSPHRASE is unset, this store and
// the CA keystore share one secret by default -- a real blast-radius
// coupling, not just convenience. An operator who wants them independent
// must set APP_CREDENTIAL_STORE_PASSPHRASE explicitly.
func outboundCredentialPassphraseFromEnv() []byte {
	if v := os.Getenv("APP_CREDENTIAL_STORE_PASSPHRASE"); v != "" {
		return []byte(v)
	}
	return []byte(os.Getenv("KRYPTKEEPER_KEYSTORE_PASSPHRASE"))
}

// newOutboundCredentialStoreFromEnv opens the same SQLite/Postgres DB as
// other providers and ensures the outbound_credentials schema exists
// (G-33: migration 000029 alone cannot be assumed to have run). Returns
// nil on any failure -- nil-tolerant, matching managed_target_store.go/
// tenant_store.go/finding_exception_store.go. NOT wired into
// RegisterHandlers -- nothing calls it yet (no HTTP surface this ticket,
// see docs/board/specs/W5-10.md); left unconstructed until a consumer
// ticket needs it, matching newFindingExceptionStoreFromEnv's (W2-06)
// precedent of "implemented, not yet instantiated."
func newOutboundCredentialStoreFromEnv() OutboundCredentialStore {
	passphrase := outboundCredentialPassphraseFromEnv()
	if len(passphrase) == 0 {
		// Fail closed, not open: an empty passphrase still "encrypts"
		// (Argon2id derives a key from it either way) but the result is
		// decryptable by anyone with the DB and no secret at all --
		// exactly the property acceptance #1 exists to prevent. Every
		// other newXFromEnv in this package fails closed on missing
		// config; this store must too.
		_ = dbProviderUnavailable("outbound-credential", fmt.Errorf("APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE must be set")) // logs the outage itself; return value is the same sentinel
		return nil
	}
	state := newDBProviderState[OutboundCredentialStore](
		"outbound-credential",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_TARGETS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) OutboundCredentialStore {
			return &sqliteOutboundCredentialStore{db: db, passphrase: passphrase}
		},
		func(db *sql.DB) OutboundCredentialStore {
			return &postgresOutboundCredentialStore{db: db, passphrase: passphrase}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("outbound-credential", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("outbound-credential", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
