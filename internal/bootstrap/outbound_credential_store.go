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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
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
	// Privileged marks an account that is high-impact on the hosts it reaches
	// (W34-11, D-208): set from the sudo preflight or by hand, audited, and
	// shown wherever the credential is used. It gates nothing.
	Privileged       bool   `json:"privileged"`
	PrivilegedReason string `json:"privileged_reason,omitempty"`
	// PrivilegedSetBy is "auto:<source>" or "manual:<principal>".
	PrivilegedSetBy string `json:"privileged_set_by,omitempty"`
	PrivilegedSetAt string `json:"privileged_set_at,omitempty"`
	// Source says where the secret lives (W38-07, D-324): "local" is the
	// encrypted row, "external" a reference fetched from SourceID's manager at
	// each use. An external credential has no secret in the hub at all, so
	// Reference and Static, which are all it stores, are safe to show.
	Source    string            `json:"source"`
	SourceID  string            `json:"source_id,omitempty"`
	Reference map[string]string `json:"reference,omitempty"`
	Static    map[string]string `json:"static,omitempty"`
}

// credentialPrivilegeStore is implemented by the DB-backed stores; other
// OutboundCredentialStore implementations simply never carry the flag.
type credentialPrivilegeStore interface {
	// SetPrivileged records the flag; clearing it clears reason, actor and time.
	SetPrivileged(ctx context.Context, id string, privileged bool, reason, setBy string) error
}

const outboundCredentialMetaCols = `id, name, credential_type, tenant, created_at, updated_at,
		COALESCE(privileged, FALSE), COALESCE(privileged_reason, ''), COALESCE(privileged_set_by, ''), COALESCE(privileged_set_at, ''),
		COALESCE(source, 'local'), COALESCE(source_id, ''), COALESCE(source_ref, '')`

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

// externalCredentialTester is implemented by the DB-backed stores: it fetches
// a reference through its source without storing anything, for the "test this
// reference" call, and returns the names of the fields the manager returned,
// never their values.
type externalCredentialTester interface {
	TestExternal(ctx context.Context, sourceID, tenant, credentialType string, ref ExternalReference) ([]string, error)
}

// externalCredentialCreator is implemented by the DB-backed stores; a store
// without it simply cannot hold external credentials.
type externalCredentialCreator interface {
	// CreateExternal stores a reference, never a secret. The source must exist
	// and belong to tenant.
	CreateExternal(ctx context.Context, id, name, credentialType, tenant, sourceID string, ref ExternalReference) (OutboundCredentialMeta, error)
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
    updated_at      TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'local',
    source_id       TEXT,
    source_ref      TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbound_credentials_tenant ON outbound_credentials(tenant);` + credentialSourceSchema

// Privileged-flag columns (migration 000343) and source columns (000386) for a
// store whose table predates them. Dialects differ in the boolean type and in ADD COLUMN IF NOT EXISTS.
var (
	outboundPrivilegedUpgradesSQLite = []string{
		"ALTER TABLE outbound_credentials ADD COLUMN privileged INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE outbound_credentials ADD COLUMN privileged_reason TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN privileged_set_by TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN privileged_set_at TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN source TEXT NOT NULL DEFAULT 'local'",
		"ALTER TABLE outbound_credentials ADD COLUMN source_id TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN source_ref TEXT",
	}
	outboundPrivilegedUpgradesPostgres = []string{
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS privileged BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS privileged_reason TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS privileged_set_by TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS privileged_set_at TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'local'",
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS source_id TEXT",
		"ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS source_ref TEXT",
	}
)

// --- SQLite implementation ---

type sqliteOutboundCredentialStore struct {
	db         *sql.DB
	passphrase []byte

	extOnce sync.Once
	ext     *externalCredentialResolver
}

func (s *sqliteOutboundCredentialStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, outboundCredentialSchema); err != nil {
		return err
	}
	for _, stmt := range outboundPrivilegedUpgradesSQLite {
		_, _ = s.db.ExecContext(ctx, stmt) // best-effort upgrade: duplicate-column error = already migrated
	}
	return nil
}

func (s *sqliteOutboundCredentialStore) SetPrivileged(ctx context.Context, id string, privileged bool, reason, setBy string) error {
	return setOutboundPrivileged(ctx, s.db, false, id, privileged, reason, setBy)
}

func (s *sqliteOutboundCredentialStore) Create(ctx context.Context, id, name, credentialType, tenant string, plaintext []byte) (OutboundCredentialMeta, error) {
	return createOutboundCredential(ctx, s.db, s.passphrase, "?, ?, ?, ?, ?, ?, ?", id, name, credentialType, tenant, plaintext)
}

func (s *sqliteOutboundCredentialStore) Get(ctx context.Context, id string) (OutboundCredentialMeta, error) {
	return scanOutboundCredentialMeta(s.db.QueryRowContext(ctx, `
		SELECT `+outboundCredentialMetaCols+`
		FROM outbound_credentials WHERE id = ?`, id))
}

func (s *sqliteOutboundCredentialStore) List(ctx context.Context) ([]OutboundCredentialMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+outboundCredentialMetaCols+`
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
	return resolveOutboundCredential(ctx, s.db, false, s.passphrase, id, s.external)
}

func (s *sqliteOutboundCredentialStore) resolveLocalOnly(ctx context.Context, id string) ([]byte, error) {
	return resolveOutboundCredential(ctx, s.db, false, s.passphrase, id, nil)
}

func (s *sqliteOutboundCredentialStore) CreateExternal(ctx context.Context, id, name, credentialType, tenant, sourceID string, ref ExternalReference) (OutboundCredentialMeta, error) {
	return createExternalOutboundCredential(ctx, s.db, false, id, name, credentialType, tenant, sourceID, ref)
}

// external builds the resolver on first use: the store is constructed from the
// environment in many places and most never see an external credential.
func (s *sqliteOutboundCredentialStore) TestExternal(ctx context.Context, sourceID, tenant, credentialType string, ref ExternalReference) ([]string, error) {
	return testExternalCredential(ctx, s.external(), sourceID, tenant, credentialType, ref)
}

func (s *sqliteOutboundCredentialStore) external() *externalCredentialResolver {
	s.extOnce.Do(func() { s.ext = newExternalResolverForDB(s.db, false, s) })
	return s.ext
}

// --- Postgres implementation ---

type postgresOutboundCredentialStore struct {
	db         *sql.DB
	passphrase []byte

	extOnce sync.Once
	ext     *externalCredentialResolver
}

func (s *postgresOutboundCredentialStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, outboundCredentialSchema); err != nil {
		return err
	}
	for _, stmt := range outboundPrivilegedUpgradesPostgres {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *postgresOutboundCredentialStore) SetPrivileged(ctx context.Context, id string, privileged bool, reason, setBy string) error {
	return setOutboundPrivileged(ctx, s.db, true, id, privileged, reason, setBy)
}

func (s *postgresOutboundCredentialStore) Create(ctx context.Context, id, name, credentialType, tenant string, plaintext []byte) (OutboundCredentialMeta, error) {
	return createOutboundCredential(ctx, s.db, s.passphrase, "$1, $2, $3, $4, $5, $6, $7", id, name, credentialType, tenant, plaintext)
}

func (s *postgresOutboundCredentialStore) Get(ctx context.Context, id string) (OutboundCredentialMeta, error) {
	return scanOutboundCredentialMeta(s.db.QueryRowContext(ctx, `
		SELECT `+outboundCredentialMetaCols+`
		FROM outbound_credentials WHERE id = $1`, id))
}

func (s *postgresOutboundCredentialStore) List(ctx context.Context) ([]OutboundCredentialMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+outboundCredentialMetaCols+`
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
	return resolveOutboundCredential(ctx, s.db, true, s.passphrase, id, s.external)
}

func (s *postgresOutboundCredentialStore) resolveLocalOnly(ctx context.Context, id string) ([]byte, error) {
	return resolveOutboundCredential(ctx, s.db, true, s.passphrase, id, nil)
}

func (s *postgresOutboundCredentialStore) CreateExternal(ctx context.Context, id, name, credentialType, tenant, sourceID string, ref ExternalReference) (OutboundCredentialMeta, error) {
	return createExternalOutboundCredential(ctx, s.db, true, id, name, credentialType, tenant, sourceID, ref)
}

func (s *postgresOutboundCredentialStore) TestExternal(ctx context.Context, sourceID, tenant, credentialType string, ref ExternalReference) ([]string, error) {
	return testExternalCredential(ctx, s.external(), sourceID, tenant, credentialType, ref)
}

func (s *postgresOutboundCredentialStore) external() *externalCredentialResolver {
	s.extOnce.Do(func() { s.ext = newExternalResolverForDB(s.db, true, s) })
	return s.ext
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
	m, err := scanMetaFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return OutboundCredentialMeta{}, errOutboundCredentialNotFound
	}
	return m, err
}

func scanMetaFrom(sc rowScanner) (OutboundCredentialMeta, error) {
	var m OutboundCredentialMeta
	var ref string
	if err := sc.Scan(&m.ID, &m.Name, &m.CredentialType, &m.Tenant, &m.CreatedAt, &m.UpdatedAt, &m.Privileged, &m.PrivilegedReason, &m.PrivilegedSetBy, &m.PrivilegedSetAt,
		&m.Source, &m.SourceID, &ref); err != nil {
		return OutboundCredentialMeta{}, err
	}
	if ref != "" {
		var r ExternalReference
		if err := json.Unmarshal([]byte(ref), &r); err == nil {
			m.Reference, m.Static = r.Reference, r.Static
		}
	}
	return m, nil
}

func scanOutboundCredentialMetaRows(rows *sql.Rows) ([]OutboundCredentialMeta, error) {
	defer rows.Close()
	items := []OutboundCredentialMeta{}
	for rows.Next() {
		m, err := scanMetaFrom(rows)
		if err != nil {
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

// resolveOutboundCredential returns a credential's plaintext. A local row is
// opened with the passphrase; an external row is fetched from its source by
// ext, and a nil ext (the source's own login, which must be local or resolving
// it could loop) refuses it.
func resolveOutboundCredential(ctx context.Context, db *sql.DB, postgres bool, passphrase []byte, id string, ext func() *externalCredentialResolver) ([]byte, error) {
	q := `SELECT envelope, credential_type, tenant, COALESCE(source, 'local'), COALESCE(source_id, ''), COALESCE(source_ref, '')
		FROM outbound_credentials WHERE id = ?`
	if postgres {
		q = rebindPostgres(q)
	}
	var envelope, credType, tenant, source, sourceID, sourceRef string
	err := db.QueryRowContext(ctx, q, id).Scan(&envelope, &credType, &tenant, &source, &sourceID, &sourceRef)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errOutboundCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	if source != CredentialSourceExternal {
		return openEnvelope(passphrase, envelope)
	}
	if ext == nil {
		return nil, resolveErr(resolveClassConfig, "credential %q is external; a credential source's own login must be a local credential", id)
	}
	var ref ExternalReference
	if err := json.Unmarshal([]byte(sourceRef), &ref); err != nil {
		return nil, resolveErr(resolveClassConfig, "credential %q has an unreadable source reference", id)
	}
	return ext().resolve(ctx, externalRow{ID: id, Type: credType, Tenant: tenant, SourceID: sourceID, Ref: ref})
}

// createExternalOutboundCredential stores a reference. It checks the source
// here, not only in the handler, so no caller can attach a credential to a
// source of another tenant or to a reference the source kind cannot read.
func createExternalOutboundCredential(ctx context.Context, db *sql.DB, postgres bool, id, name, credentialType, tenant, sourceID string, ref ExternalReference) (OutboundCredentialMeta, error) {
	if err := validateCredentialType(credentialType); err != nil {
		return OutboundCredentialMeta{}, err
	}
	if tenant == "" {
		tenant = DefaultTenant
	}
	src, err := (&dbCredentialSourceStore{db: db, postgres: postgres}).Get(ctx, sourceID)
	if err != nil {
		return OutboundCredentialMeta{}, err
	}
	if normalizeTenant(src.Tenant) != tenant {
		return OutboundCredentialMeta{}, errCredentialSourceNotFound // another tenant's source does not exist here
	}
	if err := ref.validate(src.Kind); err != nil {
		return OutboundCredentialMeta{}, err
	}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return OutboundCredentialMeta{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	q := `INSERT INTO outbound_credentials (id, name, credential_type, tenant, envelope, created_at, updated_at, source, source_id, source_ref)
		VALUES (?, ?, ?, ?, '', ?, ?, 'external', ?, ?)`
	if postgres {
		q = rebindPostgres(q)
	}
	if _, err := db.ExecContext(ctx, q, id, name, credentialType, tenant, now, now, sourceID, string(refJSON)); err != nil {
		return OutboundCredentialMeta{}, err
	}
	return OutboundCredentialMeta{
		ID: id, Name: name, CredentialType: credentialType, Tenant: tenant, CreatedAt: now, UpdatedAt: now,
		Source: CredentialSourceExternal, SourceID: sourceID, Reference: ref.Reference, Static: ref.Static,
	}, nil
}

// newExternalResolverForDB wires a resolver to a store's own database. The
// plugin manager is a light one over the same database: running a credentials
// plugin needs the stored, approved plugin bytes and the WebAssembly runtime,
// not the approval queue or trust keys.
func newExternalResolverForDB(db *sql.DB, postgres bool, local localCredentialReader) *externalCredentialResolver {
	var once sync.Once
	var mgr *DeliveryPluginManager
	return newExternalCredentialResolver(&dbCredentialSourceStore{db: db, postgres: postgres}, local, func() *DeliveryPluginManager {
		once.Do(func() { mgr = NewDeliveryPluginManager(db, postgres, nil, nil) })
		return mgr
	})
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

func setOutboundPrivileged(ctx context.Context, db *sql.DB, postgres bool, id string, privileged bool, reason, setBy string) error {
	var at any
	if !privileged {
		reason, setBy = "", ""
	} else {
		at = time.Now().UTC().Format(time.RFC3339)
	}
	q := `UPDATE outbound_credentials SET privileged = ?, privileged_reason = ?, privileged_set_by = ?, privileged_set_at = ? WHERE id = ?`
	if postgres {
		q = rebindPostgres(q)
	}
	res, err := db.ExecContext(ctx, q, boolArg(privileged, postgres),
		nullString(reason), nullString(setBy), at, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errOutboundCredentialNotFound
	}
	return nil
}
