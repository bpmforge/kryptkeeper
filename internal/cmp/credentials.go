// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

// Operator-managed CMP credentials (W26-09, D-043): PBM shared secrets that
// authenticate ir/cr/kur/rr/certConf/pollReq, and trust-anchor certificates.
// The env pair KRYPTKEEPER_CMP_SECRET / KRYPTKEEPER_CMP_REFERENCE keeps
// working beside them.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

var (
	// ErrCredentialNotFound means no credential has that id.
	ErrCredentialNotFound = errors.New("cmp credential not found")
	// ErrAlreadyRevoked means the credential was revoked earlier.
	ErrAlreadyRevoked = errors.New("cmp credential already revoked")
	// ErrNotPBM means the operation applies to PBM secrets only.
	ErrNotPBM = errors.New("cmp credential is not a PBM secret")
	// ErrDuplicateAnchor means an active trust anchor has that fingerprint.
	ErrDuplicateAnchor = errors.New("cmp trust anchor already registered")
)

// Credential kinds.
const (
	KindPBM         = "pbm"
	KindTrustAnchor = "trust_anchor"
)

// Credential is a stored credential without any secret material.
type Credential struct {
	ID, Kind, Label, SenderKID, CertSHA256, CreatedBy string
	AllowedDNSSuffixes                                []string
	CreatedAt                                         time.Time
	RotatedAt, RevokedAt, LastUsedAt                  *time.Time
}

// CredentialStore keeps PBM secrets and trust anchors.
type CredentialStore interface {
	CreatePBM(ctx context.Context, c Credential, sealedSecret string) error
	RegisterAnchor(ctx context.Context, c Credential, certPEM string) error
	List(ctx context.Context) ([]Credential, error) // newest first
	Get(ctx context.Context, id string) (Credential, error)
	Rotate(ctx context.Context, id, sealedSecret string, at time.Time) error // pbm only
	Revoke(ctx context.Context, id string, at time.Time) error
	// LookupPBM returns the active secret for a senderKID. It never reports
	// why a lookup missed (unknown, revoked and unsealable look the same).
	LookupPBM(ctx context.Context, senderKID []byte) (secret []byte, c Credential, ok bool)
	// TrustAnchors returns the active anchors. Not yet used to verify
	// messages: signature-protected CMP is a separate ticket.
	TrustAnchors(ctx context.Context) ([]*x509.Certificate, error)
}

// credCtx is what answers one request: the secret that verified it, the
// reference responses carry, and the DNS suffixes that bind the client.
type credCtx struct {
	secret, reference []byte
	suffixes          []string
	id                string
}

// WithCredentials enables API-managed credentials.
func (s *Server) WithCredentials(cs CredentialStore) *Server {
	s.credentials = cs
	return s
}

// credFor picks the credential for a request. A stored PBM secret for the
// senderKID wins; anything else (unknown or revoked kid included) falls back
// to the env pair, so the gate answers a miss exactly like a wrong secret.
func (s *Server) credFor(ctx context.Context, hdr parsedHeader) credCtx {
	if s.credentials != nil && len(hdr.SenderKID) > 0 {
		if secret, c, ok := s.credentials.LookupPBM(ctx, hdr.SenderKID); ok {
			sfx := c.AllowedDNSSuffixes
			if len(sfx) == 0 {
				sfx = s.allowedDNSSuffixes
			}
			return credCtx{secret: secret, reference: []byte(c.SenderKID), suffixes: sfx, id: c.ID}
		}
	}
	return credCtx{secret: s.secret, reference: s.reference, suffixes: s.allowedDNSSuffixes}
}

// credCacheTTL bounds how long an unsealed secret stays in memory. Sealing is
// Argon2id (64 MiB) per open, far too heavy per CMP message, and an uncached
// lookup would be a DoS lever. Revoke and Rotate clear the entry on the node
// that handled them, so revocation is immediate there and takes at most this
// long on other nodes of an HA deployment.
const credCacheTTL = 30 * time.Second

type credCacheEntry struct {
	secret  []byte
	cred    Credential
	expires time.Time
}

// DBCredentialStore keeps credentials in cmp_credentials.
type DBCredentialStore struct {
	db       *sql.DB
	postgres bool
	open     func(sealed string) ([]byte, error)
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]credCacheEntry // by senderKID; hits only
}

// NewDBCredentialStore returns a store on db. open unseals a stored secret.
func NewDBCredentialStore(db *sql.DB, postgres bool, open func(sealed string) ([]byte, error)) *DBCredentialStore {
	return &DBCredentialStore{db: db, postgres: postgres, open: open, now: time.Now, cache: map[string]credCacheEntry{}}
}

// EnsureSchema creates the table for a database that skipped migrations.
func (s *DBCredentialStore) EnsureSchema() error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS cmp_credentials (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('pbm','trust_anchor')),
  label TEXT NOT NULL DEFAULT '', sender_kid TEXT, sealed_secret TEXT, cert_pem TEXT, cert_sha256 TEXT,
  allowed_dns_suffixes TEXT NOT NULL DEFAULT '[]', created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  rotated_at TEXT, revoked_at TEXT, last_used_at TEXT)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_cmp_credentials_kid ON cmp_credentials(sender_kid) WHERE sender_kid IS NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_cmp_credentials_anchor ON cmp_credentials(cert_sha256) WHERE cert_sha256 IS NOT NULL AND revoked_at IS NULL`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("cmp credentials schema: %w", err)
		}
	}
	return nil
}

func (s *DBCredentialStore) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

const credTimeLayout = time.RFC3339

func credTime(t time.Time) string { return t.UTC().Format(credTimeLayout) }

func parseCredTime(v string) time.Time {
	t, _ := time.Parse(credTimeLayout, v)
	return t
}

func suffixesJSON(s []string) string {
	if s == nil {
		s = []string{}
	}
	b, _ := json.Marshal(s) // []string cannot fail
	return string(b)
}

func (s *DBCredentialStore) CreatePBM(ctx context.Context, c Credential, sealedSecret string) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO cmp_credentials
 (id, kind, label, sender_kid, sealed_secret, allowed_dns_suffixes, created_by, created_at)
 VALUES (?, 'pbm', ?, ?, ?, ?, ?, ?)`),
		c.ID, c.Label, c.SenderKID, sealedSecret, suffixesJSON(c.AllowedDNSSuffixes), c.CreatedBy, credTime(c.CreatedAt))
	return err
}

func (s *DBCredentialStore) RegisterAnchor(ctx context.Context, c Credential, certPEM string) error {
	var one int
	err := s.db.QueryRowContext(ctx, s.q(`SELECT 1 FROM cmp_credentials WHERE kind = 'trust_anchor' AND cert_sha256 = ? AND revoked_at IS NULL`), c.CertSHA256).Scan(&one)
	if err == nil {
		return ErrDuplicateAnchor
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO cmp_credentials
 (id, kind, label, cert_pem, cert_sha256, created_by, created_at) VALUES (?, 'trust_anchor', ?, ?, ?, ?, ?)`),
		c.ID, c.Label, certPEM, c.CertSHA256, c.CreatedBy, credTime(c.CreatedAt))
	return err
}

const credColumns = `id, kind, label, COALESCE(sender_kid, ''), COALESCE(cert_sha256, ''), allowed_dns_suffixes, created_by, created_at, rotated_at, revoked_at, last_used_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanCredential(r rowScanner) (Credential, error) {
	var c Credential
	var sfx, created string
	var rotated, revoked, used sql.NullString
	if err := r.Scan(&c.ID, &c.Kind, &c.Label, &c.SenderKID, &c.CertSHA256, &sfx, &c.CreatedBy, &created, &rotated, &revoked, &used); err != nil {
		return Credential{}, err
	}
	if err := json.Unmarshal([]byte(sfx), &c.AllowedDNSSuffixes); err != nil {
		c.AllowedDNSSuffixes = nil
	}
	c.CreatedAt = parseCredTime(created)
	for _, p := range []struct {
		v   sql.NullString
		dst **time.Time
	}{{rotated, &c.RotatedAt}, {revoked, &c.RevokedAt}, {used, &c.LastUsedAt}} {
		if p.v.Valid {
			t := parseCredTime(p.v.String)
			*p.dst = &t
		}
	}
	return c, nil
}

func (s *DBCredentialStore) List(ctx context.Context) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credColumns+` FROM cmp_credentials ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *DBCredentialStore) Get(ctx context.Context, id string) (Credential, error) {
	c, err := scanCredential(s.db.QueryRowContext(ctx, s.q(`SELECT `+credColumns+` FROM cmp_credentials WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrCredentialNotFound
	}
	return c, err
}

// forget drops cached secrets of credential id.
func (s *DBCredentialStore) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for kid, e := range s.cache {
		if e.cred.ID == id {
			delete(s.cache, kid)
		}
	}
}

func (s *DBCredentialStore) Rotate(ctx context.Context, id, sealedSecret string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE cmp_credentials SET sealed_secret = ?, rotated_at = ?
 WHERE id = ? AND kind = 'pbm' AND revoked_at IS NULL`), sealedSecret, credTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.forget(id)
		return nil
	}
	return s.whyNoUpdate(ctx, id, true)
}

func (s *DBCredentialStore) Revoke(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE cmp_credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), credTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.forget(id)
		return nil
	}
	return s.whyNoUpdate(ctx, id, false)
}

func (s *DBCredentialStore) whyNoUpdate(ctx context.Context, id string, pbmOnly bool) error {
	c, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if pbmOnly && c.Kind != KindPBM {
		return ErrNotPBM
	}
	return ErrAlreadyRevoked
}

func (s *DBCredentialStore) LookupPBM(ctx context.Context, senderKID []byte) ([]byte, Credential, bool) {
	kid := string(senderKID)
	now := s.now()
	s.mu.Lock()
	if e, ok := s.cache[kid]; ok {
		if now.Before(e.expires) {
			s.mu.Unlock()
			return append([]byte(nil), e.secret...), e.cred, true
		}
		delete(s.cache, kid)
	}
	s.mu.Unlock()

	var sealed string
	c, err := scanCredentialWithSecret(s.db.QueryRowContext(ctx, s.q(`SELECT `+credColumns+`, sealed_secret FROM cmp_credentials
 WHERE sender_kid = ? AND kind = 'pbm' AND revoked_at IS NULL`), kid), &sealed)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			logging.Infof("cmp: credential lookup: %v", err)
		}
		return nil, Credential{}, false
	}
	secret, err := s.open(sealed)
	if err != nil || len(secret) == 0 {
		logging.Warnf("cmp: credential %s cannot be unsealed", c.ID)
		return nil, Credential{}, false
	}
	// Best effort: a failed touch must not fail authentication. Done on a
	// cache fill only, so last_used_at is at most credCacheTTL stale.
	if _, err := s.db.ExecContext(ctx, s.q(`UPDATE cmp_credentials SET last_used_at = ? WHERE id = ?`), credTime(now), c.ID); err != nil {
		logging.Infof("cmp: credential %s last_used_at not updated: %v", c.ID, err)
	}
	s.mu.Lock()
	s.cache[kid] = credCacheEntry{secret: secret, cred: c, expires: now.Add(credCacheTTL)}
	s.mu.Unlock()
	return append([]byte(nil), secret...), c, true
}

func scanCredentialWithSecret(r *sql.Row, sealed *string) (Credential, error) {
	return scanCredential(secretScanner{r, sealed})
}

// secretScanner appends the sealed_secret column to a scanCredential scan.
type secretScanner struct {
	r      *sql.Row
	sealed *string
}

func (s secretScanner) Scan(dest ...any) error {
	return s.r.Scan(append(dest, s.sealed)...)
}

func (s *DBCredentialStore) TrustAnchors(ctx context.Context) ([]*x509.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cert_pem FROM cmp_credentials WHERE kind = 'trust_anchor' AND revoked_at IS NULL ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*x509.Certificate
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
	return out, rows.Err()
}

// ParseAnchorPEM validates an operator-supplied trust anchor: exactly one
// CERTIFICATE block, nothing after it, parseable and not expired. It returns
// the certificate and its lowercase hex SHA-256 fingerprint.
func ParseAnchorPEM(certPEM string, now time.Time) (*x509.Certificate, string, error) {
	block, rest := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", errors.New("certificate_pem must be a PEM CERTIFICATE")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, "", errors.New("certificate_pem must contain exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", errors.New("certificate_pem does not parse as an X.509 certificate")
	}
	if now.After(cert.NotAfter) {
		return nil, "", errors.New("certificate has expired")
	}
	sum := sha256.Sum256(cert.Raw)
	return cert, hex.EncodeToString(sum[:]), nil
}
