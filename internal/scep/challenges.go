// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

// One-time enrollment challenges (W20-16, D-121). An operator mints a
// challenge through the authenticated API for one device's names; the
// device puts it in its CSR's challengePassword; the hub consumes it once
// and issues exactly the names it was minted for. The CSR only proves the
// key. Only the challenge's SHA-256 is stored: the plaintext is returned
// once, by Create, and never logged or audited.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Challenge is a minted enrollment challenge, without its secret.
type Challenge struct {
	ID         string     `json:"id"`
	CAID       string     `json:"ca_id"`
	CommonName string     `json:"common_name"`
	DNSNames   []string   `json:"dns_names"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
}

var (
	// ErrChallengeUnknown means no challenge has that secret.
	ErrChallengeUnknown = errors.New("challenge unknown")
	// ErrChallengeUsed means the challenge was already consumed.
	ErrChallengeUsed = errors.New("challenge already used")
	// ErrChallengeExpired means the challenge outlived its expiry.
	ErrChallengeExpired = errors.New("challenge expired")
	// ErrChallengeNotFound means no unused challenge has that ID.
	ErrChallengeNotFound = errors.New("challenge not found or already used")
)

// ChallengeStore persists one-time challenges.
type ChallengeStore interface {
	// Create stores c and returns it with its ID and the plaintext secret.
	Create(ctx context.Context, c Challenge) (Challenge, string, error)
	// Consume marks the challenge with this secret used, atomically, and
	// returns it. Exactly one of any number of concurrent calls succeeds.
	Consume(ctx context.Context, secret string, now time.Time) (Challenge, error)
	List(ctx context.Context) ([]Challenge, error)
	// Delete removes an unused challenge.
	Delete(ctx context.Context, id string) error
}

const timeLayout = "2006-01-02T15:04:05Z" // fixed width, UTC: compares as text

// DBChallengeStore keeps challenges in the scep_challenges table (000066).
type DBChallengeStore struct {
	db       *sql.DB
	postgres bool
}

// NewDBChallengeStore returns a store on db, which must carry migration 000066.
func NewDBChallengeStore(db *sql.DB, postgres bool) *DBChallengeStore {
	return &DBChallengeStore{db: db, postgres: postgres}
}

func (s *DBChallengeStore) q(query string) string {
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

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create stores c. The secret is 32 random bytes in hex: hex fits the
// PrintableString encoding some clients use for challengePassword.
func (s *DBChallengeStore) Create(ctx context.Context, c Challenge) (Challenge, string, error) {
	secret, err := randomHex(32)
	if err != nil {
		return Challenge{}, "", err
	}
	id, err := randomHex(8)
	if err != nil {
		return Challenge{}, "", err
	}
	c.ID = "scepch-" + id
	c.CreatedAt = c.CreatedAt.UTC().Truncate(time.Second)
	c.ExpiresAt = c.ExpiresAt.UTC().Truncate(time.Second)
	c.UsedAt = nil
	if c.DNSNames == nil {
		c.DNSNames = []string{}
	}
	names, err := json.Marshal(c.DNSNames)
	if err != nil {
		return Challenge{}, "", err
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO scep_challenges
		(id, challenge_sha256, ca_id, common_name, dns_names, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		c.ID, hashSecret(secret), c.CAID, c.CommonName, string(names), c.CreatedBy,
		c.CreatedAt.Format(timeLayout), c.ExpiresAt.Format(timeLayout))
	if err != nil {
		return Challenge{}, "", fmt.Errorf("store scep challenge: %w", err)
	}
	return c, secret, nil
}

// Consume claims the challenge in one UPDATE, so two concurrent requests
// with the same secret cannot both succeed; the reason for a refusal is
// looked up afterwards, for the audit row only.
func (s *DBChallengeStore) Consume(ctx context.Context, secret string, now time.Time) (Challenge, error) {
	h := hashSecret(secret)
	nowText := now.UTC().Format(timeLayout)
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE scep_challenges SET used_at = ?
		WHERE challenge_sha256 = ? AND used_at IS NULL AND expires_at > ?`), nowText, h, nowText)
	if err != nil {
		return Challenge{}, fmt.Errorf("consume scep challenge: %w", err)
	}
	claimed, err := res.RowsAffected()
	if err != nil {
		return Challenge{}, err
	}
	c, found, err := s.getByHash(ctx, h)
	if err != nil {
		return Challenge{}, err
	}
	switch {
	case !found:
		return Challenge{}, ErrChallengeUnknown
	case claimed == 1:
		return c, nil
	case c.UsedAt != nil:
		return Challenge{}, ErrChallengeUsed
	default:
		return Challenge{}, ErrChallengeExpired
	}
}

const selectColumns = `id, ca_id, common_name, dns_names, created_by, created_at, expires_at, used_at`

type rowScanner interface{ Scan(...any) error }

func scanChallenge(row rowScanner) (Challenge, error) {
	var c Challenge
	var names, created, expires string
	var used sql.NullString
	if err := row.Scan(&c.ID, &c.CAID, &c.CommonName, &names, &c.CreatedBy, &created, &expires, &used); err != nil {
		return Challenge{}, err
	}
	if err := json.Unmarshal([]byte(names), &c.DNSNames); err != nil {
		return Challenge{}, fmt.Errorf("scep challenge %s: dns_names: %w", c.ID, err)
	}
	var err error
	if c.CreatedAt, err = time.Parse(timeLayout, created); err != nil {
		return Challenge{}, err
	}
	if c.ExpiresAt, err = time.Parse(timeLayout, expires); err != nil {
		return Challenge{}, err
	}
	if used.Valid {
		t, err := time.Parse(timeLayout, used.String)
		if err != nil {
			return Challenge{}, err
		}
		c.UsedAt = &t
	}
	return c, nil
}

func (s *DBChallengeStore) getByHash(ctx context.Context, h string) (Challenge, bool, error) {
	c, err := scanChallenge(s.db.QueryRowContext(ctx, s.q(`SELECT `+selectColumns+` FROM scep_challenges WHERE challenge_sha256 = ?`), h))
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, err
	}
	return c, true, nil
}

// List returns every challenge, newest first.
func (s *DBChallengeStore) List(ctx context.Context) ([]Challenge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+selectColumns+` FROM scep_challenges ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Challenge{}
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Delete removes an unused challenge; a used one stays as a record.
func (s *DBChallengeStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM scep_challenges WHERE id = ? AND used_at IS NULL`), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrChallengeNotFound
	}
	return nil
}
