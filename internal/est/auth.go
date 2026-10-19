// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

// EST authentication (W20-14, D-112). RFC 7030 3.2.3 and 3.3.2 allow two
// client credentials and the hub accepts both:
//
//   - HTTP Basic over TLS, against a configured user list. Each user may
//     enroll only names under its own DNS suffixes: the CSR's CN and DNS
//     SANs must all match, nothing else may be requested, and the subject
//     is reduced to that CN.
//   - A TLS client certificate that chains to an operator-configured trust
//     anchor (for example a device manufacturer CA). The new certificate
//     takes the presented certificate's subject and DNS SANs; the CSR only
//     proves the key.
//
// Re-enrollment needs a certificate this hub issued (ca.CheckHubClientCertificate,
// shared with WSTEP renewal) and keeps its subject and SANs.

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/ca"
)

// User is one HTTP Basic credential.
type User struct {
	Username           string   `json:"username"`
	BcryptHash         string   `json:"bcrypt_hash"`
	AllowedDNSSuffixes []string `json:"allowed_dns_suffixes"`
	// Disabled is set only by a UserSource that reports a disabled user, so
	// the audit row can say why; file users are never disabled.
	Disabled bool `json:"-"`
}

// LoadUsersFile reads a JSON array of User. Hashes are bcrypt (for example
// `htpasswd -nbB user pass`, the part after the colon).
func LoadUsersFile(path string) ([]User, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return users, nil
}

// AuditEvent is one EST authentication outcome.
type AuditEvent struct {
	Action   string // "est.enroll", "est.enroll.failure" or "est.reenroll"
	Actor    string // Basic username or certificate subject; empty when unknown
	Outcome  string // "success" or "denied"
	SourceIP string
	Detail   string
}

// AuditFunc records an AuditEvent; main adapts it to the hub's audit log.
type AuditFunc func(ctx context.Context, ev AuditEvent)

// identity is who an enrollment is for, from the credential, never the CSR.
type identity struct {
	method   string // "basic" or "certificate"
	actor    string
	subject  pkix.Name
	dnsNames []string
}

// dummyHash makes an unknown username cost the same bcrypt work as a known
// one, so response timing does not reveal which usernames exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("kryptkeeper-est-dummy"), bcrypt.DefaultCost)

// WithBasicUsers enables HTTP Basic enrollment for users. Every user needs a
// bcrypt hash and at least one DNS suffix, each starting with "." so a
// suffix can only ever match whole labels.
func (s *Server) WithBasicUsers(users []User) error {
	m := make(map[string]User, len(users))
	for _, u := range users {
		if u.Username == "" {
			return errors.New("est user with an empty username")
		}
		if _, err := bcrypt.Cost([]byte(u.BcryptHash)); err != nil {
			return fmt.Errorf("est user %q: bcrypt_hash: %w", u.Username, err)
		}
		if len(u.AllowedDNSSuffixes) == 0 {
			return fmt.Errorf("est user %q: allowed_dns_suffixes is empty", u.Username)
		}
		norm, err := ValidateSuffixes(u.AllowedDNSSuffixes)
		if err != nil {
			return fmt.Errorf("est user %q: %w", u.Username, err)
		}
		copy(u.AllowedDNSSuffixes, norm) // normalise in place, as callers have always seen
		if _, dup := m[u.Username]; dup {
			return fmt.Errorf("est user %q listed twice", u.Username)
		}
		m[u.Username] = u
	}
	s.users = m
	return nil
}

// ValidateSuffixes lower-cases and checks DNS suffixes: at least one, each
// starting with "." (so it can only match whole labels) and without a
// wildcard. It returns the normalised copy.
func ValidateSuffixes(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("allowed_dns_suffixes is empty")
	}
	out := make([]string, len(in))
	for i, sfx := range in {
		n := strings.ToLower(strings.TrimSpace(sfx))
		if len(n) < 2 || !strings.HasPrefix(n, ".") || strings.Contains(n, "*") {
			return nil, fmt.Errorf("suffix %q must look like .devices.example.com", sfx)
		}
		out[i] = n
	}
	return out, nil
}

// UserSource supplies Basic users beyond the users file (W26-07). ok is
// false for an unknown user and for a disabled one (which may come back with
// Disabled set, for the audit row only). An error means the source could not
// answer: enrollment then fails closed.
type UserSource interface {
	LookupUser(ctx context.Context, username string) (u User, ok bool, err error)
}

// WithUserSource adds src as a second place to look up Basic users. A user
// in the users file wins over one of the same name in src.
func (s *Server) WithUserSource(src UserSource) *Server {
	s.userSource = src
	return s
}

// HasFileUser reports whether the users file defines name.
func (s *Server) HasFileUser(name string) bool {
	_, ok := s.users[name]
	return ok
}

// AlertFunc receives an operational alert; main adapts it to the audit log.
type AlertFunc func(ctx context.Context, kind string, detail map[string]string)

// WithAlertFunc sets where alerts (repeated Basic failures) go.
func (s *Server) WithAlertFunc(fn AlertFunc) *Server {
	s.alert = fn
	return s
}

// WithClientCertAnchors enables enrollment by TLS client certificates that
// chain to roots. The listener must request client certificates
// (KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT) for any to arrive.
func (s *Server) WithClientCertAnchors(roots *x509.CertPool) *Server {
	s.clientRoots = roots
	return s
}

// WithReenrollment enables simplereenroll for certificates this CA issued,
// checked against rev for revocation.
func (s *Server) WithReenrollment(rev ca.RevocationChecker) *Server {
	s.revocation = rev
	return s
}

// WithAuditFunc records enrollment outcomes.
func (s *Server) WithAuditFunc(fn AuditFunc) *Server {
	s.audit = fn
	return s
}

// EnrollmentConfigured reports whether any enrollment credential is set up.
func (s *Server) EnrollmentConfigured() bool {
	return len(s.users) > 0 || s.userSource != nil || s.clientRoots != nil
}

func (s *Server) emit(r *http.Request, ev AuditEvent) {
	if s.audit == nil {
		return
	}
	ev.SourceIP = remoteHost(r)
	s.audit(r.Context(), ev)
}

func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// denyBasic answers the one 401 every failed Basic attempt gets: unknown,
// disabled and wrong password are indistinguishable to the client.
func (s *Server) denyBasic(w http.ResponseWriter, r *http.Request, user, detail string) {
	s.emit(r, AuditEvent{Action: "est.enroll.failure", Actor: user, Outcome: "denied", Detail: detail})
	s.noteBasicFailure(r, user)
	w.Header().Set("WWW-Authenticate", `Basic realm="est"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// noteBasicFailure counts a failed Basic attempt and raises the alert once
// when a username crosses the per-minute limit.
func (s *Server) noteBasicFailure(r *http.Request, user string) {
	if s.alert == nil {
		return
	}
	if n, fire := s.failures.record(user, s.now()); fire {
		s.alert(r.Context(), "est.basic.failures", map[string]string{
			"user": truncate(user, failureKeyMax), "count": strconv.Itoa(n), "source_ip": remoteHost(r),
		})
	}
}

// authenticateEnroll establishes the identity for simpleenroll, or writes
// the refusal and returns false. csr is needed only to check a Basic user's
// requested names.
func (s *Server) authenticateEnroll(w http.ResponseWriter, r *http.Request, csr *x509.CertificateRequest) (identity, bool) {
	// RFC 7030 3.2.3: credentials only over TLS. A plaintext request is
	// refused before its Authorization header is read, and is not
	// challenged, so no client is invited to send a password in the clear.
	if r.TLS == nil {
		http.Error(w, "EST requires TLS", http.StatusForbidden)
		return identity{}, false
	}

	// A client certificate that chains to a configured anchor is the
	// credential. One that does not is ignored, not refused: clients may
	// offer unrelated certificates, and Basic may still follow.
	if s.clientRoots != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range r.TLS.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: s.clientRoots, Intermediates: inter, CurrentTime: s.now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err == nil {
			return identity{method: "certificate", actor: leaf.Subject.String(), subject: leaf.Subject, dnsNames: leaf.DNSNames}, true
		}
	}

	if len(s.users) == 0 && s.userSource == nil {
		http.Error(w, "EST enrollment requires a client certificate from a trusted issuer", http.StatusUnauthorized)
		return identity{}, false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		// The bare challenge starts every Basic exchange: not audited.
		w.Header().Set("WWW-Authenticate", `Basic realm="est"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return identity{}, false
	}
	u, known := s.users[user]
	if !known && s.userSource != nil {
		var err error
		if u, known, err = s.userSource.LookupUser(r.Context(), user); err != nil {
			// Fail closed: never fall through to "unknown user".
			logging.Infof("est basic user lookup: %v", err)
			s.emit(r, AuditEvent{Action: "est.enroll.failure", Actor: user, Outcome: "failure", Detail: "user lookup unavailable"})
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return identity{}, false
		}
	}
	hash := dummyHash
	if known || u.BcryptHash != "" {
		hash = []byte(u.BcryptHash)
	}
	pwErr := bcrypt.CompareHashAndPassword(hash, []byte(pass))
	if pwErr != nil || !known {
		detail := "invalid credentials"
		if u.Disabled {
			detail = "user disabled"
		}
		s.denyBasic(w, r, user, detail)
		return identity{}, false
	}
	id, err := basicIdentity(u, csr)
	if err != nil {
		s.emit(r, AuditEvent{Action: "est.enroll.failure", Actor: user, Outcome: "denied", Detail: err.Error()})
		http.Error(w, "enrollment refused: "+err.Error(), http.StatusForbidden)
		return identity{}, false
	}
	return id, true
}

// basicIdentity binds a Basic user's request to the names it may hold: the
// CSR's CN and DNS SANs, every one under one of the user's suffixes, and
// nothing else.
func basicIdentity(u User, csr *x509.CertificateRequest) (identity, error) {
	if csr == nil { // csrattrs authenticates before any CSR exists
		return identity{method: "basic", actor: u.Username}, nil
	}
	if len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) > 0 {
		return identity{}, errors.New("only DNS names may be requested")
	}
	cn := strings.ToLower(strings.TrimSpace(csr.Subject.CommonName))
	names := make([]string, 0, len(csr.DNSNames))
	for _, n := range csr.DNSNames {
		names = append(names, strings.ToLower(strings.TrimSpace(n)))
	}
	if cn == "" && len(names) == 0 {
		return identity{}, errors.New("the request names nothing")
	}
	check := names
	if cn != "" {
		check = append([]string{cn}, names...)
	}
	for _, n := range check {
		if !nameAllowed(n, u.AllowedDNSSuffixes) {
			return identity{}, fmt.Errorf("%q is not under an allowed suffix for %s", n, u.Username)
		}
	}
	if cn == "" {
		cn = names[0]
	}
	return identity{method: "basic", actor: u.Username, subject: pkix.Name{CommonName: cn}, dnsNames: names}, nil
}

// nameAllowed reports whether name is a hostname strictly below one of
// suffixes (each starting with "."): ".devices.corp" admits a.devices.corp,
// not devices.corp or evildevices.corp.
func nameAllowed(name string, suffixes []string) bool {
	if name == "" || strings.ContainsAny(name, "* /") {
		return false
	}
	for _, sfx := range suffixes {
		label, ok := strings.CutSuffix(name, sfx)
		if ok && label != "" && !strings.HasPrefix(label, ".") && !strings.HasSuffix(label, ".") && !strings.Contains(label, "..") {
			return true
		}
	}
	return false
}

// Failed-Basic alerting (W26-07): the 11th failed attempt for one username
// inside a minute raises one alert for that window.
const (
	failureLimit   = 10
	failureWindowD = time.Minute
	failureKeyMax  = 128
	failureMaxKeys = 10000
)

type failureEntry struct {
	key     string
	start   time.Time
	count   int
	alerted bool
}

// failureWindow is a fixed-window counter per username. Keys are
// attacker-chosen, so it holds at most failureMaxKeys, evicting the oldest.
// The zero value is ready to use.
type failureWindow struct {
	mu    sync.Mutex
	byKey map[string]*list.Element
	order *list.List // front = oldest-inserted
	max   int        // 0 means failureMaxKeys; tests lower it
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// record counts one failure for user at now and returns the count and
// whether this failure is the one that should raise the alert.
func (f *failureWindow) record(user string, now time.Time) (count int, fire bool) {
	key := truncate(user, failureKeyMax)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byKey == nil {
		f.byKey, f.order = map[string]*list.Element{}, list.New()
	}
	limit := f.max
	if limit == 0 {
		limit = failureMaxKeys
	}
	el, ok := f.byKey[key]
	if !ok {
		for f.order.Len() >= limit {
			oldest := f.order.Front()
			delete(f.byKey, oldest.Value.(*failureEntry).key)
			f.order.Remove(oldest)
		}
		el = f.order.PushBack(&failureEntry{key: key, start: now})
		f.byKey[key] = el
	}
	e := el.Value.(*failureEntry)
	if now.Sub(e.start) >= failureWindowD {
		e.start, e.count, e.alerted = now, 0, false
	}
	e.count++
	if e.count > failureLimit && !e.alerted {
		e.alerted = true
		return e.count, true
	}
	return e.count, false
}

// ErrUserExists and ErrUserNotFound are the DBUserStore's lookup outcomes.
var (
	ErrUserExists   = errors.New("est user already exists")
	ErrUserNotFound = errors.New("est user not found")
)

// StoredUser is an API-managed Basic user. The hash is never serialised.
type StoredUser struct {
	Username           string     `json:"username"`
	BcryptHash         string     `json:"-"`
	AllowedDNSSuffixes []string   `json:"allowed_dns_suffixes"`
	Disabled           bool       `json:"disabled"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	PasswordRotatedAt  *time.Time `json:"password_rotated_at"`
}

// NewUserPassword returns a fresh random password (18 bytes, base64url, 24
// characters) and its bcrypt hash. The server chooses it so an admin cannot
// pick a weak one.
func NewUserPassword() (password, hash string, err error) {
	b := make([]byte, 18)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	password = base64.RawURLEncoding.EncodeToString(b)
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return password, string(h), nil
}

const userTimeLayout = time.RFC3339

// DBUserStore keeps API-managed users in est_users (migration 000182). It is
// the Server's UserSource.
type DBUserStore struct {
	db       *sql.DB
	postgres bool
}

// NewDBUserStore returns a store on db.
func NewDBUserStore(db *sql.DB, postgres bool) *DBUserStore {
	return &DBUserStore{db: db, postgres: postgres}
}

func (s *DBUserStore) q(query string) string {
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

// EnsureSchema creates est_users when migrations have not (same DDL as 000182).
func (s *DBUserStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS est_users (
  username TEXT PRIMARY KEY, bcrypt_hash TEXT NOT NULL, allowed_dns_suffixes TEXT NOT NULL DEFAULT '[]',
  disabled INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, password_rotated_at TEXT)`)
	return err
}

const userCols = `username, bcrypt_hash, allowed_dns_suffixes, disabled, created_by, created_at, updated_at, password_rotated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(sc rowScanner) (StoredUser, error) {
	var (
		u                StoredUser
		suffixes         string
		disabled         int
		created, updated string
		rotated          sql.NullString
	)
	if err := sc.Scan(&u.Username, &u.BcryptHash, &suffixes, &disabled, &u.CreatedBy, &created, &updated, &rotated); err != nil {
		return StoredUser{}, err
	}
	if err := json.Unmarshal([]byte(suffixes), &u.AllowedDNSSuffixes); err != nil {
		return StoredUser{}, fmt.Errorf("est user %q: allowed_dns_suffixes: %w", u.Username, err)
	}
	u.Disabled = disabled != 0
	var err error
	if u.CreatedAt, err = time.Parse(userTimeLayout, created); err != nil {
		return StoredUser{}, err
	}
	if u.UpdatedAt, err = time.Parse(userTimeLayout, updated); err != nil {
		return StoredUser{}, err
	}
	if rotated.Valid {
		t, err := time.Parse(userTimeLayout, rotated.String)
		if err != nil {
			return StoredUser{}, err
		}
		u.PasswordRotatedAt = &t
	}
	return u, nil
}

// Create stores u (Username, BcryptHash, AllowedDNSSuffixes, CreatedBy set).
func (s *DBUserStore) Create(ctx context.Context, u StoredUser) (StoredUser, error) {
	now := time.Now().UTC().Truncate(time.Second)
	u.CreatedAt, u.UpdatedAt, u.Disabled, u.PasswordRotatedAt = now, now, false, nil
	if u.AllowedDNSSuffixes == nil {
		u.AllowedDNSSuffixes = []string{}
	}
	raw, err := json.Marshal(u.AllowedDNSSuffixes)
	if err != nil {
		return StoredUser{}, err
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO est_users
		(username, bcrypt_hash, allowed_dns_suffixes, disabled, created_by, created_at, updated_at)
		VALUES (?, ?, ?, 0, ?, ?, ?)`),
		u.Username, u.BcryptHash, string(raw), u.CreatedBy, now.Format(userTimeLayout), now.Format(userTimeLayout))
	if err != nil {
		if _, getErr := s.Get(ctx, u.Username); getErr == nil {
			return StoredUser{}, ErrUserExists
		}
		return StoredUser{}, fmt.Errorf("store est user: %w", err)
	}
	return u, nil
}

// Get returns one user, or ErrUserNotFound.
func (s *DBUserStore) Get(ctx context.Context, username string) (StoredUser, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM est_users WHERE username = ?`), username))
	if errors.Is(err, sql.ErrNoRows) {
		return StoredUser{}, ErrUserNotFound
	}
	return u, err
}

// List returns every user, ordered by username.
func (s *DBUserStore) List(ctx context.Context) ([]StoredUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM est_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []StoredUser{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Update changes the fields that are non-nil and returns the user.
func (s *DBUserStore) Update(ctx context.Context, username string, disabled *bool, suffixes []string) (StoredUser, error) {
	u, err := s.Get(ctx, username)
	if err != nil {
		return StoredUser{}, err
	}
	if disabled != nil {
		u.Disabled = *disabled
	}
	if suffixes != nil {
		u.AllowedDNSSuffixes = suffixes
	}
	raw, err := json.Marshal(u.AllowedDNSSuffixes)
	if err != nil {
		return StoredUser{}, err
	}
	d := 0
	if u.Disabled {
		d = 1
	}
	u.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if _, err := s.db.ExecContext(ctx, s.q(`UPDATE est_users SET disabled = ?, allowed_dns_suffixes = ?, updated_at = ? WHERE username = ?`),
		d, string(raw), u.UpdatedAt.Format(userTimeLayout), username); err != nil {
		return StoredUser{}, err
	}
	return u, nil
}

// SetPassword replaces the user's hash and stamps the rotation.
func (s *DBUserStore) SetPassword(ctx context.Context, username, bcryptHash string) error {
	now := time.Now().UTC().Truncate(time.Second).Format(userTimeLayout)
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE est_users SET bcrypt_hash = ?, password_rotated_at = ?, updated_at = ? WHERE username = ?`),
		bcryptHash, now, now, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Delete removes a user.
func (s *DBUserStore) Delete(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM est_users WHERE username = ?`), username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// LookupUser implements UserSource. A disabled user is ok=false, returned
// with Disabled set so the audit row can say so.
func (s *DBUserStore) LookupUser(ctx context.Context, username string) (User, bool, error) {
	u, err := s.Get(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	out := User{Username: u.Username, BcryptHash: u.BcryptHash, AllowedDNSSuffixes: u.AllowedDNSSuffixes, Disabled: u.Disabled}
	return out, !u.Disabled, nil
}
