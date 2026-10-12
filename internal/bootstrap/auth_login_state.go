// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// loginKDFConcurrency caps simultaneous Argon2id runs (further capped to
	// GOMAXPROCS). /api/v1/auth/login is unauthenticated and per-IP limited,
	// so without a cap many distinct sources could pin loginArgonMemKiB each,
	// all at once. 4 x 19 MiB bounds the transient KDF memory at about 76 MiB.
	loginKDFConcurrency = 4

	// Per-account login backoff (A07-8), on top of the per-IP limit. The first
	// loginBackoffThreshold-1 failures are free; from the threshold on, each
	// further failure doubles the lockout from loginBackoffBase up to
	// loginBackoffMax. A lockout answers exactly like a wrong password, and
	// the account key is whatever email was submitted, so nothing reveals
	// whether the account exists. The price is that someone who knows the
	// admin's address can keep that account locked for up to loginBackoffMax
	// at a time; the per-IP limit still bounds how fast they can do it.
	loginBackoffThreshold  = 5
	loginBackoffBase       = 15 * time.Second
	loginBackoffMax        = 5 * time.Minute
	loginBackoffDecay      = 15 * time.Minute
	maxLoginBackoffEntries = 10000
)

type loginFailure struct {
	count       int
	lockedUntil time.Time
	lastFail    time.Time
}

// loginHardeningState is the login-flow state Authenticator keeps outside its
// immutable config. The zero value is ready to use, which the many tests that
// build an Authenticator literal rely on.
type loginHardeningState struct {
	hashMu       sync.RWMutex
	upgradedHash string

	kdfOnce  sync.Once
	kdfSlots chan struct{}

	backoffMu sync.Mutex
	backoff   map[string]*loginFailure
}

// authHardeningState groups the FG-7 session/login state on Authenticator.
type authHardeningState struct {
	login loginHardeningState
	saml  samlGuardState
}

// loginPasswordHash is the verifier Login checks: the in-memory Argon2id
// upgrade of a legacy hash if one has happened, else the configured value.
func (a *Authenticator) loginPasswordHash() string {
	a.hardening.login.hashMu.RLock()
	upgraded := a.hardening.login.upgradedHash
	a.hardening.login.hashMu.RUnlock()
	if upgraded != "" {
		return upgraded
	}
	return strings.TrimSpace(a.config.loginUser.PasswordHash)
}

func (a *Authenticator) kdfSlot() chan struct{} {
	s := &a.hardening.login
	s.kdfOnce.Do(func() {
		s.kdfSlots = make(chan struct{}, min(loginKDFConcurrency, max(1, runtime.GOMAXPROCS(0))))
	})
	return s.kdfSlots
}

// withKDFSlot runs fn while holding one KDF slot. It returns ctx.Err() without
// running fn if the caller gives up (client disconnect) while queued, so
// waiters do not pile up behind a login flood.
func (a *Authenticator) withKDFSlot(ctx context.Context, fn func()) error {
	slots := a.kdfSlot()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-slots }()
	fn()
	return nil
}

// verifyLoginPasswordLimited is verifyLoginPassword under the KDF slot cap.
func (a *Authenticator) verifyLoginPasswordLimited(ctx context.Context, password, pepper, stored string) (ok, legacy bool, err error) {
	err = a.withKDFSlot(ctx, func() { ok, legacy = verifyLoginPassword(password, pepper, stored) })
	return ok, legacy, err
}

// upgradeLegacyLoginHash replaces a legacy HMAC verifier with an Argon2id one
// for the rest of this process. The configured value comes from the
// environment, which the hub cannot rewrite, so the operator still has to
// persist a new hash (kryptkeeper --hash-password); the warning says so.
func (a *Authenticator) upgradeLegacyLoginHash(password, pepper string) {
	hash, err := HashLoginPassword(password, pepper)
	if err != nil {
		log.Printf("warning: could not upgrade legacy login password hash: %v", err)
		return
	}
	s := &a.hardening.login
	s.hashMu.Lock()
	first := s.upgradedHash == ""
	s.upgradedHash = hash
	s.hashMu.Unlock()
	if first {
		log.Print("warning: APP_AUTH_LOGIN_PASSWORD_HASH is a legacy HMAC-SHA256 verifier; " +
			"upgraded to Argon2id in memory for this process only. Generate a persistent one with " +
			"`kryptkeeper --hash-password` and set APP_AUTH_LOGIN_PASSWORD_HASH to it")
	}
}

func loginAccountKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:8])
}

// loginLockedOut reports whether key is inside a backoff window.
func (a *Authenticator) loginLockedOut(key string, now time.Time) bool {
	s := &a.hardening.login
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	f := s.backoff[key]
	return f != nil && now.Before(f.lockedUntil)
}

func (a *Authenticator) recordLoginFailure(key string, now time.Time) {
	s := &a.hardening.login
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	if s.backoff == nil {
		s.backoff = map[string]*loginFailure{}
	}
	f := s.backoff[key]
	if f != nil && now.Sub(f.lastFail) > loginBackoffDecay {
		f = nil
	}
	if f == nil {
		if len(s.backoff) >= maxLoginBackoffEntries {
			s.evictLoginBackoffLocked(now)
		}
		f = &loginFailure{}
		s.backoff[key] = f
	}
	f.count++
	f.lastFail = now
	if f.count >= loginBackoffThreshold {
		delay := loginBackoffBase
		for i := loginBackoffThreshold; i < f.count && delay < loginBackoffMax; i++ {
			delay *= 2
		}
		f.lockedUntil = now.Add(min(delay, loginBackoffMax))
	}
}

// evictLoginBackoffLocked frees room for a new account: first everything
// whose window and decay are over, and if the table is still full (a flood of
// distinct addresses) the stalest entry.
func (s *loginHardeningState) evictLoginBackoffLocked(now time.Time) {
	var stalest string
	var stalestAt time.Time
	for k, f := range s.backoff {
		if now.Sub(f.lastFail) > loginBackoffDecay && !now.Before(f.lockedUntil) {
			delete(s.backoff, k)
			continue
		}
		if stalest == "" || f.lastFail.Before(stalestAt) {
			stalest, stalestAt = k, f.lastFail
		}
	}
	if len(s.backoff) >= maxLoginBackoffEntries && stalest != "" {
		delete(s.backoff, stalest)
	}
}

func (a *Authenticator) clearLoginFailures(key string) {
	s := &a.hardening.login
	s.backoffMu.Lock()
	delete(s.backoff, key)
	s.backoffMu.Unlock()
}
