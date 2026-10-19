// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/clientip"
)

const (
	// DefaultPerCredential is the per-credential budget per window for
	// authenticated protocol requests.
	DefaultPerCredential = 600
	// DefaultUnauthPerIP is the per-client-IP budget per window for requests
	// that carry no verified credential.
	DefaultUnauthPerIP = 30
	// IdleEvictAfter is the guarantee tested: a key idle this long does not
	// survive the next new-key insertion. The underlying Limiter sweeps once
	// per window, so in practice idle keys go much sooner.
	IdleEvictAfter = 10 * time.Minute

	maxProtocolBody = 64 << 10
	acmeAccountPath = "/acme/account/"
)

// CredentialResolver returns a rate-limit key for a credential that EXISTS
// server-side. A client-chosen id that was not verified must return ok=false,
// otherwise an attacker escapes the per-IP bucket by inventing ids.
type CredentialResolver func(r *http.Request) (key string, ok bool)

// ThrottleFunc is told about denied requests, sampled to one per key per
// minute. scope is "credential" or "ip".
type ThrottleFunc func(r *http.Request, scope, key string)

// ProtocolLimiter keys authenticated protocol requests by verified credential
// and everything else by trusted client IP, so many clients behind one NAT do
// not starve each other while unauthenticated floods stay tightly bounded.
type ProtocolLimiter struct {
	cred, ip, notify *Limiter
	resolve          CredentialResolver
	onThrottle       ThrottleFunc
	ips              *clientip.Resolver
	now              func() time.Time // injectable for tests
}

// NewProtocolLimiter builds a limiter. Limits must be positive (callers fall
// back to the defaults); a nil resolver treats every request as unauthenticated.
func NewProtocolLimiter(perCredential, unauthPerIP int, window time.Duration, resolve CredentialResolver, onThrottle ThrottleFunc) *ProtocolLimiter {
	return &ProtocolLimiter{
		cred:       New(perCredential, window),
		ip:         New(unauthPerIP, window),
		notify:     New(1, time.Minute),
		resolve:    resolve,
		onThrottle: onThrottle,
		ips:        clientip.FromEnv(),
		now:        time.Now,
	}
}

// Allow charges the request to its bucket and reports the scope and key used.
func (p *ProtocolLimiter) Allow(r *http.Request, now time.Time) (ok bool, scope, key string) {
	if p.resolve != nil {
		if k, found := p.resolve(r); found {
			return p.cred.AllowAt("c:"+k, now), "credential", k
		}
	}
	k := p.ips.ClientIP(r)
	return p.ip.AllowAt(k, now), "ip", k
}

// Middleware answers 429 exactly like Limiter.Middleware.
func (p *ProtocolLimiter) Middleware(next http.Handler) http.Handler {
	retryAfter := strconv.Itoa(int(p.cred.window.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := p.now()
		ok, scope, key := p.Allow(r, now)
		if !ok {
			if p.onThrottle != nil && p.notify.AllowAt(scope+":"+key, now) {
				p.onThrottle(r, scope, key)
			}
			w.Header().Set("Retry-After", retryAfter)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("rate limit exceeded\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ACMECredentialResolver keys a JWS-signed ACME request by the account it names
// (kid) or, for new-account, by its external-account-binding key id. Only ids
// the server confirms exist count; the body is restored for the ACME handler.
func ACMECredentialResolver(hasAccount func(id string) bool, hasEAB func(kid string) bool) CredentialResolver {
	return func(r *http.Request) (string, bool) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/jose+json") || r.Body == nil {
			return "", false
		}
		orig := r.Body
		buf, err := io.ReadAll(io.LimitReader(orig, maxProtocolBody+1))
		// Restore whatever was consumed (plus the unread rest) so the ACME
		// handler sees the full JWS even when we decline to key on it.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), orig), orig}
		if err != nil || len(buf) > maxProtocolBody {
			return "", false
		}

		var jws struct {
			Protected string `json:"protected"`
			Payload   string `json:"payload"`
		}
		if json.Unmarshal(buf, &jws) != nil {
			return "", false
		}
		var hdr struct {
			KID string `json:"kid"`
		}
		if !decodeB64JSON(jws.Protected, &hdr) {
			return "", false
		}
		if i := strings.LastIndex(hdr.KID, acmeAccountPath); i >= 0 {
			id := hdr.KID[i+len(acmeAccountPath):]
			if id != "" && hasAccount != nil && hasAccount(id) {
				return "acme-acct:" + id, true
			}
			return "", false
		}
		var payload struct {
			EAB struct {
				Protected string `json:"protected"`
			} `json:"externalAccountBinding"`
		}
		if !decodeB64JSON(jws.Payload, &payload) {
			return "", false
		}
		var eabHdr struct {
			KID string `json:"kid"`
		}
		if !decodeB64JSON(payload.EAB.Protected, &eabHdr) || eabHdr.KID == "" {
			return "", false
		}
		if hasEAB != nil && hasEAB(eabHdr.KID) {
			return "acme-eab:" + eabHdr.KID, true
		}
		return "", false
	}
}

// BasicUserResolver keys an HTTP Basic request by its username when that user
// exists server-side. The password is not checked here: an existing user with
// a wrong password only burns that user's own bucket.
func BasicUserResolver(hasUser func(name string) bool) CredentialResolver {
	return func(r *http.Request) (string, bool) {
		user, _, ok := r.BasicAuth()
		if !ok || user == "" || hasUser == nil || !hasUser(user) {
			return "", false
		}
		return "est-user:" + user, true
	}
}

func decodeB64JSON(s string, v any) bool {
	if s == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return err == nil && json.Unmarshal(raw, v) == nil
}
