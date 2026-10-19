// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package teams implements the Microsoft Teams (Azure Bot Service) side of
// chatops approvals: Bot Framework JWT validation, activity parsing, the
// adaptive approval card and a poster for the owner-team channel.
package teams

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/notifications/chatops"
)

// ErrInvalidToken is the only validation failure surfaced: callers learn
// nothing about which check failed.
var ErrInvalidToken = errors.New("teams: invalid token")

const (
	// BotFrameworkIssuer is the iss claim of tokens the Bot Connector sends.
	BotFrameworkIssuer = "https://api.botframework.com"
	// BotFrameworkJWKSURL publishes the Bot Connector signing keys.
	BotFrameworkJWKSURL = "https://login.botframework.com/v1/.well-known/keys"

	minRSAKeyBits  = 2048
	jwksTTL        = 24 * time.Hour
	jwksMinRefresh = time.Minute
	maxJWKSBytes   = 1 << 20
)

// Validator checks the Authorization header of an inbound Bot Framework call.
type Validator struct {
	AppID  string // expected aud; empty fails closed
	Issuer string // defaults to BotFrameworkIssuer
	// JWKS returns the cached JWKS document JSON.
	JWKS func(ctx context.Context) (string, error)
	// Refresh forces a refetch (rate limited by its implementation). Used once
	// when the token's kid is not in the cached set. May be nil.
	Refresh func(ctx context.Context) (string, error)
	Now     func() time.Time
}

type jwk struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var errNoKey = errors.New("teams: kid not found")

// Validate accepts "Bearer <jwt>" and requires: 3 segments, alg RS256 (checked
// before any key lookup, so none/HS* never reach key material), a kid, a
// signature verifying under that JWKS RSA key (>= 2048 bits), iss == Issuer,
// aud == AppID, exp and nbf within chatops.MaxSkew of now, and a serviceurl
// claim exactly equal to serviceURL.
func (v *Validator) Validate(ctx context.Context, authorization string, serviceURL string) error {
	if v.AppID == "" || serviceURL == "" {
		return ErrInvalidToken
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ErrInvalidToken
	}
	segs := strings.Split(strings.TrimSpace(tok), ".")
	if len(segs) != 3 {
		return ErrInvalidToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if !decodeSegment(segs[0], &hdr) || hdr.Alg != "RS256" || hdr.Kid == "" {
		return ErrInvalidToken
	}
	var claims struct {
		Iss        string          `json:"iss"`
		Aud        json.RawMessage `json:"aud"`
		Exp        *float64        `json:"exp"`
		Nbf        *float64        `json:"nbf"`
		ServiceURL string          `json:"serviceurl"`
	}
	if !decodeSegment(segs[1], &claims) {
		return ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil || len(sig) == 0 {
		return ErrInvalidToken
	}
	key, err := v.resolveKey(ctx, hdr.Kid)
	if err != nil {
		return ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(segs[0] + "." + segs[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return ErrInvalidToken
	}
	// Claims are only trusted after the signature verified.
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if claims.Exp == nil || now.After(time.Unix(int64(*claims.Exp), 0).Add(chatops.MaxSkew)) {
		return ErrInvalidToken
	}
	if claims.Nbf != nil && now.Before(time.Unix(int64(*claims.Nbf), 0).Add(-chatops.MaxSkew)) {
		return ErrInvalidToken
	}
	issuer := v.Issuer
	if issuer == "" {
		issuer = BotFrameworkIssuer
	}
	if claims.Iss != issuer || !audMatches(claims.Aud, v.AppID) || claims.ServiceURL != serviceURL {
		return ErrInvalidToken
	}
	return nil
}

func decodeSegment(seg string, out any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	return err == nil && json.Unmarshal(raw, out) == nil
}

func audMatches(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

func (v *Validator) resolveKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if v.JWKS == nil {
		return nil, errNoKey
	}
	doc, err := v.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	key, err := rsaKeyByKID(doc, kid)
	if errors.Is(err, errNoKey) && v.Refresh != nil {
		if doc, err = v.Refresh(ctx); err != nil {
			return nil, err
		}
		return rsaKeyByKID(doc, kid)
	}
	return key, err
}

func rsaKeyByKID(doc, kid string) (*rsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal([]byte(doc), &set); err != nil {
		return nil, err
	}
	for _, k := range set.Keys {
		if k.KID != kid {
			continue
		}
		if k.KTY != "RSA" {
			return nil, errors.New("teams: jwks key is not rsa")
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(nb) == 0 {
			return nil, errors.New("teams: bad modulus")
		}
		n := new(big.Int).SetBytes(nb)
		if n.BitLen() < minRSAKeyBits {
			return nil, errors.New("teams: rsa key too small")
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(eb) == 0 || len(eb) > 4 {
			return nil, errors.New("teams: bad exponent")
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e < 3 || e%2 == 0 {
			return nil, errors.New("teams: bad exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	}
	return nil, errNoKey
}

// JWKSCache fetches the Bot Connector JWKS through the egress client, caches
// it for 24h and refetches at most once a minute when asked to.
type JWKSCache struct {
	URL  string
	HTTP *http.Client
	Now  func() time.Time

	mu      sync.Mutex
	doc     string
	fetched time.Time
	tried   time.Time
}

// NewJWKSCache returns a cache for the public Bot Framework key set.
func NewJWKSCache() *JWKSCache { return &JWKSCache{URL: BotFrameworkJWKSURL} }

func (c *JWKSCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Get returns the cached document, fetching when empty or older than 24h.
func (c *JWKSCache) Get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.doc != "" && c.now().Sub(c.fetched) < jwksTTL {
		return c.doc, nil
	}
	return c.fetchLocked(ctx)
}

// Refresh refetches unless a fetch was attempted within the last minute, in
// which case the cached document is returned unchanged.
func (c *JWKSCache) Refresh(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.doc != "" && c.now().Sub(c.tried) < jwksMinRefresh {
		return c.doc, nil
	}
	return c.fetchLocked(ctx)
}

func (c *JWKSCache) fetchLocked(ctx context.Context) (string, error) {
	c.tried = c.now()
	cl := c.HTTP
	if cl == nil {
		cl = newHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return c.doc, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return c.doc, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.doc, errors.New("teams: jwks fetch failed")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return c.doc, err
	}
	c.doc, c.fetched = string(b), c.now()
	return c.doc, nil
}

// NewValidator builds a Validator backed by the public Bot Framework key set.
// AppID is left empty: the caller sets it per request from configuration.
func NewValidator() *Validator {
	c := NewJWKSCache()
	return &Validator{Issuer: BotFrameworkIssuer, JWKS: c.Get, Refresh: c.Refresh}
}

func newHTTPClient() *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               10 * time.Second,
	}))
}
