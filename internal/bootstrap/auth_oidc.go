// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"kryptkeeper/internal/egress"
)

var errJWKSKeyNotFound = errors.New("jwks key not found")

// oidcRuntimeClient is the client for the runtime IdP calls (discovery, JWKS,
// token exchange). The save-time probe was already guarded, but these run
// later against names the IdP controls, so they get the same dial-time address
// policy: a host that rebinds to link-local/metadata after the probe, or an
// IdP document pointing at one, is refused. Redirects are same-host only so the
// client secret in a token POST is never replayed elsewhere.
//
// Loopback (and plain http, which requireHTTPSURL admits only for loopback)
// is reachable only when the operator configured a loopback URL: an IdP on
// the same host is a supported setup, but a remote IdP's discovery document
// must not be able to steer the hub into its own loopback services.
func oidcRuntimeClient(timeout time.Duration, operatorURL string) *http.Client {
	loopback := egressAllowLoopback || isLoopbackURL(operatorURL)
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true, // on-prem IdPs live on private space
		AllowLoopback:         loopback,
		RequireHTTPS:          !loopback,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               timeout,
	}))
}

// isLoopbackURL reports whether raw names a loopback host, by the same rule
// requireHTTPSURL uses to admit plain http.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch h := u.Hostname(); h {
	case "localhost":
		return true
	default:
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
}

func newManagedOIDCJWKSCache(discoveryURL string, timeout time.Duration, ttl time.Duration) (*managedOIDCJWKSCache, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("oidc timeout must be positive")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("oidc jwks ttl must be positive")
	}
	if err := requireHTTPSURL(discoveryURL); err != nil {
		return nil, fmt.Errorf("invalid OIDC discovery URL: %w", err)
	}

	return &managedOIDCJWKSCache{
		client:       oidcRuntimeClient(timeout, discoveryURL),
		discoveryURL: discoveryURL,
		ttl:          ttl,
	}, nil
}

// jwksForcedRefreshInterval is the minimum gap between IdP fetches triggered
// by an unknown kid, and jwksFailureBackoff the gap after a failed fetch with
// nothing cached. An unauthenticated caller can forge a token with any kid
// (the payload is unsigned until the key is found), so without this every
// bearer request cost two outbound IdP requests under a lock (A2A7-004).
const (
	jwksForcedRefreshInterval = 30 * time.Second
	jwksFailureBackoff        = 5 * time.Second
)

func (c *managedOIDCJWKSCache) forcedRefreshInterval() time.Duration {
	if c.forceInterval > 0 {
		return c.forceInterval
	}
	return jwksForcedRefreshInterval
}

// getJWKS returns the cached key set, fetching when it has expired or, for
// forceRefresh, when the last fetch is older than the throttle interval. A
// throttled forced refresh returns the cached set unchanged, so the caller's
// lookup of the unknown kid fails and the token is rejected. Concurrent
// callers queue on fetchMu and the later ones find the fresh attempt
// timestamp, which coalesces a burst into one fetch.
func (c *managedOIDCJWKSCache) getJWKS(ctx context.Context, forceRefresh bool, now time.Time) (string, error) {
	if !forceRefresh {
		c.mu.RLock()
		cached := c.jwksJSON
		expiresAt := c.expiresAt
		c.mu.RUnlock()
		if cached != "" && now.Before(expiresAt) {
			return cached, nil
		}
	}

	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	c.mu.RLock()
	cached, expiresAt, last := c.jwksJSON, c.expiresAt, c.lastAttempt
	c.mu.RUnlock()
	if cached != "" {
		if forceRefresh {
			if now.Sub(last) < c.forcedRefreshInterval() {
				return cached, nil
			}
		} else if now.Before(expiresAt) {
			return cached, nil
		}
	} else if !last.IsZero() && now.Sub(last) < jwksFailureBackoff {
		return "", fmt.Errorf("oidc jwks unavailable")
	}

	jwksJSON, err := c.fetchJWKS(ctx)
	c.mu.Lock()
	c.lastAttempt = now
	if err == nil {
		c.jwksJSON = jwksJSON
		c.expiresAt = now.Add(c.ttl)
	}
	c.mu.Unlock()
	if err != nil {
		return "", err
	}
	return jwksJSON, nil
}

func (c *managedOIDCJWKSCache) fetchJWKS(ctx context.Context) (string, error) {
	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := c.fetchJSON(ctx, c.discoveryURL, &discovery); err != nil {
		return "", fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	if discovery.JWKSURI == "" {
		return "", fmt.Errorf("discovery missing jwks_uri")
	}
	if err := requireHTTPSURL(discovery.JWKSURI); err != nil {
		return "", fmt.Errorf("invalid jwks_uri: %w", err)
	}

	var jwks map[string]any
	if err := c.fetchJSON(ctx, discovery.JWKSURI, &jwks); err != nil {
		return "", fmt.Errorf("fetch JWKS: %w", err)
	}
	if _, ok := jwks["keys"].([]any); !ok {
		return "", fmt.Errorf("jwks missing keys")
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return "", fmt.Errorf("encode jwks: %w", err)
	}
	return string(jwksBytes), nil
}

func (c *managedOIDCJWKSCache) fetchJSON(ctx context.Context, rawURL string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	bodyReader := io.LimitReader(resp.Body, 1<<20)
	if err := json.NewDecoder(bodyReader).Decode(target); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func validateOIDCRS256JWTManaged(ctx context.Context, token string, cache *managedOIDCJWKSCache, expectedIssuer string, expectedAudience string, tenantClaim string, now time.Time) (string, string, error) {
	jwksJSON, err := cache.getJWKS(ctx, false, now)
	if err != nil {
		return "", "", err
	}

	sub, tenant, err := validateOIDCRS256JWT(token, jwksJSON, expectedIssuer, expectedAudience, tenantClaim, now)
	if err == nil {
		return sub, tenant, nil
	}

	if !errors.Is(err, errJWKSKeyNotFound) {
		return "", "", err
	}

	refreshedJWKSJSON, refreshErr := cache.getJWKS(ctx, true, now)
	if refreshErr != nil {
		return "", "", refreshErr
	}

	return validateOIDCRS256JWT(token, refreshedJWKSJSON, expectedIssuer, expectedAudience, tenantClaim, now)
}
