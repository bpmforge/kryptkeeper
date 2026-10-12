// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func signHS256JWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	seg1 := base64.RawURLEncoding.EncodeToString(headerBytes)
	seg2 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := seg1 + "." + seg2
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// TestValidateHS256JWTExtractsTenantClaim is the W3-01 regression proving the
// configurable tenant-claim extraction actually works: a JWT carrying a
// "tenant" claim yields that value, a token without it yields empty
// (DefaultTenant), and an empty tenantClaim param disables extraction
// entirely (e.g. the login-session path, which is always super-admin).
func TestValidateHS256JWTExtractsTenantClaim(t *testing.T) {
	secret := "test-secret"
	now := time.Now()
	exp := float64(now.Add(time.Hour).Unix())

	withTenant := signHS256JWT(t, secret, map[string]any{"sub": "svc-1", "exp": exp, "tenant": "acme"})
	sub, tenant, err := validateHS256JWT(withTenant, secret, "", "", "tenant", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub != "svc-1" || tenant != "acme" {
		t.Fatalf("expected sub=svc-1 tenant=acme, got sub=%q tenant=%q", sub, tenant)
	}

	withoutTenant := signHS256JWT(t, secret, map[string]any{"sub": "svc-2", "exp": exp})
	sub, tenant, err = validateHS256JWT(withoutTenant, secret, "", "", "tenant", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub != "svc-2" || tenant != "" {
		t.Fatalf("expected sub=svc-2 tenant=<empty>, got sub=%q tenant=%q", sub, tenant)
	}

	// Empty tenantClaim (login-session path) never extracts, even if present.
	sub, tenant, err = validateHS256JWT(withTenant, secret, "", "", "", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub != "svc-1" || tenant != "" {
		t.Fatalf("expected no tenant extraction with empty claim name, got sub=%q tenant=%q", sub, tenant)
	}
}
