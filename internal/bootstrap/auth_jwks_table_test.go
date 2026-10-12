// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// rawJWT assembles header.payload.sig with no verification-relevant helpers,
// so the table can forge exactly the malformed shapes an attacker would send.
func rawJWT(t *testing.T, header, claims map[string]any, sig []byte) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// AS-02: validateOIDCRS256JWT is a hand-rolled verifier; pin the rejections
// that matter (algorithm confusion, claim checks, key selection, key size).
func TestValidateOIDCRS256JWT_RejectionTable(t *testing.T) {
	priv := generateTestRSAKey(t)
	other := generateTestRSAKey(t)
	jwks := buildTestJWKS(t, "k1", &priv.PublicKey)
	now := time.Unix(1_800_000_000, 0)
	const iss, aud = "https://idp.example.com", "kryptkeeper"
	good := func() map[string]any {
		return map[string]any{"sub": "svc", "iss": iss, "aud": aud, "exp": float64(now.Add(time.Hour).Unix())}
	}
	with := func(k string, v any) map[string]any { c := good(); c[k] = v; return c }
	without := func(k string) map[string]any { c := good(); delete(c, k); return c }

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hs := func(secret []byte, claims map[string]any) string {
		signingInput := rawJWT(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": "k1"}, claims, nil)
		signingInput = signingInput[:strings.LastIndex(signingInput, ".")]
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(signingInput))
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallJWKS := buildTestJWKS(t, "k1", &small.PublicKey)

	cases := []struct {
		name    string
		token   string
		jwks    string
		wantErr string // substring; "" = must succeed
		isKeyNF bool
	}{
		{"valid", signTestRS256JWT(t, priv, "k1", good()), jwks, "", false},
		{"alg none", rawJWT(t, map[string]any{"alg": "none", "kid": "k1"}, good(), nil), jwks, "unsupported jwt alg", false},
		{"alg None mixed case", rawJWT(t, map[string]any{"alg": "None", "kid": "k1"}, good(), nil), jwks, "unsupported jwt alg", false},
		{"HS256 keyed with DER public key", hs(pubDER, good()), jwks, "unsupported jwt alg", false},
		{"HS256 keyed with modulus bytes", hs(priv.N.Bytes(), good()), jwks, "unsupported jwt alg", false},
		{"missing kid", signTestRS256JWT(t, priv, "", good()), jwks, "missing kid", false},
		{"unknown kid", signTestRS256JWT(t, priv, "k2", good()), jwks, "jwks key not found", true},
		{"signed by a different key", signTestRS256JWT(t, other, "k1", good()), jwks, "signature mismatch", false},
		{"wrong issuer", signTestRS256JWT(t, priv, "k1", with("iss", "https://evil.example")), jwks, "issuer mismatch", false},
		{"missing issuer", signTestRS256JWT(t, priv, "k1", without("iss")), jwks, "issuer mismatch", false},
		{"wrong audience", signTestRS256JWT(t, priv, "k1", with("aud", "someone-else")), jwks, "audience mismatch", false},
		{"audience list without ours", signTestRS256JWT(t, priv, "k1", with("aud", []string{"a", "b"})), jwks, "audience mismatch", false},
		{"missing audience", signTestRS256JWT(t, priv, "k1", without("aud")), jwks, "audience mismatch", false},
		{"expired", signTestRS256JWT(t, priv, "k1", with("exp", float64(now.Add(-time.Second).Unix()))), jwks, "expired", false},
		{"exp exactly now", signTestRS256JWT(t, priv, "k1", with("exp", float64(now.Unix()))), jwks, "expired", false},
		{"missing exp", signTestRS256JWT(t, priv, "k1", without("exp")), jwks, "exp", false},
		{"nbf in the future", signTestRS256JWT(t, priv, "k1", with("nbf", float64(now.Add(10*time.Minute).Unix()))), jwks, "not yet valid", false},
		{"missing sub", signTestRS256JWT(t, priv, "k1", without("sub")), jwks, "sub", false},
		{"two segments", "a.b", jwks, "3 segments", false},
		{"tampered payload", func() string {
			parts := strings.Split(signTestRS256JWT(t, priv, "k1", good()), ".")
			forged := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","iss":"` + iss + `","aud":"` + aud + `","exp":1900000000}`))
			return parts[0] + "." + forged + "." + parts[2]
		}(), jwks, "signature mismatch", false},
		{"key below 2048 bits", signTestRS256JWT(t, small, "k1", good()), smallJWKS, "modulus too small", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub, _, err := validateOIDCRS256JWT(tc.token, tc.jwks, iss, aud, "", now)
			if tc.wantErr == "" {
				if err != nil || sub != "svc" {
					t.Fatalf("want success, got sub=%q err=%v", sub, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got success (sub=%q)", tc.wantErr, sub)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
			if tc.isKeyNF && !errors.Is(err, errJWKSKeyNotFound) {
				t.Fatalf("unknown kid must surface errJWKSKeyNotFound (drives the forced JWKS refresh), got %v", err)
			}
		})
	}
}
