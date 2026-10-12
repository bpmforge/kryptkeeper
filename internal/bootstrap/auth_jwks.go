// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const minJWKSRSAKeyBits = 2048

// validateOIDCRS256JWT returns the token's sub claim and, if tenantClaim is
// non-empty and present as a string claim, its value (W3-01 identity-bound
// tenant) — otherwise an empty tenant, meaning DefaultTenant.
func validateOIDCRS256JWT(token string, jwksJSON string, expectedIssuer string, expectedAudience string, tenantClaim string, now time.Time) (string, string, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return "", "", fmt.Errorf("jwt must have 3 segments")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return "", "", fmt.Errorf("invalid jwt header encoding")
	}

	var header map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return "", "", fmt.Errorf("invalid jwt header json")
	}

	alg, _ := header["alg"].(string)
	if alg != "RS256" {
		return "", "", fmt.Errorf("unsupported jwt alg")
	}

	kid, _ := header["kid"].(string)
	if kid == "" {
		return "", "", fmt.Errorf("jwt missing kid")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid jwt payload encoding")
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return "", "", fmt.Errorf("invalid jwt payload json")
	}

	sub, ok := payload["sub"].(string)
	if !ok || sub == "" {
		return "", "", fmt.Errorf("jwt missing string sub")
	}

	expFloat, ok := payload["exp"].(float64)
	if !ok {
		return "", "", fmt.Errorf("jwt missing numeric exp")
	}
	exp := int64(expFloat)
	if float64(exp) != expFloat {
		return "", "", fmt.Errorf("jwt exp must be unix seconds integer")
	}
	if now.Unix() >= exp {
		return "", "", fmt.Errorf("jwt expired")
	}
	if err := checkJWTNotBefore(payload, now); err != nil {
		return "", "", err
	}

	if expectedIssuer != "" {
		iss, ok := payload["iss"].(string)
		if !ok || iss != expectedIssuer {
			return "", "", fmt.Errorf("jwt issuer mismatch")
		}
	}

	if expectedAudience != "" {
		if !audienceMatches(payload["aud"], expectedAudience) {
			return "", "", fmt.Errorf("jwt audience mismatch")
		}
	}

	publicKey, err := resolveRSAPublicKeyByKID(jwksJSON, kid)
	if err != nil {
		return "", "", err
	}

	sig, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return "", "", fmt.Errorf("invalid jwt signature encoding")
	}

	signingInput := segments[0] + "." + segments[1]
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sig); err != nil {
		return "", "", fmt.Errorf("jwt signature mismatch")
	}

	var tenant string
	if tenantClaim != "" {
		tenant, _ = payload[tenantClaim].(string)
	}
	return sub, tenant, nil
}

func resolveRSAPublicKeyByKID(jwksJSON string, kid string) (*rsa.PublicKey, error) {
	var jwks struct {
		Keys []struct {
			KTY string `json:"kty"`
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		return nil, fmt.Errorf("invalid jwks json")
	}

	for _, key := range jwks.Keys {
		if key.KID != kid {
			continue
		}
		if key.KTY != "RSA" {
			return nil, fmt.Errorf("jwks key is not rsa")
		}

		modulusBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil || len(modulusBytes) == 0 {
			return nil, fmt.Errorf("invalid jwks rsa modulus")
		}
		modulus := new(big.Int).SetBytes(modulusBytes)
		// Same floor as the ACME JWS verifier: a sub-2048-bit IdP key is
		// factorable, so a signature under it proves nothing.
		if modulus.BitLen() < minJWKSRSAKeyBits {
			return nil, fmt.Errorf("jwks rsa modulus too small")
		}

		exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(exponentBytes) == 0 {
			return nil, fmt.Errorf("invalid jwks rsa exponent")
		}

		exponent := 0
		for _, b := range exponentBytes {
			if exponent > (int(^uint(0)>>1) >> 8) {
				return nil, fmt.Errorf("jwks rsa exponent too large")
			}
			exponent = (exponent << 8) | int(b)
		}
		if exponent < 3 || exponent%2 == 0 {
			return nil, fmt.Errorf("invalid jwks rsa exponent")
		}

		return &rsa.PublicKey{N: modulus, E: exponent}, nil
	}

	return nil, fmt.Errorf("%w", errJWKSKeyNotFound)
}
