// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// validateHS256JWT returns the token's sub claim and, if tenantClaim is
// non-empty and present as a string claim, its value (W3-01 identity-bound
// tenant) — otherwise an empty tenant, meaning DefaultTenant.
func validateHS256JWT(token string, secret string, expectedIssuer string, expectedAudience string, tenantClaim string, now time.Time) (string, string, error) {
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
	if alg != "HS256" {
		return "", "", fmt.Errorf("unsupported jwt alg")
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
	if !ok {
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

	sig, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return "", "", fmt.Errorf("invalid jwt signature encoding")
	}

	signingInput := segments[0] + "." + segments[1]
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sig, expectedSig) {
		return "", "", fmt.Errorf("jwt signature mismatch")
	}

	var tenant string
	if tenantClaim != "" {
		tenant, _ = payload[tenantClaim].(string)
	}
	return sub, tenant, nil
}

// jwtClockSkew is the leeway granted to a token's nbf claim so a token minted
// by an IdP whose clock runs slightly ahead is not rejected. exp gets none.
const jwtClockSkew = 60 * time.Second

// checkJWTNotBefore rejects a token whose nbf lies in the future beyond
// jwtClockSkew. A present-but-non-numeric nbf is rejected rather than ignored
// so a malformed claim can never be used to dodge the check (A02-4).
func checkJWTNotBefore(payload map[string]any, now time.Time) error {
	raw, present := payload["nbf"]
	if !present {
		return nil
	}
	nbf, ok := raw.(float64)
	if !ok {
		return fmt.Errorf("jwt nbf must be numeric")
	}
	if float64(now.Add(jwtClockSkew).Unix()) < nbf {
		return fmt.Errorf("jwt not yet valid")
	}
	return nil
}
