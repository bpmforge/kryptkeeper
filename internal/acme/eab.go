// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// EABKey is a pre-shared External Account Binding credential (RFC 8555
// §7.3.4): a MAC key identified by a key ID (kid), issued out-of-band by an
// operator to a subscriber before they may create an ACME account.
type EABKey struct {
	KID       string
	MACKey    []byte // raw HMAC key material
	Disabled  bool
	CreatedAt time.Time
}

// eabProtectedHeader is the protected header of the inner EAB JWS.
type eabProtectedHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	URL string `json:"url"`
}

// ExternalAccountBinding is the flattened-JWS structure a client submits in
// its new-account request to prove possession of a pre-shared MAC key, per
// RFC 8555 §7.3.4.
//
// Payload is base64url(JSON of the requesting account's JWK) — the same JWK
// that signs the outer account JWS (jws.go). Binding the payload to the
// account key closes G-44 (docs/work/DESIGN_REVIEW.md): an
// externalAccountBinding observed for one account's key cannot be replayed
// by a different key, because verifyExternalAccountBinding compares the
// payload's RFC 7638 thumbprint against the actual signer's thumbprint.
type ExternalAccountBinding struct {
	Protected string `json:"protected"` // base64url JSON: {alg, kid, url}
	Payload   string `json:"payload"`   // base64url(JSON of the account's JWK)
	Signature string `json:"signature"` // base64url HMAC-SHA256(protected + "." + payload)
}

var (
	errEABRequired    = errors.New("external account binding required")
	errEABUnknownKID  = errors.New("unknown eab key id")
	errEABDisabled    = errors.New("eab key disabled")
	errEABBadAlg      = errors.New("unsupported eab alg")
	errEABBadURL      = errors.New("eab url does not match request")
	errEABBadEncoding = errors.New("malformed eab binding")
	errEABBadMAC      = errors.New("eab signature verification failed")
	errEABKeyMismatch = errors.New("eab payload does not match the requesting account key")
)

// verifyExternalAccountBinding validates eab against the key store and the
// expected request URL, per RFC 8555 §7.3.4: the protected header's alg must
// be HMAC (HS256), its kid must resolve to an active EABKey, its url must
// match the endpoint the client is calling, the signature must be a valid
// HMAC-SHA256 over "protected.payload" using that key's MAC secret, and the
// payload must be base64url(JSON of the account JWK) whose RFC 7638
// thumbprint matches accountThumbprint — the actual signer of the outer
// account JWS (W1-08, closes the G-44 replay gap: a captured
// externalAccountBinding is bound to one specific account key).
func verifyExternalAccountBinding(keys eabKeyLookup, eab *ExternalAccountBinding, expectedURL string, accountThumbprint string) error {
	if eab == nil {
		return errEABRequired
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(eab.Protected)
	if err != nil {
		return fmt.Errorf("%w: protected: %v", errEABBadEncoding, err)
	}
	var hdr eabProtectedHeader
	if err := json.Unmarshal(protectedJSON, &hdr); err != nil {
		return fmt.Errorf("%w: protected: %v", errEABBadEncoding, err)
	}
	if hdr.Alg != "HS256" {
		return fmt.Errorf("%w: %q", errEABBadAlg, hdr.Alg)
	}
	if hdr.URL != expectedURL {
		return errEABBadURL
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(eab.Payload)
	if err != nil {
		return fmt.Errorf("%w: payload: %v", errEABBadEncoding, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(eab.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", errEABBadEncoding, err)
	}

	key, ok := keys.LoadEABKey(hdr.KID)
	if !ok {
		return errEABUnknownKID
	}
	if key.Disabled {
		return errEABDisabled
	}

	mac := hmac.New(sha256.New, key.MACKey)
	mac.Write([]byte(eab.Protected + "." + eab.Payload))
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(expected, sig) != 1 {
		return errEABBadMAC
	}

	var payloadJWK JSONWebKey
	if err := json.Unmarshal(payloadJSON, &payloadJWK); err != nil {
		return fmt.Errorf("%w: payload jwk: %v", errEABBadEncoding, err)
	}
	payloadThumbprint, err := jwkThumbprint(&payloadJWK)
	if err != nil {
		return fmt.Errorf("%w: payload jwk: %v", errEABBadEncoding, err)
	}
	if subtle.ConstantTimeCompare([]byte(payloadThumbprint), []byte(accountThumbprint)) != 1 {
		return errEABKeyMismatch
	}
	return nil
}

// eabKeyLookup is the read side of EAB key storage the verifier needs.
// Store (store.go) implements it for both MemStore and SQLiteStore.
type eabKeyLookup interface {
	LoadEABKey(kid string) (*EABKey, bool)
}

// eabConfig is the server's EAB posture, read once at construction from env
// (APP_ACME_EAB_REQUIRED, APP_ACME_EAB_KEYS_JSON) per D-020 (env-only config).
type eabConfig struct {
	required bool
	seedKeys []EABKey
}

// eabConfigFromEnv reads the EAB posture from the environment.
//
// APP_ACME_EAB_REQUIRED  — "true" to reject new-account requests without a
//
//	valid externalAccountBinding (default: false, EAB optional).
//
// APP_ACME_EAB_KEYS_JSON — a JSON object mapping kid -> base64url-encoded MAC
//
//	key, seeded into the store at startup, e.g.
//	{"kid-001":"c29tZS1zZWNyZXQtbWF0ZXJpYWw"}. Operators provision keys by
//	setting this env var and restarting; there is no runtime admin API for
//	EAB key management yet.
func eabConfigFromEnv() (eabConfig, error) {
	cfg := eabConfig{
		required: strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ACME_EAB_REQUIRED")), "true"),
	}
	raw := strings.TrimSpace(os.Getenv("APP_ACME_EAB_KEYS_JSON"))
	if raw == "" {
		return cfg, nil
	}
	var kids map[string]string
	if err := json.Unmarshal([]byte(raw), &kids); err != nil {
		return cfg, fmt.Errorf("APP_ACME_EAB_KEYS_JSON: invalid JSON: %w", err)
	}
	now := time.Now().UTC()
	for kid, keyB64 := range kids {
		keyBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(keyB64, "="))
		if err != nil {
			return cfg, fmt.Errorf("APP_ACME_EAB_KEYS_JSON: kid %q: invalid base64url key: %w", kid, err)
		}
		cfg.seedKeys = append(cfg.seedKeys, EABKey{KID: kid, MACKey: keyBytes, CreatedAt: now})
	}
	return cfg, nil
}

// seedEABKeys upserts each configured key into the store. Called once at
// server construction; safe to call repeatedly (idempotent upsert).
func seedEABKeys(store Store, keys []EABKey) error {
	for _, k := range keys {
		if err := store.SaveEABKey(&k); err != nil {
			return fmt.Errorf("seed eab key %q: %w", k.KID, err)
		}
	}
	return nil
}
