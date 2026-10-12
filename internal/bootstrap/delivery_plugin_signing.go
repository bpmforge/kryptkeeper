// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Delivery plugin signatures (W20-24, D-117). A publisher signs the exact
// bytes of manifest.json with a cosign key; the manifest pins the module's
// SHA-256 and declares its capabilities, so one signature covers both. The
// hub verifies offline against public keys it already holds: no Rekor, no
// Fulcio, no network. See packaging/SIGNING.md for custody.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// PluginTierVerified is a plugin signed by a key the operator trusts.
const PluginTierVerified = "verified"

// firstPartyPluginKeys is the Kryptkeeper plugin-signing public key (a
// separate key from the release key, D-117). Only a key compiled in here
// can make a plugin first-party; operators cannot add first-party keys.
//
//go:embed plugin_signing_keys.txt
var firstPartyPluginKeys []byte

// errPluginSignature refuses an install whose signature does not verify.
// An unknown signer is refused too: a signed upload is never quietly
// downgraded to community.
var errPluginSignature = errors.New("plugin signature does not verify against any trusted plugin-signing key (add the publisher's public key to KRYPTKEEPER_PLUGIN_TRUSTED_KEYS to trust it)")

type pluginKey struct {
	id  string // sha256 of the PKIX public key, hex
	pub *ecdsa.PublicKey
}

// PluginTrust is the set of keys plugin signatures are checked against.
type PluginTrust struct {
	firstParty []pluginKey
	verified   []pluginKey
}

// NewPluginTrust parses PEM public keys: firstParty keys sign first-party
// plugins, verified keys are the publishers an operator trusts.
func NewPluginTrust(firstParty, verified []byte) (*PluginTrust, error) {
	fp, err := parsePluginKeys(firstParty)
	if err != nil {
		return nil, fmt.Errorf("first-party plugin keys: %w", err)
	}
	v, err := parsePluginKeys(verified)
	if err != nil {
		return nil, fmt.Errorf("trusted plugin keys: %w", err)
	}
	return &PluginTrust{firstParty: fp, verified: v}, nil
}

// PluginTrustFromEnv is the compiled-in first-party key plus the PEM file
// named by KRYPTKEEPER_PLUGIN_TRUSTED_KEYS. A file that is set but cannot
// be read or parsed is an error, not an empty trust list.
func PluginTrustFromEnv() (*PluginTrust, error) {
	var verified []byte
	if path := strings.TrimSpace(os.Getenv("KRYPTKEEPER_PLUGIN_TRUSTED_KEYS")); path != "" {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
		if err != nil {
			return nil, fmt.Errorf("KRYPTKEEPER_PLUGIN_TRUSTED_KEYS: %w", err)
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, errors.New("KRYPTKEEPER_PLUGIN_TRUSTED_KEYS: file has no keys")
		}
		verified = raw
	}
	return NewPluginTrust(firstPartyPluginKeys, verified)
}

// Counts reports how many first-party and operator-trusted keys are loaded.
func (t *PluginTrust) Counts() (firstParty, verified int) {
	if t == nil {
		return 0, 0
	}
	return len(t.firstParty), len(t.verified)
}

// parsePluginKeys reads every PUBLIC KEY block; text outside PEM blocks is
// ignored so key files can carry comments. Only ECDSA P-256 is accepted,
// which is what `cosign generate-key-pair` produces.
func parsePluginKeys(raw []byte) ([]pluginKey, error) {
	var keys []pluginKey
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return keys, nil
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("unexpected PEM block %q (want PUBLIC KEY)", block.Type)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("plugin-signing keys must be ECDSA P-256 (cosign generate-key-pair)")
		}
		sum := sha256.Sum256(block.Bytes)
		keys = append(keys, pluginKey{id: hex.EncodeToString(sum[:]), pub: pub})
	}
}

// Classify returns the trust tier for manifestJSON given its signature, and
// the id of the key that signed it. No signature is community; a signature
// that does not verify against a trusted key is errPluginSignature.
func (t *PluginTrust) Classify(manifestJSON []byte, signature string) (tier, keyID string, err error) {
	if strings.TrimSpace(signature) == "" {
		return PluginTierCommunity, "", nil
	}
	digest := sha256.Sum256(manifestJSON)
	sig, err := decodePluginSignature(signature, digest[:])
	if err != nil {
		return "", "", err
	}
	if t == nil {
		return "", "", errPluginSignature
	}
	for _, k := range t.firstParty {
		if ecdsa.VerifyASN1(k.pub, digest[:], sig) {
			return PluginTierFirstParty, k.id, nil
		}
	}
	for _, k := range t.verified {
		if ecdsa.VerifyASN1(k.pub, digest[:], sig) {
			return PluginTierVerified, k.id, nil
		}
	}
	return "", "", errPluginSignature
}

// decodePluginSignature accepts either form cosign sign-blob writes: the
// sigstore bundle (cosign v3 default, --bundle) or a bare base64 signature
// (--output-signature). A bundle's message digest must be this manifest's.
func decodePluginSignature(signature string, digest []byte) ([]byte, error) {
	s := strings.TrimSpace(signature)
	if strings.HasPrefix(s, "{") {
		var b struct {
			MediaType        string `json:"mediaType"`
			MessageSignature *struct {
				MessageDigest *struct {
					Algorithm string `json:"algorithm"`
					Digest    string `json:"digest"`
				} `json:"messageDigest"`
				Signature string `json:"signature"`
			} `json:"messageSignature"`
		}
		if err := json.Unmarshal([]byte(s), &b); err != nil {
			return nil, fmt.Errorf("plugin signature: bundle is not JSON: %w", err)
		}
		if !strings.HasPrefix(b.MediaType, "application/vnd.dev.sigstore.bundle") || b.MessageSignature == nil {
			return nil, errors.New("plugin signature: not a sigstore message-signature bundle")
		}
		if d := b.MessageSignature.MessageDigest; d != nil {
			got, err := base64.StdEncoding.DecodeString(d.Digest)
			if err != nil || d.Algorithm != "SHA2_256" || !bytes.Equal(got, digest) {
				return nil, errors.New("plugin signature: bundle was made for a different manifest")
			}
		}
		s = b.MessageSignature.Signature
	}
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("plugin signature: not base64")
	}
	return sig, nil
}
