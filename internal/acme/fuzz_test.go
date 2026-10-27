// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

const fuzzJWSURL = "https://acme.example.com/acme/new-account"

func fuzzSignedJWS(f *testing.F) ([]byte, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	hdr, _ := json.Marshal(jwsProtectedHeader{Alg: "ES256", Nonce: "n", URL: fuzzJWSURL, JWK: jwkFromECDSAPublicKey(&priv.PublicKey)})
	protected := base64.RawURLEncoding.EncodeToString(hdr)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"termsOfServiceAgreed":true}`))
	sum := sha256.Sum256([]byte(protected + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		f.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	body, _ := json.Marshal(JWS{Protected: protected, Payload: payload, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	jwk, _ := json.Marshal(jwkFromECDSAPublicKey(&priv.PublicKey))
	return body, jwk
}

// FuzzParseAndVerifyJWS fuzzes the RFC 8555 JWS envelope: parse, header
// decode, JWK-to-key conversion and signature check. A verified result must
// carry a key.
func FuzzParseAndVerifyJWS(f *testing.F) {
	body, _ := fuzzSignedJWS(f)
	f.Add(body)
	f.Add([]byte(`{"protected":"aGVhZGVy","payload":"cGF5bG9hZA","signature":"c2ln"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		jws, err := parseJWS(data)
		if err != nil {
			return
		}
		if jws == nil {
			t.Fatal("nil JWS with nil error")
		}
		v, err := verifyJWS(jws, fuzzJWSURL, true,
			func(string) (crypto.PublicKey, error) { return nil, errAccountNotFound },
			func(string) bool { return true })
		if err == nil && (v == nil || v.PublicKey == nil) {
			t.Fatal("verified JWS without a public key")
		}
	})
}

// FuzzJWKPublicKey fuzzes JWK decoding and thumbprinting (EC, RSA, OKP).
func FuzzJWKPublicKey(f *testing.F) {
	_, jwk := fuzzSignedJWS(f)
	f.Add(jwk)
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var k JSONWebKey
		if json.Unmarshal(data, &k) != nil {
			return
		}
		if pub, err := k.publicKey(); err == nil && pub == nil {
			t.Fatal("nil key with nil error")
		}
		_, _ = jwkThumbprint(&k)
	})
}
