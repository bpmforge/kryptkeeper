// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// --- shared signing helpers for jws_test.go ---------------------------------

func jwkFromRSAPublicKey(pub *rsa.PublicKey) *JSONWebKey {
	return &JSONWebKey{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func jwkFromEd25519PublicKey(pub ed25519.PublicKey) *JSONWebKey {
	return &JSONWebKey{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
}

// signES256 signs signingInput and returns the raw R||S JWS signature.
func signES256(t *testing.T, priv *ecdsa.PrivateKey, signingInput []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := make([]byte, 64)
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	return sig
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, signingInput []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(signingInput)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return sig
}

func signEdDSA(priv ed25519.PrivateKey, signingInput []byte) []byte {
	return ed25519.Sign(priv, signingInput)
}

// buildJWS assembles a flattened-JSON JWS envelope given a raw signature
// over protectedB64+"."+payloadB64.
func buildJWS(protectedB64, payloadB64 string, sig []byte) *JWS {
	return &JWS{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func encodeHeader(t *testing.T, hdr jwsProtectedHeader) string {
	t.Helper()
	b, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func alwaysValidNonce(string) bool   { return true }
func alwaysInvalidNonce(string) bool { return false }

// --- parseJWS ---------------------------------------------------------------

func TestParseJWS_Valid(t *testing.T) {
	jws, err := parseJWS([]byte(`{"protected":"aGVhZGVy","payload":"cGF5bG9hZA","signature":"c2ln"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jws.Protected == "" || jws.Signature == "" {
		t.Fatal("expected protected and signature to be populated")
	}
}

func TestParseJWS_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"not json", "not-json"},
		{"plain object no jws fields", `{"contact":["mailto:a@example.com"]}`},
		{"missing signature", `{"protected":"aGVhZGVy","payload":"cGF5bG9hZA"}`},
		{"missing protected", `{"payload":"cGF5bG9hZA","signature":"c2ln"}`},
		{"empty body", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseJWS([]byte(tt.body)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// --- verifyJWS: happy paths per algorithm -----------------------------------

func TestVerifyJWS_ES256_NewAccount(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "test-nonce", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"termsOfServiceAgreed":true}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	result, err := verifyJWS(jws, url, true, nil, alwaysValidNonce)
	if err != nil {
		t.Fatalf("expected valid ES256 jws to verify, got: %v", err)
	}
	if string(result.Payload) != `{"termsOfServiceAgreed":true}` {
		t.Errorf("unexpected decoded payload: %s", result.Payload)
	}
}

func TestVerifyJWS_ES256_KID(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	url := "https://acme.example.com/acme/new-order"
	kid := "https://acme.example.com/acme/account/acct-1"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "test-nonce", URL: url, KID: kid}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	resolveKID := func(gotKID string) (crypto.PublicKey, error) {
		if gotKID != kid {
			t.Fatalf("resolveKID called with unexpected kid %q", gotKID)
		}
		return &priv.PublicKey, nil
	}
	result, err := verifyJWS(jws, url, false, resolveKID, alwaysValidNonce)
	if err != nil {
		t.Fatalf("expected valid kid-authenticated jws to verify, got: %v", err)
	}
	if result.KID != kid {
		t.Errorf("expected KID %q, got %q", kid, result.KID)
	}
}

func TestVerifyJWS_RS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	jwk := jwkFromRSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "RS256", Nonce: "test-nonce", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signRS256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	if _, err := verifyJWS(jws, url, true, nil, alwaysValidNonce); err != nil {
		t.Fatalf("expected valid RS256 jws to verify, got: %v", err)
	}
}

func TestVerifyJWS_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	jwk := jwkFromEd25519PublicKey(pub)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "EdDSA", Nonce: "test-nonce", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signEdDSA(priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	if _, err := verifyJWS(jws, url, true, nil, alwaysValidNonce); err != nil {
		t.Fatalf("expected valid EdDSA jws to verify, got: %v", err)
	}
}

// --- verifyJWS: negatives ----------------------------------------------------

// TestVerifyJWS_TamperedSignatureRejected proves acceptance criterion 1's
// core negative: flipping a single bit of an otherwise-valid signature must
// cause rejection.
func TestVerifyJWS_TamperedSignatureRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	sig[0] ^= 0xFF
	jws := buildJWS(protectedB64, payloadB64, sig)

	_, err := verifyJWS(jws, url, true, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSBadSignature) {
		t.Fatalf("expected errJWSBadSignature, got %v", err)
	}
}

func TestVerifyJWS_TamperedPayloadRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"termsOfServiceAgreed":true}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))

	// Attacker swaps the payload after signing without re-signing.
	tamperedPayloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"termsOfServiceAgreed":false}`))
	jws := buildJWS(protectedB64, tamperedPayloadB64, sig)

	_, err := verifyJWS(jws, url, true, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSBadSignature) {
		t.Fatalf("expected errJWSBadSignature, got %v", err)
	}
}

func TestVerifyJWS_BadNonceRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "used-nonce", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	_, err := verifyJWS(jws, url, true, nil, alwaysInvalidNonce)
	if !errors.Is(err, errJWSBadNonce) {
		t.Fatalf("expected errJWSBadNonce, got %v", err)
	}
}

func TestVerifyJWS_WrongURLRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: "https://acme.example.com/acme/new-account", JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	_, err := verifyJWS(jws, "https://acme.example.com/acme/new-order", true, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSBadURL) {
		t.Fatalf("expected errJWSBadURL, got %v", err)
	}
}

func TestVerifyJWS_UnsupportedAlgRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "none", Nonce: "n1", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	jws := buildJWS(protectedB64, payloadB64, []byte{})

	_, err := verifyJWS(jws, url, true, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSUnsupportedAlg) {
		t.Fatalf("expected errJWSUnsupportedAlg, got %v", err)
	}
}

func TestVerifyJWS_RequireJWKButKIDGivenRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, KID: "https://acme.example.com/acme/account/acct-1"}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	resolveKID := func(string) (crypto.PublicKey, error) { return &priv.PublicKey, nil }
	_, err := verifyJWS(jws, url, true, resolveKID, alwaysValidNonce)
	if !errors.Is(err, errJWSNeedsJWK) {
		t.Fatalf("expected errJWSNeedsJWK, got %v", err)
	}
}

func TestVerifyJWS_RequireKIDButJWKGivenRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-order"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	_, err := verifyJWS(jws, url, false, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSNeedsKID) {
		t.Fatalf("expected errJWSNeedsKID, got %v", err)
	}
}

func TestVerifyJWS_BothJWKAndKIDRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	url := "https://acme.example.com/acme/new-order"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, JWK: jwk, KID: "https://acme.example.com/acme/account/acct-1"}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	_, err := verifyJWS(jws, url, false, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSBothJWKAndKID) {
		t.Fatalf("expected errJWSBothJWKAndKID, got %v", err)
	}
}

func TestVerifyJWS_ResolveKIDErrorPropagates(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	url := "https://acme.example.com/acme/new-order"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, KID: "https://acme.example.com/acme/account/nonexistent"}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, priv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	resolveKID := func(string) (crypto.PublicKey, error) { return nil, errAccountNotFound }
	_, err := verifyJWS(jws, url, false, resolveKID, alwaysValidNonce)
	if !errors.Is(err, errAccountNotFound) {
		t.Fatalf("expected errAccountNotFound, got %v", err)
	}
}

func TestVerifyJWS_WrongKeyTypeForAlgRejected(t *testing.T) {
	// An RSA key signing with alg ES256 must not verify even with a
	// syntactically valid 64-byte signature blob.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromRSAPublicKey(&rsaPriv.PublicKey)
	url := "https://acme.example.com/acme/new-account"
	hdr := jwsProtectedHeader{Alg: "ES256", Nonce: "n1", URL: url, JWK: jwk}
	protectedB64 := encodeHeader(t, hdr)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := signES256(t, ecPriv, []byte(protectedB64+"."+payloadB64))
	jws := buildJWS(protectedB64, payloadB64, sig)

	_, err = verifyJWS(jws, url, true, nil, alwaysValidNonce)
	if !errors.Is(err, errJWSBadSignature) {
		t.Fatalf("expected errJWSBadSignature for RSA jwk under ES256, got %v", err)
	}
}

// --- jwkThumbprint / canonicalJWK -------------------------------------------

// TestJWKThumbprint_RFC7638Vector is the known-answer test vector from
// RFC 7638 Appendix A.
func TestJWKThumbprint_RFC7638Vector(t *testing.T) {
	jwk := &JSONWebKey{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}
	got, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Errorf("thumbprint mismatch: got %q, want %q", got, want)
	}
}

func TestJWKThumbprint_DifferentKeysDifferentThumbprints(t *testing.T) {
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tp1, err := jwkThumbprint(jwkFromECDSAPublicKey(&priv1.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint 1: %v", err)
	}
	tp2, err := jwkThumbprint(jwkFromECDSAPublicKey(&priv2.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint 2: %v", err)
	}
	if tp1 == tp2 {
		t.Error("expected different keys to produce different thumbprints")
	}

	// Same key, computed twice, must be stable.
	tp1Again, err := jwkThumbprint(jwkFromECDSAPublicKey(&priv1.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint 1 again: %v", err)
	}
	if tp1 != tp1Again {
		t.Error("expected thumbprint to be deterministic for the same key")
	}
}

func TestJWKThumbprint_UnsupportedKty(t *testing.T) {
	if _, err := jwkThumbprint(&JSONWebKey{Kty: "bogus"}); err == nil {
		t.Fatal("expected error for unsupported kty")
	}
}

// --- JSONWebKey.publicKey() round trips -------------------------------------

func TestJSONWebKey_PublicKey_EC(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFromECDSAPublicKey(&priv.PublicKey)
	pub, err := jwk.publicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.X.Cmp(priv.PublicKey.X) != 0 || ecPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("reconstructed EC public key does not match original")
	}
}

func TestJSONWebKey_PublicKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	jwk := jwkFromRSAPublicKey(&priv.PublicKey)
	pub, err := jwk.publicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 || rsaPub.E != priv.PublicKey.E {
		t.Error("reconstructed RSA public key does not match original")
	}
}

func TestJSONWebKey_PublicKey_OKP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	jwk := jwkFromEd25519PublicKey(pub)
	got, err := jwk.publicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	edPub, ok := got.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", got)
	}
	if !edPub.Equal(pub) {
		t.Error("reconstructed Ed25519 public key does not match original")
	}
}

func TestJSONWebKey_PublicKey_UnsupportedKty(t *testing.T) {
	if _, err := (&JSONWebKey{Kty: "bogus"}).publicKey(); err == nil {
		t.Fatal("expected error for unsupported kty")
	}
}

func TestJSONWebKey_PublicKey_UnsupportedCurve(t *testing.T) {
	if _, err := (&JSONWebKey{Kty: "EC", Crv: "P-384", X: "AA", Y: "AA"}).publicKey(); err == nil {
		t.Fatal("expected error for unsupported EC curve")
	}
}

// --- accountIDFromKID --------------------------------------------------------

func TestAccountIDFromKID(t *testing.T) {
	const baseURL = "https://acme.example.com"
	tests := []struct {
		name   string
		kid    string
		wantID string
		wantOK bool
	}{
		{"valid", baseURL + "/acme/account/acct-123", "acct-123", true},
		{"wrong host", "https://attacker.example.com/acme/account/acct-123", "", false},
		{"missing id", baseURL + "/acme/account/", "", false},
		{"not an account url", baseURL + "/acme/order/order-1", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := accountIDFromKID(tt.kid, baseURL)
			if ok != tt.wantOK || id != tt.wantID {
				t.Errorf("accountIDFromKID(%q) = (%q, %v), want (%q, %v)", tt.kid, id, ok, tt.wantID, tt.wantOK)
			}
		})
	}
}
