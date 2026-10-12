// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWS is the Flattened JSON Serialization envelope an ACME client submits as
// its request body per RFC 8555 §6.2.
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// jwsProtectedHeader is the outer JWS protected header per RFC 8555 §6.2:
// alg identifies the signature algorithm, nonce/url bind the request to a
// single-use server nonce and the exact endpoint URL, and exactly one of jwk
// (new-account, where no account exists yet to reference) or kid (an account
// URL, every other authenticated request) identifies the signing key.
type jwsProtectedHeader struct {
	Alg   string      `json:"alg"`
	Nonce string      `json:"nonce"`
	URL   string      `json:"url"`
	JWK   *JSONWebKey `json:"jwk,omitempty"`
	KID   string      `json:"kid,omitempty"`
}

// JSONWebKey is the subset of RFC 7517/7518/8037 needed for ACME account
// keys: RSA and EC public keys, plus Ed25519 (kty "OKP").
type JSONWebKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

var (
	errJWSMalformed      = errors.New("malformed jws request")
	errJWSUnsupportedAlg = errors.New("unsupported jws alg")
	errJWSBadURL         = errors.New("jws url does not match request")
	errJWSBadNonce       = errors.New("jws nonce invalid or already used")
	errJWSBadSignature   = errors.New("jws signature verification failed")
	errJWSNeedsJWK       = errors.New("jws protected header must contain jwk")
	errJWSNeedsKID       = errors.New("jws protected header must contain kid")
	errJWSBothJWKAndKID  = errors.New("jws protected header must not contain both jwk and kid")
	errAccountNotFound   = errors.New("account does not exist or has no bound key")
)

// verifiedJWS is the result of a successfully verified outer JWS.
type verifiedJWS struct {
	Payload   []byte
	PublicKey crypto.PublicKey
	JWK       *JSONWebKey // set only when the header carried an inline jwk
	KID       string      // set only when the header carried a kid
}

// parseJWS unmarshals the Flattened JSON Serialization envelope from a
// request body. It does not verify anything; verifyJWS does that.
func parseJWS(body []byte) (*JWS, error) {
	var jws JWS
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, fmt.Errorf("%w: %v", errJWSMalformed, err)
	}
	if jws.Protected == "" || jws.Signature == "" {
		return nil, fmt.Errorf("%w: missing protected or signature", errJWSMalformed)
	}
	return &jws, nil
}

// verifyJWS validates jws per RFC 8555 §6.2: the protected header's
// alg/nonce/url, resolves the signing key from either an inline jwk or an
// existing account (via resolveKID), and verifies the signature over
// protected+"."+payload. requireJWK is true only for new-account, where no
// account exists yet to reference by kid; every other endpoint requires kid.
func verifyJWS(jws *JWS, expectedURL string, requireJWK bool, resolveKID func(kid string) (crypto.PublicKey, error), consumeNonce func(nonce string) bool) (*verifiedJWS, error) {
	hdrJSON, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, fmt.Errorf("%w: protected: %v", errJWSMalformed, err)
	}
	var hdr jwsProtectedHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, fmt.Errorf("%w: protected: %v", errJWSMalformed, err)
	}
	if hdr.URL != expectedURL {
		return nil, errJWSBadURL
	}
	if hdr.JWK != nil && hdr.KID != "" {
		return nil, errJWSBothJWKAndKID
	}
	if requireJWK && hdr.JWK == nil {
		return nil, errJWSNeedsJWK
	}
	if !requireJWK && hdr.KID == "" {
		return nil, errJWSNeedsKID
	}

	var pub crypto.PublicKey
	if hdr.JWK != nil {
		pub, err = hdr.JWK.publicKey()
		if err != nil {
			return nil, fmt.Errorf("%w: jwk: %v", errJWSMalformed, err)
		}
	} else {
		pub, err = resolveKID(hdr.KID)
		if err != nil {
			return nil, err
		}
	}

	if !consumeNonce(hdr.Nonce) {
		return nil, errJWSBadNonce
	}

	var payload []byte
	if jws.Payload != "" {
		payload, err = base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: payload: %v", errJWSMalformed, err)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", errJWSMalformed, err)
	}

	signingInput := []byte(jws.Protected + "." + jws.Payload)
	if err := verifyJWSSignature(hdr.Alg, pub, signingInput, sig); err != nil {
		return nil, err
	}

	return &verifiedJWS{Payload: payload, PublicKey: pub, JWK: hdr.JWK, KID: hdr.KID}, nil
}

// verifyJWSSignature checks sig over signingInput for the three account-key
// algorithms this server's own keystore package can produce (RSA-2048 =>
// RS256, ECDSA P-256 => ES256, Ed25519 => EdDSA) — the key types RFC 8555
// clients commonly use.
func verifyJWSSignature(alg string, pub crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RS256 requires an RSA key", errJWSBadSignature)
		}
		sum := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, sum[:], sig); err != nil {
			return fmt.Errorf("%w: %v", errJWSBadSignature, err)
		}
		return nil
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ES256 requires a P-256 key", errJWSBadSignature)
		}
		// JWS ES256 signatures are the raw R||S concatenation (RFC 7518 §3.4),
		// not ASN.1 DER — each of R and S is exactly the P-256 coordinate size.
		if len(sig) != 64 {
			return fmt.Errorf("%w: bad ES256 signature length", errJWSBadSignature)
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		sum := sha256.Sum256(signingInput)
		if !ecdsa.Verify(ecPub, sum[:], r, s) {
			return fmt.Errorf("%w: ecdsa signature invalid", errJWSBadSignature)
		}
		return nil
	case "EdDSA":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: EdDSA requires an Ed25519 key", errJWSBadSignature)
		}
		if !ed25519.Verify(edPub, signingInput, sig) {
			return fmt.Errorf("%w: ed25519 signature invalid", errJWSBadSignature)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", errJWSUnsupportedAlg, alg)
	}
}

// publicKey converts a JSON Web Key to a crypto.PublicKey, per RFC 7518 §6.2
// (EC), §6.3 (RSA) and RFC 8037 (OKP/Ed25519).
func (k *JSONWebKey) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := jwkBigInt(k.X)
		if err != nil {
			return nil, fmt.Errorf("x: %w", err)
		}
		y, err := jwkBigInt(k.Y)
		if err != nil {
			return nil, fmt.Errorf("y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("ec point not on curve")
		}
		return pub, nil
	case "RSA":
		n, err := jwkBigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("e: %w", err)
		}
		if len(eBytes) == 0 || len(eBytes) > 8 {
			return nil, errors.New("invalid rsa exponent")
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e <= 0 {
			return nil, errors.New("invalid rsa exponent")
		}
		if n.Sign() <= 0 || n.BitLen() < 2048 {
			return nil, errors.New("rsa modulus too small")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("x: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 key length")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", k.Kty)
	}
}

func jwkBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty value")
	}
	return new(big.Int).SetBytes(b), nil
}

// jwkThumbprint computes the RFC 7638 JSON Web Key Thumbprint: SHA-256 over
// the canonical JSON of just the key's required members, base64url-encoded
// without padding. RFC 8555 §8.1 builds KeyAuthorization as
// token+"."+thumbprint, and §7.3.4 requires the External Account Binding
// payload to be bound to this same value.
func jwkThumbprint(k *JSONWebKey) (string, error) {
	canonical, err := canonicalJWK(k)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// canonicalJWK renders the RFC 7638 §3 canonical form: only the required
// members for the key type, ordered lexicographically by member name, with
// no insignificant whitespace.
func canonicalJWK(k *JSONWebKey) ([]byte, error) {
	switch k.Kty {
	case "EC":
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return nil, errors.New("incomplete EC jwk")
		}
		return json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{k.Crv, k.Kty, k.X, k.Y})
	case "RSA":
		if k.E == "" || k.N == "" {
			return nil, errors.New("incomplete RSA jwk")
		}
		return json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{k.E, k.Kty, k.N})
	case "OKP":
		if k.Crv == "" || k.X == "" {
			return nil, errors.New("incomplete OKP jwk")
		}
		return json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{k.Crv, k.Kty, k.X})
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", k.Kty)
	}
}

// accountIDFromKID extracts the account ID from a kid URL of the form
// baseURL+"/acme/account/"+id, per RFC 8555 §7.1.2 (the account URL doubles
// as its kid).
func accountIDFromKID(kid, baseURL string) (string, bool) {
	prefix := baseURL + "/acme/account/"
	if len(kid) <= len(prefix) || kid[:len(prefix)] != prefix {
		return "", false
	}
	id := kid[len(prefix):]
	if id == "" {
		return "", false
	}
	return id, true
}
