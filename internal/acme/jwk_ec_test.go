// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestJWKECPublicKeyRoundTripAndRejections(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := publicKeyToJWK(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := jwk.publicKey()
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	want, _ := priv.PublicKey.Bytes()
	gotBytes, _ := got.(*ecdsa.PublicKey).Bytes()
	if !bytes.Equal(want, gotBytes) {
		t.Fatal("round-tripped key differs")
	}

	b64 := base64.RawURLEncoding.EncodeToString
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)

	// A coordinate that lost leading zero bytes is still accepted (padded).
	if c, err := jwkCoordinate(b64([]byte{0x01}), p256CoordinateSize); err != nil || len(c) != p256CoordinateSize || c[31] != 0x01 {
		t.Fatalf("short coordinate: %x, %v", c, err)
	}
	// Longer than the field size is refused rather than truncated.
	if _, err := jwkCoordinate(b64(append([]byte{0x01}, x...)), p256CoordinateSize); err == nil {
		t.Fatal("overlong coordinate accepted")
	}
	// An off-curve point is refused.
	bad := *jwk
	y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	y[len(y)-1] ^= 0x01
	bad.Y = b64(y)
	if _, err := bad.publicKey(); err == nil {
		t.Fatal("off-curve point accepted")
	}
}
