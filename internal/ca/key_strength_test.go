// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCheckPublicKeyStrength(t *testing.T) {
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak test key
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		pub  any
		ok   bool
	}{
		{"rsa1024", &rsa1024.PublicKey, false},
		{"rsa2048", &rsa2048.PublicKey, true},
		{"p224", &p224.PublicKey, false},
		{"p256", &p256.PublicKey, true},
		{"p384", &p384.PublicKey, true},
		{"ed25519", edPub, true},
		{"nil", nil, false},
		{"string", "nope", false},
	}
	for _, c := range cases {
		if err := CheckPublicKeyStrength(c.pub); (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.ok)
		}
	}
}
