// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// FuzzParsePKIMessage fuzzes the RFC 4210 PKIMessage envelope parser and,
// when it parses, the PBM protection check against the fixture secret.
func FuzzParsePKIMessage(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	body := buildCRMFIRBody(f, priv, "fuzz-cmp")
	f.Add(buildProtectedPKIMessage(f, PKIBodyIR, body, pbmOptions{}))
	f.Add(buildProtectedPKIMessage(f, PKIBodyIR, body, pbmOptions{skip: true}))
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := parsePKIMessage(data)
		if err != nil {
			return
		}
		if msg == nil {
			t.Fatal("nil message with nil error")
		}
		_ = verifyPBMProtection(&msg.Header, msg.Protection, msg.BodyRaw.FullBytes, []byte(testSecret))
	})
}

// FuzzParseCertReqMessages fuzzes the CRMF CertReqMessages decoder, which
// also verifies proof-of-possession signatures.
func FuzzParseCertReqMessages(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(buildCRMFIRBody(f, priv, "fuzz-cmp"))
	f.Add(buildCRMFBodySANs(f, &priv.PublicKey, oidECDSAWithSHA256, func(h []byte) ([]byte, error) {
		return ecdsa.SignASN1(rand.Reader, priv, h)
	}, "fuzz-cmp", []string{"a.example.com"}))
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		reqs, err := parseCertReqMessages(data)
		if err == nil && len(reqs) == 0 {
			t.Fatal("no requests with nil error")
		}
	})
}
