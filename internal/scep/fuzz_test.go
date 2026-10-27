// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/smallstep/pkcs7"
)

// FuzzParsePKIMessage fuzzes the SCEP pkiMessage path that precedes any
// authentication: PKCS#7 parse, transactionID/senderNonce extraction, and the
// signature and messageType gate in unwrapRequest (a zero Server stops at the
// missing decrypter, after Verify and GetOnlySigner have run on the input).
func FuzzParsePKIMessage(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	cert := selfSignedRSACert(f, key, "fuzz-client")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fuzz"}}, key)
	if err != nil {
		f.Fatal(err)
	}
	msg, _, _ := buildPKIOperation(f, cert, key, cert, csrDER)
	f.Add(msg)
	f.Add(msg[:len(msg)/2])
	f.Add([]byte{0x30, 0x00})

	s := &Server{}
	f.Fuzz(func(t *testing.T, data []byte) {
		outer, err := pkcs7.Parse(data)
		if err != nil {
			return
		}
		if outer == nil {
			t.Fatal("nil PKCS7 with nil error")
		}
		txID, _, ok := transactionAndNonce(outer)
		if !ok {
			return
		}
		if _, _, _, err := s.unwrapRequest(outer, txID); err == nil {
			t.Fatal("zero Server accepted a pkiMessage")
		}
	})
}
