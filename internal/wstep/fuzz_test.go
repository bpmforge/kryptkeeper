// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"encoding/base64"
	"testing"
)

// FuzzRequestCSR drives the WS-Trust BinarySecurityToken decoder: base64,
// then PKCS#10, PKCS#7-wrapped PKCS#10 (renewal) or CMC PKIData. Rejection
// is fine; a panic or a nil request on success is not.
func FuzzRequestCSR(f *testing.F) {
	csr := hostileCSR(f)
	cmc := cmcPKIDataFor(f, csr)
	f.Add(base64.StdEncoding.EncodeToString(csr))
	f.Add(base64.StdEncoding.EncodeToString(signedDataAround(f, csr)))
	f.Add(base64.StdEncoding.EncodeToString(signedDataAround(f, cmc)))
	f.Add("")
	f.Add("!!!")

	f.Fuzz(func(t *testing.T, token string) {
		got, _, err := requestCSR(token)
		if err == nil && got == nil {
			t.Fatal("nil CSR with nil error")
		}
	})
}

// FuzzCMCCertificationRequest targets the in-house CMC PKIData ASN.1 walker
// directly so mutations are not rejected by the outer base64/PKCS#7 layers.
func FuzzCMCCertificationRequest(f *testing.F) {
	csr := hostileCSR(f)
	f.Add(cmcPKIDataFor(f, csr))
	f.Add(cmcPKIDataFor(f, csr, csr))
	f.Add(cmcPKIDataFor(f))
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		out, err := cmcCertificationRequest(der)
		if err == nil && len(out) == 0 {
			t.Fatal("empty request with nil error")
		}
	})
}
