// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// FuzzCertSpotterIssuance fuzzes the third-party Cert Spotter JSON page the
// monitor trusts nothing about: decode, then certificate parse and entry
// construction.
func FuzzCertSpotterIssuance(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xBEEF),
		Subject:      pkix.Name{CommonName: "ct.example.com"},
		DNSNames:     []string{"ct.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	page, _ := json.Marshal([]certSpotterIssuance{{
		ID: "1", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
		CertDER: base64.StdEncoding.EncodeToString(der),
	}})
	f.Add(page)
	f.Add([]byte(`[{"id":"2","cert_der":"AAAA"}]`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var items []certSpotterIssuance
		if json.Unmarshal(data, &items) != nil {
			return
		}
		for _, it := range items {
			e, err := certSpotterEntry(it)
			if err == nil && e.Serial == "" {
				t.Fatal("entry without a serial")
			}
		}
	})
}
