// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentdiscovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// W14-05: JKS/PKCS#12/kubeconfig keystore discovery — certs only, keys
// never extracted.

// p12FixtureBase64 is a THROWAWAY test PKCS#12 (self-signed
// CN=p12test.example.com, password "changeit", legacy SHA-1 MAC). The
// key inside is a generated test-only key, never used anywhere real.
const p12FixtureBase64 = `MIID3QIBAzCCA5sGCSqGSIb3DQEHAaCCA4wEggOIMIIDhDCCAlcGCSqGSIb3DQEHBqCCAkgwggJEAgEAMIICPQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIga4qshoZQ7ACAggAgIICEG8ETENyLr75RzZb0Ga/ouY1gB/G1l+llgx6bAuxqA9kjcvuIKMWVgrJDDwhF3s6RlPwWUYLnGUg2XG++LdhSbB+zetP1LN2O1Cci8Cu4imKZD4tcd1f5jRCSoa2Gdc1FPMjOsceKAMlNAnqHsTLVHbCxySIKShMpCitaWPBSGqW2VH3lPRlhKgOzA/PjCkIedPx/5eeoPDYofh4oV/2BYTNbhY2g/qYg/suzdkgVAenxBpFy3CZOi+JuN9WSJVO9uub+JnRW+dyFh1DSE2tqMM+93FLBVpCpPLByOtwVT3Y/svXU0jPyVI80HWG0+7MOiUx4TRDF2cUyKo6m/DkgCxg8HMAv8sRgplaZw0okzSpBBNIK3q/W+uPzYom/bjLau/GEihDDJtt2qkDNMm87m35YcidFdmYnuEGjj97lJzcmGmbLSWsVf4eOwYqWbSHt6TIXUf42AfDjfuULJPdVl8++YNaH9wlBSkA8CwPC07kc61Lu7IUmazFEYGFr4BdVTDKQJr/9BodV7SI+qp1RTBWp2XaUxEs9FdQ3YMA0OAjdayEPsFzzNsQNOhXO5HQndPvppXZAkGLlCqNRu5AEZaS50XfaJyEjfe/puWl57tVq7KQDAZABfPgoiE+5pPEQz5tmxbcUdoFPxntRqrk//sTYnnWEXVI9vqz5XtXvCXMYN4HYJ1w/XDgbx/eYJrbOjCCASUGCSqGSIb3DQEHAaCCARYEggESMIIBDjCCAQoGCyqGSIb3DQEMCgECoIG0MIGxMBwGCiqGSIb3DQEMAQMwDgQIHUDRXTDCCCICAggABIGQrmTRQMuQob0wP2F/8bga26dGguezI+vkRKvHea8h0L1vKT3nT70nlgpKsCqF5auIInXf+4pXdlOy3cSXuusNMlFspKLIQZvnDrQOQ+o5NoAhhmnJjyMpT/nsCCiUq7EGIUq+QB/HLedFylC52g3JY1k10wbqI/I/2yXZ+c8XwazknnoeMe82wGWbjT9S6+pDMUQwHQYJKoZIhvcNAQkUMRAeDgBwADEAMgB0AGUAcwB0MCMGCSqGSIb3DQEJFTEWBBQsP6ukUS1T05wHM+CooJfDMXlMbTA5MCEwCQYFKw4DAhoFAAQU957kBGnA6EAhBIV4Rq85E8XR5LcEELgzIJBbalJD6JBxGpD2WZMCAggA`

func testDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der
}

// buildJKS hand-encodes a JKS v2 blob: a trusted-cert entry plus a
// key entry whose encrypted key blob is [0xDE 0xAD 0xBE 0xEF] (a
// sentinel the reader must never surface) with a one-cert chain.
func buildJKS(t *testing.T, trusted, chained []byte) []byte {
	t.Helper()
	var b []byte
	u32 := func(v uint32) { var x [4]byte; binary.BigEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	u16 := func(v uint16) { var x [2]byte; binary.BigEndian.PutUint16(x[:], v); b = append(b, x[:]...) }
	i64 := func(v int64) { var x [8]byte; binary.BigEndian.PutUint64(x[:], uint64(v)); b = append(b, x[:]...) }
	utf := func(s string) { u16(uint16(len(s))); b = append(b, []byte(s)...) }
	cert := func(der []byte) { utf("X.509"); u32(uint32(len(der))); b = append(b, der...) }

	u32(jksMagic)
	u32(2) // version
	u32(2) // entry count

	// Entry 1: trusted cert.
	u32(2)
	utf("trusted-alias")
	i64(time.Now().UnixMilli())
	cert(trusted)

	// Entry 2: private key entry.
	u32(1)
	utf("key-alias")
	i64(time.Now().UnixMilli())
	secret := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	u32(uint32(len(secret)))
	b = append(b, secret...) // encrypted key blob — reader must skip
	u32(1)                   // chain length
	cert(chained)
	return b
}

func TestParseJKSExtractsCertsNotKeys(t *testing.T) {
	trusted := testDER(t, "trusted.example.com")
	chained := testDER(t, "keyentry.example.com")
	blob := buildJKS(t, trusted, chained)

	certs, err := ParseJKSCerts(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected trusted + chain cert, got %d", len(certs))
	}
	got := map[string]bool{certs[0].Subject.CommonName: true, certs[1].Subject.CommonName: true}
	if !got["trusted.example.com"] || !got["keyentry.example.com"] {
		t.Fatalf("wrong certs: %v", got)
	}
	// The key sentinel must never appear in a parsed certificate.
	for _, c := range certs {
		if strings.Contains(string(c.Raw), "\xDE\xAD\xBE\xEF") {
			t.Fatal("encrypted key bytes leaked into a cert")
		}
	}
}

func TestParsePKCS12CertsDiscardsKey(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(p12FixtureBase64)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	certs, err := ParsePKCS12Certs(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "p12test.example.com" {
		t.Fatalf("expected the fixture cert, got %+v", certs)
	}
	// A ScanKeystoreFile run must carry no PRIVATE KEY anywhere.
	var res KeystoreScanResult
	ScanKeystoreFile("/opt/app/store.p12", data, nil, &res)
	if len(res.Certs) != 1 {
		t.Fatalf("scan: %+v", res)
	}
	if strings.Contains(fmt.Sprintf("%+v", res), "PRIVATE KEY") {
		t.Fatal("scan result must not carry key material")
	}
}

func TestParseKubeconfigCerts(t *testing.T) {
	der := testDER(t, "kube-client.example.com")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kubeconfig := "apiVersion: v1\nusers:\n- name: admin\n  user:\n    client-certificate-data: " +
		base64.StdEncoding.EncodeToString(certPEM) + "\n"
	certs := ParseKubeconfigCerts([]byte(kubeconfig))
	if len(certs) != 1 || certs[0].Subject.CommonName != "kube-client.example.com" {
		t.Fatalf("kubeconfig cert: %+v", certs)
	}
}

func TestScanKeystoreCorruptStoreInventoried(t *testing.T) {
	var res KeystoreScanResult
	if !ScanKeystoreFile("/opt/broken.jks", []byte("not a keystore"), nil, &res) {
		t.Fatal(".jks must be recognized as a keystore")
	}
	if len(res.UnreadableStores) != 1 || !strings.Contains(res.UnreadableStores[0], "broken.jks") {
		t.Fatalf("corrupt store must be inventoried: %v", res.UnreadableStores)
	}
	if len(res.Certs) != 0 {
		t.Fatal("no certs from a corrupt store")
	}
}
