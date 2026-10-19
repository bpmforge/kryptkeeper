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
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pkcs12"
	sslmatepkcs12 "software.sslmate.com/src/go-pkcs12"
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

// fakeSealedKey stands in for a JCEKS key entry's Java-serialized
// SealedObject. It is clearly-marked fake bytes: the real stream magic
// (AC ED 00 05), a sentinel the scanner must never surface, and decoys that
// look like the start of a cert chain but are not.
func fakeSealedKey() []byte {
	b := []byte{0xAC, 0xED, 0x00, 0x05}
	b = append(b, []byte("FAKE-SEALED-KEY-NOT-REAL")...)
	b = append(b, 0xDE, 0xAD, 0xBE, 0xEF)
	// Decoy: plausible count + "X.509" marker, but the "DER" is not a cert.
	b = append(b, 0, 0, 0, 1, 0x00, 0x05, 'X', '.', '5', '0', '9', 0, 0, 0, 4, 1, 2, 3, 4)
	return b
}

// buildJCEKS hand-encodes a JCEKS blob: a trusted-cert entry plus a key
// entry (fake sealed blob, then a one-cert chain). With tail set, a
// secret-key (tag 3) entry follows.
func buildJCEKS(t *testing.T, trusted, chained []byte, tail bool) []byte {
	t.Helper()
	var b []byte
	u32 := func(v uint32) { var x [4]byte; binary.BigEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	u16 := func(v uint16) { var x [2]byte; binary.BigEndian.PutUint16(x[:], v); b = append(b, x[:]...) }
	i64 := func(v int64) { var x [8]byte; binary.BigEndian.PutUint64(x[:], uint64(v)); b = append(b, x[:]...) }
	utf := func(s string) { u16(uint16(len(s))); b = append(b, []byte(s)...) }
	cert := func(der []byte) { utf("X.509"); u32(uint32(len(der))); b = append(b, der...) }

	u32(jceksMagic)
	u32(2)
	if tail {
		u32(3)
	} else {
		u32(2)
	}
	u32(2)
	utf("trusted-alias")
	i64(time.Now().UnixMilli())
	cert(trusted)

	u32(1)
	utf("key-alias")
	i64(time.Now().UnixMilli())
	b = append(b, fakeSealedKey()...)
	u32(1)
	cert(chained)

	if tail {
		u32(3)
		utf("secret-alias")
		i64(time.Now().UnixMilli())
		b = append(b, 0xAC, 0xED, 0x00, 0x05)
	}
	return b
}

func TestParseJCEKSTwoCerts(t *testing.T) {
	blob := buildJCEKS(t, testDER(t, "trusted.example.com"), testDER(t, "keyentry.example.com"), false)
	certs, err := ParseJCEKSCerts(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("want 2 certs, got %d", len(certs))
	}
	got := map[string]bool{}
	for _, c := range certs {
		got[c.Subject.CommonName] = true
	}
	if !got["trusted.example.com"] || !got["keyentry.example.com"] {
		t.Fatalf("wrong certs: %v", got)
	}
}

func TestParseJCEKSNeverSurfacesKey(t *testing.T) {
	blob := buildJCEKS(t, testDER(t, "a.example.com"), testDER(t, "b.example.com"), false)
	var res KeystoreScanResult
	if !ScanKeystoreFile("/opt/app/store.jceks", blob, nil, &res) {
		t.Fatal(".jceks must be recognised")
	}
	if len(res.Certs) != 2 || len(res.UnreadableStores) != 0 {
		t.Fatalf("scan: %+v", res)
	}
	js, _ := json.Marshal(res)
	for _, leak := range []string{"PRIVATE KEY", "FAKE-SEALED-KEY", "3q2+7w", "deadbeef"} { // 3q2+7w = base64 of DE AD BE EF
		if strings.Contains(strings.ToLower(string(js)), strings.ToLower(leak)) {
			t.Fatalf("scan JSON leaks %q", leak)
		}
	}
	for _, c := range res.Certs {
		if !strings.HasPrefix(c.Source, "jceks:/opt/app/store.jceks") {
			t.Errorf("source %q lacks format and path", c.Source)
		}
	}
}

func TestParseJCEKSSecretKeyEntryStopsWithPartialCerts(t *testing.T) {
	blob := buildJCEKS(t, testDER(t, "a.example.com"), testDER(t, "b.example.com"), true)
	certs, err := ParseJCEKSCerts(blob)
	if len(certs) != 2 {
		t.Fatalf("want the 2 certs seen before the secret-key entry, got %d", len(certs))
	}
	if err == nil || !strings.Contains(err.Error(), "secret-key entry") {
		t.Fatalf("err = %v", err)
	}
}

// A bare "X.509" pattern is not enough: with no parseable cert after the
// sealed blob the chain must be reported as not located.
func TestParseJCEKSChainNotLocatedWithoutValidDER(t *testing.T) {
	var b []byte
	u32 := func(v uint32) { var x [4]byte; binary.BigEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	u16 := func(v uint16) { var x [2]byte; binary.BigEndian.PutUint16(x[:], v); b = append(b, x[:]...) }
	u32(jceksMagic)
	u32(2)
	u32(1)
	u32(1)
	u16(1)
	b = append(b, 'k')
	b = append(b, make([]byte, 8)...)
	b = append(b, fakeSealedKey()...)
	certs, err := ParseJCEKSCerts(b)
	if len(certs) != 0 || err == nil || !strings.Contains(err.Error(), "chain not located") {
		t.Fatalf("certs=%d err=%v", len(certs), err)
	}
}

func TestSniffKeystoreByContentNotExtension(t *testing.T) {
	jceks := buildJCEKS(t, testDER(t, "a.example.com"), testDER(t, "b.example.com"), false)
	if got := sniffKeystore(jceks); got != "jceks" {
		t.Fatalf("sniff = %q, want jceks", got)
	}
	if got := sniffKeystore(buildJKS(t, testDER(t, "a"), testDER(t, "b"))); got != "jks" {
		t.Fatalf("sniff = %q, want jks", got)
	}
	if got := sniffKeystore(fakeBCFKS(t)); got != "bcfks" {
		t.Fatalf("sniff = %q, want bcfks", got)
	}
	if got := sniffKeystore(testDER(t, "plain-cert.example.com")); got != "" {
		t.Fatalf("an X.509 DER must not sniff as a keystore, got %q", got)
	}
	if got := sniffKeystore([]byte("not a keystore")); got != "" {
		t.Fatalf("sniff = %q, want empty", got)
	}
	// JCEKS bytes under a .jks name are still parsed as JCEKS.
	var res KeystoreScanResult
	ScanKeystoreFile("/opt/app/mislabeled.jks", jceks, nil, &res)
	if len(res.Certs) != 2 || !strings.HasPrefix(res.Certs[0].Source, "jceks:") {
		t.Fatalf("mislabeled JCEKS: %+v", res)
	}
}

// fakeBCFKS is a structurally BCFKS-shaped DER (ObjectStore{
// EncryptedObjectStoreData{AlgorithmIdentifier{OID}, OCTET STRING}, check}).
// The OID and bytes are fake placeholders, not real BouncyCastle output.
func fakeBCFKS(t *testing.T) []byte {
	t.Helper()
	type algID struct {
		OID asn1.ObjectIdentifier
	}
	type encData struct {
		Alg     algID
		Content []byte
	}
	type store struct {
		Data  encData
		Check []byte
	}
	der, err := asn1.Marshal(store{
		Data:  encData{Alg: algID{OID: asn1.ObjectIdentifier{1, 2, 3, 4, 5}}, Content: []byte("FAKE-ENCRYPTED-STORE")},
		Check: []byte("FAKE-MAC"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestScanBCFKSUnreadableWithoutPassword(t *testing.T) {
	var res KeystoreScanResult
	if !ScanKeystoreFile("/opt/app/store.bcfks", fakeBCFKS(t), nil, &res) {
		t.Fatal(".bcfks must be recognised")
	}
	want := "/opt/app/store.bcfks: " + reasonPasswordUnknown
	if len(res.UnreadableStores) != 1 || res.UnreadableStores[0] != want || len(res.Certs) != 0 {
		t.Fatalf("scan: %+v", res)
	}
}

func TestScanKeystoreWrongPasswordReason(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "locked.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p12, err := sslmatepkcs12.LegacyDES.Encode(key, cert, nil, "test-only-not-a-default")
	if err != nil {
		t.Fatal(err)
	}

	var res KeystoreScanResult
	ScanKeystoreFile("/opt/app/locked.p12", p12, nil, &res)
	if len(res.UnreadableStores) != 1 || !strings.HasSuffix(res.UnreadableStores[0], "keystore, password unknown") || len(res.Certs) != 0 {
		t.Fatalf("wrong-password P12: %+v", res)
	}

	// A configured password opens it: no unreadable entry, cert returned.
	res = KeystoreScanResult{}
	ScanKeystoreFile("/opt/app/locked.p12", p12, []string{"test-only-not-a-default"}, &res)
	if len(res.UnreadableStores) != 0 || len(res.Certs) != 1 {
		t.Fatalf("configured password: %+v", res)
	}
}

func TestScanKeystoreNonPasswordErrorKeepsOwnText(t *testing.T) {
	var res KeystoreScanResult
	ScanKeystoreFile("/opt/app/garbage.p12", []byte("garbage"), nil, &res)
	if len(res.UnreadableStores) != 1 || strings.HasSuffix(res.UnreadableStores[0], reasonPasswordUnknown) {
		t.Fatalf("a malformed P12 is not a password problem: %v", res.UnreadableStores)
	}
}

func TestWalkLinuxCerts_FindsKeystoresAndSkipsUnrelatedConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("app/store.jceks", buildJCEKS(t, testDER(t, "w-trusted.example.com"), testDER(t, "w-key.example.com"), false))
	write("app/old.jks", buildJKS(t, testDER(t, "w-jks-a.example.com"), testDER(t, "w-jks-b.example.com")))
	write("app/broken.keystore", []byte("garbage"))
	// A "config" outside .kube must NOT be read as a kubeconfig.
	write("app/config", []byte("client-certificate-data: "+base64.StdEncoding.EncodeToString(testDER(t, "decoy.example.com"))))

	certs, err := WalkLinuxCerts([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	cns := map[string]bool{}
	for _, c := range certs {
		cns[c.Subject] = true
		if strings.Contains(c.Subject, "decoy") {
			t.Fatal("plain 'config' file outside .kube was scanned")
		}
	}
	if len(certs) != 4 {
		t.Fatalf("want 4 keystore certs (2 jceks + 2 jks), got %d: %v", len(certs), cns)
	}
}

// W34-20: keytool on JDK 11+ writes PKCS12 with a SHA-256 MAC and PBES2, which
// golang.org/x/crypto/pkcs12 cannot open.
func TestParsePKCS12CertsReadsModernEncoding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "modern-p12.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pfx, err := sslmatepkcs12.Modern2023.Encode(key, cert, nil, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	if _, oldErr := pkcs12.ToPEM(pfx, "changeit"); oldErr == nil {
		t.Skip("x/crypto/pkcs12 reads this encoding; the fallback is not exercised")
	}
	got, err := ParsePKCS12Certs(pfx, []string{"changeit", ""})
	if err != nil || len(got) != 1 || got[0].Subject.CommonName != "modern-p12.example.com" {
		t.Fatalf("certs %v err %v", got, err)
	}
}
