// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

// Fixture chain: root -> f9 intermediate (no CA basicConstraints, like the
// real device) -> attestation leaf over the device key. Generated in-test.
type fixture struct {
	root      *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	inter     *x509.Certificate
	interKey  *ecdsa.PrivateKey
	leafPEM   string
	interPEM  string
	devicePub *ecdsa.PublicKey
	notBefore time.Time
	notAfter  time.Time
}

func pemOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mkCert(t *testing.T, tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, der
}

func newRoot(t *testing.T, cn string, nb, na time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	k := genKey(t)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	c, _ := mkCert(t, tpl, tpl, &k.PublicKey, k)
	return c, k
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	f := &fixture{notBefore: nb, notAfter: na}
	f.root, f.rootKey = newRoot(t, "Fixture PIV Root", nb, na)
	f.interKey = genKey(t)
	f.inter, _ = mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fixture PIV Attestation"},
		NotBefore: nb, NotAfter: na}, f.root, &f.interKey.PublicKey, f.rootKey)
	f.interPEM = pemOf(f.inter.Raw)
	dev := genKey(t)
	f.devicePub = &dev.PublicKey
	f.leafPEM = f.leaf(t, f.inter, f.interKey, f.devicePub, true)
	return f
}

func (f *fixture) leaf(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, pub *ecdsa.PublicKey, yubico bool) string {
	t.Helper()
	serial, _ := asn1.Marshal(big.NewInt(12345678))
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "YubiKey PIV Attestation 9c"},
		NotBefore: f.notBefore, NotAfter: f.notAfter}
	if yubico {
		tpl.ExtraExtensions = []pkix.Extension{
			{Id: oidFirmware, Value: []byte{5, 4, 3}},
			{Id: oidSerial, Value: serial},
			{Id: oidPolicy, Value: []byte{2, 1}},
		}
	}
	_, der := mkCert(t, tpl, parent, pub, signer)
	return pemOf(der)
}

func (f *fixture) verifier() *Verifier {
	return &Verifier{Roots: []*x509.Certificate{f.root}}
}

func TestVerifyAcceptsChainedAttestation(t *testing.T) {
	f := newFixture(t)
	res, err := f.verifier().VerifyYubiKeyPIV(f.leafPEM, []string{f.interPEM}, f.devicePub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(f.devicePub)
	if res.Format != FormatYubiKeyPIV || res.Serial != "12345678" || res.Firmware != "5.4.3" ||
		res.PINPolicy != 2 || res.TouchPolicy != 1 || res.KeySPKISHA256 != sha256Hex(spki) ||
		res.VendorRootSHA256 != sha256Hex(f.root.Raw) || res.VerifiedAt.IsZero() {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyRejectsForgedRoot(t *testing.T) {
	f := newFixture(t)
	other, _ := newRoot(t, "Fixture PIV Root", f.notBefore, f.notAfter) // same subject, different key
	v := &Verifier{Roots: []*x509.Certificate{other}}
	_, err := v.VerifyYubiKeyPIV(f.leafPEM, []string{f.interPEM}, f.devicePub)
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation, got %v", err)
	}
	// Missing intermediate also fails.
	if _, err := f.verifier().VerifyYubiKeyPIV(f.leafPEM, nil, f.devicePub); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation without intermediate, got %v", err)
	}
}

func TestVerifyRejectsKeyMismatch(t *testing.T) {
	f := newFixture(t)
	_, err := f.verifier().VerifyYubiKeyPIV(f.leafPEM, []string{f.interPEM}, &genKey(t).PublicKey)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("want ErrKeyMismatch, got %v", err)
	}
}

func TestVerifyRejectsPlainCertWithoutYubicoExtension(t *testing.T) {
	f := newFixture(t)
	plain := f.leaf(t, f.inter, f.interKey, f.devicePub, false)
	_, err := f.verifier().VerifyYubiKeyPIV(plain, []string{f.interPEM}, f.devicePub)
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	f := newFixture(t)
	v := f.verifier()
	v.Now = func() time.Time { return f.notAfter.Add(time.Hour) }
	_, err := v.VerifyYubiKeyPIV(f.leafPEM, []string{f.interPEM}, f.devicePub)
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation, got %v", err)
	}
}

func TestEmptyRootsFailsClosed(t *testing.T) {
	f := newFixture(t)
	_, err := (&Verifier{}).VerifyYubiKeyPIV(f.leafPEM, []string{f.interPEM}, f.devicePub)
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation, got %v", err)
	}
}

func TestRejectsOversizeAndGarbage(t *testing.T) {
	f := newFixture(t)
	v := f.verifier()
	big := make([]byte, maxPEMBytes+1)
	for _, in := range []string{"", "junk", string(big)} {
		if _, err := v.VerifyYubiKeyPIV(in, nil, f.devicePub); !errors.Is(err, ErrInvalidAttestation) {
			t.Fatalf("input len %d: want ErrInvalidAttestation, got %v", len(in), err)
		}
	}
	many := []string{f.interPEM, f.interPEM, f.interPEM, f.interPEM}
	if _, err := v.VerifyYubiKeyPIV(f.leafPEM, many, f.devicePub); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("too many intermediates: %v", err)
	}
}

func TestNewVerifierShipsNoRootsAndLoadsDir(t *testing.T) {
	t.Setenv(RootsDirEnv, "")
	v, err := NewVerifier()
	if err != nil || len(v.Roots) != 0 {
		t.Fatalf("embedded: roots=%d err=%v", len(v.Roots), err)
	}
	f := newFixture(t)
	dir := t.TempDir()
	writeFile(t, dir+"/root.pem", pemOf(f.root.Raw))
	t.Setenv(RootsDirEnv, dir)
	v, err = NewVerifier()
	if err != nil || len(v.Roots) != 1 {
		t.Fatalf("dir: roots=%d err=%v", len(v.Roots), err)
	}
	if _, err := v.VerifyYubiKeyPIV(f.leafPEM, []string{f.interPEM}, f.devicePub); err != nil {
		t.Fatalf("verify with dir root: %v", err)
	}
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
