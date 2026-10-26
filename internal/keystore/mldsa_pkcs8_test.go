// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var mldsaLevels = []Algorithm{MLDSA44, MLDSA65, MLDSA87}

func mldsaVerify(t *testing.T, algo Algorithm, pub crypto.PublicKey, msg, sig []byte) bool {
	t.Helper()
	switch algo {
	case MLDSA44:
		return mldsa44.Verify(pub.(*mldsa44.PublicKey), msg, nil, sig)
	case MLDSA65:
		return mldsa65.Verify(pub.(*mldsa65.PublicKey), msg, nil, sig)
	default:
		return mldsa87.Verify(pub.(*mldsa87.PublicKey), msg, nil, sig)
	}
}

func TestMLDSAPKCS8RoundTripAllLevels(t *testing.T) {
	for _, algo := range mldsaLevels {
		t.Run(string(algo), func(t *testing.T) {
			_, pub, signer, err := generateMLDSAKey(rand.Reader, algo)
			if err != nil {
				t.Fatal(err)
			}
			der, err := MarshalMLDSAPKCS8(signer)
			if err != nil {
				t.Fatal(err)
			}
			// Freshly generated key retains its seed => seed form: 04 22 80 20 ...
			oid, _ := MLDSAOIDForAlgo(algo)
			var env pkcs8Envelope
			if _, err := asn1.Unmarshal(der, &env); err != nil {
				t.Fatal(err)
			}
			if !env.Algo.Algorithm.Equal(oid) || env.PrivateKey[0] != 0x80 || len(env.PrivateKey) != 34 {
				t.Fatalf("expected seed-form PKCS#8, got first byte %#x len %d", env.PrivateKey[0], len(env.PrivateKey))
			}
			parsed, pAlgo, err := ParseMLDSAPKCS8(der)
			if err != nil || pAlgo != algo {
				t.Fatalf("parse: %v algo=%s", err, pAlgo)
			}
			msg := []byte("round trip")
			sig, err := parsed.Sign(rand.Reader, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !mldsaVerify(t, algo, pub, msg, sig) {
				t.Fatal("signature from parsed key does not verify under original public key")
			}
		})
	}
}

func TestMLDSAPKCS8ExpandedFormFromStore(t *testing.T) {
	s := newTestStore(t)
	for _, algo := range mldsaLevels {
		id := "exp-" + string(algo)
		if _, err := s.GenerateKey(id, algo); err != nil {
			t.Fatal(err)
		}
		der, err := s.ExportPrivateKeyPKCS8(id)
		if err != nil {
			t.Fatal(err)
		}
		var env pkcs8Envelope
		if _, err := asn1.Unmarshal(der, &env); err != nil {
			t.Fatal(err)
		}
		if env.PrivateKey[0] != 0x04 {
			t.Fatalf("%s: stored key should export expandedKey form, got %#x", algo, env.PrivateKey[0])
		}
		parsed, _, err := ParseMLDSAPKCS8(der)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := s.PublicKey(id)
		sig, _ := parsed.Sign(rand.Reader, []byte("m"), nil)
		if !mldsaVerify(t, algo, pub, []byte("m"), sig) {
			t.Fatalf("%s: verify failed", algo)
		}
	}
}

func TestMLDSAPKCS8BothForm(t *testing.T) {
	_, _, signer, _ := generateMLDSAKey(rand.Reader, MLDSA44)
	sk := signer.(*mldsa44.PrivateKey)
	exp, _ := sk.MarshalBinary()
	inner, _ := asn1.Marshal(mldsaBoth{Seed: sk.Seed(), ExpandedKey: exp})
	oid, _ := MLDSAOIDForAlgo(MLDSA44)
	der, _ := asn1.Marshal(pkcs8Envelope{Algo: pkcs8AlgID{oid}, PrivateKey: inner})
	if _, _, err := ParseMLDSAPKCS8(der); err != nil {
		t.Fatalf("both form: %v", err)
	}
	// Mismatched seed must be rejected.
	bad := make([]byte, 32)
	inner, _ = asn1.Marshal(mldsaBoth{Seed: bad, ExpandedKey: exp})
	der, _ = asn1.Marshal(pkcs8Envelope{Algo: pkcs8AlgID{oid}, PrivateKey: inner})
	if _, _, err := ParseMLDSAPKCS8(der); err == nil {
		t.Fatal("mismatched both form accepted")
	}
}

func TestParseMLDSAPKCS8Negative(t *testing.T) {
	_, _, signer, _ := generateMLDSAKey(rand.Reader, MLDSA65)
	good, _ := MarshalMLDSAPKCS8(signer)
	oid65, _ := MLDSAOIDForAlgo(MLDSA65)
	seedInner := append([]byte{0x80, 0x20}, make([]byte, 32)...)
	short, _ := asn1.Marshal([]byte{1, 2, 3})
	rsaOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	withParams, _ := asn1.Marshal(struct {
		Version int
		Algo    struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		PrivateKey []byte
	}{0, struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}{oid65, asn1.NullRawValue}, seedInner})
	enc := func(v int, o asn1.ObjectIdentifier, pk []byte) []byte {
		b, _ := asn1.Marshal(pkcs8Envelope{Version: v, Algo: pkcs8AlgID{o}, PrivateKey: pk})
		return b
	}
	cases := map[string][]byte{
		"trailing data":    append(append([]byte{}, good...), 0),
		"wrong oid":        enc(0, rsaOID, seedInner),
		"params present":   withParams,
		"bad version":      enc(1, oid65, seedInner),
		"short seed":       enc(0, oid65, []byte{0x80, 0x1f, 0}),
		"short expanded":   enc(0, oid65, short),
		"empty privateKey": enc(0, oid65, nil),
		"unknown choice":   enc(0, oid65, []byte{0x05, 0x00}),
		"garbage":          {1, 2, 3},
	}
	for name, der := range cases {
		if _, _, err := ParseMLDSAPKCS8(der); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Level mismatch: ML-DSA-44 expanded bytes under the 65 OID.
	_, _, s44, _ := generateMLDSAKey(rand.Reader, MLDSA44)
	b44, _ := s44.(*mldsa44.PrivateKey).MarshalBinary()
	in, _ := asn1.Marshal(b44)
	if _, _, err := ParseMLDSAPKCS8(enc(0, oid65, in)); err == nil {
		t.Error("level mismatch accepted")
	}
}

func TestExportPrivateKeyPKCS8Classical(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GenerateKey("ec", ECDSAP256); err != nil {
		t.Fatal(err)
	}
	der, err := s.ExportPrivateKeyPKCS8("ec")
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := s.PublicKey("ec")
	if !k.(*ecdsa.PrivateKey).PublicKey.Equal(pub) {
		t.Fatal("public key mismatch")
	}
	if _, err := s.ExportPrivateKeyPKCS8("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
}

func TestRouterExportPKCS8RefusesNonSoftware(t *testing.T) {
	soft := newTestStore(t)
	other := &nonExportStore{Store: soft}
	r, err := NewRouter("software", map[string]Store{"software": soft, "hsm": other})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := soft.GenerateKey("k1", MLDSA65); err != nil {
		t.Fatal(err)
	}
	if der, err := r.ExportPrivateKeyPKCS8("k1"); err != nil || len(der) == 0 {
		t.Fatalf("software export via router: %v", err)
	}
	r.mu.Lock()
	r.assign["k1"] = "hsm"
	r.mu.Unlock()
	if _, err := r.ExportPrivateKeyPKCS8("k1"); !errors.Is(err, ErrPrivateKeyNotExportable) {
		t.Fatalf("want ErrPrivateKeyNotExportable, got %v", err)
	}
}

// nonExportStore embeds only the Store interface, hiding ExportPrivateKeyPKCS8.
type nonExportStore struct{ Store }

var opensslSemver = regexp.MustCompile(`OpenSSL (\d+)\.(\d+)`)

func requireOpenSSL35(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed; skipping ML-DSA interop")
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Skipf("openssl version failed: %v", err)
	}
	m := opensslSemver.FindStringSubmatch(string(out))
	if m == nil {
		t.Skipf("cannot parse openssl version %q", out)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	if maj < 3 || (maj == 3 && min < 5) {
		t.Skipf("openssl %d.%d < 3.5 lacks ML-DSA; skipping interop", maj, min)
	}
	return bin
}

func TestMLDSAPKCS8OpenSSLInterop(t *testing.T) {
	bin := requireOpenSSL35(t)
	s := newTestStore(t)
	for _, algo := range mldsaLevels {
		for _, form := range []string{"expanded", "seed"} {
			t.Run(string(algo)+"/"+form, func(t *testing.T) {
				var der []byte
				var pub crypto.PublicKey
				if form == "expanded" {
					id := "ossl-" + string(algo)
					if _, err := s.GenerateKey(id, algo); err != nil {
						t.Fatal(err)
					}
					var err error
					if der, err = s.ExportPrivateKeyPKCS8(id); err != nil {
						t.Fatal(err)
					}
					pub, _ = s.PublicKey(id)
				} else {
					_, p, signer, _ := generateMLDSAKey(rand.Reader, algo)
					pub = p
					var err error
					if der, err = MarshalMLDSAPKCS8(signer); err != nil {
						t.Fatal(err)
					}
				}
				dir := t.TempDir()
				keyFile := filepath.Join(dir, "k.pem")
				if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(bin, "pkey", "-in", keyFile, "-noout", "-text_pub").CombinedOutput(); err != nil {
					t.Fatalf("openssl pkey -text_pub: %v\n%s", err, out)
				}
				pubPEM, err := exec.Command(bin, "pkey", "-in", keyFile, "-pubout").Output()
				if err != nil {
					t.Fatalf("openssl pkey -pubout: %v", err)
				}
				blk, _ := pem.Decode(pubPEM)
				if blk == nil {
					t.Fatal("no PUBLIC KEY from openssl")
				}
				pubRaw, _ := pub.(MLDSAPublicKey).MarshalBinary()
				oid, _ := MLDSAOIDForAlgo(algo)
				want, _ := asn1.Marshal(struct {
					Algo pkcs8AlgID
					Key  asn1.BitString
				}{pkcs8AlgID{oid}, asn1.BitString{Bytes: pubRaw, BitLength: 8 * len(pubRaw)}})
				if !bytes.Equal(blk.Bytes, want) {
					t.Fatal("SPKI from openssl differs from keystore public key")
				}

				// openssl signs with the exported key; circl verifies.
				msg := []byte("signed by openssl")
				msgFile, sigFile := filepath.Join(dir, "m"), filepath.Join(dir, "s")
				_ = os.WriteFile(msgFile, msg, 0o600)
				if out, err := exec.Command(bin, "pkeyutl", "-sign", "-rawin", "-inkey", keyFile, "-in", msgFile, "-out", sigFile).CombinedOutput(); err != nil {
					t.Fatalf("openssl pkeyutl -sign: %v\n%s", err, out)
				}
				sig, _ := os.ReadFile(sigFile)
				if !mldsaVerify(t, algo, pub, msg, sig) {
					t.Fatal("circl rejected openssl signature")
				}
			})
		}
	}
}
