// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"
)

type corpusCert struct {
	name string
	weak bool // ground truth from how the builder made the cert, never from the code under test
	cert *x509.Certificate
}

// buildWeakCryptoCorpus returns exactly 200 certificates (100 weak, 100 clean).
// Keys are synthetic (no keygen): the flag rules only read key size, algorithm
// and signature algorithm, and Go refuses to generate sub-1024-bit RSA anyway.
func buildWeakCryptoCorpus(now time.Time) []corpusCert {
	day := 24 * time.Hour
	var corpus []corpusCert

	rsaKey := func(bits int) *rsa.PublicKey {
		return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
	}
	base := func(sig x509.SignatureAlgorithm) *x509.Certificate {
		return &x509.Certificate{
			IsCA: true, SignatureAlgorithm: sig,
			NotBefore: now.Add(-30 * day), NotAfter: now.Add(200 * day),
		}
	}
	rsaCert := func(bits int, sig x509.SignatureAlgorithm) *x509.Certificate {
		c := base(sig)
		c.PublicKeyAlgorithm, c.PublicKey = x509.RSA, rsaKey(bits)
		return c
	}
	ecCert := func(curve elliptic.Curve) *x509.Certificate {
		c := base(x509.ECDSAWithSHA256)
		c.PublicKeyAlgorithm, c.PublicKey = x509.ECDSA, &ecdsa.PublicKey{Curve: curve}
		return c
	}
	add := func(prefix string, n int, weak bool, mk func() *x509.Certificate) {
		for i := 0; i < n; i++ {
			corpus = append(corpus, corpusCert{name: fmt.Sprintf("%s-%02d", prefix, i), weak: weak, cert: mk()})
		}
	}

	add("weak-rsa2048-sha1", 24, true, func() *x509.Certificate { return rsaCert(2048, x509.SHA1WithRSA) })
	add("weak-rsa2048-md5", 8, true, func() *x509.Certificate { return rsaCert(2048, x509.MD5WithRSA) })
	add("weak-ecdsa-sha1", 5, true, func() *x509.Certificate {
		c := ecCert(elliptic.P256())
		c.SignatureAlgorithm = x509.ECDSAWithSHA1
		return c
	})
	add("weak-dsa-sha1", 3, true, func() *x509.Certificate {
		c := base(x509.DSAWithSHA1)
		c.PublicKeyAlgorithm = x509.DSA
		return c
	})
	add("weak-rsa2048-md2", 2, true, func() *x509.Certificate { return rsaCert(2048, x509.MD2WithRSA) })
	add("weak-rsa1024", 25, true, func() *x509.Certificate { return rsaCert(1024, x509.SHA256WithRSA) })
	add("weak-rsa512", 8, true, func() *x509.Certificate { return rsaCert(512, x509.SHA256WithRSA) })
	add("weak-p224", 25, true, func() *x509.Certificate { return ecCert(elliptic.P224()) })

	add("clean-rsa2048", 20, false, func() *x509.Certificate { return rsaCert(2048, x509.SHA256WithRSA) })
	add("clean-rsa3072", 20, false, func() *x509.Certificate { return rsaCert(3072, x509.SHA256WithRSA) })
	add("clean-p256", 20, false, func() *x509.Certificate { return ecCert(elliptic.P256()) })
	add("clean-p384", 15, false, func() *x509.Certificate { return ecCert(elliptic.P384()) })
	add("clean-ed25519", 10, false, func() *x509.Certificate {
		c := base(x509.PureEd25519)
		c.PublicKeyAlgorithm, c.PublicKey = x509.Ed25519, ed25519.PublicKey(make([]byte, 32))
		return c
	})
	// ML-DSA subject keys are unparseable by crypto/x509: nil key, unknown algorithm.
	add("clean-pqc", 10, false, func() *x509.Certificate {
		c := base(x509.UnknownSignatureAlgorithm)
		c.PublicKeyAlgorithm = x509.UnknownPublicKeyAlgorithm
		return c
	})
	// Undated certs raise EXPIRED, which is not a weak-crypto flag.
	add("clean-undated", 5, false, func() *x509.Certificate {
		c := rsaCert(2048, x509.SHA256WithRSA)
		c.NotBefore, c.NotAfter = time.Time{}, time.Time{}
		return c
	})
	return corpus
}

func TestWeakCryptoFlagAccuracy(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	weakFlags := []string{"WEAK_SIGNATURE", "WEAK_RSA_KEY", "WEAK_EC_KEY"}

	corpus := buildWeakCryptoCorpus(now)
	weakTotal := 0
	for _, c := range corpus {
		if c.weak {
			weakTotal++
		}
	}
	if len(corpus) != 200 || weakTotal != 100 {
		t.Fatalf("corpus = %d certs (%d weak), want 200 (100 weak)", len(corpus), weakTotal)
	}

	var tp, fn, fp int
	for _, c := range corpus {
		flags := computeRiskFlags(c.cert, false, now)
		predicted := false
		for _, w := range weakFlags {
			if containsFlag(flags, w) {
				predicted = true
				break
			}
		}
		switch {
		case c.weak && predicted:
			tp++
		case c.weak && !predicted:
			fn++
			t.Errorf("false negative: %s flags=%v", c.name, flags)
		case !c.weak && predicted:
			fp++
			t.Errorf("false positive: %s flags=%v", c.name, flags)
		}
	}

	recall := 100 * float64(tp) / float64(tp+fn)
	precision := 100 * float64(tp) / float64(tp+fp)
	t.Logf("weak-crypto flag accuracy: corpus=%d recall=%.1f%% precision=%.1f%% (TP=%d FN=%d FP=%d)",
		len(corpus), recall, precision, tp, fn, fp)

	if fn != 0 {
		t.Errorf("recall %.1f%%, want 100%%", recall)
	}
	if fp > 2 {
		t.Errorf("false positives = %d, want <= 2 (precision %.1f%%)", fp, precision)
	}
}
